# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "boto3>=1.34",
#     "requests>=2.31",
# ]
# ///
"""
VPC Flow Log Anomaly Detector.

Analyzes VPC Flow Logs from S3 for traffic anomalies including top-talker
outliers, DROP-list matches, suspicious east-west traffic, and flow log gaps.
Report-only - never auto-blocks traffic.
"""
from __future__ import annotations

import argparse
import gzip
import ipaddress
import statistics
import sys
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator, Literal

# --------------------------------------------------------------------------
# CONSTANTS
# --------------------------------------------------------------------------

INGRESS_ONLY_PORTS: frozenset[int] = frozenset({22, 3389, 5432})

RFC1918_NETWORKS: tuple[ipaddress.IPv4Network, ...] = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
)

# Cache directory: ~/.cache/aws-audit-skills
CACHE_DIR: Path = Path.home() / ".cache" / "aws-audit-skills"
DROP_LIST_URL: str = "https://www.spamhaus.org/drop/drop.txt"

GAP_THRESHOLD_SECONDS: int = 300  # 5 minutes
ZSCORE_THRESHOLD: float = 2.0

# --------------------------------------------------------------------------
# TYPE DEFINITIONS
# --------------------------------------------------------------------------

Severity = Literal["CRITICAL", "HIGH", "MEDIUM"]
AnomalyType = Literal["top_talker", "drop_list", "east_west", "gap"]


@dataclass(frozen=True, slots=True)
class FlowRecord:
    """Single VPC Flow Log record (version 2 default format)."""

    timestamp: datetime  # start field converted to datetime
    src_addr: str  # IPv4 dotted-quad
    dst_addr: str  # IPv4 dotted-quad
    src_port: int  # 0-65535
    dst_port: int  # 0-65535
    protocol: int  # 6=TCP, 17=UDP, 1=ICMP
    bytes_transferred: int  # bytes field
    action: str  # "ACCEPT" or "REJECT"


@dataclass(frozen=True, slots=True)
class Anomaly:
    """Detected traffic anomaly."""

    anomaly_type: AnomalyType
    severity: Severity
    evidence: dict[str, str | int | float]  # Type-specific evidence
    suggestion: str  # Recommended next step


@dataclass(frozen=True, slots=True)
class BaselineStats:
    """Per-IP traffic baseline statistics."""

    ip: str
    mean_bytes: float
    stddev_bytes: float


# --------------------------------------------------------------------------
# DROP LIST CACHE
# --------------------------------------------------------------------------


class DropListCache:
    """Fetches and caches Spamhaus DROP list with 24h TTL."""

    CACHE_PATH: Path = Path.home() / ".cache" / "aws-audit-skills" / "drop.txt"
    DROP_LIST_URL: str = "https://www.spamhaus.org/drop/drop.txt"
    TTL_SECONDS: int = 86400  # 24 hours

    def __init__(self, cache_path: Path | None = None) -> None:
        """Initialize cache. Uses default path if none provided."""
        self.cache_path = cache_path or self.CACHE_PATH

    def get_cidrs(self) -> list[ipaddress.IPv4Network]:
        """
        Returns list of DROP CIDRs. Fetches if cache missing/stale.

        Returns:
            List of IPv4Network objects for CIDR matching.

        Raises:
            RuntimeError: If fetch fails and no cached version exists.
        """
        if self._is_cache_valid():
            content = self.cache_path.read_text()
        else:
            try:
                content = self._fetch_and_cache()
            except Exception as e:
                # Try to use stale cache if available
                if self.cache_path.exists():
                    content = self.cache_path.read_text()
                else:
                    raise RuntimeError(
                        "Failed to fetch Spamhaus DROP list and no cached version available."
                    ) from e
        return self._parse_drop_list(content)

    def _is_cache_valid(self) -> bool:
        """Check if cache exists and mtime is within TTL."""
        if not self.cache_path.exists():
            return False
        mtime = self.cache_path.stat().st_mtime
        age = datetime.now().timestamp() - mtime
        return age < self.TTL_SECONDS

    def _fetch_and_cache(self) -> str:
        """Fetch DROP list from URL, write to cache, return content."""
        import requests

        response = requests.get(self.DROP_LIST_URL, timeout=30)
        response.raise_for_status()
        content = response.text

        # Ensure cache directory exists
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        self.cache_path.write_text(content)
        return content

    def _parse_drop_list(self, content: str) -> list[ipaddress.IPv4Network]:
        """Parse DROP list format: 'CIDR ; SBLnnnnn' per line."""
        cidrs: list[ipaddress.IPv4Network] = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith(";"):
                continue
            # Format: "CIDR ; SBLnnnnn" or just "CIDR"
            parts = line.split(";")
            cidr_str = parts[0].strip()
            try:
                cidrs.append(ipaddress.IPv4Network(cidr_str, strict=False))
            except ValueError:
                continue  # Skip invalid CIDRs
        return cidrs


# --------------------------------------------------------------------------
# FLOW LOG PARSER
# --------------------------------------------------------------------------


def parse_flow_line(line: str) -> FlowRecord | None:
    """
    Parse single VPC Flow Log line (version 2 default format).

    Args:
        line: Space-delimited flow log line.

    Returns:
        FlowRecord if valid data line, None for header/NODATA/SKIPDATA lines.

    Example:
        >>> parse_flow_line("2 123456789012 eni-abc 10.0.1.5 52.94.236.248 443 49152 6 10 1000 1700000000 1700000060 ACCEPT OK")
        FlowRecord(timestamp=datetime(2023, 11, 14, ...), src_addr='10.0.1.5', ...)
    """
    line = line.strip()
    if not line:
        return None

    parts = line.split()
    if len(parts) < 14:
        return None

    # Skip header lines and NODATA/SKIPDATA
    if parts[0] == "version" or parts[12] in ("NODATA", "SKIPDATA"):
        return None

    try:
        # Field mapping from VPC Flow Log default format (version 2)
        # Position: 0=version, 1=account-id, 2=interface-id, 3=srcaddr, 4=dstaddr
        # 5=srcport, 6=dstport, 7=protocol, 8=packets, 9=bytes, 10=start, 11=end
        # 12=action, 13=log-status
        timestamp = datetime.fromtimestamp(int(parts[10]), tz=timezone.utc)
        src_addr = parts[3]
        dst_addr = parts[4]
        src_port = int(parts[5])
        dst_port = int(parts[6])
        protocol = int(parts[7])
        bytes_transferred = int(parts[9])
        action = parts[12]

        return FlowRecord(
            timestamp=timestamp,
            src_addr=src_addr,
            dst_addr=dst_addr,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            bytes_transferred=bytes_transferred,
            action=action,
        )
    except (ValueError, IndexError):
        return None


def iter_flow_records(lines: Iterable[str]) -> Iterator[FlowRecord]:
    """
    Stream parse flow log lines into FlowRecord objects.

    Args:
        lines: Iterable of flow log lines (e.g., from file or S3 object).

    Yields:
        FlowRecord for each valid data line. Skips headers and invalid lines.
    """
    for line in lines:
        record = parse_flow_line(line)
        if record is not None:
            yield record


# --------------------------------------------------------------------------
# HELPER FUNCTIONS
# --------------------------------------------------------------------------


def is_private_ip(ip: str) -> bool:
    """Check if IP is in RFC 1918 private address space."""
    try:
        addr = ipaddress.IPv4Address(ip)
        return any(addr in network for network in RFC1918_NETWORKS)
    except ValueError:
        return False


def ip_in_cidrs(
    ip: str, cidrs: list[ipaddress.IPv4Network]
) -> ipaddress.IPv4Network | None:
    """
    Check if IP falls within any CIDR. Returns matching CIDR or None.

    Uses ipaddress.IPv4Address(ip) in network comparison.
    """
    try:
        addr = ipaddress.IPv4Address(ip)
        for cidr in cidrs:
            if addr in cidr:
                return cidr
    except ValueError:
        pass
    return None


# --------------------------------------------------------------------------
# DETECTORS
# --------------------------------------------------------------------------


def compute_baseline_stats(
    records: Iterable[FlowRecord],
) -> dict[str, BaselineStats]:
    """
    Compute per-IP mean and stddev of bytes transferred.

    Args:
        records: Flow records from baseline period (e.g., 7 days).

    Returns:
        Dict mapping IP address to BaselineStats.
    """
    ip_bytes: dict[str, list[int]] = defaultdict(list)
    for record in records:
        ip_bytes[record.src_addr].append(record.bytes_transferred)

    result: dict[str, BaselineStats] = {}
    for ip, byte_list in ip_bytes.items():
        if len(byte_list) < 2:
            # Can't compute stddev with < 2 samples; use 0
            mean = float(byte_list[0]) if byte_list else 0.0
            stddev = 0.0
        else:
            mean = statistics.mean(byte_list)
            stddev = statistics.stdev(byte_list)
        result[ip] = BaselineStats(ip=ip, mean_bytes=mean, stddev_bytes=stddev)
    return result


def detect_top_talkers(
    current_records: list[FlowRecord],
    baseline_stats: dict[str, BaselineStats],
    zscore_threshold: float = ZSCORE_THRESHOLD,
) -> list[Anomaly]:
    """
    Detect IPs with traffic volume z-score above threshold.

    Args:
        current_records: Flow records from analysis period.
        baseline_stats: Pre-computed baseline statistics per IP.
        zscore_threshold: Z-score threshold for flagging (default 2.0).

    Returns:
        List of Anomaly objects with type="top_talker".

    Severity mapping:
        - z > 5.0: CRITICAL
        - z > 3.0: HIGH
        - z > 2.0: MEDIUM

    Edge case: If stddev=0 and current != mean, severity=HIGH.
    """
    # Aggregate current bytes by IP
    ip_current_bytes: dict[str, int] = defaultdict(int)
    for record in current_records:
        ip_current_bytes[record.src_addr] += record.bytes_transferred

    anomalies: list[Anomaly] = []
    for ip, current_bytes in ip_current_bytes.items():
        if ip not in baseline_stats:
            continue

        stats = baseline_stats[ip]
        mean = stats.mean_bytes
        stddev = stats.stddev_bytes

        # Handle edge case: stddev = 0
        if stddev == 0:
            if current_bytes != mean:
                # Flag as HIGH when we can't compute z-score but traffic differs
                anomalies.append(
                    Anomaly(
                        anomaly_type="top_talker",
                        severity="HIGH",
                        evidence={
                            "ip": ip,
                            "bytes_24h": current_bytes,
                            "baseline_mean": mean,
                            "baseline_stddev": stddev,
                            "zscore": float("inf"),
                        },
                        suggestion="Investigate workload; baseline has zero variance",
                    )
                )
            continue

        zscore = (current_bytes - mean) / stddev

        if zscore <= zscore_threshold:
            continue

        # Determine severity
        if zscore > 5.0:
            severity: Severity = "CRITICAL"
        elif zscore > 3.0:
            severity = "HIGH"
        else:
            severity = "MEDIUM"

        anomalies.append(
            Anomaly(
                anomaly_type="top_talker",
                severity=severity,
                evidence={
                    "ip": ip,
                    "bytes_24h": current_bytes,
                    "baseline_mean": mean,
                    "baseline_stddev": stddev,
                    "zscore": round(zscore, 2),
                },
                suggestion="Investigate workload; consider rate limiting",
            )
        )

    return anomalies


def detect_drop_matches(
    records: list[FlowRecord],
    drop_cidrs: list[ipaddress.IPv4Network],
) -> list[Anomaly]:
    """
    Detect outbound traffic to Spamhaus DROP-listed IPs.

    Args:
        records: Flow records to analyze.
        drop_cidrs: List of DROP CIDR networks.

    Returns:
        List of Anomaly objects with type="drop_list", severity="CRITICAL".

    Only matches ACCEPT records where dst_addr falls within a DROP CIDR.
    """
    anomalies: list[Anomaly] = []
    for record in records:
        if record.action != "ACCEPT":
            continue

        matched_cidr = ip_in_cidrs(record.dst_addr, drop_cidrs)
        if matched_cidr is not None:
            anomalies.append(
                Anomaly(
                    anomaly_type="drop_list",
                    severity="CRITICAL",
                    evidence={
                        "src_ip": record.src_addr,
                        "dst_ip": record.dst_addr,
                        "dst_port": record.dst_port,
                        "bytes": record.bytes_transferred,
                        "matched_cidr": str(matched_cidr),
                    },
                    suggestion="Block egress to this CIDR; investigate potential compromise",
                )
            )

    return anomalies


def detect_east_west(records: list[FlowRecord]) -> list[Anomaly]:
    """
    Detect internal traffic on ingress-only ports.

    Args:
        records: Flow records to analyze.

    Returns:
        List of Anomaly objects with type="east_west".

    Flags when:
        - src_addr is private AND dst_addr is private
        - dst_port in INGRESS_ONLY_PORTS
        - action == "ACCEPT"

    Severity mapping:
        - Port 5432 (PostgreSQL): HIGH
        - Port 22, 3389 (SSH, RDP): MEDIUM
    """
    anomalies: list[Anomaly] = []
    for record in records:
        if record.action != "ACCEPT":
            continue

        if not is_private_ip(record.src_addr) or not is_private_ip(record.dst_addr):
            continue

        if record.dst_port not in INGRESS_ONLY_PORTS:
            continue

        # Determine severity based on port
        if record.dst_port == 5432:
            severity: Severity = "HIGH"
            suggestion = "Verify legitimate database access; consider restricting"
        elif record.dst_port == 22:
            severity = "MEDIUM"
            suggestion = "Verify legitimate SSH; consider bastion pattern"
        else:  # 3389 RDP
            severity = "MEDIUM"
            suggestion = "Verify legitimate RDP; consider restricting"

        # Protocol number to name
        protocol_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(
            record.protocol, str(record.protocol)
        )

        anomalies.append(
            Anomaly(
                anomaly_type="east_west",
                severity=severity,
                evidence={
                    "src_ip": record.src_addr,
                    "dst_ip": record.dst_addr,
                    "port": record.dst_port,
                    "protocol": protocol_name,
                    "bytes": record.bytes_transferred,
                },
                suggestion=suggestion,
            )
        )

    return anomalies


def detect_gaps(records: list[FlowRecord]) -> list[Anomaly]:
    """
    Detect missing flow log intervals.

    Args:
        records: Flow records to analyze (will be sorted by timestamp).

    Returns:
        List of Anomaly objects with type="gap".

    Flags gaps > GAP_THRESHOLD_SECONDS between consecutive records.

    Severity mapping:
        - gap > 3600s (60 min): CRITICAL
        - gap > 900s (15 min): HIGH
        - gap > 300s (5 min): MEDIUM
    """
    if len(records) < 2:
        return []

    sorted_records = sorted(records, key=lambda r: r.timestamp)
    anomalies: list[Anomaly] = []

    for i in range(1, len(sorted_records)):
        prev = sorted_records[i - 1]
        curr = sorted_records[i]

        gap_seconds = (curr.timestamp - prev.timestamp).total_seconds()

        if gap_seconds <= GAP_THRESHOLD_SECONDS:
            continue

        # Determine severity
        if gap_seconds > 3600:
            severity: Severity = "CRITICAL"
        elif gap_seconds > 900:
            severity = "HIGH"
        else:
            severity = "MEDIUM"

        anomalies.append(
            Anomaly(
                anomaly_type="gap",
                severity=severity,
                evidence={
                    "start_time": prev.timestamp.isoformat(),
                    "end_time": curr.timestamp.isoformat(),
                    "gap_seconds": int(gap_seconds),
                },
                suggestion="Check Flow Log configuration; verify ENI attachment",
            )
        )

    return anomalies


# --------------------------------------------------------------------------
# S3 CLIENT
# --------------------------------------------------------------------------


class FlowLogS3Client:
    """Read VPC Flow Logs from S3."""

    def __init__(
        self,
        vpc_id: str,
        s3_client: Any = None,  # boto3 S3 client (injected for testing)
        ec2_client: Any = None,  # boto3 EC2 client (injected for testing)
    ) -> None:
        """Initialize with VPC ID. Creates boto3 clients if not injected."""
        import boto3

        self.vpc_id = vpc_id
        self.s3_client = s3_client or boto3.client("s3")
        self.ec2_client = ec2_client or boto3.client("ec2")
        self._bucket: str | None = None
        self._prefix: str | None = None

    def get_flow_log_bucket(self) -> tuple[str, str]:
        """
        Discover S3 bucket and prefix for VPC flow logs.

        Returns:
            Tuple of (bucket_name, key_prefix).

        Raises:
            RuntimeError: If no S3-destination flow log configured for VPC.
        """
        if self._bucket is not None and self._prefix is not None:
            return self._bucket, self._prefix

        response = self.ec2_client.describe_flow_logs(
            Filters=[{"Name": "resource-id", "Values": [self.vpc_id]}]
        )

        for flow_log in response.get("FlowLogs", []):
            if flow_log.get("LogDestinationType") == "s3":
                destination = flow_log.get("LogDestination", "")
                # Format: arn:aws:s3:::bucket-name/prefix or arn:aws:s3:::bucket-name
                if destination.startswith("arn:aws:s3:::"):
                    path = destination[len("arn:aws:s3:::") :]
                    if "/" in path:
                        self._bucket, self._prefix = path.split("/", 1)
                    else:
                        self._bucket = path
                        self._prefix = ""
                    return self._bucket, self._prefix

        raise RuntimeError(
            f"No S3-destination flow logs configured for VPC {self.vpc_id}."
        )

    def list_log_objects(
        self,
        start_time: datetime,
        end_time: datetime,
    ) -> Iterator[str]:
        """
        List S3 object keys for flow logs in time range.

        Args:
            start_time: Start of analysis window.
            end_time: End of analysis window.

        Yields:
            S3 object keys matching the time range.
        """
        bucket, prefix = self.get_flow_log_bucket()

        # Build date-based prefixes to search
        current = start_time
        while current <= end_time:
            date_prefix = current.strftime("%Y/%m/%d/")
            full_prefix = f"{prefix}/{date_prefix}" if prefix else date_prefix

            paginator = self.s3_client.get_paginator("list_objects_v2")
            for page in paginator.paginate(Bucket=bucket, Prefix=full_prefix):
                for obj in page.get("Contents", []):
                    yield obj["Key"]

            current += timedelta(days=1)

    def iter_records(
        self,
        start_time: datetime,
        end_time: datetime,
    ) -> Iterator[FlowRecord]:
        """
        Stream flow records from S3 for time range.

        Handles pagination and gzip decompression.
        """
        bucket, _ = self.get_flow_log_bucket()

        for key in self.list_log_objects(start_time, end_time):
            response = self.s3_client.get_object(Bucket=bucket, Key=key)
            body = response["Body"].read()

            # Decompress if gzipped
            if key.endswith(".gz"):
                body = gzip.decompress(body)

            lines = body.decode("utf-8").splitlines()
            for record in iter_flow_records(lines):
                # Filter by time range
                if start_time <= record.timestamp <= end_time:
                    yield record


# --------------------------------------------------------------------------
# FIXTURES
# --------------------------------------------------------------------------


class FixtureProvider:
    """Provides deterministic test data for --dry-run mode."""

    @staticmethod
    def get_current_records() -> list[FlowRecord]:
        """
        Returns fixture flow records with known anomalies:
        - Top talker: 10.0.1.15 with 50GB (z-score ~9.0)
        - DROP match: 10.0.2.10 -> 185.56.80.1:443
        - East-west: 10.0.3.5 -> 10.0.4.10:22
        - Gap: 30-minute gap in timestamps
        """
        base_time = datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc)

        return [
            # Normal traffic record (before gap)
            FlowRecord(
                timestamp=base_time,
                src_addr="10.0.1.10",
                dst_addr="52.94.236.248",
                src_port=49152,
                dst_port=443,
                protocol=6,
                bytes_transferred=1000000,
                action="ACCEPT",
            ),
            # Top talker: 50GB transferred
            FlowRecord(
                timestamp=base_time + timedelta(minutes=1),
                src_addr="10.0.1.15",
                dst_addr="52.94.236.248",
                src_port=49153,
                dst_port=443,
                protocol=6,
                bytes_transferred=53_687_091_200,  # 50GB
                action="ACCEPT",
            ),
            # DROP list match: traffic to known-bad IP
            FlowRecord(
                timestamp=base_time + timedelta(minutes=2),
                src_addr="10.0.2.10",
                dst_addr="185.56.80.1",
                src_port=49154,
                dst_port=443,
                protocol=6,
                bytes_transferred=1258291,
                action="ACCEPT",
            ),
            # East-west SSH traffic
            FlowRecord(
                timestamp=base_time + timedelta(minutes=3),
                src_addr="10.0.3.5",
                dst_addr="10.0.4.10",
                src_port=49155,
                dst_port=22,
                protocol=6,
                bytes_transferred=512000,
                action="ACCEPT",
            ),
            # Record after 30-minute gap (creates gap anomaly)
            FlowRecord(
                timestamp=base_time + timedelta(minutes=33),
                src_addr="10.0.1.10",
                dst_addr="52.94.236.248",
                src_port=49156,
                dst_port=443,
                protocol=6,
                bytes_transferred=500000,
                action="ACCEPT",
            ),
            # East-west PostgreSQL traffic
            FlowRecord(
                timestamp=base_time + timedelta(minutes=34),
                src_addr="10.0.5.1",
                dst_addr="10.0.6.2",
                src_port=49157,
                dst_port=5432,
                protocol=6,
                bytes_transferred=250000,
                action="ACCEPT",
            ),
        ]

    @staticmethod
    def get_baseline_stats() -> dict[str, BaselineStats]:
        """
        Returns fixture baseline with:
        - 10.0.1.15: mean=5GB, stddev=0.5GB (makes 50GB a z-score of ~90)
        """
        return {
            "10.0.1.15": BaselineStats(
                ip="10.0.1.15",
                mean_bytes=5_368_709_120,  # 5GB
                stddev_bytes=536_870_912,  # 0.5GB
            ),
            "10.0.1.10": BaselineStats(
                ip="10.0.1.10",
                mean_bytes=1_000_000,
                stddev_bytes=100_000,
            ),
            "10.0.2.10": BaselineStats(
                ip="10.0.2.10",
                mean_bytes=500_000,
                stddev_bytes=50_000,
            ),
        }

    @staticmethod
    def get_drop_cidrs() -> list[ipaddress.IPv4Network]:
        """
        Returns fixture DROP CIDRs:
        - 185.56.80.0/22 (matches fixture DROP record)
        - 193.169.252.0/24
        - 5.188.10.0/24
        """
        return [
            ipaddress.IPv4Network("185.56.80.0/22"),
            ipaddress.IPv4Network("193.169.252.0/24"),
            ipaddress.IPv4Network("5.188.10.0/24"),
        ]


# --------------------------------------------------------------------------
# REPORT GENERATOR
# --------------------------------------------------------------------------


def _format_bytes(n: int | float) -> str:
    """Format bytes as human-readable string (e.g., '1.5 GB')."""
    n = float(n)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(n) < 1024.0:
            return f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} PB"


def _format_anomaly_table(
    anomalies: list[Anomaly],
    anomaly_type: AnomalyType,
) -> str:
    """Generate markdown table for specific anomaly type."""
    filtered = [a for a in anomalies if a.anomaly_type == anomaly_type]

    if not filtered:
        return "_No anomalies detected._\n"

    if anomaly_type == "top_talker":
        lines = [
            "| IP Address | Bytes (24h) | 7-Day Mean | Z-Score | Severity | Suggested Next Step |",
            "|------------|-------------|------------|---------|----------|---------------------|",
        ]
        for a in filtered:
            e = a.evidence
            lines.append(
                f"| {e['ip']} | {_format_bytes(e['bytes_24h'])} | "
                f"{_format_bytes(e['baseline_mean'])} | {e['zscore']} | "
                f"{a.severity} | {a.suggestion} |"
            )

    elif anomaly_type == "drop_list":
        lines = [
            "| Source IP | Dest IP | Dest Port | Bytes | Severity | Suggested Next Step |",
            "|-----------|---------|-----------|-------|----------|---------------------|",
        ]
        for a in filtered:
            e = a.evidence
            lines.append(
                f"| {e['src_ip']} | {e['dst_ip']} | {e['dst_port']} | "
                f"{_format_bytes(e['bytes'])} | {a.severity} | {a.suggestion} |"
            )

    elif anomaly_type == "east_west":
        lines = [
            "| Source IP | Dest IP | Port | Protocol | Bytes | Severity | Suggested Next Step |",
            "|-----------|---------|------|----------|-------|----------|---------------------|",
        ]
        for a in filtered:
            e = a.evidence
            lines.append(
                f"| {e['src_ip']} | {e['dst_ip']} | {e['port']} | "
                f"{e['protocol']} | {_format_bytes(e['bytes'])} | {a.severity} | {a.suggestion} |"
            )

    elif anomaly_type == "gap":
        lines = [
            "| Start Time | End Time | Gap Duration | Severity | Suggested Next Step |",
            "|------------|----------|--------------|----------|---------------------|",
        ]
        for a in filtered:
            e = a.evidence
            gap_mins = int(e["gap_seconds"]) // 60
            lines.append(
                f"| {e['start_time']} | {e['end_time']} | {gap_mins} min | "
                f"{a.severity} | {a.suggestion} |"
            )

    else:
        return "_Unknown anomaly type._\n"

    return "\n".join(lines) + "\n"


def generate_report(
    vpc_id: str,
    start_time: datetime,
    end_time: datetime,
    anomalies: list[Anomaly],
    dry_run: bool = False,
) -> str:
    """
    Generate markdown report from anomalies.

    Args:
        vpc_id: VPC identifier.
        start_time: Analysis window start.
        end_time: Analysis window end.
        anomalies: All detected anomalies.
        dry_run: Whether running in dry-run mode.

    Returns:
        Complete markdown report string.
    """
    mode = "Dry-Run" if dry_run else "Live"

    # Count by severity
    critical_count = sum(1 for a in anomalies if a.severity == "CRITICAL")
    high_count = sum(1 for a in anomalies if a.severity == "HIGH")
    medium_count = sum(1 for a in anomalies if a.severity == "MEDIUM")
    total_count = len(anomalies)

    report_lines = [
        "# VPC Flow Anomaly Report",
        "",
        f"**VPC**: {vpc_id}",
        f"**Analysis Period**: {start_time.isoformat()} to {end_time.isoformat()}",
        f"**Mode**: {mode}",
        "",
        "## Top Talker Anomalies",
        "",
        "IPs with traffic volume z-score > 2.0 vs 7-day baseline.",
        "",
        _format_anomaly_table(anomalies, "top_talker"),
        "",
        "## DROP List Matches",
        "",
        "Outbound traffic to Spamhaus DROP-listed IP ranges.",
        "",
        _format_anomaly_table(anomalies, "drop_list"),
        "",
        "## Suspicious East-West Traffic",
        "",
        "Internal traffic on ports typically ingress-only (22, 3389, 5432).",
        "",
        _format_anomaly_table(anomalies, "east_west"),
        "",
        "## Flow Log Gaps",
        "",
        "Detected missing log intervals (>5 min gap between records).",
        "",
        _format_anomaly_table(anomalies, "gap"),
        "",
        "## Summary",
        "",
        f"- **Total Anomalies**: {total_count}",
        f"- **Critical**: {critical_count}",
        f"- **High**: {high_count}",
        f"- **Medium**: {medium_count}",
        "",
    ]

    return "\n".join(report_lines)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """
    Parse command-line arguments.

    Arguments:
        --vpc-id VPC_ID    : VPC ID to analyze (required unless --dry-run)
        --lookback-hours N : Hours of logs to analyze (default: 24)
        --dry-run          : Use fixture data, no AWS calls

    Returns:
        Namespace with: vpc_id (str|None), lookback_hours (int), dry_run (bool)

    Validation:
        - If not dry_run and vpc_id is None: parser.error()
    """
    parser = argparse.ArgumentParser(
        description="Analyze VPC Flow Logs for traffic anomalies."
    )
    parser.add_argument(
        "--vpc-id",
        metavar="VPC_ID",
        help="VPC ID to analyze (required unless --dry-run)",
    )
    parser.add_argument(
        "--lookback-hours",
        metavar="N",
        type=int,
        default=24,
        help="Hours of logs to analyze (default: 24)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Use fixture data, no AWS calls",
    )

    args = parser.parse_args(argv)

    # Validate: vpc-id required unless dry-run
    if not args.dry_run and not args.vpc_id:
        parser.error("--vpc-id is required unless --dry-run is specified")

    return args


def main(argv: list[str] | None = None) -> int:
    """
    Entry point for CLI.

    Flow:
    1. Parse arguments
    2. If dry_run: use FixtureProvider
    3. Else: use FlowLogS3Client to fetch records
    4. Run all detectors
    5. Generate and print report
    6. Return 0 on success, 1 on error
    """
    args = parse_args(argv)

    end_time = datetime.now(tz=timezone.utc)
    start_time = end_time - timedelta(hours=args.lookback_hours)

    try:
        if args.dry_run:
            # Use fixture data
            vpc_id = args.vpc_id or "vpc-dry-run"
            records = FixtureProvider.get_current_records()
            baseline_stats = FixtureProvider.get_baseline_stats()
            drop_cidrs = FixtureProvider.get_drop_cidrs()
        else:
            # Use live AWS data
            vpc_id = args.vpc_id
            client = FlowLogS3Client(vpc_id)
            records = list(client.iter_records(start_time, end_time))

            # Compute baseline from 7 days of data
            baseline_start = start_time - timedelta(days=7)
            baseline_records = list(client.iter_records(baseline_start, start_time))
            baseline_stats = compute_baseline_stats(baseline_records)

            # Fetch DROP list
            cache = DropListCache()
            drop_cidrs = cache.get_cidrs()

        # Run all detectors
        anomalies: list[Anomaly] = []
        anomalies.extend(detect_top_talkers(records, baseline_stats))
        anomalies.extend(detect_drop_matches(records, drop_cidrs))
        anomalies.extend(detect_east_west(records))
        anomalies.extend(detect_gaps(records))

        # Generate and print report
        report = generate_report(
            vpc_id=vpc_id,
            start_time=start_time,
            end_time=end_time,
            anomalies=anomalies,
            dry_run=args.dry_run,
        )
        print(report)

        return 0

    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        # Handle boto3 exceptions
        error_str = str(e)
        if "NoCredentialsError" in type(e).__name__:
            print(
                "Error: AWS credentials not found. Configure via AWS CLI or environment.",
                file=sys.stderr,
            )
        elif "AccessDenied" in error_str:
            print(f"Error: Access denied. Check IAM permissions.", file=sys.stderr)
        elif "InvalidVpcID" in error_str or "InvalidVpcId" in error_str:
            print(
                f"Error: VPC {args.vpc_id} not found or not accessible.",
                file=sys.stderr,
            )
        else:
            print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
