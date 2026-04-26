# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "boto3>=1.34",
# ]
# ///

"""
CloudTrail Novel Country Login Detection
Detects ConsoleLogin events from countries or IPs not seen in the last 30 days.
"""

import argparse
import json
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

# Constants
CACHE_DIR: Path = Path.home() / ".cache" / "aws-audit-skills"
BASELINE_PATH: Path = CACHE_DIR / "novel-country-baseline.json"
BASELINE_TTL_DAYS: int = 30
DEFAULT_LOOKBACK_HOURS: int = 24


# Type Definitions
@dataclass(frozen=True, slots=True)
class LoginEvent:
    """Immutable representation of a CloudTrail ConsoleLogin event."""

    event_time: datetime
    principal: str  # userIdentity.principalId or userName
    source_ip: str
    country: str
    success: bool  # responseElements.ConsoleLogin == "Success"


@dataclass(frozen=True, slots=True)
class BaselineEntry:
    """An entry in the 30-day rolling baseline."""

    principal: str
    source_ip: str
    country: str
    timestamp: datetime  # When this (principal, ip, country) was last seen


@dataclass(frozen=True, slots=True)
class Finding:
    """A novel login finding to report."""

    event_time: datetime
    principal: str
    source_ip: str
    country: str
    severity: Literal["high", "med"]

    def __lt__(self, other: "Finding") -> bool:
        """Sort by severity (high first), then by event_time (newest first)."""
        severity_order = {"high": 0, "med": 1}
        if severity_order[self.severity] != severity_order[other.severity]:
            return severity_order[self.severity] < severity_order[other.severity]
        return self.event_time > other.event_time  # Newest first within same severity


# DRY_RUN_FIXTURES
DRY_RUN_FIXTURES: dict = {
    "lookup_events": {
        "Events": [
            {
                "EventTime": datetime(2024, 4, 26, 10, 0, 0, tzinfo=timezone.utc),
                "EventName": "ConsoleLogin",
                "Username": "alice",
                "CloudTrailEvent": json.dumps(
                    {
                        "userIdentity": {
                            "type": "IAMUser",
                            "principalId": "AIDAEXAMPLE1",
                            "userName": "alice",
                        },
                        "sourceIPAddress": "198.51.100.23",
                        "responseElements": {"ConsoleLogin": "Success"},
                    }
                ),
            },
            {
                "EventTime": datetime(2024, 4, 26, 9, 30, 0, tzinfo=timezone.utc),
                "EventName": "ConsoleLogin",
                "Username": "bob",
                "CloudTrailEvent": json.dumps(
                    {
                        "userIdentity": {
                            "type": "IAMUser",
                            "principalId": "AIDAEXAMPLE2",
                            "userName": "bob",
                        },
                        "sourceIPAddress": "203.0.113.50",
                        "responseElements": {"ConsoleLogin": "Success"},
                    }
                ),
            },
        ]
    },
    "geoip": {
        "198.51.100.23": "DE",  # Germany - novel country
        "203.0.113.50": "US",  # USA - known country, novel IP in dry-run baseline
        "192.0.2.100": "US",  # USA - known country, known IP (in baseline)
    },
    "baseline": {
        "version": 1,
        "entries": [
            {
                "principal": "AIDAEXAMPLE2",
                "source_ip": "192.0.2.100",
                "country": "US",
                "timestamp": "2024-04-20T08:00:00Z",
            }
        ],
    },
}


class BaselineManager:
    """Manages the 30-day rolling baseline of seen (principal, ip, country) tuples."""

    def __init__(
        self, baseline_path: Path = BASELINE_PATH, ttl_days: int = BASELINE_TTL_DAYS
    ):
        self.baseline_path = baseline_path
        self.ttl_days = ttl_days
        self._entries: list[BaselineEntry] = []
        self._loaded = False

    def load(self) -> None:
        """Load baseline from disk. Creates empty baseline if file doesn't exist."""
        if not self.baseline_path.exists():
            self._entries = []
            self._loaded = True
            return

        try:
            with open(self.baseline_path, "r") as f:
                data = json.load(f)
            self._entries = [
                BaselineEntry(
                    principal=e["principal"],
                    source_ip=e["source_ip"],
                    country=e["country"],
                    timestamp=datetime.fromisoformat(
                        e["timestamp"].replace("Z", "+00:00")
                    ),
                )
                for e in data.get("entries", [])
            ]
        except (json.JSONDecodeError, KeyError, ValueError):
            self._entries = []

        self._loaded = True

    def load_from_dict(self, data: dict) -> None:
        """Load baseline from dict (for dry-run mode)."""
        self._entries = [
            BaselineEntry(
                principal=e["principal"],
                source_ip=e["source_ip"],
                country=e["country"],
                timestamp=datetime.fromisoformat(e["timestamp"].replace("Z", "+00:00")),
            )
            for e in data.get("entries", [])
        ]
        self._loaded = True

    def save(self) -> None:
        """Save baseline to disk, pruning entries older than TTL."""
        self.baseline_path.parent.mkdir(parents=True, exist_ok=True)

        cutoff = datetime.now(timezone.utc) - timedelta(days=self.ttl_days)
        valid_entries = [e for e in self._entries if e.timestamp > cutoff]

        data = {
            "version": 1,
            "entries": [
                {
                    "principal": e.principal,
                    "source_ip": e.source_ip,
                    "country": e.country,
                    "timestamp": e.timestamp.isoformat().replace("+00:00", "Z"),
                }
                for e in valid_entries
            ],
        }

        # Atomic write: write to temp file, then rename
        temp_path = self.baseline_path.with_suffix(".tmp")
        with open(temp_path, "w") as f:
            json.dump(data, f, indent=2)
        temp_path.rename(self.baseline_path)

        self._entries = valid_entries

    def is_known_country(self, principal: str, country: str) -> bool:
        """Check if this principal has logged in from this country before."""
        return any(
            e.principal == principal and e.country == country for e in self._entries
        )

    def is_known_ip(self, principal: str, source_ip: str) -> bool:
        """Check if this principal has logged in from this IP before."""
        return any(
            e.principal == principal and e.source_ip == source_ip for e in self._entries
        )

    def add_entry(
        self, principal: str, source_ip: str, country: str, timestamp: datetime
    ) -> None:
        """Add or update an entry in the baseline."""
        # Remove existing entry for same (principal, ip) to update timestamp
        self._entries = [
            e
            for e in self._entries
            if not (e.principal == principal and e.source_ip == source_ip)
        ]
        self._entries.append(
            BaselineEntry(
                principal=principal, source_ip=source_ip, country=country, timestamp=timestamp
            )
        )


class GeoIPResolver:
    """Resolves IP addresses to country codes."""

    def __init__(self, fixtures: dict[str, str] | None = None):
        self._fixtures = fixtures or {}

    def resolve(self, ip: str) -> str:
        """
        Return 2-letter country code for IP.

        In fixture mode: looks up from fixtures dict.
        In production mode: returns "UNKNOWN" (real GeoIP out of scope).
        """
        if self._fixtures:
            return self._fixtures.get(ip, "UNKNOWN")
        return "UNKNOWN"


class NoveltyDetector:
    """Detects novel logins by comparing against baseline."""

    def __init__(self, baseline: BaselineManager):
        self.baseline = baseline

    def detect(self, events: list[LoginEvent]) -> list[Finding]:
        """
        Analyze login events and return findings for novel logins.

        Severity assignment:
        - "high": Novel country (principal never logged in from this country)
        - "med": Novel IP in known country (new IP, but country seen before)

        Returns sorted list: high severity first, then by event_time descending.
        """
        findings: list[Finding] = []

        for event in events:
            if not event.success:
                continue  # Only flag successful logins per PRD

            known_country = self.baseline.is_known_country(event.principal, event.country)
            known_ip = self.baseline.is_known_ip(event.principal, event.source_ip)

            if not known_country:
                # Novel country = high severity
                findings.append(
                    Finding(
                        event_time=event.event_time,
                        principal=event.principal,
                        source_ip=event.source_ip,
                        country=event.country,
                        severity="high",
                    )
                )
            elif not known_ip:
                # Known country but novel IP = medium severity
                findings.append(
                    Finding(
                        event_time=event.event_time,
                        principal=event.principal,
                        source_ip=event.source_ip,
                        country=event.country,
                        severity="med",
                    )
                )
            # else: known country AND known IP = no finding

            # Update baseline with this event
            self.baseline.add_entry(
                principal=event.principal,
                source_ip=event.source_ip,
                country=event.country,
                timestamp=event.event_time,
            )

        return sorted(findings)


def fetch_console_logins(
    client, lookback_hours: int, geoip_resolver: GeoIPResolver
) -> list[LoginEvent]:
    """
    Fetch ConsoleLogin events from CloudTrail LookupEvents API.

    Args:
        client: boto3 CloudTrail client (real or stubbed)
        lookback_hours: Hours of history to query
        geoip_resolver: Resolver for IP-to-country mapping

    Returns:
        List of LoginEvent dataclasses
    """
    events: list[LoginEvent] = []

    start_time = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)
    end_time = datetime.now(timezone.utc)

    paginator = client.get_paginator("lookup_events")
    page_iterator = paginator.paginate(
        LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": "ConsoleLogin"}],
        StartTime=start_time,
        EndTime=end_time,
    )

    for page in page_iterator:
        for event in page.get("Events", []):
            ct_event = json.loads(event.get("CloudTrailEvent", "{}"))

            user_identity = ct_event.get("userIdentity", {})
            principal = user_identity.get("principalId") or user_identity.get(
                "userName", "UNKNOWN"
            )
            source_ip = ct_event.get("sourceIPAddress", "UNKNOWN")

            response_elements = ct_event.get("responseElements", {})
            success = response_elements.get("ConsoleLogin") == "Success"

            country = geoip_resolver.resolve(source_ip)

            events.append(
                LoginEvent(
                    event_time=event["EventTime"],
                    principal=principal,
                    source_ip=source_ip,
                    country=country,
                    success=success,
                )
            )

    return events


def format_markdown_table(findings: list[Finding]) -> str:
    """
    Format findings as markdown table.

    Columns: event_time | principal | source_ip | country | severity
    """
    lines = [
        "# CloudTrail Novel Country Login Report",
        "",
        f"**Generated**: {datetime.now(timezone.utc).isoformat()}",
        "",
    ]

    if not findings:
        lines.append("No novel logins detected.")
        return "\n".join(lines)

    lines.extend(
        [
            f"**Findings**: {len(findings)} novel login(s) detected",
            "",
            "| event_time | principal | source_ip | country | severity |",
            "|------------|-----------|-----------|---------|----------|",
        ]
    )

    for f in findings:
        event_time_str = f.event_time.strftime("%Y-%m-%d %H:%M:%S UTC")
        lines.append(
            f"| {event_time_str} | {f.principal} | {f.source_ip} | {f.country} | {f.severity} |"
        )

    return "\n".join(lines)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(
        description="Detect ConsoleLogin events from novel countries or IPs"
    )
    parser.add_argument(
        "--lookback-hours",
        type=int,
        default=DEFAULT_LOOKBACK_HOURS,
        help=f"Hours of CloudTrail history to scan (default: {DEFAULT_LOOKBACK_HOURS})",
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Use fixture data instead of AWS APIs"
    )
    parser.add_argument(
        "--region", type=str, default=None, help="AWS region (uses boto3 default if not specified)"
    )

    args = parser.parse_args(argv)

    if args.lookback_hours < 1:
        parser.error("--lookback-hours must be at least 1")

    return args


def main(argv: list[str] | None = None) -> int:
    """
    CLI entry point.

    Returns:
        0: Success
        1: AWS/runtime error
    """
    args = parse_args(argv)

    try:
        baseline = BaselineManager()

        if args.dry_run:
            # Use fixture data
            baseline.load_from_dict(DRY_RUN_FIXTURES["baseline"])
            geoip = GeoIPResolver(fixtures=DRY_RUN_FIXTURES["geoip"])

            # Parse fixture events
            events = []
            for e in DRY_RUN_FIXTURES["lookup_events"]["Events"]:
                ct_event = json.loads(e["CloudTrailEvent"])
                user_identity = ct_event.get("userIdentity", {})
                principal = user_identity.get("principalId") or user_identity.get(
                    "userName", "UNKNOWN"
                )
                source_ip = ct_event.get("sourceIPAddress", "UNKNOWN")
                response_elements = ct_event.get("responseElements", {})
                success = response_elements.get("ConsoleLogin") == "Success"
                country = geoip.resolve(source_ip)

                events.append(
                    LoginEvent(
                        event_time=e["EventTime"],
                        principal=principal,
                        source_ip=source_ip,
                        country=country,
                        success=success,
                    )
                )
        else:
            # Real AWS mode
            baseline.load()
            geoip = GeoIPResolver()

            client_kwargs = {}
            if args.region:
                client_kwargs["region_name"] = args.region
            client = boto3.client("cloudtrail", **client_kwargs)

            events = fetch_console_logins(client, args.lookback_hours, geoip)

        # Detect novel logins
        detector = NoveltyDetector(baseline)
        findings = detector.detect(events)

        # Save updated baseline (skip in dry-run to avoid polluting cache)
        if not args.dry_run:
            baseline.save()

        # Output report
        report = format_markdown_table(findings)
        print(report)

        return 0

    except NoCredentialsError:
        print("Error: AWS credentials not configured.", file=sys.stderr)
        return 1
    except ClientError as e:
        print(f"Error: AWS API error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
