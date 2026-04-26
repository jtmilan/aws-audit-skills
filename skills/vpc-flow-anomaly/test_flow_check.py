# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "pytest>=8.0",
# ]
# ///
"""
Pytest test suite for VPC Flow Log Anomaly Detector.

Tests cover all detector functions using constructed FlowRecord objects
without requiring AWS credentials or mocking.
"""
from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta, timezone

import pytest

from flow_check import (
    Anomaly,
    BaselineStats,
    FlowRecord,
    detect_drop_matches,
    detect_east_west,
    detect_gaps,
    detect_top_talkers,
    is_private_ip,
    parse_flow_line,
)


# --------------------------------------------------------------------------
# TEST FIXTURES
# --------------------------------------------------------------------------


def make_flow_record(
    *,
    timestamp: datetime | None = None,
    src_addr: str = "10.0.1.1",
    dst_addr: str = "52.94.236.248",
    src_port: int = 49152,
    dst_port: int = 443,
    protocol: int = 6,
    bytes_transferred: int = 1000,
    action: str = "ACCEPT",
) -> FlowRecord:
    """Helper to create FlowRecord with sensible defaults."""
    if timestamp is None:
        timestamp = datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
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


# --------------------------------------------------------------------------
# REQUIRED TESTS (Architecture Section 8.2)
# --------------------------------------------------------------------------


def test_zscore_anomaly():
    """
    Verify top-talker detection with z-score > 5.

    Setup:
        - Baseline: IP 10.0.1.15 with mean=1000, stddev=100
        - Current: IP 10.0.1.15 with 1600 bytes (z-score = 6.0)

    Assert:
        - Returns exactly 1 anomaly
        - anomaly_type == "top_talker"
        - severity == "CRITICAL" (z > 5.0)
        - evidence["ip"] == "10.0.1.15"
        - evidence["zscore"] > 5.0
    """
    # Create baseline with mean=1000, stddev=100
    baseline_stats = {
        "10.0.1.15": BaselineStats(
            ip="10.0.1.15",
            mean_bytes=1000.0,
            stddev_bytes=100.0,
        ),
    }

    # Create current record with 1600 bytes (z-score = (1600-1000)/100 = 6.0)
    current_records = [
        make_flow_record(
            src_addr="10.0.1.15",
            bytes_transferred=1600,
        ),
    ]

    # Run detector
    anomalies = detect_top_talkers(current_records, baseline_stats)

    # Assertions
    assert len(anomalies) == 1
    anomaly = anomalies[0]
    assert anomaly.anomaly_type == "top_talker"
    assert anomaly.severity == "CRITICAL"  # z > 5.0
    assert anomaly.evidence["ip"] == "10.0.1.15"
    assert anomaly.evidence["zscore"] > 5.0


def test_drop_list_match():
    """
    Verify DROP list CIDR matching.

    Setup:
        - DROP CIDR: 185.56.80.0/22
        - Record: dst_addr=185.56.80.1, action=ACCEPT

    Assert:
        - Returns exactly 1 anomaly
        - anomaly_type == "drop_list"
        - severity == "CRITICAL"
        - evidence["matched_cidr"] == "185.56.80.0/22"
    """
    # Create DROP CIDR list
    drop_cidrs = [ipaddress.IPv4Network("185.56.80.0/22")]

    # Create record with destination in DROP list
    records = [
        make_flow_record(
            src_addr="10.0.2.10",
            dst_addr="185.56.80.1",
            dst_port=443,
            bytes_transferred=1258291,
            action="ACCEPT",
        ),
    ]

    # Run detector
    anomalies = detect_drop_matches(records, drop_cidrs)

    # Assertions
    assert len(anomalies) == 1
    anomaly = anomalies[0]
    assert anomaly.anomaly_type == "drop_list"
    assert anomaly.severity == "CRITICAL"
    assert anomaly.evidence["matched_cidr"] == "185.56.80.0/22"
    assert anomaly.evidence["dst_ip"] == "185.56.80.1"
    assert anomaly.evidence["src_ip"] == "10.0.2.10"


def test_gap_detection():
    """
    Verify flow log gap detection.

    Setup:
        - Record 1: timestamp = T
        - Record 2: timestamp = T + 30 minutes

    Assert:
        - Returns exactly 1 anomaly
        - anomaly_type == "gap"
        - evidence["gap_seconds"] == 1800
        - severity == "HIGH" (15-60 min range)
    """
    base_time = datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc)

    # Create records with 30-minute gap
    records = [
        make_flow_record(timestamp=base_time),
        make_flow_record(timestamp=base_time + timedelta(minutes=30)),
    ]

    # Run detector
    anomalies = detect_gaps(records)

    # Assertions
    assert len(anomalies) == 1
    anomaly = anomalies[0]
    assert anomaly.anomaly_type == "gap"
    assert anomaly.evidence["gap_seconds"] == 1800  # 30 minutes
    assert anomaly.severity == "HIGH"  # 15-60 min range


# --------------------------------------------------------------------------
# ADDITIONAL RECOMMENDED TESTS (Architecture Section 8.3)
# --------------------------------------------------------------------------


def test_east_west_ssh():
    """Verify east-west detection for SSH on private IPs."""
    records = [
        make_flow_record(
            src_addr="10.0.3.5",
            dst_addr="10.0.4.10",
            dst_port=22,
            protocol=6,
            bytes_transferred=512000,
            action="ACCEPT",
        ),
    ]

    anomalies = detect_east_west(records)

    assert len(anomalies) == 1
    anomaly = anomalies[0]
    assert anomaly.anomaly_type == "east_west"
    assert anomaly.severity == "MEDIUM"  # SSH is MEDIUM
    assert anomaly.evidence["port"] == 22
    assert anomaly.evidence["src_ip"] == "10.0.3.5"
    assert anomaly.evidence["dst_ip"] == "10.0.4.10"


def test_east_west_postgresql():
    """Verify east-west detection for PostgreSQL (HIGH severity)."""
    records = [
        make_flow_record(
            src_addr="10.0.5.1",
            dst_addr="10.0.6.2",
            dst_port=5432,
            protocol=6,
            action="ACCEPT",
        ),
    ]

    anomalies = detect_east_west(records)

    assert len(anomalies) == 1
    assert anomalies[0].severity == "HIGH"  # PostgreSQL is HIGH
    assert anomalies[0].evidence["port"] == 5432


def test_parse_flow_line_valid():
    """Verify flow line parsing produces correct FlowRecord."""
    line = "2 123456789012 eni-abc 10.0.1.5 52.94.236.248 443 49152 6 10 1000 1700000000 1700000060 ACCEPT OK"

    record = parse_flow_line(line)

    assert record is not None
    assert record.src_addr == "10.0.1.5"
    assert record.dst_addr == "52.94.236.248"
    assert record.src_port == 443
    assert record.dst_port == 49152
    assert record.protocol == 6
    assert record.bytes_transferred == 1000
    assert record.action == "ACCEPT"
    assert record.timestamp.year == 2023  # Unix epoch 1700000000


def test_parse_flow_line_header():
    """Verify header lines return None."""
    header = "version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status"

    result = parse_flow_line(header)

    assert result is None


def test_parse_flow_line_nodata():
    """Verify NODATA lines return None."""
    line = "2 123456789012 eni-abc - - - - - - - 1700000000 1700000060 NODATA OK"

    result = parse_flow_line(line)

    assert result is None


def test_is_private_ip():
    """Verify RFC 1918 detection for all three ranges."""
    # 10.0.0.0/8
    assert is_private_ip("10.0.0.1") is True
    assert is_private_ip("10.255.255.255") is True

    # 172.16.0.0/12
    assert is_private_ip("172.16.0.1") is True
    assert is_private_ip("172.31.255.255") is True
    assert is_private_ip("172.32.0.1") is False  # Outside /12

    # 192.168.0.0/16
    assert is_private_ip("192.168.0.1") is True
    assert is_private_ip("192.168.255.255") is True

    # Public IPs
    assert is_private_ip("8.8.8.8") is False
    assert is_private_ip("52.94.236.248") is False


def test_zscore_stddev_zero():
    """Verify z-score edge case when stddev=0."""
    # Baseline with stddev=0 (only one data point in history)
    baseline_stats = {
        "10.0.1.20": BaselineStats(
            ip="10.0.1.20",
            mean_bytes=1000.0,
            stddev_bytes=0.0,
        ),
    }

    # Current traffic different from mean
    current_records = [
        make_flow_record(
            src_addr="10.0.1.20",
            bytes_transferred=2000,
        ),
    ]

    anomalies = detect_top_talkers(current_records, baseline_stats)

    # Should flag as HIGH when stddev=0 and current differs from mean
    assert len(anomalies) == 1
    assert anomalies[0].severity == "HIGH"


def test_gap_critical_severity():
    """Verify gap > 60 minutes returns CRITICAL severity."""
    base_time = datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc)

    records = [
        make_flow_record(timestamp=base_time),
        make_flow_record(timestamp=base_time + timedelta(minutes=65)),
    ]

    anomalies = detect_gaps(records)

    assert len(anomalies) == 1
    assert anomalies[0].severity == "CRITICAL"
    assert anomalies[0].evidence["gap_seconds"] == 3900  # 65 minutes


def test_gap_medium_severity():
    """Verify gap > 5 minutes but < 15 minutes returns MEDIUM severity."""
    base_time = datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc)

    records = [
        make_flow_record(timestamp=base_time),
        make_flow_record(timestamp=base_time + timedelta(minutes=6)),
    ]

    anomalies = detect_gaps(records)

    assert len(anomalies) == 1
    assert anomalies[0].severity == "MEDIUM"


def test_drop_list_no_match_on_reject():
    """Verify DROP list does not match REJECT action records."""
    drop_cidrs = [ipaddress.IPv4Network("185.56.80.0/22")]

    records = [
        make_flow_record(
            dst_addr="185.56.80.1",
            action="REJECT",  # Should not match
        ),
    ]

    anomalies = detect_drop_matches(records, drop_cidrs)

    assert len(anomalies) == 0


def test_east_west_no_match_public_ip():
    """Verify east-west does not flag traffic with public IPs."""
    records = [
        make_flow_record(
            src_addr="10.0.3.5",
            dst_addr="8.8.8.8",  # Public IP
            dst_port=22,
            action="ACCEPT",
        ),
    ]

    anomalies = detect_east_west(records)

    assert len(anomalies) == 0


def test_zscore_high_severity():
    """Verify z-score > 3.0 but <= 5.0 returns HIGH severity."""
    baseline_stats = {
        "10.0.1.15": BaselineStats(
            ip="10.0.1.15",
            mean_bytes=1000.0,
            stddev_bytes=100.0,
        ),
    }

    # z-score = (1400-1000)/100 = 4.0 (HIGH range: >3.0, <=5.0)
    current_records = [
        make_flow_record(
            src_addr="10.0.1.15",
            bytes_transferred=1400,
        ),
    ]

    anomalies = detect_top_talkers(current_records, baseline_stats)

    assert len(anomalies) == 1
    assert anomalies[0].severity == "HIGH"


def test_zscore_medium_severity():
    """Verify z-score > 2.0 but <= 3.0 returns MEDIUM severity."""
    baseline_stats = {
        "10.0.1.15": BaselineStats(
            ip="10.0.1.15",
            mean_bytes=1000.0,
            stddev_bytes=100.0,
        ),
    }

    # z-score = (1250-1000)/100 = 2.5 (MEDIUM range: >2.0, <=3.0)
    current_records = [
        make_flow_record(
            src_addr="10.0.1.15",
            bytes_transferred=1250,
        ),
    ]

    anomalies = detect_top_talkers(current_records, baseline_stats)

    assert len(anomalies) == 1
    assert anomalies[0].severity == "MEDIUM"


def test_empty_records_no_anomalies():
    """Verify empty record lists produce no anomalies."""
    assert detect_gaps([]) == []
    assert detect_east_west([]) == []
    assert detect_drop_matches([], []) == []
    assert detect_top_talkers([], {}) == []
