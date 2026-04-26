# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "boto3>=1.34",
#     "pytest>=8.0",
# ]
# ///

"""
Test suite for CloudTrail Novel Country Login Detection.
Tests detection logic, baseline management, and file creation.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from detect import (
    BaselineManager,
    Finding,
    GeoIPResolver,
    LoginEvent,
    NoveltyDetector,
)


def test_novel_country_detected():
    """Event from a new country is flagged as high severity."""
    # Setup baseline with only US logins for this principal
    baseline = BaselineManager()
    baseline.load_from_dict(
        {
            "version": 1,
            "entries": [
                {
                    "principal": "AIDATEST123",
                    "source_ip": "192.0.2.1",
                    "country": "US",
                    "timestamp": "2024-04-20T10:00:00Z",
                }
            ],
        }
    )

    # Create a login event from Germany (novel country)
    events = [
        LoginEvent(
            event_time=datetime(2024, 4, 26, 10, 0, 0, tzinfo=timezone.utc),
            principal="AIDATEST123",
            source_ip="198.51.100.50",
            country="DE",  # Novel country
            success=True,
        )
    ]

    detector = NoveltyDetector(baseline)
    findings = detector.detect(events)

    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert findings[0].country == "DE"
    assert findings[0].principal == "AIDATEST123"


def test_known_country_ignored():
    """Event from known country AND known IP produces no findings."""
    # Setup baseline with this exact (principal, ip, country) combination
    baseline = BaselineManager()
    baseline.load_from_dict(
        {
            "version": 1,
            "entries": [
                {
                    "principal": "AIDATEST456",
                    "source_ip": "203.0.113.50",
                    "country": "US",
                    "timestamp": "2024-04-20T10:00:00Z",
                }
            ],
        }
    )

    # Login from same IP, same country
    events = [
        LoginEvent(
            event_time=datetime(2024, 4, 26, 11, 0, 0, tzinfo=timezone.utc),
            principal="AIDATEST456",
            source_ip="203.0.113.50",
            country="US",
            success=True,
        )
    ]

    detector = NoveltyDetector(baseline)
    findings = detector.detect(events)

    assert len(findings) == 0


def test_baseline_auto_created_on_first_run(tmp_path):
    """Empty cache directory results in baseline file being created."""
    # Use temp directory for baseline
    baseline_path = tmp_path / "novel-country-baseline.json"

    # Verify file doesn't exist
    assert not baseline_path.exists()

    # Create baseline manager with custom path
    baseline = BaselineManager(baseline_path=baseline_path)
    baseline.load()

    # Add an entry and save (use current time to ensure it passes TTL filter)
    current_time = datetime.now(timezone.utc)
    baseline.add_entry(
        principal="AIDATEST789",
        source_ip="192.0.2.50",
        country="CA",
        timestamp=current_time,
    )
    baseline.save()

    # Verify file was created
    assert baseline_path.exists()

    # Verify content is valid JSON with expected structure
    with open(baseline_path) as f:
        data = json.load(f)

    assert data["version"] == 1
    assert len(data["entries"]) == 1
    assert data["entries"][0]["principal"] == "AIDATEST789"
    assert data["entries"][0]["country"] == "CA"
