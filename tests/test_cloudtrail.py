"""
test_cloudtrail.py — Tests for CloudTrailAnalyzer

All tests are offline and do not contact AWS CloudTrail.
"""

import json

from src.cloudtrail_analyzer import CloudTrailAnalyzer


# =========================================================
# Initialization
# =========================================================

def test_cloudtrail_init():
    """Test CloudTrail analyzer initialization."""

    analyzer = CloudTrailAnalyzer(days=30)

    assert analyzer.cloudtrail is not None
    assert analyzer.days == 30


def test_cloudtrail_default_days():
    """Test analyzer initialization with default days."""

    analyzer = CloudTrailAnalyzer()

    assert analyzer.cloudtrail is not None
    assert analyzer.days > 0


def test_cloudtrail_custom_days():
    """Test different analysis periods."""

    analyzer = CloudTrailAnalyzer(days=7)

    assert analyzer.days == 7


def test_cloudtrail_large_days():
    """Test a larger CloudTrail analysis period."""

    analyzer = CloudTrailAnalyzer(days=365)

    assert analyzer.days == 365


# =========================================================
# _extract_actions()
# =========================================================

def test_extract_actions_empty_events():
    """Empty event list should return no actions."""

    analyzer = CloudTrailAnalyzer()

    actions = analyzer._extract_actions([])

    assert actions == []


def test_extract_actions_requires_event_source():
    """EventName alone is not enough — service:Action needs EventSource too."""

    analyzer = CloudTrailAnalyzer()

    events = [
        {"EventName": "GetObject"}
    ]

    assert analyzer._extract_actions(events) == []


def test_extract_actions_with_source():
    """CloudTrail events should produce service-qualified IAM actions."""

    analyzer = CloudTrailAnalyzer()

    events = [
        {
            "EventName": "GetObject",
            "EventSource": "s3.amazonaws.com",
        },
        {
            "EventName": "PutObject",
            "EventSource": "s3.amazonaws.com",
        },
    ]

    actions = analyzer._extract_actions(events)

    assert actions == ["s3:GetObject", "s3:PutObject"]


def test_extract_actions_applies_iam_override():
    """ListBuckets event name maps to the real IAM action ListAllMyBuckets."""

    analyzer = CloudTrailAnalyzer()

    events = [
        {
            "EventName": "ListBuckets",
            "EventSource": "s3.amazonaws.com",
        }
    ]

    assert analyzer._extract_actions(events) == [
        "s3:ListAllMyBuckets"
    ]


def test_extract_actions_none_event_name():
    """An event with EventName=None should produce no action."""

    analyzer = CloudTrailAnalyzer()

    events = [
        {
            "EventName": None,
            "EventSource": "s3.amazonaws.com",
        }
    ]

    assert analyzer._extract_actions(events) == []


def test_extract_actions_empty_event_name():
    """An event with an empty EventName should produce no action."""

    analyzer = CloudTrailAnalyzer()

    events = [
        {
            "EventName": "",
            "EventSource": "s3.amazonaws.com",
        }
    ]

    assert analyzer._extract_actions(events) == []


# =========================================================
# _extract_source_ips()
# =========================================================

def test_extract_source_ips_returns_set():
    """Source IP extraction should return a set."""

    analyzer = CloudTrailAnalyzer()

    ips = analyzer._extract_source_ips([])

    assert isinstance(ips, set)
    assert ips == set()


def test_extract_source_ips_dedup_is_a_set():
    """Duplicate source IPs should be deduplicated."""

    analyzer = CloudTrailAnalyzer()

    events = [
        {
            "CloudTrailEvent": (
                '{"sourceIPAddress": "192.168.1.1"}'
            )
        },
        {
            "CloudTrailEvent": (
                '{"sourceIPAddress": "192.168.1.1"}'
            )
        },
    ]

    ips = analyzer._extract_source_ips(events)

    assert ips == {"192.168.1.1"}


def test_extract_source_ips_missing_field():
    """An event without sourceIPAddress should produce no IP."""

    analyzer = CloudTrailAnalyzer()

    events = [
        {
            "CloudTrailEvent": json.dumps({
                "eventName": "GetObject",
                "eventSource": "s3.amazonaws.com",
            })
        }
    ]

    ips = analyzer._extract_source_ips(events)

    assert isinstance(ips, set)
    assert ips == set()


def test_extract_source_ips_multiple_ips():
    """Test extraction of several unique IP addresses."""

    analyzer = CloudTrailAnalyzer()

    events = [
        {
            "CloudTrailEvent": (
                '{"sourceIPAddress": "192.168.1.1"}'
            )
        },
        {
            "CloudTrailEvent": (
                '{"sourceIPAddress": "10.0.0.1"}'
            )
        },
        {
            "CloudTrailEvent": (
                '{"sourceIPAddress": "172.16.0.1"}'
            )
        },
    ]

    ips = analyzer._extract_source_ips(events)

    assert ips == {
        "192.168.1.1",
        "10.0.0.1",
        "172.16.0.1",
    }


# =========================================================
# Combined event edge cases
# =========================================================

def test_multiple_events_with_duplicates():
    """Test deduplication across actions and IP addresses."""

    analyzer = CloudTrailAnalyzer()

    events = [
        {
            "EventName": "GetObject",
            "EventSource": "s3.amazonaws.com",
            "CloudTrailEvent": json.dumps({
                "sourceIPAddress": "10.0.0.1"
            }),
        },
        {
            "EventName": "GetObject",
            "EventSource": "s3.amazonaws.com",
            "CloudTrailEvent": json.dumps({
                "sourceIPAddress": "10.0.0.1"
            }),
        },
        {
            "EventName": "PutObject",
            "EventSource": "s3.amazonaws.com",
            "CloudTrailEvent": json.dumps({
                "sourceIPAddress": "10.0.0.2"
            }),
        },
    ]

    actions = analyzer._extract_actions(events)
    ips = analyzer._extract_source_ips(events)

    assert actions == [
        "s3:GetObject",
        "s3:GetObject",
        "s3:PutObject",
    ]

    assert ips == {
        "10.0.0.1",
        "10.0.0.2",
    }