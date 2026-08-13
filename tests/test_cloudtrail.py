import pytest
from src.cloudtrail_analyzer import CloudTrailAnalyzer

def test_cloudtrail_init():
    """Test CloudTrail analyzer initialization"""
    analyzer = CloudTrailAnalyzer(days=30)
    assert analyzer.cloudtrail is not None
    assert analyzer.days == 30

def test_extract_actions():
    """Test action extraction"""
    analyzer = CloudTrailAnalyzer()
    events = [
        {'EventName': 'GetObject'},
        {'EventName': 'PutObject'},
        {'EventName': 'GetObject'}  # Duplicate
    ]
    actions = analyzer._extract_actions(events)
    assert len(actions) == 2
    assert 'getobject' in actions

def test_extract_source_ips():
    """Test IP extraction"""
    analyzer = CloudTrailAnalyzer()
    events = [
        {'CloudTrailEvent': '{"sourceIPAddress": "192.168.1.1"}'},
        {'CloudTrailEvent': '{"sourceIPAddress": "10.0.0.1"}'}
    ]
    ips = analyzer._extract_source_ips(events)
    assert '192.168.1.1' in ips
    assert '10.0.0.1' in ips