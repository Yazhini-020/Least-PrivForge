import pytest
from src.risk_scorer import RiskScorer

def test_scorer_init():
    """Test risk scorer initialization"""
    scorer = RiskScorer()
    assert scorer is not None

def test_score_critical_policy():
    """Test CRITICAL severity (Action:* + Resource:*)"""
    scorer = RiskScorer()
    policy = {
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
    }
    result = scorer.score_policy(policy, is_internet_facing=True)
    assert result['severity'] == 'CRITICAL'
    assert result['score'] > 0.7

def test_score_high_policy():
    """Test HIGH severity (wildcard actions, multiple services)"""
    scorer = RiskScorer()
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:*", "iam:*", "ec2:*", "lambda:*"],
                "Resource": "arn:aws:s3:::bucket/*"
            }
        ]
    }
    result = scorer.score_policy(policy)
    assert result['severity'] in ['HIGH', 'CRITICAL']

def test_score_clean_policy():
    """Test LOW severity (specific actions, scoped resources)"""
    scorer = RiskScorer()
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject"],
                "Resource": "arn:aws:s3:::bucket/*"
            }
        ]
    }
    result = scorer.score_policy(policy)
    assert result['severity'] == 'LOW'
    assert result['score'] < 0.3

def test_extract_services():
    """Test service extraction"""
    scorer = RiskScorer()
    policy = {
        "Statement": [
            {"Action": ["s3:GetObject", "iam:CreateUser", "ec2:RunInstances"]}
        ]
    }
    services = scorer._extract_services(policy)
    assert 's3' in services
    assert 'iam' in services
    assert 'ec2' in services