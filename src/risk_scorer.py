from typing import Dict, Any, List
import json

class RiskScorer:
    """
    Score IAM policies based on blast radius and exposure.
    Rule-based scoring first, ML (XGBoost) added in Week 4.
    """
    
    def __init__(self):
        self.wildcard_weight = 0.35
        self.multi_service_weight = 0.25
        self.admin_actions_weight = 0.20
        self.internet_facing_weight = 0.20
    
    def score_policy(self, policy_json: Dict[str, Any], 
                    entity_type: str = 'role',
                    is_internet_facing: bool = False) -> Dict[str, Any]:
        """
        Score a single policy on blast radius.
        Return: {score: 0.0-1.0, severity: LOW/MEDIUM/HIGH/CRITICAL, reasons: []}
        """
        
        score = 0.0
        reasons = []
        
        # Feature 1: Wildcard actions
        has_action_wildcard = self._check_action_wildcard(policy_json)
        if has_action_wildcard:
            score += self.wildcard_weight
            reasons.append("Action:* grants all permissions")
        
        # Feature 2: Wildcard resources
        has_resource_wildcard = self._check_resource_wildcard(policy_json)
        if has_resource_wildcard:
            score += self.wildcard_weight
            reasons.append("Resource:* exposes entire account")
        
        # Feature 3: Multiple high-risk services
        services = self._extract_services(policy_json)
        if len(services) > 3:
            score += self.multi_service_weight
            reasons.append(f"Policy grants access to {len(services)} services: {', '.join(sorted(services)[:5])}")
        
        # Feature 4: Admin-level actions
        admin_actions = self._check_admin_actions(policy_json)
        if admin_actions:
            score += self.admin_actions_weight
            reasons.append(f"Admin actions detected: {', '.join(admin_actions[:3])}")
        
        # Feature 5: Internet-facing entities
        if is_internet_facing:
            score += self.internet_facing_weight
            reasons.append("Entity is internet-facing (high blast radius)")
        
        # Normalize score to 0.0-1.0
        score = min(score, 1.0)
        
        # Map to severity
        severity = self._score_to_severity(score)
        
        return {
            'score': round(score, 3),
            'severity': severity,
            'reasons': reasons,
            'features': {
                'has_action_wildcard': has_action_wildcard,
                'has_resource_wildcard': has_resource_wildcard,
                'num_services': len(services),
                'num_admin_actions': len(admin_actions),
                'is_internet_facing': is_internet_facing
            }
        }
    
    def _check_action_wildcard(self, policy_json: Dict) -> bool:
        """Check if policy has Action:*"""
        for statement in policy_json.get('Statement', []):
            actions = statement.get('Action', [])
            if isinstance(actions, str):
                actions = [actions]
            if '*' in actions:
                return True
        return False
    
    def _check_resource_wildcard(self, policy_json: Dict) -> bool:
        """Check if policy has Resource:*"""
        for statement in policy_json.get('Statement', []):
            resources = statement.get('Resource', [])
            if isinstance(resources, str):
                resources = [resources]
            if '*' in resources:
                return True
        return False
    
    def _extract_services(self, policy_json: Dict) -> set:
        """Extract AWS services from policy (s3, iam, ec2, etc.)"""
        services = set()
        
        for statement in policy_json.get('Statement', []):
            actions = statement.get('Action', [])
            if isinstance(actions, str):
                actions = [actions]
            
            for action in actions:
                # Extract service from "service:Action" format
                if ':' in action:
                    service = action.split(':')[0]
                    if service != '*':
                        services.add(service)
        
        return services
    
    def _check_admin_actions(self, policy_json: Dict) -> List[str]:
        """Detect admin-level actions that enable privilege escalation"""
        admin_keywords = [
            'iam:CreateAccessKey',
            'iam:AttachUserPolicy',
            'iam:AttachRolePolicy',
            'iam:PutUserPolicy',
            'iam:PutRolePolicy',
            'sts:AssumeRole',
            'ec2:AuthorizeSecurityGroup',
            'lambda:InvokeFunction'
        ]
        
        detected = []
        
        for statement in policy_json.get('Statement', []):
            actions = statement.get('Action', [])
            if isinstance(actions, str):
                actions = [actions]
            
            for action in actions:
                for admin_action in admin_keywords:
                    if action == admin_action or action.endswith(':*'):
                        if admin_action not in detected:
                            detected.append(admin_action)
        
        return detected
    
    def _score_to_severity(self, score: float) -> str:
        """Map numeric score to severity level"""
        if score >= 0.8:
            return 'CRITICAL'
        elif score >= 0.6:
            return 'HIGH'
        elif score >= 0.4:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def score_multiple_policies(self, findings: List[Dict]) -> List[Dict]:
        """Score multiple findings from scanner"""
        scored = []
        
        for finding in findings:
            policy_json = finding.get('policy_json', {})
            entity_type = finding.get('entity_type', 'role')
            
            # Check if internet-facing (simplified - Lambda + API Gateway = internet-facing)
            is_internet_facing = entity_type == 'role' and 'lambda' in finding.get('entity_name', '').lower()
            
            score_result = self.score_policy(policy_json, entity_type, is_internet_facing)
            
            scored.append({
                **finding,
                **score_result
            })
        
        # Sort by score (highest risk first)
        return sorted(scored, key=lambda x: x['score'], reverse=True)

if __name__ == '__main__':
    scorer = RiskScorer()
    
    # Test on a policy
    test_policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*"
            }
        ]
    }
    
    result = scorer.score_policy(test_policy, entity_type='role', is_internet_facing=True)
    print(json.dumps(result, indent=2))