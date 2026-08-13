import boto3
import json
from datetime import datetime, timedelta
from typing import List, Dict, Set, Any
from collections import Counter

class CloudTrailAnalyzer:
    """Extract actual IAM actions used by roles over N days"""
    
    def __init__(self, profile: str = 'default', region: str = 'eu-central-1', days: int = 2):
        session = boto3.Session(profile_name=profile, region_name=region)
        self.cloudtrail = session.client('cloudtrail', region_name=region)
        self.iam = session.client('iam', region_name=region)
        self.days = days
    
    def analyze_role_usage(self, role_name: str) -> Dict[str, Any]:
        """
        Get CloudTrail events for a role over N days.
        Return: {role_name, actions_used, action_count, last_activity, source_ips}
        """
        
        role_arn = self._get_role_arn(role_name)
        if not role_arn:
            return {'role_name': role_name, 'error': 'Role not found'}
        
        # Query CloudTrail for events
        events = self._get_cloudtrail_events(role_arn)
        
        if not events:
            return {
                'role_name': role_name,
                'role_arn': role_arn,
                'actions_used': [],
                'action_count': 0,
                'last_activity': None,
                'source_ips': [],
                'days_analyzed': self.days,
                'status': 'no_activity'
            }
        
        # Extract actions and metadata
        actions = self._extract_actions(events)
        source_ips = self._extract_source_ips(events)
        last_activity = self._get_last_activity(events)
        
        return {
            'role_name': role_name,
            'role_arn': role_arn,
            'actions_used': sorted(list(actions)),
            'action_count': len(actions),
            'action_frequency': dict(Counter([a for event in events for a in self._extract_actions([event])])),
            'last_activity': last_activity,
            'source_ips': sorted(list(source_ips)),
            'days_analyzed': self.days,
            'events_count': len(events),
            'status': 'analyzed'
        }
    
    def _get_role_arn(self, role_name: str) -> str:
        """Get role ARN from role name"""
        try:
            response = self.iam.get_role(RoleName=role_name)
            return response['Role']['Arn']
        except Exception as e:
            print(f"[!] Error getting role ARN for {role_name}: {e}")
            return None
    
    def _get_cloudtrail_events(self, role_arn: str) -> List[Dict]:
        """Query CloudTrail for events related to this role"""
        events = []
        start_time = datetime.utcnow() - timedelta(days=self.days)
        
        try:
            paginator = self.cloudtrail.get_paginator('lookup_events')
            
            for page in paginator.paginate(
                LookupAttributes=[
                    {
                        'AttributeKey': 'ResourceType',
                        'AttributeValue': 'AWS::IAM::Role'
                    }
                ],
                StartTime=start_time,
                MaxResults=50
            ):
                for event in page.get('Events', []):
                    # Filter for this specific role
                    if role_arn in str(event.get('Resources', [])):
                        events.append(event)
        except Exception as e:
            print(f"[!] CloudTrail error for {role_arn}: {e}")
        
        return events
    
    def _extract_actions(self, events: List[Dict]) -> Set[str]:
        """Extract AWS API actions from CloudTrail events"""
        actions = set()
        
        for event in events:
            event_name = event.get('EventName', '')
            # Map CloudTrail event names to IAM actions (simplified)
            # In production, you'd have a mapping table
            if event_name:
                # Convert camelCase to service:Action format
                # e.g., PutObject → s3:PutObject
                parts = event_name
                actions.add(parts.lower())  # Simplified for now
        
        return actions
    
    def _extract_source_ips(self, events: List[Dict]) -> Set[str]:
        """Extract source IPs from CloudTrail events"""
        ips = set()
        
        for event in events:
            cloud_trail_event = json.loads(event.get('CloudTrailEvent', '{}'))
            source_ip = cloud_trail_event.get('sourceIPAddress', 'unknown')
            if source_ip:
                ips.add(source_ip)
        
        return ips
    
    def _get_last_activity(self, events: List[Dict]) -> str:
        """Get timestamp of last activity"""
        if not events:
            return None
        
        # CloudTrail events are sorted newest first
        return str(events[0].get('EventTime', 'unknown'))
    
    def analyze_multiple_roles(self, role_names: List[str]) -> List[Dict[str, Any]]:
        """Analyze usage for multiple roles"""
        results = []
        
        for role_name in role_names:
            print(f"[*] Analyzing {role_name}...")
            result = self.analyze_role_usage(role_name)
            results.append(result)
        
        return results

if __name__ == '__main__':
    analyzer = CloudTrailAnalyzer(days=30)
    
    # Test on your roles from scanner
    roles = ['test-lambda-over-privileged', 'test-lambda-clean']
    results = analyzer.analyze_multiple_roles(roles)
    
    print(json.dumps(results, indent=2, default=str))