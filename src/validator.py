import json
import subprocess
from typing import Dict, Any, Tuple

class PolicyValidator:
    """Validate IAM policy JSON syntax and logical consistency"""
    
    def __init__(self):
        self.opa_binary = 'opa'  # Make sure opa is in your PATH
    
    def validate_policy_json(self, policy: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate that a policy is valid IAM JSON.
        Return: {is_valid: bool, errors: [], suggestions: []}
        """
        
        errors = []
        suggestions = []
        
        # Check basic structure
        if not isinstance(policy, dict):
            return {'is_valid': False, 'errors': ['Policy must be a JSON object']}
        
        if 'Statement' not in policy:
            errors.append("Missing 'Statement' field")
        
        if not isinstance(policy.get('Statement', []), list):
            errors.append("'Statement' must be an array")
        
        # Validate each statement
        for idx, statement in enumerate(policy.get('Statement', [])):
            if not isinstance(statement, dict):
                errors.append(f"Statement {idx} must be an object")
                continue
            
            # Check required fields
            if 'Effect' not in statement:
                errors.append(f"Statement {idx}: missing 'Effect' field")
            elif statement['Effect'] not in ['Allow', 'Deny']:
                errors.append(f"Statement {idx}: Effect must be 'Allow' or 'Deny'")
            
            if 'Action' not in statement:
                errors.append(f"Statement {idx}: missing 'Action' field")
            
            if 'Resource' not in statement:
                suggestions.append(f"Statement {idx}: consider specifying 'Resource' for clarity")
            
            # Validate Action format
            actions = statement.get('Action', [])
            if isinstance(actions, str):
                actions = [actions]
            
            for action in actions:
                if not self._is_valid_action_format(action):
                    errors.append(f"Statement {idx}: invalid action format '{action}'")
            
            # Validate Resource format
            resources = statement.get('Resource', [])
            if isinstance(resources, str):
                resources = [resources]
            
            for resource in resources:
                if not self._is_valid_resource_format(resource):
                    errors.append(f"Statement {idx}: invalid resource format '{resource}'")
        
        return {
            'is_valid': len(errors) == 0,
            'errors': errors,
            'suggestions': suggestions,
            'statement_count': len(policy.get('Statement', []))
        }
    
    def _is_valid_action_format(self, action: str) -> bool:
        """Validate action is service:Action or *"""
        if action == '*':
            return True
        
        if ':' not in action:
            return False
        
        parts = action.split(':')
        if len(parts) != 2:
            return False
        
        service, act = parts
        # Allow wildcards in action part
        return service != '' and act != ''
    
    def _is_valid_resource_format(self, resource: str) -> bool:
        """Validate resource is ARN or *"""
        if resource == '*':
            return True
        
        # Simple ARN validation: arn:partition:service:region:account-id:resource
        if resource.startswith('arn:'):
            parts = resource.split(':')
            return len(parts) >= 6
        
        return False
    
    def validate_with_opa(self, policy: Dict[str, Any], policy_name: str = 'test') -> Dict[str, Any]:
        """
        Use OPA/Rego to validate the policy (if opa binary is available).
        Falls back to basic validation if OPA not found.
        """
        
        try:
            # Try to use OPA
            rego_code = f"""
            package validate
            
            import data.policy
            
            deny[msg] {{
                policy.Statement[_].Effect != "Allow"
                msg := "Only Allow statements supported"
            }}
            
            deny[msg] {{
                policy.Statement[_].Action == ""
                msg := "Action cannot be empty"
            }}
            """
            
            # Write policy to temp file
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                json.dump(policy, f)
                temp_file = f.name
            
            # Run OPA (simplified - in production you'd handle this better)
            result = subprocess.run(
                [self.opa_binary, 'eval', '-d', rego_code, f'data.validate'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                return {
                    'opa_validation': 'passed',
                    'opa_output': result.stdout
                }
            else:
                return {
                    'opa_validation': 'failed',
                    'opa_errors': result.stderr
                }
        
        except (FileNotFoundError, subprocess.TimeoutExpired):
            # OPA not available, fall back to basic validation
            return self.validate_policy_json(policy)

if __name__ == '__main__':
    validator = PolicyValidator()
    
    # Test valid policy
    valid_policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::bucket/*"
            }
        ]
    }
    
    result = validator.validate_policy_json(valid_policy)
    print("Valid policy:")
    print(json.dumps(result, indent=2))
    
    # Test invalid policy
    invalid_policy = {
        "Statement": [
            {"Effect": "Maybe", "Action": ""}
        ]
    }
    
    result = validator.validate_policy_json(invalid_policy)
    print("\nInvalid policy:")
    print(json.dumps(result, indent=2))