"""
ai_generator.py — AI Policy Generation Engine (Module 4)
AI IAM Least-Privilege Enforcer

What this file does
-------------------
Takes an over-privileged IAM policy finding + its CloudTrail usage data,
sends both to Claude Haiku with a structured prompt, and returns a
least-privilege replacement policy grounded in actual observed behavior.

This is the core differentiator of the project: recommendations are based
on what a role ACTUALLY did (CloudTrail), not just AI guessing from the
policy text alone.

Self-healing loop
------------------
If the generated policy fails validation (see validator.py), the error
is fed back to Claude for regeneration — up to MAX_RETRIES times — before
giving up and returning the best attempt with a warning.

Author: Member 2
Sprint: Week 5-6
"""

import json
import logging
import os
from typing import Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger(__name__)

MAX_RETRIES = 3
MODEL = "claude-haiku-4-5-20251001"


def _get_client():
    """Return an Anthropic client using the API key from environment."""
    try:
        import anthropic
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise RuntimeError(
                "ANTHROPIC_API_KEY not found in environment. "
                "Add it to your .env file and make sure it's loaded "
                "(python-dotenv load_dotenv() must run before this)."
            )
        return anthropic.Anthropic(api_key=api_key)
    except ImportError:
        raise RuntimeError(
            "anthropic package not installed. Run: pip install anthropic"
        )


def _build_system_prompt() -> str:
    """
    System prompt establishing Claude's role and the strict output format.
    Kept separate from the user prompt so it stays constant across retries.
    """
    return """You are an AWS IAM security expert specializing in the principle of least privilege.

Your job: given an over-privileged IAM policy and data showing which actions
were ACTUALLY used by that role/user in the last N days, generate a replacement
policy that grants ONLY the actions that were actually observed in use, scoped
to the narrowest reasonable resources.

Rules you must follow:
1. Never include Action:"*" or Resource:"*" in your output unless there is
   truly no way to scope it (explain why in that rare case).
2. Base the Action list strictly on the "actions_used" data provided — do not
   guess or add actions that were not observed, even if they seem "probably needed".
3. If actions_used is empty, generate the tightest reasonable policy based on
   the original policy's apparent intent, and clearly flag low confidence.
4. Preserve the original Effect ("Allow") and any Condition blocks that were
   present in the original policy.
5. Output ONLY valid JSON in the exact schema below — no markdown, no prose,
   no code fences, nothing else.

Output schema (return exactly this structure):
{
  "policy": {
    "Version": "2012-10-17",
    "Statement": [ ... ]
  },
  "explanation": "one paragraph, plain English, what this policy does",
  "removed_actions": ["list", "of", "actions", "removed", "from", "original"],
  "confidence": "high" | "medium" | "low",
  "confidence_reason": "one sentence explaining the confidence level"
}"""


def _build_user_prompt(finding: dict, usage_data: dict, previous_error: Optional[str] = None) -> str:
    """
    Build the user prompt from a scanner finding + CloudTrail usage data.
    If previous_error is set, this is a retry — include the failed attempt
    and the validation error so Claude can self-correct.
    """
    actions_used = usage_data.get("actions_used", [])
    action_count = usage_data.get("action_count", 0)
    days_analyzed = usage_data.get("days_analyzed", 30)

    prompt = f"""Original over-privileged policy (entity: {finding['entity_name']}, type: {finding['entity_type']}):

{json.dumps(finding['policy_json'], indent=2)}

Finding: {finding['finding_type']}
Problem: {finding['description']}

CloudTrail usage data — actual actions observed over the last {days_analyzed} days:
{json.dumps(actions_used, indent=2) if actions_used else "[] (no activity observed — role may be new, unused, or CloudTrail data unavailable)"}

Total distinct actions used: {action_count}

Generate the least-privilege replacement policy following the rules and output schema in your instructions."""

    if previous_error:
        prompt += f"""

IMPORTANT — your previous attempt failed validation with this error:
{previous_error}

Fix the issue and regenerate. Return the corrected policy in the same JSON schema."""

    return prompt


def generate_least_privilege_policy(finding: dict, usage_data: dict) -> dict:
    """
    Main entry point. Generates a least-privilege replacement policy for
    a single finding, using CloudTrail usage data as ground truth.

    Args:
        finding:    A single finding dict from scanner.py (must include
                    policy_json, entity_name, entity_type, finding_type,
                    description).
        usage_data: A dict from cloudtrail_analyzer.py's analyze_role_usage()
                    (actions_used, action_count, days_analyzed, etc).
                    Pass {} if no CloudTrail data is available.

    Returns:
        {
            "success": bool,
            "policy": dict | None,
            "explanation": str,
            "removed_actions": list[str],
            "confidence": str,
            "confidence_reason": str,
            "attempts": int,
            "raw_response": str,   # last raw Claude response, for debugging
        }
    """
    client = _get_client()
    system_prompt = _build_system_prompt()

    previous_error = None
    last_raw_response = ""

    for attempt in range(1, MAX_RETRIES + 1):
        log.info("Generating policy for %s (attempt %d/%d)...",
                 finding['entity_name'], attempt, MAX_RETRIES)

        user_prompt = _build_user_prompt(finding, usage_data, previous_error)

        try:
            response = client.messages.create(
                model=MODEL,
                max_tokens=1500,
                system=system_prompt,
                messages=[{"role": "user", "content": user_prompt}]
            )
            raw_text = response.content[0].text
            last_raw_response = raw_text

        except Exception as exc:
            log.error("Claude API call failed: %s", exc)
            return {
                "success": False,
                "policy": None,
                "explanation": f"API call failed: {exc}",
                "removed_actions": [],
                "confidence": "low",
                "confidence_reason": "Generation failed due to API error",
                "attempts": attempt,
                "raw_response": "",
            }

        # Parse Claude's JSON response
        parsed = _parse_response(raw_text)
        if parsed is None:
            previous_error = "Response was not valid JSON matching the required schema."
            log.warning("  → Attempt %d: Claude returned unparseable output, retrying...", attempt)
            continue

        # Validate the generated policy structurally
        from src.validator import PolicyValidator
        validator = PolicyValidator()
        validation = validator.validate_policy_json(parsed["policy"])

        if validation["is_valid"]:
            log.info("  → Valid policy generated on attempt %d", attempt)
            return {
                "success": True,
                "policy": parsed["policy"],
                "explanation": parsed.get("explanation", ""),
                "removed_actions": parsed.get("removed_actions", []),
                "confidence": parsed.get("confidence", "medium"),
                "confidence_reason": parsed.get("confidence_reason", ""),
                "attempts": attempt,
                "raw_response": raw_text,
            }

        # Validation failed — prepare for retry with error feedback
        previous_error = "; ".join(validation["errors"])
        log.warning("  → Attempt %d: validation failed (%s), retrying...", attempt, previous_error)

    # Exhausted all retries
    log.error("Failed to generate valid policy after %d attempts", MAX_RETRIES)
    return {
        "success": False,
        "policy": None,
        "explanation": "Could not generate a valid policy after multiple attempts.",
        "removed_actions": [],
        "confidence": "low",
        "confidence_reason": f"All {MAX_RETRIES} attempts failed validation",
        "attempts": MAX_RETRIES,
        "raw_response": last_raw_response,
    }


def _parse_response(raw_text: str) -> Optional[dict]:
    """
    Parse Claude's response as JSON. Handles the common case where Claude
    wraps output in markdown code fences despite instructions not to.
    """
    text = raw_text.strip()

    # Strip markdown code fences if present
    if text.startswith("```"):
        lines = text.split("\n")
        text = "\n".join(lines[1:-1]) if lines[-1].strip() == "```" else "\n".join(lines[1:])
        text = text.replace("```json", "").replace("```", "").strip()

    try:
        parsed = json.loads(text)
        if "policy" not in parsed:
            log.warning("Parsed JSON missing 'policy' key")
            return None
        return parsed
    except json.JSONDecodeError as exc:
        log.warning("JSON parse failed: %s", exc)
        return None


def generate_for_findings(findings: list, usage_data_map: dict) -> list:
    """
    Batch version — generates replacement policies for multiple findings.

    Args:
        findings:        list of finding dicts from scanner.py
        usage_data_map:  dict mapping entity_name -> usage_data (from
                          cloudtrail_analyzer.py's analyze_multiple_roles)

    Returns:
        list of finding dicts, each with a new "ai_recommendation" key
        containing the generate_least_privilege_policy() result.
    """
    results = []

    for finding in findings:
        entity_name = finding["entity_name"]
        usage_data = usage_data_map.get(entity_name, {})

        recommendation = generate_least_privilege_policy(finding, usage_data)

        results.append({
            **finding,
            "ai_recommendation": recommendation
        })

    return results


# ══════════════════════════════════════════════════════════════════════════════
#  QUICK MANUAL TEST
#  python -m src.ai_generator
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    from dotenv import load_dotenv
    load_dotenv()

    print("\n" + "=" * 60)
    print("  AI Policy Generator — Manual Test")
    print("=" * 60 + "\n")

    # Test finding — an over-privileged S3 role
    test_finding = {
        "entity_name": "test-lambda-payments",
        "entity_type": "role",
        "policy_name": "S3-full-access",
        "policy_json": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:*",
                    "Resource": "*"
                }
            ]
        },
        "finding_type": "SERVICE_WILDCARD_WITH_WILDCARD_RESOURCE",
        "description": "Statement grants full access to s3 on Resource:\"*\""
    }

    # Simulated CloudTrail usage — role only ever did these 3 things
    test_usage = {
        "actions_used": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
        "action_count": 3,
        "days_analyzed": 30,
    }

    result = generate_least_privilege_policy(test_finding, test_usage)

    print(f"Success: {result['success']}")
    print(f"Confidence: {result['confidence']} — {result['confidence_reason']}")
    print(f"Attempts: {result['attempts']}\n")

    if result['success']:
        print("Generated policy:")
        print(json.dumps(result['policy'], indent=2))
        print(f"\nExplanation: {result['explanation']}")
        print(f"\nRemoved actions: {result['removed_actions']}")
    else:
        print(f"Failed: {result['explanation']}")