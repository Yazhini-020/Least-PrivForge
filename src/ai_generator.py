"""
ai_generator.py — AI Policy Generation Engine (Module 4)
AI IAM Least-Privilege Enforcer

Now using NVIDIA NIM (llama-3.1-nemotron-nano-8b) instead of Anthropic Claude.
NIM exposes an OpenAI-compatible API, so we use the openai SDK
pointed at NVIDIA's endpoint.
"""

import json
import logging
import os
from typing import Optional, Dict, Any

from src.validator import PolicyValidator

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger(__name__)

MAX_RETRIES = 3
NIM_BASE_URL = "https://integrate.api.nvidia.com/v1"
MODEL = os.environ.get("NVIDIA_MODEL", "nvidia/nemotron-3-super-120b-a12b")


def _get_client():
    """Return an OpenAI-compatible client pointed at NVIDIA NIM."""
    try:
        from openai import OpenAI
        api_key = os.environ.get("NVIDIA_API_KEY")
        if not api_key:
            raise RuntimeError(
                "NVIDIA_API_KEY not found in environment. "
                "Add it to your .env file and make sure it's loaded "
                "(python-dotenv load_dotenv() must run before this)."
            )
        return OpenAI(base_url=NIM_BASE_URL, api_key=api_key)
    except ImportError:
        raise RuntimeError(
            "openai package not installed. Run: pip install openai"
        )


def _build_system_prompt() -> str:
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
5. If a DATA QUALITY WARNING is present in the user message, the temporal
   findings (rarely-used actions, business-hours-only actions) are UNRELIABLE.
   Do not use them as sole justification for removing an action or restricting
   it to a time window. Set "confidence" to "low" or "medium" (never "high")
   and say why in "confidence_reason".
6. If a RISK ASSESSMENT block is present with a note about read-only actions,
   mention this nuance in your "explanation" field — e.g. that the wildcard
   resource is flagged but the actions themselves are non-destructive — rather
   than treating every CRITICAL/HIGH label identically regardless of what the
   actions actually do.
7. Output ONLY valid JSON in the exact schema below — no markdown, no prose,
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


def _build_data_quality_block(temporal_payload: Optional[Dict[str, Any]]) -> str:
    """Render the temporal analyzer's data_quality + notes as a prompt block.

    temporal_payload is expected to come from
    TemporalAccessAnalyzer.build_ai_payload() — {"notes": [...], "data_quality": {...}}.
    Returns "" if no temporal payload was supplied (e.g. finding has no
    temporal analysis attached), so callers that don't use it are unaffected.
    """
    if not temporal_payload:
        return ""

    dq = temporal_payload.get("data_quality", {})
    notes = temporal_payload.get("notes", [])

    if not dq.get("complete", True):
        instruction = (
            "DATA QUALITY WARNING: The temporal analysis below is INCOMPLETE — "
            f"{dq.get('entries_skipped', '?')} of {dq.get('total_entries_received', '?')} "
            "CloudTrail entries could not be parsed and were excluded. Because of this:\n"
            "- Do NOT treat any action described as 'rarely used' as confidently safe "
            "to remove. The observed low usage count may be an artifact of missing "
            "data, not actual rarity.\n"
            "- Do NOT treat any action described as 'business hours only' as confidently "
            "restrictable to a time window. Missing entries may include out-of-window "
            "usage that was never counted.\n"
            "- Prefer the more permissive/conservative option wherever this analysis "
            "is the deciding factor, and set confidence accordingly."
        )
    else:
        instruction = "DATA QUALITY: Complete — all CloudTrail entries for this role parsed successfully."

    notes_block = "\n".join(f"- {n}" for n in notes) if notes else "(no temporal findings)"

    return f"""
{instruction}

TEMPORAL ACCESS FINDINGS:
{notes_block}
"""
def _build_risk_context_block(finding: dict) -> str:
    """
    Render the ML risk scorer's output (severity, score, method) as a
    prompt block, when present. finding comes pre-merged with
    RiskScorer.score_multiple_policies() output ({**finding, **result}),
    so severity/score/method live directly on the finding dict — no
    separate parameter needed.

    Also flags the known model limitation: the XGBoost scorer currently
    weighs Resource:"*" heavily regardless of whether the actions granted
    are read-only or destructive. Instructing the LLM to notice this
    nuance compensates for that blind spot using the LLM's contextual
    understanding of the actual action names.
    """
    severity = finding.get("severity")
    score = finding.get("score")
    method = finding.get("method")

    if severity is None:
        return ""

    actions = finding.get("actions", [])
    read_only_prefixes = ("Get", "List", "Describe", "LookupEvents")
    looks_read_only = bool(actions) and all(
        isinstance(a, str) and (":" in a) and
        any(a.split(":", 1)[1].startswith(p) for p in read_only_prefixes)
        for a in actions
    )

    block = f"""
RISK ASSESSMENT (from trained ML model):
- Severity: {severity}
- Risk Score: {score} (0.0-1.0 scale)
- Scoring method: {method}
"""
    if looks_read_only and severity in ("CRITICAL", "HIGH"):
        block += (
            "\nNOTE: The ML risk score above is elevated primarily due to a "
            "Resource:\"*\" wildcard, but the actions in this policy appear to be "
            "READ-ONLY (Get/List/Describe/LookupEvents). The current scoring model "
            "does not yet distinguish read-only wildcards from destructive ones. "
            "Take this into account in your explanation — you may note that the "
            "practical risk is lower than the raw severity label suggests, without "
            "changing the generated policy's scoping logic.\n"
        )
    return block


def _build_user_prompt(
    finding: dict,
    usage_data: dict,
    previous_error: Optional[str] = None,
    temporal_payload: Optional[Dict[str, Any]] = None,
) -> str:
    actions_used = usage_data.get("actions_used", [])
    action_count = usage_data.get("action_count", 0)
    days_analyzed = usage_data.get("days_analyzed", 30)

    data_quality_block = _build_data_quality_block(temporal_payload)
    risk_context_block = _build_risk_context_block(finding)
    prompt = f"""Original over-privileged policy (entity: {finding['entity_name']}, type: {finding['entity_type']}):

{json.dumps(finding['policy_json'], indent=2)}

Finding: {finding['finding_type']}
Problem: {finding['description']}

CloudTrail usage data — actual actions observed over the last {days_analyzed} days:
{json.dumps(actions_used, indent=2) if actions_used else "[] (no activity observed — role may be new, unused, or CloudTrail data unavailable)"}

Total distinct actions used: {action_count}
{data_quality_block}
{risk_context_block}
Generate the least-privilege replacement policy following the rules and output schema in your instructions.
Return ONLY the JSON object, nothing else."""

    if previous_error:
        prompt += f"""

IMPORTANT — your previous attempt failed validation with this error:
{previous_error}

Fix the issue and regenerate. Return the corrected policy in the same JSON schema."""

    return prompt


def generate_least_privilege_policy(
    finding: dict,
    usage_data: dict,
    temporal_payload: Optional[Dict[str, Any]] = None,
) -> dict:
    """
    Main entry point. Generates a least-privilege replacement policy for
    a single finding, using CloudTrail usage data as ground truth.

    temporal_payload: optional output of TemporalAccessAnalyzer.build_ai_payload(),
    i.e. {"notes": [...], "data_quality": {...}}. When its data_quality.complete
    is False, this function also enforces a confidence ceiling on the result
    regardless of what the model returns — see the enforcement note below.
    """
    client = _get_client()
    system_prompt = _build_system_prompt()

    previous_error = None
    last_raw_response = ""
    data_incomplete = bool(temporal_payload) and not temporal_payload.get("data_quality", {}).get("complete", True)

    for attempt in range(1, MAX_RETRIES + 1):
        log.info("Generating policy for %s (attempt %d/%d)...",
                 finding['entity_name'], attempt, MAX_RETRIES)

        user_prompt = _build_user_prompt(finding, usage_data, previous_error, temporal_payload)

        try:
            response = client.chat.completions.create(
                model=MODEL,
                max_tokens=1500,
                temperature=0.2,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                extra_body={"chat_template_kwargs": {"thinking": False}}
            )
            raw_text = response.choices[0].message.content
            last_raw_response = raw_text

        except Exception as exc:
            log.error("NVIDIA NIM API call failed (attempt %d/%d): %s", attempt, MAX_RETRIES, exc)
            if attempt == MAX_RETRIES:
                return {
                    "success": False,
                    "policy": None,
                    "explanation": f"API call failed: {exc}",
                    "removed_actions": [],
                    "confidence": "low",
                    "confidence_reason": "Generation failed due to API error",
                    "attempts": attempt,
                    "raw_response": "",
                    "based_on_incomplete_data": data_incomplete,
                }
            log.warning("  → Attempt %d: API call failed, retrying...", attempt)
            continue

        parsed = _parse_response(raw_text)
        if parsed is None:
            previous_error = "Response was not valid JSON matching the required schema."
            log.warning("  → Attempt %d: model returned unparseable output, retrying...", attempt)
            continue

        validator = PolicyValidator()
        validation = validator.validate_policy_json(parsed["policy"])

        if validation["is_valid"]:
            log.info("  → Valid policy generated on attempt %d", attempt)

            confidence = parsed.get("confidence", "medium")
            confidence_reason = parsed.get("confidence_reason", "")

            # Enforcement, not just instruction: don't trust the model to have
            # honored rule 5 in the system prompt. If the temporal data behind
            # this recommendation was incomplete, cap confidence server-side —
            # a prompt rule is a request, this is a guarantee.
            if data_incomplete and confidence == "high":
                log.warning(
                    "  → Model returned confidence=high despite incomplete temporal "
                    "data for %s; downgrading to medium.", finding['entity_name']
                )
                confidence = "medium"
                confidence_reason = (
                    "Downgraded from 'high': underlying CloudTrail temporal data was "
                    "incomplete for this role. " + confidence_reason
                ).strip()

            return {
                "success": True,
                "policy": parsed["policy"],
                "explanation": parsed.get("explanation", ""),
                "removed_actions": parsed.get("removed_actions", []),
                "confidence": confidence,
                "confidence_reason": confidence_reason,
                "attempts": attempt,
                "raw_response": raw_text,
                "based_on_incomplete_data": data_incomplete,
            }

        previous_error = "; ".join(validation["errors"])
        log.warning("  → Attempt %d: validation failed (%s), retrying...", attempt, previous_error)

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
        "based_on_incomplete_data": data_incomplete,
    }


def _parse_response(raw_text: str) -> Optional[dict]:
    """Parse model response as JSON, stripping markdown fences if present."""
    text = raw_text.strip()

    if text.startswith("```"):
        lines = text.split("\n")
        text = "\n".join(lines[1:-1]) if lines[-1].strip() == "```" else "\n".join(lines[1:])
        text = text.replace("```json", "").replace("```", "").strip()

    try:
        parsed = json.loads(text)
        if not isinstance(parsed, dict) or "policy" not in parsed:
            log.warning("Parsed JSON missing 'policy' key")
            return None
        return parsed
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1 and end > start:
            try:
                parsed = json.loads(text[start:end + 1])
                if "policy" in parsed:
                    return parsed
            except json.JSONDecodeError as exc:
                log.warning("JSON parse failed even after extraction: %s", exc)
        return None


def generate_for_findings(
    findings: list,
    usage_data_map: dict,
    temporal_payload_map: Optional[Dict[str, Dict[str, Any]]] = None,
) -> list:
    """Batch version — generates replacement policies for multiple findings.

    Findings with no CloudTrail evidence are skipped instead of sent to the
    model: an empty actions_used list gives the AI nothing to scope a policy
    from, and it reliably returns Action: [], which is not deployable and
    not a least-privilege recommendation, just an absence-of-data artifact.

    temporal_payload_map: optional {entity_name: TemporalAccessAnalyzer.build_ai_payload() result}.
    """
    results = []
    temporal_payload_map = temporal_payload_map or {}

    for finding in findings:
        entity_name = finding["entity_name"]
        entity_type = finding.get("entity_type")
        usage_data = usage_data_map.get(entity_name, {})
        temporal_payload = temporal_payload_map.get(entity_name)

        skip_reason = None
        if entity_type != "role":
            skip_reason = (
                f"CloudTrail usage analysis currently covers roles only, so "
                f"there is no usage evidence for this {entity_type}. "
                f"Review it manually — for a group with a high-privilege "
                f"managed policy like AdministratorAccess, the right fix is "
                f"a human decision about who actually needs it, not an "
                f"AI-generated scoped policy."
            )
        elif usage_data.get("action_count", 0) == 0:
            skip_reason = (
                "No CloudTrail activity was found for this role in the "
                "scanned window, so any generated policy would be a guess "
                "rather than evidence-based. Check whether it is unused "
                "(python -m src.cli orphaned) or widen --days."
            )

        if skip_reason:
            results.append({**finding, "ai_recommendation": {
                "success": False, "skipped": True, "policy": None,
                "explanation": skip_reason, "removed_actions": [],
                "confidence": "low", "confidence_reason": "No usage evidence",
                "attempts": 0, "raw_response": "",
                "based_on_incomplete_data": True,
            }})
            continue

        recommendation = generate_least_privilege_policy(finding, usage_data, temporal_payload)

        results.append({
            **finding,
            "ai_recommendation": recommendation
        })

    return results


if __name__ == "__main__":
    from dotenv import load_dotenv
    load_dotenv()

    print("\n" + "=" * 60)
    print("  AI Policy Generator (NVIDIA NIM) — Manual Test")
    print("=" * 60 + "\n")

    test_finding = {
        "entity_name": "test-lambda-payments",
        "entity_type": "role",
        "policy_name": "S3-full-access",
        "policy_json": {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "s3:*", "Resource": "*"}
            ]
        },
        "finding_type": "SERVICE_WILDCARD_WITH_WILDCARD_RESOURCE",
        "description": "Statement grants full access to s3 on Resource:\"*\""
    }

    test_usage = {
        "actions_used": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
        "action_count": 3,
        "days_analyzed": 30,
    }

    # Example of a temporal payload with incomplete data, as produced by
    # TemporalAccessAnalyzer.build_ai_payload()
    test_temporal_payload = {
        "notes": [
            "s3:GetObject was used only 2 time(s) in the observed window — "
            "review whether this permission is still required."
        ],
        "data_quality": {
            "complete": False,
            "total_entries_received": 50,
            "entries_skipped": 3,
            "skipped_details": [],
        },
    }

    result = generate_least_privilege_policy(test_finding, test_usage, test_temporal_payload)

    print(f"Success: {result['success']}")
    print(f"Confidence: {result['confidence']} — {result['confidence_reason']}")
    print(f"Based on incomplete data: {result.get('based_on_incomplete_data')}")
    print(f"Attempts: {result['attempts']}\n")

    if result['success']:
        print("Generated policy:")
        print(json.dumps(result['policy'], indent=2))
        print(f"\nExplanation: {result['explanation']}")
        print(f"\nRemoved actions: {result['removed_actions']}")
    else:
        print(f"Failed: {result['explanation']}")