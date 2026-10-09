"""
cloudtrail_analyzer.py — CloudTrail Usage Analyzer (Module 3)
AI IAM Least-Privilege Enforcer

Extracts the actual "service:Action" calls made by an IAM role over the
last N days.

IMPORTANT: CloudTrail's LookupEvents "Username" attribute does NOT match
an IAM role's name. For an assumed-role session, CloudTrail records the
*role session name* as Username (e.g. "my-session-name" or an
auto-generated name from the calling service), while the actual role
name only appears inside the event body, at either:
    userIdentity.sessionContext.sessionIssuer.userName
    userIdentity.arn  ->  "arn:aws:sts::<acct>:assumed-role/<ROLE_NAME>/<session>"
So this analyzer pulls events unfiltered (by time window only) and
matches each event against the role by inspecting its userIdentity,
instead of relying on a Username lookup filter.

Output actions are normalized to the same "service:Action" format used
by scanner.py's findings, so ml_features.py and ai_generator.py can
consume them without any translation step.
"""

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Set, Any, Optional
from collections import Counter
import boto3

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger(__name__)
IAM_ACTION_OVERRIDES = {
    "s3:ListBuckets": "s3:ListAllMyBuckets",
    "s3:ListObjects": "s3:ListBucket",
    "s3:ListObjectsV2": "s3:ListBucket",
    "s3:HeadBucket": "s3:ListBucket",
    "s3:HeadObject": "s3:GetObject",
}


def to_iam_action(service: str, event_name: str) -> str:
    raw = f"{service}:{event_name}"
    return IAM_ACTION_OVERRIDES.get(raw, raw)
MAX_EVENTS_PER_ROLE = 500     # hard cap on MATCHED events for a role
MAX_EVENTS_SCANNED = 5000     # hard cap on total account events scanned per role,
                               # so a quiet role in a noisy account doesn't page forever


class CloudTrailAnalyzer:
    """Extract actual AWS API actions used by IAM roles over N days."""

    def __init__(self, profile: Optional[str] = "default", region: str = "eu-central-1", days: int = 30):
        try:
            session = boto3.Session(profile_name=profile, region_name=region) if profile else boto3.Session(region_name=region)
        except Exception:
            session = boto3.Session(region_name=region)
        self.cloudtrail = session.client("cloudtrail", region_name=region)
        self.iam = session.client("iam", region_name=region)
        self.days = days

    def analyze_role_usage(self, role_name: str) -> Dict[str, Any]:
        """
        Get CloudTrail events for a role over the configured window.

        Returns:
            {role_name, role_arn, actions_used, action_count,
             action_frequency, last_activity, source_ips,
             days_analyzed, events_count, events_scanned, status}
        """
        role_arn = self._get_role_arn(role_name)
        if not role_arn:
            return {
                "role_name": role_name,
                "role_arn": None,
                "actions_used": [],
                "action_count": 0,
                "action_frequency": {},
                "last_activity": None,
                "source_ips": [],
                "days_analyzed": self.days,
                "events_count": 0,
                "events_scanned": 0,
                "status": "role_not_found",
            }

        events, events_scanned = self._get_cloudtrail_events(role_name)

        if not events:
            return {
                "role_name": role_name,
                "role_arn": role_arn,
                "actions_used": [],
                "action_count": 0,
                "action_frequency": {},
                "last_activity": None,
                "source_ips": [],
                "days_analyzed": self.days,
                "events_count": 0,
                "events_scanned": events_scanned,
                "status": "no_activity",
            }

        action_list = self._extract_actions(events)
        actions_set = set(action_list)
        source_ips = self._extract_source_ips(events)
        last_activity = self._get_last_activity(events)

        return {
            "role_name": role_name,
            "role_arn": role_arn,
            "actions_used": sorted(actions_set),
            "action_count": len(actions_set),
            "action_frequency": dict(Counter(action_list)),
            "last_activity": last_activity,
            "source_ips": sorted(source_ips),
            "days_analyzed": self.days,
            "events_count": len(events),
            "events_scanned": events_scanned,
            "status": "analyzed",
        }
    
    def _process_event_once(self, event: Dict) -> Dict[str, Any]:
        """
        Parse a CloudTrailEvent's JSON body exactly once and extract
        everything downstream code needs from it (session issuer / arn
        for role matching, source IP, action, timestamp). Previously,
        _event_matches_role and _extract_source_ips each parsed the same
        JSON independently — on a 5000-event scan that's up to 10,000+
        redundant json.loads() calls, which is the actual source of the
        slowdown, not any logic in temporal_analyzer.py.
        """
        raw = event.get("CloudTrailEvent", "{}")
        try:
            detail = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            detail = {}

        user_identity = detail.get("userIdentity", {}) or {}
        session_issuer_name = (
            user_identity.get("sessionContext", {})
            .get("sessionIssuer", {})
            .get("userName")
        )
        arn = user_identity.get("arn", "") or ""
        source_ip = detail.get("sourceIPAddress")

        event_name = event.get("EventName", "")
        event_source = event.get("EventSource", "")
        service = event_source.replace(".amazonaws.com", "") if event_source else ""

        return {
            "session_issuer_name": session_issuer_name,
            "arn": arn,
            "source_ip": source_ip,
            "action": to_iam_action(service, event_name) if service and event_name else None,
            "event_time": event.get("EventTime"),
        }

    def _matches_role(self, parsed: Dict, role_name: str) -> bool:
        """Role-match check using an already-parsed event (see _process_event_once)."""
        if parsed["session_issuer_name"] == role_name:
            return True
        if f"assumed-role/{role_name}/" in parsed["arn"]:
            return True
        return False
    
    def _get_role_arn(self, role_name: str) -> Optional[str]:
        """Get role ARN from role name."""
        try:
            response = self.iam.get_role(RoleName=role_name)
            return response["Role"]["Arn"]
        except Exception as exc:
            log.warning("Could not fetch ARN for role %s: %s", role_name, exc)
            return None

    def _event_matches_role(self, event: Dict, role_name: str) -> bool:
        """
        Determine whether a CloudTrail event was made using credentials
        from this specific IAM role.

        Primary signal: userIdentity.sessionContext.sessionIssuer.userName,
        which CloudTrail sets to the actual role name for any event made
        with temporary credentials obtained by assuming the role. This is
        reliable regardless of what the caller named their role session.

        Fallback signal: the "assumed-role/<role_name>/" segment of
        userIdentity.arn, in case sessionIssuer is absent for some event
        shape.
        """
        raw = event.get("CloudTrailEvent", "{}")
        try:
            detail = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return False

        user_identity = detail.get("userIdentity", {}) or {}

        session_issuer_name = (
            user_identity.get("sessionContext", {})
            .get("sessionIssuer", {})
            .get("userName")
        )
        if session_issuer_name == role_name:
            return True

        arn = user_identity.get("arn", "") or ""
        if f"assumed-role/{role_name}/" in arn:
            return True

        return False

    def _get_cloudtrail_events(self, role_name: str) -> tuple:
        """
        Query CloudTrail for events in the configured time window and
        return only those actually made by this role, along with the
        total number of raw account events scanned to find them.

        No LookupAttributes filter is applied on the API call itself,
        since there is no CloudTrail lookup attribute that matches an
        IAM role name directly (see module docstring) — filtering
        happens client-side via _event_matches_role.
        """
        matched_events = []
        events_scanned = 0
        start_time = datetime.now(timezone.utc) - timedelta(days=self.days)
        end_time = datetime.now(timezone.utc)

        try:
            paginator = self.cloudtrail.get_paginator("lookup_events")
            for page in paginator.paginate(
                StartTime=start_time,
                EndTime=end_time,
                MaxResults=50,
            ):
                page_events = page.get("Events", [])
                events_scanned += len(page_events)

                for event in page_events:
                        parsed = self._process_event_once(event)
                        if self._matches_role(parsed, role_name):
                            matched_events.append(event)
                        if len(matched_events) >= MAX_EVENTS_PER_ROLE:
                            log.info(
                                "Reached %d matched-event cap for %s, stopping pagination early",
                                MAX_EVENTS_PER_ROLE, role_name
                            )
                            return matched_events[:MAX_EVENTS_PER_ROLE], events_scanned

                if events_scanned >= MAX_EVENTS_SCANNED:
                    log.info(
                        "Reached %d scanned-event cap while searching for %s activity, "
                        "stopping pagination early (found %d matches so far)",
                        MAX_EVENTS_SCANNED, role_name, len(matched_events)
                    )
                    break
        except Exception as exc:
            log.warning("CloudTrail lookup failed for role %s: %s", role_name, exc)

        return matched_events, events_scanned
    def _get_events_for_multiple_roles(self, role_names: List[str]) -> Dict[str, List[Dict]]:
        """
        Single-pass equivalent of calling _get_cloudtrail_events() once per
        role. Scans the account's CloudTrail history ONE time and buckets
        matched events by role, instead of re-scanning the full time window
        independently for every role — which is what made analyzing N roles
        take N times as long as analyzing one.
        """
        matched_by_role: Dict[str, List[Dict]] = {name: [] for name in role_names}
        events_scanned = 0
        start_time = datetime.now(timezone.utc) - timedelta(days=self.days)
        end_time = datetime.now(timezone.utc)

        try:
            paginator = self.cloudtrail.get_paginator("lookup_events")
            for page in paginator.paginate(
                StartTime=start_time,
                EndTime=end_time,
                MaxResults=50,
            ):
                page_events = page.get("Events", [])
                events_scanned += len(page_events)

                for event in page_events:
                    for role_name in role_names:
                        if len(matched_by_role[role_name]) >= MAX_EVENTS_PER_ROLE:
                            continue
                        if self._event_matches_role(event, role_name):
                            matched_by_role[role_name].append(event)

                if events_scanned >= MAX_EVENTS_SCANNED:
                    log.info(
                        "Reached %d scanned-event cap for batch role analysis, "
                        "stopping pagination early", MAX_EVENTS_SCANNED
                    )
                    break
        except Exception as exc:
            log.warning("CloudTrail batch lookup failed: %s", exc)

        for role_name, events in matched_by_role.items():
            log.info("  %-35s → %d matched event(s)", role_name, len(events))

        return matched_by_role
    def _extract_actions(self, events: List[Dict]) -> List[str]:
        """
        Extract 'service:Action' strings from CloudTrail events, matching
        the same format scanner.py uses for policy actions (e.g. "s3:GetObject").
        Returns a list (not a set) so callers can compute frequency counts.
        """
        actions = []
        for event in events:
            event_name = event.get("EventName", "")
            event_source = event.get("EventSource", "")
            if not event_name or not event_source:
                continue
            # EventSource looks like "s3.amazonaws.com" → normalize to "s3"
            service = event_source.replace(".amazonaws.com", "")
            actions.append(to_iam_action(service, event_name))
        return actions

    def _extract_source_ips(self, events: List[Dict]) -> Set[str]:
        """Extract source IPs from CloudTrail events."""
        ips = set()
        for event in events:
            raw = event.get("CloudTrailEvent", "{}")
            try:
                detail = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                continue
            source_ip = detail.get("sourceIPAddress")
            if source_ip:
                ips.add(source_ip)
        return ips

    def _get_last_activity(self, events: List[Dict]) -> Optional[str]:
        """Return the ISO timestamp of the most recent event, if any."""
        timestamps = [e.get("EventTime") for e in events if e.get("EventTime")]
        if not timestamps:
            return None
        return str(max(timestamps))

    def get_action_timestamps(self, role_name: str) -> List[Dict[str, Any]]:
        """
        Return each action call paired with its timestamp, for temporal
        pattern analysis. Single-pass: each raw event is JSON-parsed
        exactly once via _process_event_once, instead of the old approach
        where role-matching and action extraction parsed the same event
        body separately.
        """
        events, _ = self._get_cloudtrail_events(role_name)
        result = []
        for event in events:
            parsed = self._process_event_once(event)
            if parsed["action"] and parsed["event_time"]:
                result.append({"action": parsed["action"], "event_time": parsed["event_time"]})
        return result
    
    def analyze_multiple_roles(self, role_names: List[str]) -> Dict[str, Dict[str, Any]]:
        """
        Analyze usage for multiple roles in a single CloudTrail scan pass,
        instead of one full scan per role.
        """
        if not role_names:
            return {}

        log.info("Scanning CloudTrail once for all %d role(s)...", len(role_names))
        events_by_role = self._get_events_for_multiple_roles(role_names)

        results = {}
        for role_name in role_names:
            role_arn = self._get_role_arn(role_name)
            events = events_by_role.get(role_name, [])

            if not role_arn:
                results[role_name] = {
                    "role_name": role_name, "role_arn": None,
                    "actions_used": [], "action_count": 0, "action_frequency": {},
                    "last_activity": None, "source_ips": [], "days_analyzed": self.days,
                    "events_count": 0, "events_scanned": 0, "status": "role_not_found",
                }
                continue

            if not events:
                results[role_name] = {
                    "role_name": role_name, "role_arn": role_arn,
                    "actions_used": [], "action_count": 0, "action_frequency": {},
                    "last_activity": None, "source_ips": [], "days_analyzed": self.days,
                    "events_count": 0, "events_scanned": 0, "status": "no_activity",
                }
                continue

            action_list = self._extract_actions(events)
            actions_set = set(action_list)
            results[role_name] = {
                "role_name": role_name, "role_arn": role_arn,
                "actions_used": sorted(actions_set),
                "action_count": len(actions_set),
                "action_frequency": dict(Counter(action_list)),
                "last_activity": self._get_last_activity(events),
                "source_ips": sorted(self._extract_source_ips(events)),
                "days_analyzed": self.days,
                "events_count": len(events),
                "events_scanned": 0,
                "status": "analyzed",
            }

        return results
    
if __name__ == "__main__":
    from src.scanner import scan_all

    log.info("Fetching real findings from scanner to determine which roles to analyze...")
    findings = scan_all(use_mock=False)

    role_names = sorted({
        f["entity_name"] for f in findings if f["entity_type"] == "role"
    })

    if not role_names:
        log.warning(
            "No over-privileged roles found by the scanner — nothing to analyze. "
            "Create a test role with an over-privileged policy in AWS first."
        )
    else:
        log.info("Found %d over-privileged role(s) to analyze: %s", len(role_names), role_names)
        analyzer = CloudTrailAnalyzer(days=30)
        results = analyzer.analyze_multiple_roles(role_names)
        print(json.dumps(results, indent=2, default=str))