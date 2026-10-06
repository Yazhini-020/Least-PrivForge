"""
temporal_analyzer.py — Temporal Access Pattern Analyzer
AI IAM Least-Privilege Enforcer
"""

import logging
from collections import defaultdict
from datetime import datetime, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
from typing import List, Dict, Any, Union

log = logging.getLogger(__name__)

BUSINESS_HOUR_START = 9
BUSINESS_HOUR_END = 18
BUSINESS_WEEKDAYS = {"Monday", "Tuesday", "Wednesday", "Thursday", "Friday"}
RARE_USE_THRESHOLD = 2


class TemporalAccessAnalyzer:
    """Analyze time-of-use patterns from CloudTrail action timestamps.

    CloudTrail `eventTime` values are always UTC. Business-hours
    classification is meaningless unless evaluated in the org's actual
    local timezone, so callers must supply one (or explicitly opt into UTC).
    """

    def __init__(self, org_timezone: str = "UTC"):
        try:
            self._tz = ZoneInfo(org_timezone)
        except ZoneInfoNotFoundError as e:
            raise ValueError(
                f"Invalid org_timezone {org_timezone!r} passed to "
                f"TemporalAccessAnalyzer — expected an IANA name like "
                f"'America/New_York'. Original error: {e}"
            ) from e
          
    def _localize(self, ts: Union[datetime, str]) -> datetime:
        if isinstance(ts, str):
            try:
                ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except ValueError:
                raise ValueError(f"unparseable event_time string: {ts!r}")
        if not isinstance(ts, datetime):
            raise TypeError(f"event_time must be datetime or ISO string, got {type(ts).__name__}")
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return ts.astimezone(self._tz)
    
    def analyze(self, action_timestamps: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not action_timestamps:
            return {
                "per_action": {},
                "summary": {
                    "total_actions_analyzed": 0,
                    "business_hours_only_actions": [],
                    "rarely_used_actions": [],
                },
                "data_quality": {
                    "complete": True,
                    "total_entries_received": 0,
                    "entries_skipped": 0,
                    "skipped_details": [],
                },
            }

        grouped = defaultdict(list)
        skipped_details = []

        for i, entry in enumerate(action_timestamps):
            action = entry.get("action") if isinstance(entry, dict) else None
            try:
                if not isinstance(entry, dict):
                    raise TypeError(f"entry must be a dict, got {type(entry).__name__}")
                if "action" not in entry:
                    raise KeyError("missing required key 'action'")
                if "event_time" not in entry:
                    raise KeyError("missing required key 'event_time'")
                localized = self._localize(entry["event_time"])
            except (KeyError, TypeError, ValueError) as e:
                reason = str(e)
                skipped_details.append({"index": i, "action": action, "reason": reason})
                log.warning(
                    "Skipping malformed action_timestamp entry at index %d (action=%r): %s",
                    i, action, reason,
                )
                continue
            grouped[action].append(localized)

        if skipped_details:
            log.error(
                "TemporalAccessAnalyzer: %d of %d entries were malformed and skipped — "
                "analysis is running on incomplete data.",
                len(skipped_details), len(action_timestamps),
            )

        per_action = {}
        business_hours_only_actions = []
        rarely_used_actions = []

        for action, timestamps in grouped.items():
            timestamps.sort()
            hours_used = sorted({t.hour for t in timestamps})
            weekdays_used = sorted({t.strftime("%A") for t in timestamps})

            hours_in_range = all(BUSINESS_HOUR_START <= h < BUSINESS_HOUR_END for h in hours_used)
            weekdays_only = all(d in BUSINESS_WEEKDAYS for d in weekdays_used)
            business_hours_only = hours_in_range and weekdays_only

            is_rarely_used = len(timestamps) <= RARE_USE_THRESHOLD

            per_action[action] = {
                "count": len(timestamps),
                "hours_used": hours_used,
                "weekdays_used": weekdays_used,
                "business_hours_only": business_hours_only,
                "is_rarely_used": is_rarely_used,
                "first_seen": str(timestamps[0]),
                "last_seen": str(timestamps[-1]),
                "timezone": str(self._tz),
            }

            if business_hours_only:
                business_hours_only_actions.append(action)
            if is_rarely_used:
                rarely_used_actions.append(action)

        return {
            "per_action": per_action,
            "summary": {
                "total_actions_analyzed": len(per_action),
                "business_hours_only_actions": business_hours_only_actions,
                "rarely_used_actions": rarely_used_actions,
            },
            "data_quality": {
                "complete": len(skipped_details) == 0,
                "total_entries_received": len(action_timestamps),
                "entries_skipped": len(skipped_details),
                "skipped_details": skipped_details,
            },
        }

    def build_insight_notes(self, analysis: Dict[str, Any]) -> List[str]:
        notes = []
        summary = analysis.get("summary", {})
        dq = analysis.get("data_quality", {})

        if not dq.get("complete", True):
            notes.append(
                f"⚠ {dq['entries_skipped']} of {dq['total_entries_received']} "
                f"CloudTrail entries were malformed and excluded from this analysis — "
                f"findings below may be based on incomplete data."
            )

        for action in summary.get("business_hours_only_actions", []):
            tz = analysis["per_action"][action]["timezone"]
            notes.append(
                f"{action} was only ever used on weekdays during business hours "
                f"({BUSINESS_HOUR_START}:00-{BUSINESS_HOUR_END}:00 {tz}) in the observed window."
            )

        for action in summary.get("rarely_used_actions", []):
            count = analysis["per_action"][action]["count"]
            notes.append(
                f"{action} was used only {count} time(s) in the observed window — "
                f"review whether this permission is still required."
            )

        return notes

    def build_ai_payload(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Structured payload for the AI policy generator's prompt.

        `data_quality` is deliberately a sibling of `notes`, not folded
        into it — the generator must branch on `data_quality.complete`
        as a hard structural signal, not infer caution from prose.
        """
        return {
            "notes": self.build_insight_notes(analysis),
            "data_quality": analysis.get("data_quality", {
                "complete": True,
                "total_entries_received": 0,
                "entries_skipped": 0,
                "skipped_details": [],
            }),
        }