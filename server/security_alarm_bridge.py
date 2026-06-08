"""
SafeVision — Security Alarm Bridge
=====================================
Connects the ModelProtection SecurityMonitor to the AlarmEngine.

When SecurityMonitor detects a threat event (brute-force, privilege escalation,
integrity failure, sustained comm errors, etc.), this bridge fires a structured
alarm through AlarmEngine, which:
  - Persists the alarm to MongoDB
  - Sends Twilio SMS to zone-assigned guards
  - Streams the event to the dashboard via SSE
  - Shows a toast notification in the dashboard UI

Usage  (drop-in replacement in server.py):
    from security_alarm_bridge import SecurityAlarmBridge
    sec_mon = SecurityAlarmBridge(audit_log, alarm_engine)

    # Then use sec_mon exactly as you used SecurityMonitor — nothing else changes.
"""

from __future__ import annotations

import datetime
import logging
import sys
from pathlib import Path

#   Import from parent package                         
_SERVER_DIR = Path(__file__).resolve().parent
if str(_SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(_SERVER_DIR))

from model.model_protection import SecurityMonitor   # noqa: E402
from alarm_engine import AlarmEngine                 # noqa: E402

logger = logging.getLogger(__name__)


#   Severity mapping                              
# Maps SecurityMonitor event types to alarm severity levels.
_EVENT_SEVERITY: dict[str, str] = {
    "BRUTE_FORCE_DETECTED":         "CRITICAL",
    "PRIVILEGE_ESCALATION_DETECTED":"CRITICAL",
    "INTEGRITY_FAILURE":            "CRITICAL",
    "RAPID_ACCESS_DETECTED":        "WARNING",
    "COMM_ERROR":                   "WARNING",
    "ANOMALY_DETECTED":             "WARNING",
    "SUSTAINED_ANOMALY_RATE":       "WARNING",
}

# Events that are frequent/expected at INFO level — do NOT fire alarms for these
_IGNORED_EVENTS: set[str] = {
    "AUTH_SUCCESS",
    "MODEL_SCAN",
    "ACCESS_CHECK",
    "FILE_DELETE",
    "RETENTION_RUN",
    "USER_CREATED",
    "USER_DELETED",
    "ROLE_CHANGED",
}


class SecurityAlarmBridge(SecurityMonitor):
    """
    Drop-in replacement for SecurityMonitor that forwards threat events to
    AlarmEngine.

    Parameters
    ----------
    audit_log : AuditLogger
        The existing audit logger instance (passed through to SecurityMonitor).
    alarm_engine : AlarmEngine
        The running AlarmEngine instance (from server.py).
    camera_id : str
        Identifier used for the alarm's camera_id field when no camera is
        naturally associated with a security event (e.g. 'SYSTEM').
    location : str
        Location string used in the alarm record.
    **kwargs
        Forwarded to SecurityMonitor.__init__() (thresholds, window_seconds…).
    """

    def __init__(
        self,
        audit_log,
        alarm_engine:  AlarmEngine,
        camera_id:     str = "SYSTEM",
        location:      str = "Security System",
        **kwargs,
    ) -> None:
        super().__init__(audit_log, **kwargs)
        self._alarm_engine = alarm_engine
        self._camera_id    = camera_id
        self._location     = location

    #   Override the private _alert hook                   ─

    def _alert(self, event: str, actor: str, detail: str) -> None:
        # Always call the parent (writes to audit log, prints to console)
        super()._alert(event, actor, detail)

        # Skip non-threat events
        if event in _IGNORED_EVENTS:
            return

        severity = _EVENT_SEVERITY.get(event, "WARNING")
        label    = f"SECURITY:{event}"

        logger.warning(
            f"[SECURITY BRIDGE] {severity} event '{event}' from '{actor}' "
            f"→ firing alarm | detail: {detail}"
        )

        try:
            self._alarm_engine.evaluate(
                label       = label,
                probability = 1.0 if severity == "CRITICAL" else 0.86,
                camera_id   = self._camera_id,
                location    = self._location,
                timestamp   = datetime.datetime.utcnow(),
            )
        except Exception as e:
            logger.error(f"[SECURITY BRIDGE] AlarmEngine.evaluate() failed: {e}")
