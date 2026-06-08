"""
SafeVision Alarm Engine
========================
Evaluates each inference result against loaded alarm rules and:
  1. Fires alarms with cooldown deduplication (per camera + rule)
  2. Persists alarms to MongoDB `alarms` collection
  3. Sends Twilio SMS to registered guard phone numbers
  4. Optionally sends email via SMTP
  5. Writes to a JSONL log for SSE streaming to the dashboard

Usage (from server.py):
    engine = AlarmEngine()
    engine.evaluate(
        label='VIOLENCE',
        probability=0.72,
        camera_id='CAM-01',
        location='Lobby',
        timestamp=datetime.datetime.utcnow(),
    )
"""

from __future__ import annotations

import json
import logging
import os
import smtplib
import threading
import datetime
import uuid
from dataclasses import dataclass, field
from email.mime.text import MIMEText
from pathlib import Path
from typing import Optional

try:
    import numpy as np
except ImportError:
    np = None

try:
    import cv2
except ImportError:
    cv2 = None

try:
    import alarm_config as cfg
except ImportError:
    cfg = None

try:
    from twilio.rest import Client  # type: ignore
except ImportError:
    Client = None

from storage import JsonCollection
from guard_manager import GuardManager
from model.model_protection import FileEncryptor

logger = logging.getLogger(__name__)

#   Paths                                   
_DIR = Path(__file__).resolve().parent

if cfg is not None and hasattr(cfg, "RULES_PATH"):
    RULES_PATH = Path(cfg.RULES_PATH)
    ALARM_LOG  = Path(cfg.ALARM_LOG)
    ALARMS_DB_PATH = Path(cfg.ALARMS_DB_PATH)
    SNAPSHOTS_DIR = Path(cfg.SNAPSHOTS_DIR)
else:
    RULES_PATH = _DIR / "alarm_rules.json"
    ALARM_LOG  = _DIR / "alarms.jsonl"
    ALARMS_DB_PATH = _DIR / "database" / "alarms.jsonl"
    SNAPSHOTS_DIR = _DIR / "database" / "snapshots"

#   File-based Storage                            ─
_ALARMS_COL = JsonCollection(str(ALARMS_DB_PATH))



#   Data Structures                              

class AlarmState:
    ACTIVE       = "ACTIVE"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    DISMISSED    = "DISMISSED"


@dataclass
class AlarmRule:
    id:               str
    name:             str
    enabled:          bool
    label_triggers:   list[str]          # e.g. ["VIOLENCE"] or ["VIOLENCE","PRE-VIOLENCE"]
    min_probability:  float
    cooldown_seconds: int
    severity:         str               # "CRITICAL" | "WARNING"
    cameras:          list[str]         # empty list = all cameras
    notify_sms:       bool
    notify_email:     bool
    description:      str = ""


@dataclass
class FiredAlarm:
    alarm_id:        str
    rule_id:         str
    rule_name:       str
    severity:        str
    label:           str
    probability:     float
    camera_id:       str
    location:        str
    fired_at:        datetime.datetime
    state:           str = AlarmState.ACTIVE
    ack_at:          Optional[datetime.datetime] = None
    dismiss_at:      Optional[datetime.datetime] = None
    sms_sent:        bool = False
    email_sent:      bool = False
    notified_guards: list = None   # names of guards notified by SMS
    snapshot_path:   Optional[str] = None



#   Alarm Engine                               ─

class AlarmEngine:
    """
    Thread-safe alarm engine.  Instantiate once in server.py and call
    `evaluate()` after every inference window.
    """

    def __init__(self, rules_path: Path = RULES_PATH):
        self._lock       = threading.Lock()
        self._rules: list[AlarmRule] = []
        # cooldown tracking: (rule_id, camera_id) → last_fired datetime
        self._last_fired: dict[tuple[str, str], datetime.datetime] = {}
        self.master_key:   Optional[str] = None
        self._encryptor =  FileEncryptor()
        self._load_rules(rules_path)

        # lazy-import alarm_config so it's not required at module load time
        if cfg is not None:
            self._cfg = cfg
        else:
            self._cfg = None
            logger.warning("[ALARM] alarm_config.py not found — SMS/email disabled")

    #   Rule Management                            ─

    def _load_rules(self, path: Path) -> None:
        if not path.exists():
            logger.warning(f"[ALARM] Rules file not found: {path}. Using empty ruleset.")
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                raw = json.load(f)
            self._rules = [
                AlarmRule(
                    id               = r["id"],
                    name             = r["name"],
                    enabled          = r.get("enabled", True),
                    label_triggers   = r.get("label_triggers", ["VIOLENCE"]),
                    min_probability  = float(r.get("min_probability", 0.55)),
                    cooldown_seconds = int(r.get("cooldown_seconds", 60)),
                    severity         = r.get("severity", "CRITICAL"),
                    cameras          = r.get("cameras", []),
                    notify_sms       = r.get("notify_sms", True),
                    notify_email     = r.get("notify_email", False),
                    description      = r.get("description", ""),
                )
                for r in raw
            ]
            logger.info(f"[ALARM] Loaded {len(self._rules)} alarm rules from {path}")
        except Exception as e:
            logger.error(f"[ALARM] Failed to load rules: {e}")

    def reload_rules(self) -> None:
        """Hot-reload rules from disk without restarting server."""
        with self._lock:
            self._rules.clear()
            self._load_rules(RULES_PATH)

    def get_rules(self) -> list[dict]:
        with self._lock:
            return [vars(r) for r in self._rules]

    def save_rules(self, rules_data: list[dict]) -> None:
        """Overwrite alarm_rules.json and hot-reload."""
        with open(RULES_PATH, "w", encoding="utf-8") as f:
            json.dump(rules_data, f, indent=2, ensure_ascii=False)
        self.reload_rules()

    def add_rule(self, rule_data: dict) -> str:
        """Add a new rule, returns its id."""
        rule_data.setdefault("id", "rule-" + uuid.uuid4().hex[:8])
        rules = []
        if RULES_PATH.exists():
            with open(RULES_PATH, "r", encoding="utf-8") as f:
                rules = json.load(f)
        rules.append(rule_data)
        self.save_rules(rules)
        return rule_data["id"]

    def delete_rule(self, rule_id: str) -> bool:
        """Delete rule by id, returns True if found."""
        if not RULES_PATH.exists():
            return False
        with open(RULES_PATH, "r", encoding="utf-8") as f:
            rules = json.load(f)
        new_rules = [r for r in rules if r.get("id") != rule_id]
        if len(new_rules) == len(rules):
            return False
        self.save_rules(new_rules)
        return True

    def set_master_key(self, key: str):
        """Set the key used for snapshot encryption at rest."""
        self.master_key = key

    #   Evaluate                               ─

    def evaluate(
        self,
        label:       str,
        probability: float,
        camera_id:   str,
        location:    str,
        timestamp:   Optional[datetime.datetime] = None,
        frame:       Optional[np.ndarray] = None,
    ) -> list[FiredAlarm]:

        """
        Called after every inference window.
        Returns list of newly fired alarms (usually empty or one item).
        """
        if timestamp is None:
            timestamp = datetime.datetime.utcnow()

        fired = []
        with self._lock:
            for rule in self._rules:
                if not rule.enabled:
                    continue
                if label not in rule.label_triggers:
                    continue
                if probability < rule.min_probability:
                    continue
                if rule.cameras and camera_id not in rule.cameras:
                    continue

                # Cooldown check
                key = (rule.id, camera_id)
                last = self._last_fired.get(key)
                if last:
                    elapsed = (timestamp - last).total_seconds()
                    if elapsed < rule.cooldown_seconds:
                        logger.debug(
                            f"[ALARM] Cooldown active for rule={rule.id} cam={camera_id} "
                            f"({elapsed:.0f}s / {rule.cooldown_seconds}s)"
                        )
                        continue

                # Fire alarm
                alarm = self._fire(rule, label, probability, camera_id, location, timestamp, frame)
                self._last_fired[key] = timestamp
                fired.append(alarm)


        return fired

    def _fire(
        self,
        rule:        AlarmRule,
        label:       str,
        probability: float,
        camera_id:   str,
        location:    str,
        timestamp:   datetime.datetime,
        frame:       Optional[np.ndarray] = None,
    ) -> FiredAlarm:
        alarm_id = uuid.uuid4().hex
        
        # Save snapshot if frame is provided
        snapshot_path = None
        if frame is not None:
            try:
                if cv2 is None:
                    raise ImportError("cv2 not found")
                # Ensure directory exists
                snap_dir = SNAPSHOTS_DIR
                snap_dir.mkdir(parents=True, exist_ok=True)
                
                snap_filename = f"snap_{alarm_id}.png"
                full_path = snap_dir / snap_filename
                cv2.imwrite(str(full_path), frame)
                rel_path = f"database/snapshots/{snap_filename}"
                
                # Encrypt at rest if master key is provided
                if self.master_key:
                    enc_path = str(full_path) + ".enc"
                    self._encryptor.encrypt_file(str(full_path), enc_path, self.master_key)
                    # Securely delete original
                    if os.path.exists(enc_path):
                        os.remove(str(full_path))
                        rel_path += ".enc"
                        logger.info(f"[ALARM] Snapshot encrypted at rest: {rel_path}")
                
                snapshot_path = rel_path
            except Exception as e:
                logger.error(f"[ALARM] Failed to save snapshot: {e}")

        alarm = FiredAlarm(
            alarm_id    = alarm_id,
            rule_id     = rule.id,
            rule_name   = rule.name,
            severity    = rule.severity,
            label       = label,
            probability = probability,
            camera_id   = camera_id,
            location    = location,
            fired_at    = timestamp,
            snapshot_path = snapshot_path,
        )


        logger.warning(
            f"[ALARM] 🚨 {rule.severity} fired | rule={rule.name} | "
            f"cam={camera_id} | label={label} | prob={probability:.3f}"
        )

        # Persist to MongoDB
        self._persist(alarm)

        # Append to JSONL for SSE
        self._append_log(alarm)

        # Notifications (non-blocking)
        if rule.notify_sms:
            threading.Thread(
                target=self._send_sms, args=(alarm,), daemon=True
            ).start()
        if rule.notify_email:
            threading.Thread(
                target=self._send_email, args=(alarm,), daemon=True
            ).start()

        return alarm

    #   Persistence                              

    def _persist(self, alarm: FiredAlarm) -> None:
        doc = {
            "alarm_id":        alarm.alarm_id,
            "rule_id":         alarm.rule_id,
            "rule_name":       alarm.rule_name,
            "severity":        alarm.severity,
            "label":           alarm.label,
            "probability":     alarm.probability,
            "camera_id":       alarm.camera_id,
            "location":        alarm.location,
            "fired_at":        alarm.fired_at,
            "state":           alarm.state,
            "ack_at":          alarm.ack_at,
            "dismiss_at":      alarm.dismiss_at,
            "sms_sent":        alarm.sms_sent,
            "email_sent":      alarm.email_sent,
            "notified_guards": alarm.notified_guards or [],
            "snapshot_path":   alarm.snapshot_path,
        }

        try:
            _ALARMS_COL.insert_one(doc)
        except Exception as e:
            logger.error(f"[ALARM] MongoDB insert failed: {e}")

    def _append_log(self, alarm: FiredAlarm) -> None:
        """Append a JSON line to alarms.jsonl for the SSE endpoint."""
        record = {
            "alarm_id":        alarm.alarm_id,
            "rule_name":       alarm.rule_name,
            "severity":        alarm.severity,
            "label":           alarm.label,
            "probability":     round(alarm.probability, 4),
            "camera_id":       alarm.camera_id,
            "location":        alarm.location,
            "fired_at":        alarm.fired_at.isoformat(),
            "state":           alarm.state,
            "notified_guards": alarm.notified_guards or [],
            "sms_sent":        alarm.sms_sent,
            "snapshot_path":   alarm.snapshot_path,
        }

        try:
            with open(ALARM_LOG, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
        except Exception as e:
            logger.error(f"[ALARM] Log write failed: {e}")

    #   Alarm State Transitions                        ─

    @staticmethod
    def acknowledge(alarm_id: str) -> bool:
        result = _ALARMS_COL.update_one(
            {"alarm_id": alarm_id, "state": AlarmState.ACTIVE},
            {"$set": {"state": AlarmState.ACKNOWLEDGED, "ack_at": datetime.datetime.utcnow()}},
        )
        return result.modified_count > 0

    @staticmethod
    def dismiss(alarm_id: str) -> bool:
        result = _ALARMS_COL.update_one(
            {"alarm_id": alarm_id, "state": {"$in": [AlarmState.ACTIVE, AlarmState.ACKNOWLEDGED]}},
            {"$set": {"state": AlarmState.DISMISSED, "dismiss_at": datetime.datetime.utcnow()}},
        )
        return result.modified_count > 0

    @staticmethod
    def get_alarms(
        state:     Optional[str] = None,
        camera_id: Optional[str] = None,
        limit:     int = 100,
    ) -> list[dict]:
        query: dict = {}
        if state:
            query["state"] = state
        if camera_id:
            query["camera_id"] = camera_id
        cursor = (
            _ALARMS_COL.find(query, {"_id": 0})
                        .sort("fired_at", -1)
                        .limit(limit)
        )
        return list(cursor)

    @staticmethod
    def get_stats() -> dict:
        pipeline = [{"$group": {"_id": "$state", "count": {"$sum": 1}}}]
        result = {AlarmState.ACTIVE: 0, AlarmState.ACKNOWLEDGED: 0, AlarmState.DISMISSED: 0}
        for doc in _ALARMS_COL.aggregate(pipeline):
            result[doc["_id"]] = doc["count"]
        result["total"] = sum(result.values())
        return result

    #   SMS Notification (Twilio)                       ─

    def _send_sms(self, alarm: FiredAlarm) -> None:
        cfg = self._cfg
        if cfg is None or not getattr(cfg, "TWILIO_ENABLED", False):
            return

        #   Zone-based guard lookup (primary)               ─
        # Find guards assigned to the zone covering this camera.
        zone_guards = GuardManager.get_guards_for_camera(alarm.camera_id)

        # Build list of (name, phone) to notify
        targets: list[tuple[str, str]] = []
        if zone_guards:
            targets = [(g["name"], g["phone"]) for g in zone_guards if g.get("phone")]

        #   Fallback to config-level phone list               
        if not targets:
            fallback = getattr(cfg, "GUARD_PHONE_NUMBERS", [])
            fallback = [n.strip() for n in fallback if n.strip()]
            targets  = [(f"Guard ({n})", n) for n in fallback]

        if not targets:
            logger.info("[ALARM] No guards to notify — SMS skipped")
            return

        # Choose template based on label type and severity
        is_security = alarm.label.startswith("SECURITY:")
        if is_security:
            template = getattr(cfg, "SMS_TEMPLATE_SECURITY",
                               "SECURITY THREAT: {label} on {camera_id} at {timestamp}")
        elif alarm.severity == "CRITICAL":
            template = getattr(cfg, "SMS_TEMPLATE_VIOLENCE",
                               "VIOLENCE at {camera_id} ({probability_pct}%) - {timestamp}")
        else:
            template = getattr(cfg, "SMS_TEMPLATE_PREVIOLENCE",
                               "PRE-VIOLENCE at {camera_id} ({probability_pct}%) - {timestamp}")

        body = template.format(
            label         = alarm.label,
            camera_id     = alarm.camera_id,
            location      = alarm.location,
            probability   = alarm.probability,
            probability_pct = round(alarm.probability * 100, 1),
            timestamp     = alarm.fired_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
            rule_name     = alarm.rule_name,
        )

        logger.info(
            f"[ALARM] SMS body:\n{body}\n"
            f"[ALARM] Notifying {len(targets)} guard(s): "
            f"{', '.join(name for name, _ in targets)}"
        )

        try:
            if Client is None:
                raise ImportError("twilio package not installed")
            client   = Client(cfg.TWILIO_ACCOUNT_SID, cfg.TWILIO_AUTH_TOKEN)
            sent_all = True
            notified: list[str] = []
            for name, number in targets:
                try:
                    msg = client.messages.create(
                        body  = body,
                        from_ = cfg.TWILIO_FROM_NUMBER,
                        to    = number,
                    )
                    logger.info(f"[ALARM] SMS → {name} ({number}) sid={msg.sid}")
                    notified.append(name)
                except Exception as e:
                    sent_all = False
                    logger.error(f"[ALARM] SMS to {name} ({number}) failed: {e}")

            _ALARMS_COL.update_one(
                {"alarm_id": alarm.alarm_id},
                {"$set": {"sms_sent": sent_all, "notified_guards": notified}},
            )
            alarm.sms_sent        = sent_all
            alarm.notified_guards = notified
        except ImportError:
            logger.error("[ALARM] twilio package not installed. Run: pip install twilio")

    #   Email Notification (SMTP)                       ─

    def _send_email(self, alarm: FiredAlarm) -> None:
        cfg = self._cfg
        if cfg is None or not getattr(cfg, "SMTP_ENABLED", False):
            return

        # Zone-based guard email lookup (primary) — same pattern as SMS
        zone_guards = GuardManager.get_guards_for_camera(alarm.camera_id)
        recipients: list[str] = []
        if zone_guards:
            recipients = [g["email"] for g in zone_guards if g.get("email")]

        # Fallback to static ALERT_EMAILS in .env
        if not recipients:
            fallback = getattr(cfg, "ALERT_EMAILS", [])
            recipients = [r.strip() for r in fallback if r.strip()]

        if not recipients:
            logger.info("[ALARM] No guard emails to notify — email skipped")
            return

        is_security = alarm.label.startswith("SECURITY:")
        label_display = alarm.label.replace("SECURITY:", "") if is_security else alarm.label
        icon = "\U0001f510" if is_security else ("\U0001f6a8" if alarm.severity == "CRITICAL" else "\u26a0\ufe0f")

        subject = (
            f"{icon} [{alarm.severity}] {label_display} "
            f"\u2014 {alarm.camera_id} / {alarm.location}"
        )
        body = (
            f"{icon} SafeVision ALARM FIRED\n"
            f"{'=' * 44}\n"
            f"Severity   : {alarm.severity}\n"
            f"Detection  : {label_display}\n"
            f"Confidence : {alarm.probability:.1%}\n"
            f"Camera     : {alarm.camera_id}\n"
            f"Location   : {alarm.location}\n"
            f"Time (UTC) : {alarm.fired_at.strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"Rule       : {alarm.rule_name}\n"
            f"Alarm ID   : {alarm.alarm_id}\n"
            f"{'=' * 44}\n"
            f"Log in to the SafeVision Security Center to acknowledge this alarm."
        )

        logger.info(
            f"[ALARM] Sending email to {len(recipients)} recipient(s): {recipients}"
        )

        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"]    = getattr(cfg, "SMTP_FROM", "SafeVision")
        msg["To"]      = ", ".join(recipients)

        try:
            with smtplib.SMTP(cfg.SMTP_HOST, cfg.SMTP_PORT, timeout=10) as smtp:
                smtp.starttls()
                smtp.login(cfg.SMTP_USER, cfg.SMTP_PASSWORD)
                smtp.sendmail(cfg.SMTP_FROM, recipients, msg.as_string())
            logger.info(f"[ALARM] Email sent to {recipients}")
            _ALARMS_COL.update_one(
                {"alarm_id": alarm.alarm_id},
                {"$set": {"email_sent": True}},
            )
        except Exception as e:
            logger.error(f"[ALARM] Email failed: {e}")

    #   Retention                               ─

    def prune_old_alarms(self, max_age_days: int = 30) -> int:
        """Remove DISMISSED alarms older than max_age_days. Returns deleted count."""
        cutoff = datetime.datetime.utcnow() - datetime.timedelta(days=max_age_days)
        result = _ALARMS_COL.delete_many({
            "state": AlarmState.DISMISSED,
            "fired_at": {"$lt": cutoff},
        })
        count = result.deleted_count
        if count:
            logger.info(f"[ALARM] Pruned {count} old dismissed alarms")
        return count
