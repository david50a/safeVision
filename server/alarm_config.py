import os
from pathlib import Path
from dotenv import load_dotenv
from secret_manager import secrets

def get_secret(key: str, default: str = "") -> str:
    """Try to get from SecretManager, fallback to env, then default."""
    try:
        val = secrets.get(key)
        if val is not None:
            return str(val)
    except Exception:
        pass
    return os.getenv(key, default)

# Ensure environment variables are loaded
load_dotenv()

#  Paths
_SERVER_DIR = Path(__file__).resolve().parent if '__file__' in globals() else Path.cwd()
DATA_DIR = Path(os.getenv("SAFEVISION_DATA_DIR", str(_SERVER_DIR)))

RULES_PATH = DATA_DIR / "alarm_rules.json"
ALARM_LOG = DATA_DIR / "alarms.jsonl"
ALARMS_DB_PATH = DATA_DIR / "database" / "alarms.jsonl"
SNAPSHOTS_DIR = DATA_DIR / "database" / "snapshots"

#  Internal Communication Security
_secret_path = DATA_DIR / "internal_secret.key"
if _secret_path.exists():
    with open(_secret_path, "r") as f:
        INTERNAL_STREAM_SECRET = f.read().strip()
else:
    import secrets
    INTERNAL_STREAM_SECRET = secrets.token_hex(32)
    try:
        with open(_secret_path, "w") as f:
            f.write(INTERNAL_STREAM_SECRET)
    except Exception:
        pass

_cors_origins = os.getenv("CORS_ORIGINS", "")
CORS_ORIGINS = [o.strip() for o in _cors_origins.split(",") if o.strip()]

#  SMS Notifications (Twilio) 
TWILIO_ENABLED         = get_secret("TWILIO_ENABLED", "false").lower() == "true"
TWILIO_ACCOUNT_SID     = get_secret("TWILIO_ACCOUNT_SID", "")
TWILIO_AUTH_TOKEN      = get_secret("TWILIO_AUTH_TOKEN", "")
TWILIO_FROM_NUMBER     = get_secret("TWILIO_FROM_NUMBER", "")

# Fallback phone numbers if no zone-based guards are found
_guard_phones = os.getenv("GUARD_PHONE_NUMBERS", "")
GUARD_PHONE_NUMBERS    = [n.strip() for n in _guard_phones.split(",") if n.strip()]

# SMS Templates
# Variables available: {label}, {camera_id}, {location}, {probability}, {probability_pct}, {timestamp}, {rule_name}
SMS_TEMPLATE_VIOLENCE = (
    "VIOLENCE DETECTED: {probability_pct}%\n"
    "Cam: {camera_id} ({location})\n"
    "Rule: {rule_name}\n"
    "Time: {timestamp}"
)
SMS_TEMPLATE_PREVIOLENCE = (
    "PRE-VIOLENCE WARNING: {probability_pct}%\n"
    "Cam: {camera_id} ({location})\n"
    "Rule: {rule_name}\n"
    "Time: {timestamp}"
)
SMS_TEMPLATE_SECURITY = (
    "SECURITY THREAT: {label}\n"
    "Sys: {camera_id} ({location})\n"
    "Time: {timestamp}"
)


#  Email Notifications (SMTP)
SMTP_ENABLED  = get_secret("SMTP_ENABLED", "false").lower() == "true"
SMTP_HOST     = get_secret("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT     = int(get_secret("SMTP_PORT", "587"))
SMTP_USER     = get_secret("SMTP_USER", "")
SMTP_PASSWORD = get_secret("SMTP_PASSWORD", "")
SMTP_FROM     = get_secret("SMTP_FROM", "SafeVision <noreply@safevision.local>")

_alert_emails = os.getenv("ALERT_EMAILS", "")
ALERT_EMAILS  = [e.strip() for e in _alert_emails.split(",") if e.strip()]


#  Dashboard Features 
SOUND_ALERTS_ENABLED = True
