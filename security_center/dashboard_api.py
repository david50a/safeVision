"""
SafeVision Security Center  REST API
======================================
Flask HTTPS server providing endpoints for the Security Center dashboard.
Reads event data from ../server/database/*.jsonl files.
"""

import os, json, time, hashlib, hmac, threading, datetime, secrets
from functools import wraps
from pathlib import Path
import sys
import io
import re
import tempfile
import subprocess
import traceback
import importlib.util
from werkzeug.security import check_password_hash
from flask import Flask, request, jsonify, Response, send_from_directory, g
from flask_sock import Sock
import socket
import logging

try:
    from cryptography.fernet import Fernet
except ImportError:
    Fernet = None

try:
    from dateutil import parser
except ImportError:
    parser = None

try:
    import cv2
except ImportError:
    cv2 = None

# Paths  
BASE_DIR    = Path(__file__).resolve().parent
PROJECT_DIR = BASE_DIR.parent
SERVER_DIR  = PROJECT_DIR / "server"
STATIC_DIR  = BASE_DIR / "static"
CERT_FILE   = str(SERVER_DIR / "server.crt")
KEY_FILE    = str(SERVER_DIR / "server.key")

# Bootstrap path so we can import modules from server/
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

try:
    import live_stream_key
except ImportError:
    live_stream_key = None

try:
    from secret_manager import SecretManager
except ImportError:
    SecretManager = None

try:
    import alarm_config as cfg
    DATA_DIR = Path(getattr(cfg, "DATA_DIR", SERVER_DIR))
except ImportError:
    cfg = None
    DATA_DIR = SERVER_DIR

DB_DIR      = DATA_DIR / "database"

try:
    from alarm_engine import AlarmEngine, AlarmState, ALARM_LOG
    from storage import get_collection
    _alarm_engine = AlarmEngine()
    _EVENTS_COL = get_collection("events")
except Exception as _alarm_import_err:
    _alarm_engine = None
    ALARM_LOG     = DATA_DIR / "alarms.jsonl"
    _EVENTS_COL   = None
    logging.getLogger(__name__).warning(f"Storage or AlarmEngine unavailable: {_alarm_import_err}")

try:
    from guard_manager import GuardManager, ZoneManager
except Exception as _gm_err:
    GuardManager = None
    ZoneManager  = None
    logging.getLogger(__name__).warning(f"GuardManager unavailable: {_gm_err}")

try:
    from report_engine import ViolenceReportEngine
except Exception as _re_err:
    ViolenceReportEngine = None
    logging.getLogger(__name__).warning(f"ViolenceReportEngine unavailable: {_re_err}")

# Ap  
app = Flask(__name__, static_folder=str(STATIC_DIR), static_url_path="/static")
app.config["SECRET_KEY"] = secrets.token_hex(32)
HMAC_KEY = secrets.token_bytes(32)
sock = Sock(app)

# Live Streaming Globals
LATEST_FRAMES = {}  # { camera_id: encrypted_payload }

def udp_receiver():
    """Background thread to receive encrypted video frames from the ML Server."""
    try:
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        udp_sock.bind(('127.0.0.1', 5555))
        while True:
            data, _ = udp_sock.recvfrom(65535)
            # data = sig + \n + header + \n + payload
            parts = data.split(b'\n', 2)
            if len(parts) == 3:
                try:
                    sig = parts[0]
                    payload_to_verify = parts[1] + b'\n' + parts[2]
                    expected = hmac.new(cfg.INTERNAL_STREAM_SECRET.encode(), payload_to_verify, hashlib.sha256).hexdigest().encode('utf-8')
                    if not hmac.compare_digest(sig, expected):
                        continue
                        
                    header = json.loads(parts[1].decode('utf-8'))
                    cam_id = header.get("camera_id")
                    if cam_id:
                        LATEST_FRAMES[cam_id] = parts[2]
                except Exception:
                    pass
    except Exception as e:
        logging.getLogger(__name__).error(f"UDP receiver failed: {e}")

threading.Thread(target=udp_receiver, daemon=True).start()

# Role-Based Access Control
try:
    from model.model_protection import RBACManager, AuditLogger, FileEncryptor
    from cryptography.fernet import Fernet
    _dashboard_audit = AuditLogger(str(DATA_DIR / "dashboard_audit.jsonl"))
    rbac = RBACManager(str(DATA_DIR / "rbac_db.json"), _dashboard_audit)
except Exception as _rbac_err:
    rbac = None
    FileEncryptor = None
    logging.getLogger(__name__).error(f"RBACManager unavailable: {_rbac_err}")

# User store - Fallback for backward compatibility if RBAC fails
USERS = {}

# In-memory token store  {token: {user, role, exp}}
TOKENS: dict[str, dict] = {}
START_TIME = time.time()

# Helpers

def _sign(data: str) -> str:
    """SHA-256 HMAC signature."""
    return hmac.new(HMAC_KEY, data.encode(), hashlib.sha256).hexdigest()


def _make_token(username: str, role: str) -> str:
    token = secrets.token_urlsafe(48)
    TOKENS[token] = {
        "user": username,
        "role": role,
        "exp":  time.time() + 8 * 3600,   # 8 h
    }
    return token


def login_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        auth = request.headers.get("Authorization", "")
        token = ""
        if auth.startswith("Bearer "):
            token = auth[7:]
        else:
            # Fallback for SSE (EventSource)
            token = request.args.get("token", "")

        if not token:
            return jsonify(error="Missing token"), 401

        info = TOKENS.get(token)
        if not info or info["exp"] < time.time():
            TOKENS.pop(token, None)
            return jsonify(error="Invalid or expired token"), 401
        g.user = info["user"]
        g.role = info["role"]
        return f(*a, **kw)
    return wrapper


def _read_db(collection_name: str, query: dict = {}, limit: int = 0) -> list[dict]:
    coll = get_collection(collection_name)
    cursor = coll.find(query, {"_id": 0})
    if limit > 0:
        cursor = cursor.limit(limit)
    return list(cursor)


def _signed_json(data, status=200):
    body = json.dumps(data, default=str)
    resp = Response(body, status=status, mimetype="application/json")
    resp.headers["X-Signature"] = _sign(body)
    resp.headers["X-Signature-Algorithm"] = "HMAC-SHA256"
    return resp


 # Auth
 
@app.route("/api/login", methods=["POST"])
def api_login():
    body = request.get_json(force=True, silent=True) or {}
    username = body.get("username", "")
    password = body.get("password", "")
    
    if rbac:
        role = rbac.authenticate(username, password)
        if role:
            token = _make_token(username, role)
            return _signed_json({
                "token": token,
                "role": role,
                "user": username,
            })
    
    # Fallback/Legacy
    user = USERS.get(username)
    if not user or not check_password_hash(user["password"], password):
        return jsonify(error="Invalid credentials"), 401
    token = _make_token(username, user["role"])
    return _signed_json({
        "token": token,
        "role": user["role"],
        "user": username,
    })


# Stream Key
@app.route("/api/stream/key")
@login_required
def api_stream_key():
    try:
        if live_stream_key is None:
            raise ImportError("live_stream_key module is None")
        key = live_stream_key.get_base64_key()
        return _signed_json({"key": key})
    except Exception as e:
        return jsonify(error=f"Key generation failed: {str(e)}"), 500

# Live Stream WebSocket
@sock.route('/api/stream/<camera_id>')
def stream_socket(ws, camera_id):
    print(f"DEBUG stream_socket: client attempting to connect for {camera_id}")
    token = request.args.get("token")
    if not token or token not in TOKENS or TOKENS[token]["exp"] < time.time():
        print(f"DEBUG stream_socket: unauthorized for token {token}")
        ws.send(json.dumps({"error": "Unauthorized"}))
        ws.close()
        return

    print(f"DEBUG stream_socket: connection authorized for {camera_id}")
    last_sent = None
    sent_count = 0
    try:
        while True:
            frame = LATEST_FRAMES.get(camera_id)
            if frame and frame != last_sent:
                ws.send(frame)
                last_sent = frame
                sent_count += 1
                if sent_count % 20 == 0:
                    print(f"DEBUG stream_socket: sent {sent_count} frames to {camera_id}")
            time.sleep(0.01)
    except Exception as e:
        print(f"DEBUG stream_socket: connection error {e}")
    finally:
        print(f"DEBUG stream_socket: connection closed")
        ws.close()

@app.route("/api/internal/stream", methods=["POST"])
def api_internal_stream():
    """Fallback for when UDP is blocked. Receives encrypted frames via POST."""
    try:
        data = request.get_data()
        parts = data.split(b'\n', 2)
        if len(parts) == 3:
            sig = parts[0]
            payload_to_verify = parts[1] + b'\n' + parts[2]
            expected = hmac.new(cfg.INTERNAL_STREAM_SECRET.encode(), payload_to_verify, hashlib.sha256).hexdigest().encode('utf-8')
            if not hmac.compare_digest(sig, expected):
                return "Unauthorized", 401
                
            header = json.loads(parts[1].decode('utf-8'))
            cam_id = header.get("camera_id")
            if cam_id:
                LATEST_FRAMES[cam_id] = parts[2]
        return "OK", 200
    except Exception:
        return "Error", 500

@app.route("/api/debug/frames")
def api_debug_frames():
    return jsonify({
        "camera_ids": list(LATEST_FRAMES.keys()),
        "frame_count": {cid: len(payload) for cid, payload in LATEST_FRAMES.items()}
    })

# Alerts  

@app.route("/api/alerts")
@login_required
def api_alerts():
    # filters
    risk = request.args.get("risk_level")
    camera = request.args.get("camera_id")
    limit = int(request.args.get("limit", 100))
    
    query = {}
    if risk is not None:
        query["risk_level"] = int(risk)
    if camera:
        query["camera_id"] = camera
        
    events = _read_db("events", query, limit)
    events.reverse()                   # newest first (find().limit() usually returns oldest first if no sort)
    # Actually, we should probably sort by timestamp in MongoDB
    coll = get_collection("events")
    cursor = coll.find(query, {"_id": 0}).sort("timestamp", -1).limit(limit)
    events = list(cursor)
    
    return _signed_json({"alerts": events, "total": len(events)})


@app.route("/api/alerts/realtime")
@login_required
def api_alerts_realtime():
    """SSE stream polls MongoDB for new entries."""
    def generate():
        coll = get_collection("events")
        # Start from now
        last_ts = datetime.datetime.utcnow()
        
        while True:
            # Query for events newer than last_ts
            query = {"timestamp": {"$gt": last_ts}}
            new_events = list(coll.find(query, {"_id": 0}).sort("timestamp", 1))
            
            for ev in new_events:
                yield f"data: {json.dumps(ev, default=str)}\n\n"
                ts = ev["timestamp"]
                if isinstance(ts, str):
                    last_ts = parser.parse(ts)
                elif hasattr(ts, "replace"):
                    last_ts = ts.replace(tzinfo=None)
                else:
                    last_ts = ts
            
            time.sleep(1.0)

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# Guardiance (Model Protection)  

def _read_audit_jsonl() -> list[dict]:
    path = DATA_DIR / "server_audit.jsonl"
    if not path.exists():
        return []
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return rows

@app.route("/api/guard/audit")
@login_required
def api_guard_audit():
    events = _read_audit_jsonl()
    limit = int(request.args.get("limit", 100))
    events = events[-limit:]
    events.reverse()  # newest first
    return _signed_json({"audit": events, "total": len(events)})

@app.route("/api/guard/realtime")
@login_required
def api_guard_realtime():
    """SSE stream – tails server_audit.jsonl for new protection events."""
    path = DATA_DIR / "server_audit.jsonl"
    def generate():
        if not path.exists():
            return
        with open(path, "r", encoding="utf-8") as f:
            f.seek(0, 2)
            while True:
                line = f.readline()
                if line.strip():
                    yield f"data: {line.strip()}\n\n"
                else:
                    time.sleep(0.5)
    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

@app.route("/api/guard/stats")
@login_required
def api_guard_stats():
    events = _read_audit_jsonl()
    total = len(events)
    blocks = sum(1 for e in events if e.get("event") == "BLOCK" or (not e.get("success", True) and e.get("event") == "MODEL_SCAN"))
    auth_fails = sum(1 for e in events if e.get("event") == "AUTH_FAILED" or e.get("event") == "COMM_ERROR")
    anomalies = sum(1 for e in events if e.get("event") == "ANOMALY_DETECTED")
    return _signed_json({
        "total_events": total,
        "blocked_frames": blocks,
        "auth_failures": auth_fails,
        "anomalies": anomalies
    })


 # Server Status  (active camera clients, uptime)
 
def _parse_server_log() -> dict:
    """
    Scan server.log to reconstruct live client state.
    Returns { active_clients, total_sessions, last_event, uptime_seconds }.
    """
    log_path = DATA_DIR / "server.log"
    if not log_path.exists():
        return {"active_clients": 0, "total_sessions": 0, "last_event": None}

    connected   = 0
    sessions    = 0
    last_ts     = None
    first_ts    = None

    connect_re    = re.compile(r"\[SERVER\] Client connected:")
    disconnect_re = re.compile(r"\[SERVER\] Client .* disconnected")
    ts_re         = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})")

    try:
        with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                m = ts_re.match(line)
                if m:
                    last_ts = m.group(1)
                    if first_ts is None:
                        first_ts = last_ts
                if connect_re.search(line):
                    connected += 1
                    sessions  += 1
                elif disconnect_re.search(line):
                    connected = max(0, connected - 1)
    except Exception:
        pass

    uptime = None
    if first_ts:
        try:
            t0 = datetime.datetime.strptime(first_ts, "%Y-%m-%d %H:%M:%S")
            uptime = round((datetime.datetime.utcnow() - t0).total_seconds())
        except Exception:
            pass

    return {
        "active_clients":  connected,
        "total_sessions":  sessions,
        "last_event":      last_ts,
        "uptime_seconds":  uptime,
    }


@app.route("/api/server/status")
@login_required
def api_server_status():
    data = _parse_server_log()
    data["server_time"] = datetime.datetime.utcnow().isoformat() + "Z"
    return _signed_json(data)


 # Alarms
 
@app.route("/api/alarms")
@login_required
def api_alarms():
    if _alarm_engine is None:
        return jsonify(error="AlarmEngine unavailable"), 503
    state     = request.args.get("state")
    camera_id = request.args.get("camera_id")
    limit     = int(request.args.get("limit", 100))
    alarms    = AlarmEngine.get_alarms(state=state, camera_id=camera_id, limit=limit)
    return _signed_json({"alarms": alarms, "total": len(alarms)})


@app.route("/api/alarms/stats")
@login_required
def api_alarms_stats():
    if _alarm_engine is None:
        return jsonify(error="AlarmEngine unavailable"), 503
    return _signed_json(AlarmEngine.get_stats())


@app.route("/api/alarms/realtime")
@login_required
def api_alarms_realtime():
    """SSE stream — tails alarms.jsonl for new alarm events."""
    path = Path(ALARM_LOG)

    def generate():
        path.touch(exist_ok=True)
        with open(path, "r", encoding="utf-8") as f:
            f.seek(0, 2)          # jump to end
            while True:
                line = f.readline()
                if line.strip():
                    yield f"data: {line.strip()}\n\n"
                else:
                    time.sleep(0.3)

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/api/alarms/<alarm_id>/acknowledge", methods=["POST"])
@login_required
def api_alarm_acknowledge(alarm_id):
    if _alarm_engine is None:
        return jsonify(error="AlarmEngine unavailable"), 503
    ok = AlarmEngine.acknowledge(alarm_id)
    if ok:
        return _signed_json({"status": "acknowledged", "alarm_id": alarm_id})
    return jsonify(error="Alarm not found or already acknowledged"), 404


@app.route("/api/alarms/<alarm_id>/dismiss", methods=["POST"])
@login_required
def api_alarm_dismiss(alarm_id):
    if _alarm_engine is None:
        return jsonify(error="AlarmEngine unavailable"), 503
    ok = AlarmEngine.dismiss(alarm_id)
    if ok:
        return _signed_json({"status": "dismissed", "alarm_id": alarm_id})
    return jsonify(error="Alarm not found or already dismissed"), 404


 # Alarm Rules
 
@app.route("/api/alarm-rules", methods=["GET"])
@login_required
def api_alarm_rules_get():
    if _alarm_engine is None:
        return jsonify(error="AlarmEngine unavailable"), 503
    return _signed_json({"rules": _alarm_engine.get_rules()})


@app.route("/api/alarm-rules", methods=["POST"])
@login_required
def api_alarm_rules_create():
    if g.role != "admin":
        return jsonify(error="Admin only"), 403
    if _alarm_engine is None:
        return jsonify(error="AlarmEngine unavailable"), 503
    body = request.get_json(force=True, silent=True) or {}
    required = ["name", "label_triggers", "min_probability", "severity"]
    for field_name in required:
        if field_name not in body:
            return jsonify(error=f"Missing field: {field_name}"), 400
    rule_id = _alarm_engine.add_rule(body)
    return _signed_json({"status": "created", "rule_id": rule_id}), 201


@app.route("/api/alarm-rules/<rule_id>", methods=["DELETE"])
@login_required
def api_alarm_rules_delete(rule_id):
    if g.role != "admin":
        return jsonify(error="Admin only"), 403
    if _alarm_engine is None:
        return jsonify(error="AlarmEngine unavailable"), 503
    ok = _alarm_engine.delete_rule(rule_id)
    if ok:
        return _signed_json({"status": "deleted", "rule_id": rule_id})
    return jsonify(error="Rule not found"), 404




@app.route("/api/reports/summary")
@login_required
def api_reports_summary():
    events = _read_db("events")
    total = len(events)
    risk_0 = sum(1 for e in events if e.get("risk_level") == 0)
    risk_1 = sum(1 for e in events if e.get("risk_level") in (1, 2))
    cameras = {}
    for e in events:
        c = e.get("camera_id", "unknown")
        cameras[c] = cameras.get(c, 0) + 1
    safe_pct = round(risk_0 / total * 100, 1) if total else 0
    avg_prob = round(sum(e.get("probability", 0) for e in events) / total, 3) if total else 0
    return _signed_json({
        "total_events": total,
        "safe_events": risk_0,
        "alert_events": risk_1,
        "safe_percentage": safe_pct,
        "average_probability": avg_prob,
        "cameras": cameras,
    })


@app.route("/api/reports/timeline")
@login_required
def api_reports_timeline():
    events = _read_db("events")
    buckets: dict[str, dict] = {}
    for e in events:
        ts = e.get("timestamp")
        if not ts: continue
        try:
            if isinstance(ts, datetime.datetime):
                sec = ts.strftime("%Y-%m-%d %H:%M:%S")
            else:
                sec = str(ts)[:19]
            buckets.setdefault(sec, {"safe": 0, "alert": 0})
            if e.get("risk_level") == 0:
                buckets[sec]["safe"] += 1
            else:
                buckets[sec]["alert"] += 1
        except Exception:
            pass
    # return sorted
    timeline = [{"time": k, **v} for k, v in sorted(buckets.items())]
    return _signed_json({"timeline": timeline})

@app.route("/api/reports/violence")
@login_required
def api_reports_violence():
    """Main violence report endpoint. Accepts date-range + filter params."""
    if ViolenceReportEngine is None:
        return jsonify(error="ReportEngine unavailable"), 503
    try:
        from_str  = request.args.get("from")
        to_str    = request.args.get("to")
        camera_id = request.args.get("camera_id") or None
        severity  = request.args.get("severity")  or None
        limit     = int(request.args.get("limit", 500))

        now = datetime.datetime.utcnow()
        from_dt = _parse_date(from_str) or (now - datetime.timedelta(days=30))
        to_dt   = _parse_date(to_str,   end_of_day=True) or now

        data = ViolenceReportEngine.get_report_data(
            from_dt=from_dt, to_dt=to_dt,
            camera_id=camera_id, severity=severity, limit=limit,
        )
        return _signed_json(data)
    except Exception as e:
        return jsonify(error=str(e)), 500


@app.route("/api/reports/violence/csv")
@login_required
def api_reports_violence_csv():
    """Download violence incidents as CSV."""
    if ViolenceReportEngine is None:
        return jsonify(error="ReportEngine unavailable"), 503
    try:
        from_dt = _parse_date(request.args.get("from")) or \
                  (datetime.datetime.utcnow() - datetime.timedelta(days=30))
        to_dt   = _parse_date(request.args.get("to"), end_of_day=True) or \
                  datetime.datetime.utcnow()
        data = ViolenceReportEngine.get_report_data(
            from_dt=from_dt, to_dt=to_dt,
            camera_id=request.args.get("camera_id") or None,
            severity=request.args.get("severity")   or None,
        )
        csv_str  = ViolenceReportEngine.export_csv(data)
        filename = f"violence_report_{from_dt.strftime('%Y%m%d')}_{to_dt.strftime('%Y%m%d')}.csv"
        return Response(
            csv_str,
            mimetype="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except Exception as e:
        return jsonify(error=str(e)), 500


@app.route("/api/reports/violence/pdf")
@login_required
def api_reports_violence_pdf():
    """Download violence report as PDF (requires reportlab)."""
    if ViolenceReportEngine is None:
        return jsonify(error="ReportEngine unavailable"), 503
    try:
        key = request.args.get("encryption_key")
        if not key:
            return jsonify(error="An encryption key is required to download the PDF."), 401
            
        if SecretManager is None:
            raise ImportError("SecretManager not found")
        sec = SecretManager(str(DB_DIR / "secrets.enc"))
        if not sec.unlock(key):
            return jsonify(error="Incorrect master key provided."), 401
            
        from_dt = _parse_date(request.args.get("from")) or \
                  (datetime.datetime.utcnow() - datetime.timedelta(days=30))
        to_dt   = _parse_date(request.args.get("to"), end_of_day=True) or \
                  datetime.datetime.utcnow()
        data    = ViolenceReportEngine.get_report_data(
            from_dt=from_dt, to_dt=to_dt,
            camera_id=request.args.get("camera_id") or None,
            severity=request.args.get("severity")   or None,
        )
        pdf_bytes = ViolenceReportEngine.export_pdf(data, password=key)
        filename  = f"violence_report_{from_dt.strftime('%Y%m%d')}_{to_dt.strftime('%Y%m%d')}.pdf"
        return Response(
            pdf_bytes,
            mimetype="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except RuntimeError as e:
        return jsonify(error=str(e)), 503
    except Exception as e:
        return jsonify(error=str(e)), 500


def _parse_date(s: str, end_of_day: bool = False):
    """Parse YYYY-MM-DD string to datetime. Returns None on failure."""
    if not s:
        return None
    try:
        dt = datetime.datetime.strptime(s[:10], "%Y-%m-%d")
        if end_of_day:
            dt = dt.replace(hour=23, minute=59, second=59)
        return dt
    except Exception:
        return None


 # System
 
@app.route("/api/system/status")
@login_required
def api_system_status():
    uptime = time.time() - START_TIME
    db_files = {}
    if DB_DIR.exists():
        for f in DB_DIR.iterdir():
            if f.is_file():
                db_files[f.name] = f.stat().st_size

    # read config values
    model_version = "v2"
    location = "HISPIN"
    try:
        spec = importlib.util.spec_from_file_location("config", str(SERVER_DIR / "config.py"))
        cfg = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cfg)
        model_version = getattr(cfg, "MODEL_VERSION", model_version)
        location = getattr(cfg, "LOCATION", location)
    except Exception:
        pass

    return _signed_json({
        "status": "operational",
        "uptime_seconds": round(uptime, 1),
        "uptime_human": str(datetime.timedelta(seconds=int(uptime))),
        "model_version": model_version,
        "location": location,
        "database_files": db_files,
        "tls_enabled": True,
        "cert_file": os.path.basename(CERT_FILE),
    })


@app.route("/api/system/security")
@login_required
def api_system_security():
    return _signed_json({
        "transport_encryption": {
            "protocol": "TLS/SSL",
            "certificate": "server.crt",
            "key": "server.key (RSA)",
            "status": "active",
        },
        "digital_signatures": {
            "algorithm": "HMAC-SHA256",
            "header": "X-Signature",
            "description": "Every API response includes a SHA-256 HMAC signature for integrity verification.",
        },
        "data_integrity": {
            "algorithm": "SHA-256",
            "applied_to": ["API responses", "Database records", "Model weights"],
        },
        "access_control": {
            "type": "RBAC (Role-Based Access Control)",
            "roles": [
                {"name": "admin",  "permissions": ["read", "write", "manage_users", "system_config"]},
                {"name": "viewer", "permissions": ["read"]},
            ],
        },
        "encryption_layer": {
            "stream_cipher": "AES-256-GCM",
            "key_exchange": "Diffie-Hellman",
            "model_protection": "AES encrypted (.pth.enc), decrypted at runtime",
        },
    })


 # Frontend (serve static files)
 
@app.route("/")
def index():
    return send_from_directory(str(STATIC_DIR), "index.html")


 # CORS (simple)
 
@app.after_request
def after_request(resp):
    origin = request.headers.get("Origin")
    cors_origins = getattr(cfg, "CORS_ORIGINS", []) if cfg else []
    if cors_origins:
        if origin in cors_origins:
            resp.headers["Access-Control-Allow-Origin"] = origin
    else:
        resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    return resp


 # Guards
 
def _gm_check():
    if GuardManager is None:
        return jsonify(error="GuardManager unavailable"), 503
    return None


@app.route("/api/guards", methods=["GET"])
@login_required
def api_guards_list():
    err = _gm_check()
    if err: return err
    active_only = request.args.get("active") == "1"
    guards = GuardManager.list_guards(active_only=active_only)
    return _signed_json({"guards": guards, "total": len(guards)})


@app.route("/api/guards", methods=["POST"])
@login_required
def api_guards_create():
    if g.role != "admin":
        return jsonify(error="Admin only"), 403
    err = _gm_check()
    if err: return err
    body = request.get_json(force=True, silent=True) or {}
    if not body.get("name") or not body.get("phone"):
        return jsonify(error="name and phone are required"), 400
    guard = GuardManager.create_guard(
        name     = body["name"],
        phone    = body["phone"],
        email    = body.get("email", ""),
        badge_id = body.get("badge_id", ""),
        notes    = body.get("notes", ""),
    )
    return _signed_json({"status": "created", "guard": guard}), 201


@app.route("/api/guards/<guard_id>", methods=["PUT"])
@login_required
def api_guards_update(guard_id):
    if g.role != "admin":
        return jsonify(error="Admin only"), 403
    err = _gm_check()
    if err: return err
    body = request.get_json(force=True, silent=True) or {}
    ok = GuardManager.update_guard(guard_id, body)
    if ok:
        return _signed_json({"status": "updated"})
    return jsonify(error="Guard not found or nothing changed"), 404


@app.route("/api/guards/<guard_id>", methods=["DELETE"])
@login_required
def api_guards_delete(guard_id):
    if g.role != "admin":
        return jsonify(error="Admin only"), 403
    err = _gm_check()
    if err: return err
    ok = GuardManager.delete_guard(guard_id)
    if ok:
        return _signed_json({"status": "deleted"})
    return jsonify(error="Guard not found"), 404


@app.route("/api/guards/<guard_id>/assign-zone", methods=["POST"])
@login_required
def api_guards_assign_zone(guard_id):
    if g.role != "admin":
        return jsonify(error="Admin only"), 403
    err = _gm_check()
    if err: return err
    body    = request.get_json(force=True, silent=True) or {}
    zone_id = body.get("zone_id")
    if not zone_id:
        return jsonify(error="zone_id required"), 400
    ok = GuardManager.assign_to_zone(guard_id, zone_id)
    if ok:
        return _signed_json({"status": "assigned"})
    return jsonify(error="Guard not found"), 404


@app.route("/api/guards/<guard_id>/remove-zone", methods=["POST"])
@login_required
def api_guards_remove_zone(guard_id):
    if g.role != "admin":
        return jsonify(error="Admin only"), 403
    err = _gm_check()
    if err: return err
    body    = request.get_json(force=True, silent=True) or {}
    zone_id = body.get("zone_id")
    if not zone_id:
        return jsonify(error="zone_id required"), 400
    ok = GuardManager.remove_from_zone(guard_id, zone_id)
    if ok:
        return _signed_json({"status": "removed"})
    return jsonify(error="Guard not found"), 404


 # Recordings
 
@app.route("/api/recordings", methods=["GET"])
@login_required
def api_recordings_list():
    if g.role != "admin":
        return jsonify(error="Admin only"), 403
    recordings_dir = SERVER_DIR / "recordings"
    files = []
    if recordings_dir.exists():
        for f in recordings_dir.iterdir():
            if f.is_file() and f.name.endswith(".mp4.enc"):
                stat = f.stat()
                files.append({
                    "filename": f.name,
                    "size": stat.st_size,
                    "date": datetime.datetime.fromtimestamp(stat.st_mtime).isoformat() + "Z"
                })
    # Sort by date descending
    files.sort(key=lambda x: x["date"], reverse=True)
    return _signed_json({"recordings": files, "total": len(files)})

@app.route("/api/recordings/<filename>/decrypt", methods=["POST"])
@login_required
def api_recordings_decrypt(filename):
    if g.role != "admin":
        return jsonify(error="Admin only"), 403
    
    if FileEncryptor is None or 'Fernet' not in globals():
        return jsonify(error="Encryption tools unavailable"), 503

    body = request.get_json(force=True, silent=True) or {}
    master_key = body.get("key")
    if not master_key:
        return jsonify(error="master key required"), 400

    if SecretManager is None:
        return jsonify(error="SecretManager unavailable"), 503
    sec = SecretManager(str(DB_DIR / "secrets.enc"))
    if not sec.unlock(master_key):
        return jsonify(error="Incorrect master key"), 403

    filepath = SERVER_DIR / "recordings" / filename
    if not filepath.exists() or not filepath.is_file():
        return jsonify(error="File not found"), 404

    try:
        raw = filepath.read_bytes()
        encryptor = FileEncryptor()
        
        if not raw.startswith(encryptor.MAGIC):
            return jsonify(error="Not a protected file"), 400
            
        salt = raw[len(encryptor.MAGIC): len(encryptor.MAGIC) + encryptor.SALT_LEN]
        enc  = raw[len(encryptor.MAGIC) + encryptor.SALT_LEN:]
        
        # We need to manually derive the key to use with Fernet
        key = encryptor._derive_key(master_key, salt)
        data = Fernet(key).decrypt(enc)
        
        # Check codec and transcode on-the-fly if not H.264
        if cv2 is None:
            raise ImportError("cv2 not found")
        
        temp_name = None
        try:
            with tempfile.NamedTemporaryFile(suffix='.mp4', delete=False) as f:
                f.write(data)
                temp_name = f.name
            
            is_h264 = False
            cap = cv2.VideoCapture(temp_name)
            if cap.isOpened():
                fourcc = int(cap.get(cv2.CAP_PROP_FOURCC))
                codec_str = "".join([chr((fourcc >> (i * 8)) & 0xFF) for i in range(4)]).lower()
                if 'avc' in codec_str or 'h26' in codec_str:
                    is_h264 = True
                cap.release()
                
            if not is_h264:
                transcoded_name = temp_name + '_h264.mp4'
                ffmpeg_cmd = [
                    'ffmpeg', '-y',
                    '-i', temp_name,
                    '-vcodec', 'libx264',
                    '-pix_fmt', 'yuv420p',
                    '-movflags', 'faststart',
                    transcoded_name
                ]
                res = subprocess.run(ffmpeg_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                if res.returncode == 0 and os.path.exists(transcoded_name):
                    data = Path(transcoded_name).read_bytes()
                    # Re-encrypt back to the same file path so future plays are fast and H.264
                    try:
                        encryptor.encrypt_file(transcoded_name, str(filepath), master_key)
                    except Exception as re_enc_err:
                        pass
                    try:
                        os.remove(transcoded_name)
                    except:
                        pass
        except Exception as transcode_err:
            app.logger.error(f"Transcode error: {transcode_err}")
            app.logger.error(traceback.format_exc())
        finally:
            if temp_name and os.path.exists(temp_name):
                try:
                    os.remove(temp_name)
                except:
                    pass
        
        return Response(data, mimetype="video/mp4")
    except Exception as e:
        return jsonify(error=f"Decryption failed, incorrect password or corrupt file: {str(e)}"), 403

@app.route("/api/verify-master-key", methods=["POST"])
@login_required
def api_verify_master_key():
    if g.role != "admin":
        return jsonify(error="Admin only"), 403
    body = request.get_json(force=True, silent=True) or {}
    key = body.get("key")
    if not key:
        return jsonify(error="master key required"), 400
    if SecretManager is None:
        return jsonify(error="SecretManager unavailable"), 503
    sec = SecretManager(str(DB_DIR / "secrets.enc"))
    if not sec.unlock(key):
        return jsonify(error="Incorrect master key"), 403
    return _signed_json({"status": "ok"})

 # Zones
 
@app.route("/api/zones", methods=["GET"])
@login_required
def api_zones_list():
    err = _gm_check()
    if err: return err
    zones = ZoneManager.list_zones()
    # Annotate each zone with guard count
    for z in zones:
        guards = GuardManager.list_guards()
        z["guard_count"] = sum(
            1 for gu in guards if z["zone_id"] in gu.get("zones", [])
        )
    return _signed_json({"zones": zones, "total": len(zones)})


@app.route("/api/zones", methods=["POST"])
@login_required
def api_zones_create():
    if g.role != "admin":
        return jsonify(error="Admin only"), 403
    err = _gm_check()
    if err: return err
    body = request.get_json(force=True, silent=True) or {}
    if not body.get("name"):
        return jsonify(error="name is required"), 400
    zone = ZoneManager.create_zone(
        name        = body["name"],
        cameras     = body.get("cameras", []),
        description = body.get("description", ""),
    )
    return _signed_json({"status": "created", "zone": zone}), 201


@app.route("/api/zones/<zone_id>", methods=["PUT"])
@login_required
def api_zones_update(zone_id):
    if g.role != "admin":
        return jsonify(error="Admin only"), 403
    err = _gm_check()
    if err: return err
    body = request.get_json(force=True, silent=True) or {}
    ok = ZoneManager.update_zone(zone_id, body)
    if ok:
        return _signed_json({"status": "updated"})
    return jsonify(error="Zone not found or nothing changed"), 404


@app.route("/api/zones/<zone_id>", methods=["DELETE"])
@login_required
def api_zones_delete(zone_id):
    if g.role != "admin":
        return jsonify(error="Admin only"), 403
    err = _gm_check()
    if err: return err
    ok = ZoneManager.delete_zone(zone_id)
    if ok:
        return _signed_json({"status": "deleted"})
    return jsonify(error="Zone not found"), 404


@app.route("/api/zones/<zone_id>/cameras", methods=["POST"])
@login_required
def api_zones_add_camera(zone_id):
    if g.role != "admin":
        return jsonify(error="Admin only"), 403
    err = _gm_check()
    if err: return err
    body      = request.get_json(force=True, silent=True) or {}
    camera_id = body.get("camera_id")
    if not camera_id:
        return jsonify(error="camera_id required"), 400
    ok = ZoneManager.add_camera(zone_id, camera_id)
    if ok:
        return _signed_json({"status": "camera added"})
    return jsonify(error="Zone not found"), 404


@app.route("/api/zones/<zone_id>/cameras/<camera_id>", methods=["DELETE"])
@login_required
def api_zones_remove_camera(zone_id, camera_id):
    if g.role != "admin":
        return jsonify(error="Admin only"), 403
    err = _gm_check()
    if err: return err
    ok = ZoneManager.remove_camera(zone_id, camera_id)
    if ok:
        return _signed_json({"status": "camera removed"})
    return jsonify(error="Zone not found"), 404


 # Main
if __name__ == "__main__":
    print("==============================================")
    print("   SafeVision Security Center                ")
    print("   https://localhost:5000                     ")
    print("==============================================")
    app.run(
        host="0.0.0.0",
        port=5000,
        ssl_context=(CERT_FILE, KEY_FILE),
        debug=True,
    )
