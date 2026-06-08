import socket
import threading
import subprocess
from queue import Queue
from collections import deque
import numpy as np
import torch
import onnxruntime as ort
import onnx
import config
import SecureVideoStreamWithDH
from model.lstm_model import SafeVisionLSTM
from model.lstm_model import extract_features, build_sequence_features
from model.export_onnx_util import export_to_onnx
import cv2
import ssl
import traceback
import os
import hashlib
import json
import model.model_protection as protector
from model.model_protection import FileEncryptor
import getpass
import model.vision as vision
from storage import JsonCollection
import logging
from alarm_engine import AlarmEngine
from secret_manager import secrets
from security_alarm_bridge import SecurityAlarmBridge
import datetime
import struct
from stream_broadcaster import broadcaster
import time
from report_engine import ViolenceReportEngine
from dateutil import parser
from PIL import Image
import time
import stat
import getpass
import struct
import io

class CppInferenceDaemon:
    def __init__(self, exe_path, onnx_path):
        self.exe_path = exe_path
        self.onnx_path = onnx_path
        self.process = None
        self._start_process()

    def _start_process(self):
        cmd = [self.exe_path, "--model", self.onnx_path, "--interactive"]
        self.process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0
        )
        logging.info(f"C++ Inference Daemon started: {self.exe_path}")

    def predict(self, sequence_features):
        if self.process.poll() is not None:
            logging.warning("C++ Inference Daemon died. Restarting...")
            self._start_process()

        try:
            # Send features as binary (floats)
            # sequence_features is (30, 440)
            data = sequence_features.astype(np.float32).tobytes()
            self.process.stdin.write(data)
            self.process.stdin.flush()

            # Read result from stdout
            line = self.process.stdout.readline().decode().strip()
            if not line:
                return None, None

            parts = line.split()
            pred_idx = int(parts[0])
            probs = [float(p) for p in parts[1:-1]]
            return pred_idx, probs
        except Exception as e:
            logging.error(f"C++ Inference error: {e}")
            return None, None

    def stop(self):
        if self.process:
            self.process.terminate()
# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("server.log"),
        logging.StreamHandler() # Also log to console
    ]
)

#  File-based Storage 
_EVENTS_COL = JsonCollection("database/events.jsonl")
_FEAT_SEQ_COL = JsonCollection("database/feature_sequence.jsonl")
_FEAT_FRAME_COL = JsonCollection("database/feature_frame.jsonl")
_SYS_LOG_COL = JsonCollection("database/system_log.jsonl")

#  Alarm Engine 
alarm_engine = AlarmEngine()

def _alarm_retention_worker():
    while True:
        alarm_engine.prune_old_alarms(max_age_days=30)
        time.sleep(86400)  # daily

threading.Thread(target=_alarm_retention_worker, daemon=True).start()

DATA_PATH = 'data'
os.makedirs(DATA_PATH, exist_ok=True)

#  Model Protection Initialization 
audit_log = protector.AuditLogger('server_audit.jsonl')
# SecurityAlarmBridge wraps SecurityMonitor — all sec_mon.record_*() calls now
# also fire AlarmEngine alarms and SMS the responsible zone guards.
sec_mon     = SecurityAlarmBridge(
    audit_log,
    alarm_engine,
    camera_id = "SYSTEM",
    location  = "Security System",
)
privacy = protector.PrivacyEngine(audit_log, blur_strength=30, fallback_blur=True)
access_ctrl = protector.AccessControl()
rbac = protector.RBACManager('rbac_db.json', audit_log)

# Create a default admin user if DB is newly created and empty
if not rbac.list_users():
    print("\n[INITIAL SETUP] No users found in RBAC database.")
    while True:
        admin_pwd = getpass.getpass("Enter password for default 'admin' account: ")
        confirm_pwd = getpass.getpass("Confirm password: ")
        if admin_pwd == confirm_pwd and admin_pwd:
            break
        print("Passwords do not match or are empty. Try again.")
    rbac.create_user('admin', admin_pwd, 'admin')

# Paths for data retention
SNAP_PATH = os.path.join(os.path.dirname(__file__), 'database', 'snapshots')
REC_PATH = os.path.join(os.path.dirname(__file__), 'recordings')
REPORT_PATH = os.path.join(os.path.dirname(__file__), 'reports')
os.makedirs(REPORT_PATH, exist_ok=True)

retention = protector.RetentionManager(audit_log, max_age_days=30)  
guard = protector.VisualInputGuard(strict=True, audit_log='server_audit.jsonl')
stream_protector = protector.VideoStreamProtector(FileEncryptor(), audit_log, output_dir='recordings')

def run_retention_tasks():
    """Performs all data retention and cleanup tasks."""
    try:
        temp_retention = protector.RetentionManager(audit_log, max_age_days=1)
        temp_retention.run([DATA_PATH], patterns='*.png')
        retention.run([SNAP_PATH], patterns='*.enc')
        retention.run([SNAP_PATH], patterns='*.png') 
        retention.run([REC_PATH], patterns='*.enc')
        alarm_engine.prune_old_alarms(max_age_days=30)
        
    except Exception as e:
        logging.error(f"[SYSTEM] Retention task error: {e}")

def retention_worker():
    """Background thread to periodically clean up sensitive data."""
    while True:
        time.sleep(3600) 
        run_retention_tasks()

def report_generation_worker():
    """Generates a daily security report at midnight."""
    engine = ViolenceReportEngine()
    while True:
        try:
            now = datetime.datetime.now()
            tomorrow = now + datetime.timedelta(days=1)
            midnight = datetime.datetime(tomorrow.year, tomorrow.month, tomorrow.day, 0, 0, 0)
            wait_seconds = (midnight - now).total_seconds()
            logging.info(f"[REPORT] Daily report scheduled in {wait_seconds/3600:.1f} hours.")
            time.sleep(wait_seconds)
            report_name = f"Daily_Summary_{now.strftime('%Y-%m-%d')}.pdf"
            report_file = os.path.join(REPORT_PATH, report_name)
            logging.info(f"[REPORT] Generating daily summary: {report_name}")
            day_ago = datetime.datetime.utcnow() - datetime.timedelta(days=1)
            report_data = ViolenceReportEngine.get_report_data(from_dt=day_ago)
            
            if report_data.get("incidents"):
                pdf_bytes = ViolenceReportEngine.export_pdf(report_data, password=_password)
                with open(report_file, 'wb') as f:
                    f.write(pdf_bytes)
                audit_log.log('REPORT_GENERATED', 'system', f'Automated daily report saved: {report_name}')
            else:
                logging.info("[REPORT] No incidents in last 24h, skipping report.")
                
        except Exception as e:
            logging.error(f"[REPORT] Automated report worker error: {e}")
            time.sleep(3600) # retry in an hour

# Perform initial retention run synchronously so logs appear before the password prompt
print("[SYSTEM] Initializing data retention check...")
run_retention_tasks()

threading.Thread(target=retention_worker, daemon=True).start()
threading.Thread(target=report_generation_worker, daemon=True).start()

_pt_enc_path   = r"C:\safeVision\server\model\model.pt.enc"
_pt_dec_path   = r"C:\safeVision\server\model\model.pt"
_onnx_enc_path = r"C:\safeVision\server\model\model.onnx.enc" 
_onnx_path     = r"C:\safeVision\server\model\model.onnx"

_password = os.getenv("SAFEVISION_MASTER_KEY")
if not _password:
    _password = getpass.getpass("Model decryption password: ")
alarm_engine.set_master_key(_password)

# Unlock secrets
if not secrets.unlock(_password):
    logging.error("Failed to unlock SecretManager. Check password.")
    exit(1)
secrets.save(_password)


# Derive a dedicated HMAC key using PBKDF2
# We use a static salt to separate the context from other uses of the master key
hmac_salt = b"safevision_audit_log_hmac_salt"
derived_hmac_key = hashlib.pbkdf2_hmac(
    'sha256', 
    _password.encode('utf-8'), 
    hmac_salt, 
    100000 # Number of iterations
)

# Set HMAC key for audit log integrity
audit_log.set_hmac_key(derived_hmac_key)
audit_log.log('HMAC_KEY_SET', 'system', 'Audit log HMAC signing enabled with derived key.')

encryptor = FileEncryptor()

#   1. Load or Generate Protected ONNX                     
for temp_path in [_onnx_path, _pt_dec_path]:
    if os.path.exists(temp_path):
        try:
            os.chmod(temp_path, stat.S_IWRITE)
            os.remove(temp_path)
        except Exception as e:
            logging.warning(f"Failed to clean up old plaintext model {temp_path}: {e}")

onnx_bytes = None
if os.path.exists(_onnx_enc_path):
    logging.info("Decrypting protected ONNX model to memory...")
    try:
        onnx_bytes = encryptor.decrypt_to_memory(_onnx_enc_path, _password)
    except Exception as e:
        logging.error(f"Failed to decrypt ONNX model: {e}")
        exit(1)
else:
    logging.info("Protected ONNX not found. Generating from PyTorch weights...")
    try:
        # Load PT model in-memory
        pt_bytes = encryptor.decrypt_to_memory(_pt_enc_path, _password)
        device = torch.device("cpu")
        model = SafeVisionLSTM(input_size=440, hidden_size=128, num_classes=3).to(device)
        model.load_state_dict(torch.load(io.BytesIO(pt_bytes), map_location=device))
        model.eval()
        
        # Export to ONNX
        logging.info("Exporting PyTorch model to ONNX...")
        export_to_onnx(model, _onnx_path, input_size=440, sequence_len=30, observe_ratio=0.4)
        
        # Encrypt the exported ONNX for future use
        logging.info("Protecting ONNX model for future starts...")
        encryptor.encrypt_file(_onnx_path, _onnx_enc_path, _password)
        
        # Read the generated ONNX bytes into memory for loading
        with open(_onnx_path, 'rb') as f:
            onnx_bytes = f.read()
            
        # Clean up temporary ONNX file immediately
        os.remove(_onnx_path)
        del model
        
    except Exception as e:
        logging.error(f"Failed to generate protected ONNX: {e}")
        exit(1)

#   2. Initialize Inference Engines                      ─
# Load ONNX session
logging.info("Initializing ONNXRuntime Session...")
ort_session = ort.InferenceSession(onnx_bytes, providers=['CPUExecutionProvider'])
logging.info("ONNXRuntime Session initialized.")

# Check for C++ Inference Engine
_cpp_exe_path = r"model\safevision_inference.exe"
cpp_daemon = None
if os.path.exists(_cpp_exe_path):
    try:
        with open(_onnx_path, 'wb') as f:
            f.write(onnx_bytes)
        access_ctrl.set_permissions(_onnx_path, 'readonly')
        cpp_daemon = CppInferenceDaemon(_cpp_exe_path, _onnx_path)
        logging.info("Using C++ Inference Engine (safevision_inference.exe)")
    except Exception as e:
        logging.error(f"Failed to start C++ Inference Engine: {e}")
else:
    logging.info("C++ Inference Engine not found. Falling back to Python ONNXRuntime.")
#   3. Cleanup Plaintext Models                         ─
# Give the C++ daemon and ORT session a moment to open the files
time.sleep(1.0) 
for path in [_onnx_path, _pt_dec_path]:
    if os.path.exists(path):
        try:
           
            os.chmod(path, stat.S_IWRITE)
            protector.SecureFileRemover.secure_delete(path)
            logging.info(f"Plaintext model removed from disk: {path}")
        except Exception as e:
            logging.warning(f"Could not remove temporary file {path}: {e}")

#   Concurrency guard                             
# PyTorch CPU inference is not thread-safe when multiple threads share the same
# model object without locking.  A single lock ensures only one client runs
# inference at a time; all other processing (frame decode, feature extraction,
# DB writes) still runs in parallel across threads.
_model_lock      = threading.Lock()
_connected_count = 0
_count_lock      = threading.Lock()

def _client_count() -> int:
    return _connected_count

#   Inference config                              
OBSERVE_RATIO = 0.4    # match training curriculum end — sees first 40% of sequence
                       # fires earlier AND matches what the model was optimised for

# Alert thresholds — lowered from defaults to compensate for CCTV/compressed
# footage producing lower flow magnitudes than RWF-2000 handheld training data
SAFE_THRESHOLD         = 0.20   # below → SAFE
PRE_VIOLENCE_THRESHOLD = 0.40   # below → PRE-VIOLENCE, above → VIOLENCE

# Scales up production flow to match the distribution the model trained on.
# Tune this: raise if model still misses events, lower if too many false alarms.
FLOW_SCALE = 0.33

SAFE_THRESHOLD         = 0.30
PRE_VIOLENCE_THRESHOLD = 0.55

def get_label(class_idx: int) -> str:
    labels = ['SAFE', 'PRE-VIOLENCE', 'VIOLENCE']
    return labels[class_idx] if 0 <= class_idx < 3 else 'UNKNOWN'


def normalize_features(seq: np.ndarray) -> np.ndarray:
    """
    Scale up flow features within the combined sequence.
    seq: (T, 440) — layout: pose(308) | flow_raw(44) | flow_vel(44) | flow_acc(44)
    """
    seq = seq.copy()
    # Only scale the flow parts (last 132 features)
    seq[:, 308:] *= FLOW_SCALE
    return np.clip(seq, -10.0, 10.0)


#   Per-client inference handler                        
def handle_client(client_socket, stream):
    global cpp_daemon
    client_addr = client_socket.getpeername()
    
    #   RBAC Authentication                        ─
    try:
        
        auth_len = struct.unpack('!I', client_socket.recv(4))[0]
        auth_data = json.loads(client_socket.recv(auth_len).decode('utf-8'))
        username = auth_data.get('username', 'unknown')

        # Check for account lockout
        if sec_mon.is_locked_out(username):
            logging.warning(f"[SECURE] Blocked connection from locked-out user: {username} ({client_addr})")
            sec_mon.audit.log('LOCKOUT_BLOCK', 'security_monitor', f"Blocked login attempt for locked account: {username}")
            client_socket.close()
            return
        
        role = rbac.authenticate(username, auth_data['password'])
        if not role:
            logging.warning(f"[SECURE] Authentication failed for {client_addr}")
            sec_mon.record_auth_failure(auth_data['username'])
            client_socket.close()
            return
        
        logging.info(f"[SECURE] Authenticated {auth_data['username']} with role {role}")
    except Exception as e:
        logging.error(f"[SECURE] Authentication error: {e}")
        sec_mon.record_comm_error(f"Authentication payload error from {client_addr}")
        client_socket.close()
        return

    # Per-client temp file — avoids cross-client frame collisions
    frame_path  = os.path.join(DATA_PATH, f'frame_{client_addr[1]}.png')

    # Track connected clients
    global _connected_count
    with _count_lock:
        _connected_count += 1
        count = _connected_count
    logging.info(f"[SERVER] Active clients: {count}")

    sequence  = deque(maxlen=30)
    frame_buffer = deque(maxlen=60)   # ~6 seconds at 10fps
    prev_gray = prev_kp = prev_vel = None
    history   = deque(maxlen=3)   # reduced from 5 — faster response on CCTV

    # Decouple inference from frame receiving to prevent stream slideshow/lag.
    # The receiving thread immediately scans, blurs, and broadcasts frames to the dashboard,
    # while a worker thread processes frames for inference as fast as possible.
    inference_queue = Queue()
    client_active = [True]

    def inference_worker():
        nonlocal prev_gray, prev_kp, prev_vel
        while client_active[0]:
            try:
                # Use a small timeout so the loop can regularly check client_active[0]
                item = inference_queue.get(timeout=0.5)
                if item is None:
                    break
                work_frame, work_metadata = item

                #   Feature extraction                     
                features, curr_kp, curr_vel, curr_gray, _ = extract_features(
                    work_frame, prev_kp, prev_vel, prev_gray
                )
                prev_kp, prev_vel, prev_gray = curr_kp, curr_vel, curr_gray

                sequence.append(features)
                if len(sequence) < 30:
                    continue

                #   Build sequence features (440) and normalise
                seq_features = build_sequence_features(list(sequence))
                seq_features = normalize_features(seq_features)
                input_tensor = torch.tensor(
                    seq_features, dtype=torch.float32
                ).unsqueeze(0)  # (1, 30, 440)

                #   Inference (using C++ Daemon or Python fallback)     
                with _model_lock:
                    global cpp_daemon
                    probs_list = None
                    if cpp_daemon:
                        # Use C++ Inference
                        label_idx, probs_list = cpp_daemon.predict(seq_features)
                        if label_idx is None:
                            cpp_daemon = None
                            logging.error("C++ Inference failed, falling back to Python.")
                    
                    if not cpp_daemon:
                        # Use Python ONNXRuntime (Fallback)
                        ort_inputs = {ort_session.get_inputs()[0].name: input_tensor.numpy()}
                        logits = ort_session.run(None, ort_inputs)[0]
                        exp_logits = np.exp(logits)
                        probs = exp_logits / np.sum(exp_logits, axis=1, keepdims=True)
                        label_idx = int(np.argmax(probs[0]))
                        probs_list = probs[0].tolist()

                # Smooth over last 3 windows to suppress single-frame spikes
                history.append(label_idx)
                avg_label_idx = max(set(history), key=list(history).count)
                label = get_label(avg_label_idx)
                danger_prob = float(probs_list[avg_label_idx]) if probs_list is not None else 0.0
                logging.info(
                    f"[{client_addr}] {label:<14} | "
                    f"prob_vio={danger_prob:.3f}"
                )
                if label in ('PRE-VIOLENCE', 'VIOLENCE'):
                    _cam_id   = work_metadata.get('camera_id',  client_addr[0])
                    _location = work_metadata.get('location',   'Unknown')
                    fired_alarms = alarm_engine.evaluate(
                        label       = label,
                        probability = danger_prob,
                        camera_id   = _cam_id,
                        location    = _location,
                        timestamp   = datetime.datetime.utcnow(),
                        frame       = work_frame,
                    )
                    if fired_alarms:
                        logging.info(f"[SERVER] Fired {len(fired_alarms)} alarms, saving incident stream...")
                        threading.Thread(
                            target=stream_protector.save_stream,
                            args=(list(frame_buffer), _cam_id, _password),
                            daemon=True
                        ).start()

                distances = (
                    vision.compute_distances(curr_kp)
                    if not np.all(curr_kp == 0)
                    else np.zeros(5)
                )
                try:
                    insert2database(
                        work_metadata,
                        prediction=avg_label_idx,
                        probability=danger_prob,
                        velocity=curr_vel,
                        prev_velocity=prev_vel if prev_vel is not None
                                      else np.zeros_like(curr_vel),
                        angles=list(vision.compute_angles(curr_kp)),
                        distances=list(distances),
                    )
                except Exception as e:
                    logging.error(f"[DB ERROR] {e}")

            except Exception:
                # Catch queue.Empty or any other exception inside worker loop
                pass
    # Start inference worker thread
    inference_thread = threading.Thread(target=inference_worker, daemon=True)
    inference_thread.start()

    try:
        while True:
            metadata, frame_bytes = stream.receive_frame(client_socket, timeout=10)
            np_arr = np.frombuffer(frame_bytes, np.uint8)
            frame  = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)

            if frame is None:
                continue
            # Security scan (in-memory)
            pil_img = Image.fromarray(cv2.cvtColor(frame, cv2.COLOR_BGR2RGB))
            
            try:
                result, pil_img_clean = guard.scan_image(pil_img)
            except Exception as e:
                logging.warning(f"[GUARD] {client_addr} scan_image exception: {e}")
                sec_mon.record_comm_error(f"Scan exception from {client_addr}: {e}")
                continue
            
            if result['verdict'] == 'BLOCK':
                logging.warning(f"[GUARD] {client_addr} frame blocked")
                sec_mon.record_comm_error(f"Blocked frame from {client_addr}")
                continue

            # Apply face blurring on the original full-size frame for display/recordings
            display_frame = privacy.blur_faces_image(frame)
            if display_frame is None:
                display_frame = frame

            # Store processed full-size frame in buffer for incident recording
            frame_buffer.append(display_frame)

            # Broadcast full-size uncropped live frame to the Dashboard API
            _cam_id = metadata.get('camera_id', client_addr[0])
            broadcaster.broadcast_frame(_cam_id, display_frame)

            # Convert sanitized PIL image (224x224 cropped) to BGR for the ML model
            model_frame = cv2.cvtColor(np.array(pil_img_clean), cv2.COLOR_RGB2BGR)

            # Push model_frame to inference queue (dropping previous items if full to keep zero latency)
            while not inference_queue.empty():
                try:
                    inference_queue.get_nowait()
                except Exception:
                    break
            inference_queue.put((model_frame, metadata))

    except Exception as e:
        logging.error(f"[ERROR] {client_addr}: {e}", exc_info=True)
    finally:
        try:
            end_frame = np.zeros((480, 640, 3), dtype=np.uint8)
            text = "CAMERA OFFLINE"
            font = cv2.FONT_HERSHEY_SIMPLEX
            text_size = cv2.getTextSize(text, font, 1.5, 3)[0]
            text_x = (640 - text_size[0]) // 2
            text_y = (480 + text_size[1]) // 2
            cv2.putText(end_frame, text, (text_x, text_y), font, 1.5, (0, 0, 255), 3, cv2.LINE_AA)
            last_cam_id = locals().get('_cam_id', client_addr[0])
            broadcaster.broadcast_frame(last_cam_id, end_frame)
        except Exception:
            pass
            
        client_active[0] = False
        inference_queue.put(None)  # Signal worker thread to stop
        client_socket.close()
        if os.path.exists(frame_path):
            protector.SecureFileRemover.secure_delete(frame_path)
        with _count_lock:
            _connected_count = max(0, _connected_count - 1)
        logging.info(f"[SERVER] Client {client_addr} disconnected. Active clients: {_connected_count}")

def insert2database(
    data: dict,
    prediction: int,
    probability: float,
    velocity,
    prev_velocity,
    angles,
    distances,
) -> None:
    event_id = data['timestamp'] + '_' + data['camera_id']
    time = parser.parse(data['timestamp']).strftime('%Y-%m-%d-%H-%M-%S').split('-') 
    time=[int(t) for t in time]   
    log_id = 0
    time[0]%=1000
    for n in time:
        log_id = log_id * 100 + int(n)
    event_document = {
        'event_id':      event_id,
        'camera_id':     data['camera_id'],
        'location':      data['location'],
        'model_version': config.MODEL_VERSION,
        'timestamp':     parser.parse(data['timestamp']),
        'risk_level':    int(prediction),
        'probability':   float(probability)
    }
    feature_sequence_document={
            'label':'safe' if prediction == 0 else 'violence',
            'fps':float(data['fps']),
            'window_seconds': 30 / float(data['fps'])
    }
    feature_frame_document={
            'joint_velocities':to_serializable(velocity),
            'joint_accelerations':to_serializable(prev_velocity),
            'angles':                to_serializable(angles),
            'inter_person_distance': to_serializable(distances),
        }
    system_log_document={
        'log_id':log_id,
        'event_id':event_id,
        'timestamp':datetime.datetime.now().strftime('%Y-%m-%d-%H-%M-%S'),
        'module':'lstm_v15'
    }
    
    _EVENTS_COL.insert_one(to_serializable(event_document))
    _FEAT_SEQ_COL.insert_one(to_serializable(feature_sequence_document))
    _FEAT_FRAME_COL.insert_one(to_serializable(feature_frame_document))
    _SYS_LOG_COL.insert_one(to_serializable(system_log_document))



def to_serializable(x):
    if isinstance(x, np.ndarray):
        return x.tolist()
    if isinstance(x, np.floating):
        return float(x)
    if isinstance(x, np.integer):
        return int(x)
    if isinstance(x, list):
        return [to_serializable(i) for i in x]
    if isinstance(x, dict):
        return {k: to_serializable(v) for k, v in x.items()}
    return x


#   Server                                   
def run_server():
    # Harden SSL Context
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers('ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384')
    context.options |= ssl.OP_NO_COMPRESSION  # Prevent CRIME attack
    context.options |= ssl.OP_SINGLE_ECDH_USE
    
    context.load_cert_chain(certfile="server.crt", keyfile="server.key")

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)  # disable Nagle — reduces latency
    server_socket.bind((config.IP, config.PORT))
    server_socket.listen(32)   # backlog: handle burst of connections
    logging.info(f"[SERVER] Listening on {config.IP}:{config.PORT}")

    try:
        while True:
            raw_socket, client_address = server_socket.accept()
            logging.info(f"[SERVER] Client connected: {client_address}")
            
            # Set socket options on raw socket before SSL wrapping
            raw_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            raw_socket.settimeout(30)  # Timeout for SSL handshake
            
            try:
                # Wrap the client socket with SSL after accepting
                client_socket = context.wrap_socket(raw_socket, server_side=True)
                client_socket.settimeout(None)  # Disable timeout for data transmission
                
                stream = SecureVideoStreamWithDH.SecureVideoServerWithDH()
                if stream.preform_handshake_server(client_socket):
                    logging.info(f"[SECURE] Handshake success: {client_address}")
                    client_thread = threading.Thread(
                        target=handle_client,
                        args=(client_socket, stream),
                        daemon=True,
                    )
                    client_thread.start()
                else:
                    logging.warning(f"[SECURE] Handshake failed: {client_address}")
                    sec_mon.record_comm_error(f"Handshake failed: {client_address}")
                    client_socket.close()
            except ssl.SSLError as e:
                logging.error(f"[SSL] SSL error with {client_address}: {e}")
                sec_mon.record_comm_error(f"SSL error from {client_address}: {e}")
                raw_socket.close()
            except socket.timeout:
                logging.error(f"[SSL] SSL handshake timeout with {client_address}")
                sec_mon.record_comm_error(f"SSL handshake timeout: {client_address}")
                raw_socket.close()
            except Exception as e:
                logging.error(f"[ERROR] Error accepting client {client_address}: {e}")
                raw_socket.close()
    except KeyboardInterrupt:
        logging.info("[SERVER] Shutting down...")
    finally:
        server_socket.close()


if __name__ == "__main__":
    run_server()