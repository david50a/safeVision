import socket
import cv2
import json
import logging
import os
import sys
from pathlib import Path
import threading
import time
from queue import Queue
import http.client
import ssl
import hmac
import hashlib
import alarm_config

# Load user's custom AES-GCM256 module
BUILD_DIR = Path(__file__).parents[1] / "build" / "lib.win-amd64-cpython-312"
if str(BUILD_DIR) not in sys.path:
    sys.path.insert(0, str(BUILD_DIR))

try:
    import gcm
    logging.info("Successfully loaded custom AES-GCM256 module.")
except ImportError:
    logging.error(f"Failed to load custom gcm module from {BUILD_DIR}")
    # Fallback to cryptography if needed, but the user asked for "my AES-GCM256"
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    gcm = None

from live_stream_key import get_stream_key

class StreamBroadcaster:
    def __init__(self, port=5555):
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.key = get_stream_key()
        if gcm:
            self.cipher = gcm.GCM()
            self.cipher.setKey(list(self.key))
        else:
            self.cipher = AESGCM(self.key)
        logging.info(f"StreamBroadcaster initialized on UDP port {self.port}")
        
        # HTTP Fallback Configuration
        self.http_fallback_url = "https://127.0.0.1:5000/api/internal/stream"
        self._conn = None
        self._conn_lock = threading.Lock()
        
        # Single background worker thread and queue to send fallback frames sequentially
        self.fallback_queue = Queue(maxsize=10)
        self.fallback_worker = threading.Thread(target=self._fallback_worker_loop, daemon=True)
        self.fallback_worker.start()

    def _send_http_fallback(self, message):
        with self._conn_lock:
            try:
                if self._conn is None:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    self._conn = http.client.HTTPSConnection("127.0.0.1", 5000, context=ctx, timeout=0.5)
                
                self._conn.request("POST", "/api/internal/stream", body=message)
                resp = self._conn.getresponse()
                resp.read() # Read response body to allow connection reuse
            except Exception as e:
                # Reset connection on failure so it attempts to reconnect next time
                if self._conn:
                    try:
                        self._conn.close()
                    except Exception:
                        pass
                    self._conn = None

    def _fallback_worker_loop(self):
        while True:
            try:
                message = self.fallback_queue.get()
                if message is None:
                    break
                self._send_http_fallback(message)
                self.fallback_queue.task_done()
            except Exception:
                pass

    def broadcast_frame(self, camera_id: str, frame):
        try:
            # Encode frame to JPEG
            encode_param = [int(cv2.IMWRITE_JPEG_QUALITY), 60]
            ret, buffer = cv2.imencode('.jpg', frame, encode_param)
            if not ret:
                return

            # AES-GCM Encryption
            nonce = os.urandom(12)
            
            if gcm:
                # Custom module returns (ciphertext, tag)
                ciphertext, tag = self.cipher.encrypt(nonce, buffer.tobytes(), b"")
                encrypted_payload = nonce + ciphertext + tag
            else:
                # cryptography returns ciphertext + tag
                ciphertext_with_tag = self.cipher.encrypt(nonce, buffer.tobytes(), None)
                encrypted_payload = nonce + ciphertext_with_tag
            
            # Create message: JSON Header + \n + Encrypted Payload
            header = json.dumps({
                "camera_id": camera_id,
                "timestamp": time.time()
            }).encode('utf-8')
            payload = header + b'\n' + encrypted_payload
            
            # Sign the payload
            sig = hmac.new(alarm_config.INTERNAL_STREAM_SECRET.encode(), payload, hashlib.sha256).hexdigest()
            message = sig.encode('utf-8') + b'\n' + payload
            
            # Try UDP first
            if len(message) < 65000:
                try:
                    self.sock.sendto(message, ('127.0.0.1', self.port))
                except Exception:
                    pass
            
            # Queue for HTTP fallback in the background
            try:
                if self.fallback_queue.full():
                    try:
                        self.fallback_queue.get_nowait()
                    except Exception:
                        pass
                self.fallback_queue.put_nowait(message)
            except Exception:
                pass
                
        except Exception as e:
            logging.debug(f"Failed to broadcast frame for {camera_id}: {e}")

# Global instance
broadcaster = StreamBroadcaster()
