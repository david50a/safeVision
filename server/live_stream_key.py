import os
import base64
from pathlib import Path

KEY_FILE = Path(__file__).parent / ".stream.key"

def get_stream_key() -> bytes:
    """Returns the raw 32-byte key for AES-GCM stream encryption."""
    if not KEY_FILE.exists():
        key = os.urandom(32)
        with open(KEY_FILE, "wb") as f:
            f.write(key)
        return key
    else:
        with open(KEY_FILE, "rb") as f:
            return f.read()

def get_base64_key() -> str:
    """Returns the base64 encoded key for the web client."""
    return base64.b64encode(get_stream_key()).decode('utf-8')

