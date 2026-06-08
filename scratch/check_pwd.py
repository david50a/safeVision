
import hashlib
import hmac
import base64
import os

def verify_password(password: str, hashed: str) -> bool:
    raw = base64.urlsafe_b64decode(hashed.encode())
    salt = raw[:16]
    kdf = raw[16:]
    new_kdf = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 480_000)
    return hmac.compare_digest(new_kdf, kdf)

hashed = "8b2yejCoPdKpvr49OXEQeJIIQQuW531rAxPtKBH9zde-3BaWtNolvQhm_yHJvTi0"
print(f"Is 'admin'? {verify_password('admin', hashed)}")
