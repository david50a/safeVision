import hashlib
import hmac
import base64

def verify_password(password: str, hashed: str) -> bool:
    try:
        raw = base64.urlsafe_b64decode(hashed.encode())
        salt = raw[:16]
        kdf = raw[16:]
        new_kdf = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 480_000)
        return hmac.compare_digest(new_kdf, kdf)
    except Exception as e:
        return False

def main():
    hashes = {
        "check_pwd.py hash": "8b2yejCoPdKpvr49OXEQeJIIQQuW531rAxPtKBH9zde-3BaWtNolvQhm_yHJvTi0",
        "rbac_db.json hash": "MKFlfm5RnEnHCX9JGRPPdKT_WhgznILYrLnBxeTrJQjoiP4SHY6mNm-mxsiVtpGf"
    }
    
    candidates = [
        "admin", "safevision", "password", "security", "system", "HISPIN",
        "d3eeae17bf968c42c55da337ac905736", "123456", "12345678", "123456789",
        "safevision_secret", "violence", "rwf2000", "rwf-2000", "RWF-2000", "RWF2000",
        "lstm", "mediapipe", "privacy", "guard", "zone", "alert", "alarm", "report", "pdf"
    ]
    
    # Let's search transcript lines for password or key strings
    # We can also add some other common candidate strings
    
    for name, h in hashes.items():
        print(f"Testing for {name} ({h}):")
        for pwd in candidates:
            if verify_password(pwd, h):
                print(f"  SUCCESS: Password is '{pwd}'")
                
if __name__ == "__main__":
    main()
