import sys
from pathlib import Path

# Add server to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "server"))

from model.model_protection import FileEncryptor

def try_decrypt():
    enc = FileEncryptor()
    src = r"c:\safeVision\server\database\snapshots\snap_fef85e0656234895be6b9d27af069e71.png.enc"
    dest = r"c:\safeVision\server\database\snapshots\decrypted_test_try.png"
    
    passwords = [
        "admin", "safevision", "password", "security", "system", "HISPIN",
        "d3eeae17bf968c42c55da337ac905736", "Bgwy2VKXIxOIrPE9ddLrZx-qBbKb6R5hDy7AoD85rlio90MX5LnSar8QbWlfsIo5"
    ]
    
    for pwd in passwords:
        print(f"Trying password: {pwd}")
        if enc.decrypt_file(src, dest, pwd):
            print(f"SUCCESS! Password is: {pwd}")
            return
    print("Failed to decrypt with standard passwords.")

if __name__ == "__main__":
    try_decrypt()
