import json
import os
import getpass
from pathlib import Path

# Add server to path to use FileEncryptor
import sys
server_path = str(Path(__file__).resolve().parent.parent / "server")
if server_path not in sys.path:
    sys.path.append(server_path)

from model.model_protection import FileEncryptor

def deploy_camera():
    print("=== SafeVision Camera Deployment Utility ===")
    
    username = input("Enter Camera Username (RBAC): ")
    password = getpass.getpass("Enter Camera Password (RBAC): ")
    device_key = getpass.getpass("Create a Local Device Key (to protect this camera's secrets): ")
    
    secrets = {
        "username": username,
        "password": password
    }
    
    temp_json = "camera_secrets.json"
    target_enc = "secrets.enc"
    
    try:
        with open(temp_json, "w") as f:
            json.dump(secrets, f)
            
        encryptor = FileEncryptor()
        encryptor.encrypt_file(temp_json, target_enc, device_key)
        
        print(f"\nSUCCESS! '{target_enc}' generated.")
        print("You can now safely delete the hardcoded credentials in client.py.")
        
    finally:
        if os.path.exists(temp_json):
            os.remove(temp_json)

if __name__ == "__main__":
    deploy_camera()
