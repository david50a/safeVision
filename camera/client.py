import config
import socket
import ssl
import getpass
from pathlib import Path
import sys
import os
import json
import struct
import SecureVideoStreamWithDH
# Add server to path to use FileEncryptor
server_path = str(Path(__file__).resolve().parent.parent / "server")
if server_path not in sys.path:
    sys.path.append(server_path)


context = ssl.create_default_context()
context.check_hostname = False
cert_path = os.path.join(server_path, "server.crt")
if not os.path.exists(cert_path):
    print(f"[ERROR] server.crt not found at {cert_path}. Cannot establish secure connection.")
    exit(1)
context.load_verify_locations(cert_path)
context.verify_mode = ssl.CERT_REQUIRED

def send_packet(metadata: dict, data: bytes):
    if stream.send_frame(client, data, metadata):
        print(f'frame sent successfully')
    else:
        print(f'frame sending failed')

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.settimeout(30)  # Set timeout for initial connection
try:
    client = context.wrap_socket(client, server_hostname=config.IP)
    client.connect((config.IP, config.PORT))
    client.settimeout(None)  # Disable timeout after initial connection (will be set per-operation)
except ssl.SSLError as e:
    print(f'[ERROR] SSL Connection failed: {e}')
    exit(1)
except Exception as e:
    print(f'[ERROR] Connection failed: {e}')
    exit(1)
print('[INFO] Connected to server')
stream = SecureVideoStreamWithDH.SecureVideoClientWithDH()
if stream.preform_handshake_client(client):
    print('[INFO] Handshake successful')
    
    # Authentication credentials
    auth_data_dict = {}
    
    secrets_path = Path("secrets.enc")
    if secrets_path.exists():
        device_key = getpass.getpass("Enter Device Key to unlock camera secrets: ")
        temp_dec = Path("secrets.tmp.json")
        try:
            from model.model_protection import FileEncryptor
            enc = FileEncryptor()
            if enc.decrypt_file(str(secrets_path), str(temp_dec), device_key):
                with open(temp_dec, "r") as f:
                    auth_data_dict = json.load(f)
                print('[INFO] Local secrets unlocked')
            else:
                print('[ERROR] Failed to unlock secrets. Using fallbacks.')
        except Exception as e:
            print(f'[ERROR] Secret loading failed: {e}')
        finally:
            if temp_dec.exists():
                os.remove(temp_dec)

    if not auth_data_dict:
        print('[INFO] No secrets loaded. Manual login required.')
        auth_data_dict['username'] = input("Enter RBAC Username: ")
        auth_data_dict['password'] = getpass.getpass("Enter RBAC Password: ")

    auth_data = json.dumps(auth_data_dict)
    client.sendall(struct.pack('!I', len(auth_data)))
    client.sendall(auth_data.encode('utf-8'))
    print('[INFO] Authentication sent')
else:
    print('[ERROR] Handshake failed')
    exit()
