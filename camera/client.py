import socket
import config
import SecureVideoStreamWithDH
import ssl

context=ssl.create_default_context()
context.check_hostname=False
context.verify_mode=ssl.CERT_NONE
def send_packet(metadata:dict,data:bytes):
    if stream.send_frame(client,data,metadata):
        print(f'frame sent successfully')
    else:
        print(f'frame sending failed')

client=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
client=context.wrap_socket(client,server_hostname=config.IP)
client.connect((config.IP,config.PORT))
print('[INFO] Connected to server')
stream = SecureVideoStreamWithDH.SecureVideoClientWithDH()
if stream.preform_handshake_client(client):
    print('[INFO] Handshake successful')
else:
    print('[ERROR] Handshake failed')
    exit()
