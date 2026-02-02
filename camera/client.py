import socket
import config
import SecureVideoStreamWithDH

def send_packet(metadata:dict,data:bytes):
    if stream.send_frame(client,data,metadata):
        print(f'frame sent successfully')
    else:
        print(f'frame sending failed')

client=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
client.connect((config.IP,config.PORT))
print('[INFO] Connected to server')
stream = SecureVideoStreamWithDH.SecureVideoClientWithDH()
if stream.preform_handshake_client(client):
    print('[INFO] Handshake successful')
else:
    print('[ERROR] Handshake failed')
    exit()
