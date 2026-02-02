import threading
import socket
import time
import config
import SecureVideoStreamWithDH
def run_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((config.IP, config.PORT))
    server_socket.listen()
    clients=[]
    print(f"[INFO] Server listening on {config.IP}:{config.PORT}")
    while True:
        client_socket, client_address = server_socket.accept()
        print(f"[INFO] Accepted connection from {client_address[0]}:{client_address[1]}")
        stream=SecureVideoStreamWithDH.SecureVideoSeverWithDH()
        if stream.preform_handshake_server(client_socket):
            print('[INFO] Handshake successful')
            clients.append((client_socket,stream))
            client_thread = threading.Thread(target=handle_client, args=(client_socket,stream))
            client_thread.start()
        else:
            print('[ERROR] Handshake failed')
            clients.append(client_socket)

def handle_client(client_socket:socket.socket,stream:SecureVideoStreamWithDH.SecureVideoSeverWithDH):
    while True:
        try:
            metadata,frame= stream.receive_frame(client_socket,timeout=10)

            print(f"[INFO] Received data from {client_socket.getpeername()}")

        except RuntimeError:
            print('timeout waiting for frame')
            break
        except Exception as e:
            print(f"[ERROR] Error handling client: {e}")
            break

run_server()