import threading
import socket
import config
from collections import deque
import SecureVideoStreamWithDH
import numpy as np
import torch
from lstm_model import ViolenceLSTM
import vision

device = torch.device("cpu")

model = ViolenceLSTM()
model.load_state_dict(torch.load("model.pt", map_location=device))
model.eval()

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

def handle_client(client_socket, stream):
    sequence = deque(maxlen=30)

    while True:
        try:
            metadata, frame_bytes = stream.receive_frame(client_socket, timeout=10)

            frame = vision.data2numpy(
                frame_bytes,
                config.FRAME_HEIGHT,
                config.FRAME_WIDTH
            )

            keypoints = vision.imgpose(frame, vision.pose)
            sequence.append(keypoints)

            if len(sequence) == 30:
                input_tensor = torch.tensor(
                    np.array(sequence),
                    dtype=torch.float32
                ).unsqueeze(0)

                with torch.no_grad():
                    output = model(input_tensor)
                    prediction = torch.argmax(output, dim=1).item()

                print(f"[PREDICTION] {client_socket.getpeername()} → {prediction}")

        except Exception as e:
            print(f"[ERROR] {e}")
            break

run_server()
