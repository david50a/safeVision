import socket
import threading
from queue import Queue
from collections import deque
import numpy as np
import torch
import config
import SecureVideoStreamWithDH
from model.lstm_model import SafeVisionLSTM
from model.lstm_model import extract_features
import cv2


device = torch.device("cpu")
model = SafeVisionLSTM().to(device)
model.load_state_dict(torch.load("model.pt", map_location=device))
model.eval()
frame_queue = Queue(maxsize=200)
pose_queue = Queue(maxsize=200)
sequence = deque(maxlen=30)

def handle_client(client_socket, stream):
    prev_keypoints = None
    prev_velocity = None

    try:

        while True:
            metadata, frame_bytes = stream.receive_frame(client_socket, timeout=10)
            np_arr = np.frombuffer(frame_bytes, np.uint8)
            frame = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)
            if frame is None:
                continue
            features, prev_keypoints, prev_velocity = extract_features(
                frame,
                prev_keypoints,
                prev_velocity
            )
            sequence.append(features)
            if len(sequence) < 30:
                continue
            input_tensor = torch.tensor(
                np.array(sequence),
                dtype=torch.float32
            ).unsqueeze(0)

            with torch.no_grad():
                output = model(input_tensor)
                probs = torch.softmax(output, dim=1)
                prediction = torch.argmax(probs, dim=1).item()
                confidence = probs.max().item()
            print(
                f"[PREDICTION] {client_socket.getpeername()} → "
                f"{prediction} (conf={confidence:.2f})"
            )
    except Exception as e:
        print("[ERROR]", e)
    finally:
        client_socket.close()

def pose_worker():

    prev_keypoints = None
    prev_velocity = None

    while True:

        frame = frame_queue.get()
        if frame is None:
            break
        try:
            features, prev_keypoints, prev_velocity = extract_features(
                frame,
                prev_keypoints,
                prev_velocity
            )

            pose_queue.put(features)

        except Exception as e:
            print("[POSE ERROR]", e)

def model_worker():
    prediction_history = deque(maxlen=5)

    while True:
        features = pose_queue.get()
        sequence.append(features)

        if len(sequence) < 30:
            continue
        input_tensor = torch.tensor(
            np.array(sequence),
            dtype=torch.float32
        ).unsqueeze(0).to(device)

        with torch.no_grad():
            output = model(input_tensor)
            probs = torch.softmax(output, dim=1)
            prediction = torch.argmax(probs, dim=1).item()
            confidence = probs.max().item()

        prediction_history.append(prediction)
        # smoothing
        if prediction_history.count(2) >= 3:
            alert = "VIOLENCE"
        elif prediction_history.count(1) >= 3:
            alert = "PRE-VIOLENCE"
        else:
            alert = "SAFE"

        print(f"[AI] {alert} | pred={prediction} | conf={confidence:.2f}")


def run_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((config.IP, config.PORT))
    server_socket.listen()
    print(f"[SERVER] Listening on {config.IP}:{config.PORT}")
    while True:
        client_socket, client_address = server_socket.accept()
        print(f"[SERVER] Client {client_address}")
        stream = SecureVideoStreamWithDH.SecureVideoServerWithDH()
        if stream.preform_handshake_server(client_socket):
            print("[SECURE] Handshake success")
            client_thread = threading.Thread(
                target=handle_client,
                args=(client_socket, stream),
                daemon=True
            )
            client_thread.start()
        else:
            print("[SECURE] Handshake failed")
            client_socket.close()


def start_system():
    threading.Thread(target=pose_worker, daemon=True).start()
    threading.Thread(target=model_worker, daemon=True).start()
    run_server()

if __name__ == "__main__":
    start_system()