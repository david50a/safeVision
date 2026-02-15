import os
import cv2
import numpy as np
from collections import deque
import lstm_model

SEQUENCE_LENGTH = 30
DATA_PATH = "data"

def build_dataset():
    X = []
    y = []

    class_names = sorted(os.listdir(DATA_PATH))

    for label, class_name in enumerate(class_names):
        class_path = os.path.join(DATA_PATH, class_name)

        for video_file in os.listdir(class_path):
            video_path = os.path.join(class_path, video_file)

            cap = cv2.VideoCapture(video_path)
            sequence = deque(maxlen=SEQUENCE_LENGTH)

            while cap.isOpened():
                ret, frame = cap.read()
                if not ret:
                    break

                sequence, _ = lstm_model.process_frame(
                    frame,
                    sequence,
                    draw=False
                )

                if len(sequence) == SEQUENCE_LENGTH:
                    features = lstm_model.add_velocity(sequence)
                    X.append(features)
                    y.append(label)

            cap.release()

    X = np.array(X)
    y = np.array(y)

    np.save("X.npy", X)
    np.save("y.npy", y)

    print("Dataset saved.")
    print("Shape:", X.shape)

if __name__ == "__main__":
    build_dataset()
