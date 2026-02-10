import torch
import torch.nn as nn
import numpy as np
import mediapipe as mp
import cv2
from collections import deque
import config

mp_pose = mp.solutions.pose
mp_drawing = mp.solutions.drawing_utils

pose = mp_pose.Pose(
    static_image_mode=False,
    model_complexity=1,
    enable_segmentation=False,
    min_detection_confidence=0.5,
    min_tracking_confidence=0.5,
)

def data2numpy(data: bytes) -> np.ndarray:
    frame = np.frombuffer(data, dtype=np.uint8)
    frame = frame.reshape(
        (config.FRAME_HEIGHT, config.FRAME_WIDTH, 3)
    )
    return frame


def extract_keypoints(results):
    keypoints = []
    if results.pose_landmarks:
        for lm in results.pose_landmarks.landmark:
            keypoints.extend([lm.x, lm.y, lm.z])
    else:
        keypoints = [0] * 99
    return np.array(keypoints)


def normalize_keypoints(keypoints):
    keypoints = keypoints.reshape(33, 3)

    hip_center = (keypoints[23] + keypoints[24]) / 2
    keypoints = keypoints - hip_center

    # נרמול לפי כתפיים
    shoulder_dist = np.linalg.norm(keypoints[11] - keypoints[12])
    if shoulder_dist > 0:
        keypoints = keypoints / shoulder_dist

    return keypoints.flatten()

############################################
# ========== FEATURE ENGINEERING ==========
############################################

def add_velocity(sequence):
    seq = np.array(sequence)
    velocity = np.diff(seq, axis=0)

    velocity = np.vstack([
        np.zeros_like(seq[0]),
        velocity
    ])

    return np.concatenate([seq, velocity], axis=1)

def process_frame(frame, sequence, draw=False):
    img_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
    results = pose.process(img_rgb)

    keypoints = extract_keypoints(results)
    keypoints = normalize_keypoints(keypoints)

    sequence.append(keypoints)

    if draw and results.pose_landmarks:
        mp_drawing.draw_landmarks(
            frame,
            results.pose_landmarks,
            mp_pose.POSE_CONNECTIONS
        )

    return sequence, frame

class SafeVisionLSTM(nn.Module):
    def __init__(self,
                 input_size=198,
                 hidden_size=128,
                 num_classes=3):
        super().__init__()

        # Feature Extractor
        self.feature_extractor = nn.Sequential(
            nn.Linear(input_size, 256),
            nn.ReLU(),
            nn.BatchNorm1d(256),
            nn.Dropout(0.3),
            nn.Linear(256, 128),
            nn.ReLU()
        )

        # LSTM
        self.lstm = nn.LSTM(
            input_size=128,
            hidden_size=hidden_size,
            batch_first=True
        )

        # Classifier
        self.classifier = nn.Sequential(
            nn.Dropout(0.3),
            nn.Linear(hidden_size, num_classes)
        )

    def forward(self, x):
        B, T, F = x.shape

        x = x.view(B * T, F)
        x = self.feature_extractor(x)
        x = x.view(B, T, -1)

        out, _ = self.lstm(x)

        out = out[:, -1, :]
        return self.classifier(out)
    

def predict_sequence(model, sequence):
    if len(sequence) < 30:
        return None

    features = add_velocity(sequence)
    tensor = torch.tensor(
        features,
        dtype=torch.float32
    ).unsqueeze(0)

    with torch.no_grad():
        output = model(tensor)
        prediction = torch.argmax(output, dim=1).item()

    return prediction
