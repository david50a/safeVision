import torch
import torch.nn as nn
import numpy as np
import mediapipe as mp
import cv2
import config

def data2numpy(data: bytes) -> np.ndarray:
    frame = np.frombuffer(data, dtype=np.uint8)
    frame = frame.reshape(
        (config.FRAME_HEIGHT, config.FRAME_WIDTH, 3)
    )
    return frame


import numpy as np
import cv2
import mediapipe as mp

mp_pose = mp.solutions.pose
mp_drawing = mp.solutions.drawing_utils

pose = mp_pose.Pose(
    static_image_mode=False,
    model_complexity=1,
    enable_segmentation=False,
    min_detection_confidence=0.5,
    min_tracking_confidence=0.5,
)


def extract_keypoints(results):
    if results.pose_landmarks:
        keypoints = []
        for lm in results.pose_landmarks.landmark:
            keypoints.extend([lm.x, lm.y, lm.z])
        return np.array(keypoints)
    return np.zeros(99)


def normalize_keypoints(keypoints):
    keypoints = keypoints.reshape(33, 3)

    # Center around hips
    hip_center = (keypoints[23] + keypoints[24]) / 2
    keypoints -= hip_center

    # Scale by shoulder width
    shoulder_dist = np.linalg.norm(keypoints[11] - keypoints[12])
    if shoulder_dist > 0:
        keypoints /= shoulder_dist

    return keypoints.flatten()


def compute_velocity(curr, prev):
    if prev is None:
        return np.zeros_like(curr)
    return curr - prev


def compute_acceleration(curr_vel, prev_vel):
    if prev_vel is None:
        return np.zeros_like(curr_vel)
    return curr_vel - prev_vel


def compute_distances(keypoints):
    kp = keypoints.reshape(33, 3)

    pairs = [
        (11, 12),  # shoulders
        (13, 14),  # elbows
        (15, 16),  # wrists
        (23, 24),  # hips
        (27, 28),  # ankles
    ]

    distances = []
    for a, b in pairs:
        distances.append(np.linalg.norm(kp[a] - kp[b]))

    return np.array(distances)

def compute_angle(a, b, c):
    ba = a - b
    bc = c - b

    cos_angle = np.dot(ba, bc) / (
        np.linalg.norm(ba) * np.linalg.norm(bc) + 1e-6
    )
    return np.arccos(np.clip(cos_angle, -1.0, 1.0))


def compute_angles(keypoints):
    kp = keypoints.reshape(33, 3)

    angles = []

    # Elbows
    angles.append(compute_angle(kp[11], kp[13], kp[15]))  # left
    angles.append(compute_angle(kp[12], kp[14], kp[16]))  # right

    # Knees
    angles.append(compute_angle(kp[23], kp[25], kp[27]))
    angles.append(compute_angle(kp[24], kp[26], kp[28]))

    # Shoulders
    angles.append(compute_angle(kp[13], kp[11], kp[23]))
    angles.append(compute_angle(kp[14], kp[12], kp[24]))

    return np.array(angles)

def extract_features(frame, prev_keypoints=None, prev_velocity=None):
    img_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
    results = pose.process(img_rgb)

    keypoints = extract_keypoints(results)
    keypoints = normalize_keypoints(keypoints)

    velocity = compute_velocity(keypoints, prev_keypoints)
    acceleration = compute_acceleration(velocity, prev_velocity)

    distances = compute_distances(keypoints)
    angles = compute_angles(keypoints)

    features = np.concatenate([
        keypoints,
        velocity,
        acceleration,
        distances,
        angles
    ])

    return features, keypoints, velocity

class Attention(nn.Module):
    def __init__(self, hidden_size):
        super().__init__()
        self.attn = nn.Linear(hidden_size, 1)

    def forward(self, lstm_output):
        weights = torch.softmax(
            self.attn(lstm_output),
            dim=1
        )
        context = torch.sum(weights * lstm_output, dim=1)
        return context

class SafeVisionLSTM(nn.Module):
    def __init__(self,
                 input_size=308,
                 hidden_size=128,
                 num_classes=3):
        super().__init__()

        self.feature_extractor = nn.Sequential(
            nn.Linear(input_size, 256),
            nn.ReLU(),
            nn.LayerNorm(256),
            nn.Dropout(0.3),
            nn.Linear(256, 128),
            nn.ReLU()
        )

        self.lstm = nn.LSTM(
            input_size=128,
            hidden_size=hidden_size,
            batch_first=True,
            bidirectional=True
        )

        self.attention = Attention(hidden_size)

        self.classifier = nn.Sequential(
            nn.Dropout(0.3),
            nn.Linear(hidden_size * 2, num_classes)
        )

    def forward(self, x):
        B, T, F = x.shape

        x = x.reshape(B * T, F)
        x = self.feature_extractor(x)
        x = x.reshape(B, T, -1)

        lstm_out, _ = self.lstm(x)

        context = self.attention(lstm_out)

        return self.classifier(context)


def process_full_sequence(model, frame_buffer):
    """
    frame_buffer: List of raw video frames (length 30)
    """
    sequence_features = []
    prev_kp, prev_vel = None, None

    for frame in frame_buffer:
        # Use your existing extract_features function
        features, curr_kp, curr_vel = extract_features(frame, prev_kp, prev_vel)
        sequence_features.append(features)

        # Update states for next frame derivative
        prev_kp, prev_vel = curr_kp, curr_vel

    # Convert to tensor [Batch, Seq_Len, Features]
    input_tensor = torch.tensor(np.array(sequence_features), dtype=torch.float32).unsqueeze(0)

    model.eval()
    with torch.no_grad():
        logits = model(input_tensor)
        probs = torch.softmax(logits, dim=1)
        prediction = torch.argmax(probs, dim=1).item()

    return prediction