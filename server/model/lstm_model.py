import torch
import torch.nn as nn
import numpy as np
import mediapipe as mp
from mediapipe.tasks.python import vision
from mediapipe.tasks.python.core.base_options import BaseOptions
import cv2
import server.config as config
import os


def data2numpy(data: bytes) -> np.ndarray:
    frame = np.frombuffer(data, dtype=np.uint8)
    frame = frame.reshape(
        (config.FRAME_HEIGHT, config.FRAME_WIDTH, 3)
    )
    return frame


# ── MediaPipe detector (lazy singleton) ──────────────────────────────────────
_detector = None

def get_detector():
    global _detector
    if _detector is None:
        model_path = os.path.join(os.path.dirname(__file__), "pose_landmarker_lite.task")
        base_options = BaseOptions(model_asset_path=model_path)
        options = vision.PoseLandmarkerOptions(
            base_options=base_options,
            running_mode=vision.RunningMode.IMAGE
        )
        _detector = vision.PoseLandmarker.create_from_options(options)
    return _detector


# ── Feature extraction ────────────────────────────────────────────────────────
def extract_keypoints(results):
    if results.pose_landmarks and len(results.pose_landmarks) > 0:
        keypoints = []
        for lm in results.pose_landmarks[0]:
            keypoints.extend([lm.x, lm.y, lm.z])
        return np.array(keypoints, dtype=np.float32)
    return np.zeros(99, dtype=np.float32)


def normalize_keypoints(keypoints):
    keypoints = keypoints.reshape(33, 3)
    hip_center = (keypoints[23] + keypoints[24]) / 2
    keypoints -= hip_center
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
    return np.array([np.linalg.norm(kp[a] - kp[b]) for a, b in pairs])


def compute_angle(a, b, c):
    ba = a - b
    bc = c - b
    cos_angle = np.dot(ba, bc) / (np.linalg.norm(ba) * np.linalg.norm(bc) + 1e-6)
    return np.arccos(np.clip(cos_angle, -1.0, 1.0))


def compute_angles(keypoints):
    kp = keypoints.reshape(33, 3)
    return np.array([
        compute_angle(kp[11], kp[13], kp[15]),  # left elbow
        compute_angle(kp[12], kp[14], kp[16]),  # right elbow
        compute_angle(kp[23], kp[25], kp[27]),  # left knee
        compute_angle(kp[24], kp[26], kp[28]),  # right knee
        compute_angle(kp[13], kp[11], kp[23]),  # left shoulder
        compute_angle(kp[14], kp[12], kp[24]),  # right shoulder
    ])


def extract_features(frame, prev_keypoints=None, prev_velocity=None):
    img_rgb  = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
    mp_image = mp.Image(image_format=mp.ImageFormat.SRGB, data=img_rgb)
    results  = get_detector().detect(mp_image)

    keypoints    = extract_keypoints(results)
    keypoints    = normalize_keypoints(keypoints)
    velocity     = compute_velocity(keypoints, prev_keypoints)
    acceleration = compute_acceleration(velocity, prev_velocity)
    distances    = compute_distances(keypoints)
    angles       = compute_angles(keypoints)

    # 99 + 99 + 99 + 5 + 6 = 308 features
    features = np.concatenate([keypoints, velocity, acceleration, distances, angles])
    return features, keypoints, velocity


# ── Building blocks ───────────────────────────────────────────────────────────

class TemporalAttention(nn.Module):
    """
    Multi-head attention over the time dimension.
    More expressive than a single linear attention — captures
    different aspects of the motion sequence simultaneously.
    """
    def __init__(self, hidden_size, num_heads=4):
        super().__init__()
        self.attn = nn.MultiheadAttention(
            embed_dim=hidden_size,
            num_heads=num_heads,
            dropout=0.1,
            batch_first=True
        )
        self.norm = nn.LayerNorm(hidden_size)

    def forward(self, x):
        # Self-attention over time steps: [B, T, H] → [B, T, H]
        attn_out, _ = self.attn(x, x, x)
        x = self.norm(x + attn_out)          # residual + norm
        return x.mean(dim=1)                 # mean-pool → [B, H]


class MotionEncoder(nn.Module):
    """
    Projects raw per-frame features into a richer embedding.
    Uses residual connection so gradients flow cleanly.
    """
    def __init__(self, input_size, embed_size=256):
        super().__init__()
        self.proj = nn.Sequential(
            nn.Linear(input_size, embed_size),
            nn.GELU(),
            nn.LayerNorm(embed_size),
            nn.Dropout(0.2),
        )
        # Residual projection if sizes differ
        self.residual = (
            nn.Linear(input_size, embed_size)
            if input_size != embed_size else nn.Identity()
        )

    def forward(self, x):
        return self.proj(x) + self.residual(x)


# ── Main model ────────────────────────────────────────────────────────────────

class SafeVisionLSTM(nn.Module):
    """
    Violence anticipation model.

    Architecture:
      1. MotionEncoder   — per-frame feature projection with residual
      2. Bidirectional   — NO. Unidirectional LSTM (cannot peek at future)
      3. TemporalAttn    — multi-head self-attention over observed frames
      4. FutureProjector — projects last hidden state into future space
      5. Classifier      — predicts class from blended context

    observe_ratio controls how much of the sequence is shown at inference.
    During training this is annealed from 1.0 → 0.4 (curriculum learning).
    """
    def __init__(self,
                 input_size=308,
                 hidden_size=256,    # increased from 128 → richer representation
                 num_classes=3,
                 num_heads=4,
                 num_lstm_layers=2,
                 dropout=0.3):
        super().__init__()

        self.hidden_size = hidden_size
        embed_size = 256

        # 1. Per-frame motion encoding
        self.motion_encoder = MotionEncoder(input_size, embed_size)

        # 2. Temporal sequence modelling (unidirectional — no future leakage)
        self.lstm = nn.LSTM(
            input_size=embed_size,
            hidden_size=hidden_size,
            num_layers=num_lstm_layers,
            batch_first=True,
            bidirectional=False,
            dropout=0.3,
        )

        # 3. Multi-head attention over LSTM outputs
        self.temporal_attn = TemporalAttention(hidden_size, num_heads=num_heads)

        # 4. Future state projector (from last hidden state)
        self.future_projector = nn.Sequential(
            nn.Linear(hidden_size, hidden_size),
            nn.GELU(),
            nn.Dropout(dropout),
        )

        # 5. Classifier
        self.classifier = nn.Sequential(
            nn.LayerNorm(hidden_size),
            nn.Dropout(dropout),
            nn.Linear(hidden_size, hidden_size // 2),
            nn.GELU(),
            nn.Dropout(dropout * 0.5),
            nn.Linear(hidden_size // 2, num_classes),
        )

        self._init_weights()

    def _init_weights(self):
        for m in self.modules():
            if isinstance(m, nn.Linear):
                nn.init.xavier_uniform_(m.weight)
                if m.bias is not None:
                    nn.init.zeros_(m.bias)
            elif isinstance(m, nn.LSTM):
                for name, param in m.named_parameters():
                    if 'weight' in name:
                        nn.init.orthogonal_(param)
                    elif 'bias' in name:
                        nn.init.zeros_(param)

    def forward(self, x, observe_ratio=0.6):
        B, T, F = x.shape

        # Clamp to at least 1 frame
        observe_len = max(1, int(T * observe_ratio))
        x = x[:, :observe_len, :]                      # [B, observe_len, F]

        # Per-frame encoding — reshape for Linear layers
        x = x.reshape(B * observe_len, F)
        x = self.motion_encoder(x)                     # [B*observe_len, embed]
        x = x.reshape(B, observe_len, -1)              # [B, observe_len, embed]

        # LSTM temporal modelling
        lstm_out, (h_n, _) = self.lstm(x)
        # lstm_out: [B, observe_len, hidden]
        # h_n:      [num_layers, B, hidden]

        # Multi-head attention pooling over observed frames
        attn_context = self.temporal_attn(lstm_out)    # [B, hidden]

        # Project last hidden state as "anticipated future"
        future_context = self.future_projector(h_n[-1])  # [B, hidden]

        # Blend: attended past + projected future
        context = attn_context + future_context        # [B, hidden]

        return self.classifier(context)                # [B, num_classes]


# ── Inference helper ──────────────────────────────────────────────────────────
def process_full_sequence(model, frame_buffer, observe_ratio=0.6):
    """
    frame_buffer:  list of raw BGR frames
    observe_ratio: fraction of clip to observe before predicting
    Returns predicted class index.
    """
    sequence_features = []
    prev_kp, prev_vel = None, None

    for frame in frame_buffer:
        features, curr_kp, curr_vel = extract_features(frame, prev_kp, prev_vel)
        sequence_features.append(features)
        prev_kp, prev_vel = curr_kp, curr_vel

    input_tensor = torch.tensor(
        np.array(sequence_features), dtype=torch.float32
    ).unsqueeze(0)  # [1, T, F]

    model.eval()
    with torch.no_grad():
        logits     = model(input_tensor, observe_ratio=observe_ratio)
        probs      = torch.softmax(logits, dim=1)
        prediction = torch.argmax(probs, dim=1).item()

    return prediction