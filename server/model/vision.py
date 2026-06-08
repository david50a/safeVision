import numpy as np
import cv2
import mediapipe as mp
from mediapipe.tasks.python.vision import PoseLandmarker
from mediapipe.tasks.python.core.base_options import BaseOptions
from mediapipe.tasks.python import vision as mp_vision
import atexit
import os
import logging

FLOW_BINS = 8
GRID_ROWS = 4
GRID_COLS = 4
FLOW_RESIZE_W = 160
FLOW_RESIZE_H = 120

os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'
logging.getLogger('mediapipe').setLevel(logging.ERROR)

# Suppress Windows shutdown crash
PoseLandmarker.__del__ = lambda self: None

LANDMARKS     = 33
KEYPOINT_SIZE = LANDMARKS * 3   # 99

_MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           'pose_landmarker_full.task')

#   IMAGE mode (live server)                          
_image_landmarker = None

def _get_image_landmarker():
    global _image_landmarker
    if _image_landmarker is None:  
        options = mp_vision.PoseLandmarkerOptions(
            base_options=BaseOptions(model_asset_path=_MODEL_PATH),
            running_mode=mp_vision.RunningMode.IMAGE,
        )
        _image_landmarker = PoseLandmarker.create_from_options(options)

        def _cleanup():
            try:
                _image_landmarker.close()
            except Exception:
                pass
        atexit.register(_cleanup)

    return _image_landmarker


POSE_CONNECTIONS = [
    (0, 1), (1, 2), (2, 3), (3, 7),
    (0, 4), (4, 5), (5, 6), (6, 8),
    (9, 10),
    (11, 12), (11, 13), (13, 15), (15, 17), (15, 19), (15, 21), (17, 19),
    (12, 14), (14, 16), (16, 18), (16, 20), (16, 22), (18, 20),
    (11, 23), (12, 24), (23, 24),
    (23, 25), (25, 27), (27, 29), (27, 31), (29, 31),
    (24, 26), (26, 28), (28, 30), (28, 32), (30, 32),
]


#   VIDEO mode (dataset builder)                        
class VideoProcessor:
    """
    Context manager for fast sequential video processing using VIDEO mode.
    VIDEO mode is ~30-40% faster than IMAGE mode for sequential frames.
    IMPORTANT: timestamps must be strictly increasing per instance.
    Create a new VideoProcessor for each video.
    """
    def __init__(self, model_path: str = None):
        self.model_path  = model_path or _MODEL_PATH
        self._landmarker = None

    def __enter__(self):
        opts = mp_vision.PoseLandmarkerOptions(
            base_options=BaseOptions(model_asset_path=self.model_path),
            running_mode=mp_vision.RunningMode.VIDEO,
            min_pose_detection_confidence=0.5,
            min_pose_presence_confidence=0.5,
            min_tracking_confidence=0.5,
        )
        self._landmarker = mp_vision.PoseLandmarker.create_from_options(opts)
        return self

    def __exit__(self, *args):
        if self._landmarker:
            try:
                self._landmarker.close()
            except Exception:
                pass
            self._landmarker = None

    def close(self):
        """Manual cleanup if not using context manager."""
        self.__exit__(None, None, None)

    def process(self, frame, timestamp_ms: int) -> np.ndarray:
        """
        Process one frame. Returns (99,) keypoints — zeros if no pose detected.
        Never returns None.
        """
        if frame is None:
            return np.zeros(KEYPOINT_SIZE, dtype=np.float32)
        try:
            img_rgb  = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            mp_image = mp.Image(image_format=mp.ImageFormat.SRGB, data=img_rgb)
            result   = self._landmarker.detect_for_video(mp_image, timestamp_ms)
            return extract_waypoints(result)
        except Exception as e:
            print(f"[VISION VideoProcessor ERROR] {e}")
            return np.zeros(KEYPOINT_SIZE, dtype=np.float32)


#   Feature extraction                             
def extract_waypoints(detection_result) -> np.ndarray:
    if not detection_result.pose_landmarks:
        return np.zeros(KEYPOINT_SIZE, dtype=np.float32)
    kp = []
    for lm in detection_result.pose_landmarks[0]:
        kp.extend([lm.x, lm.y, lm.z])
    return np.array(kp, dtype=np.float32)


def imgpose(frame, draw: bool = False):
    """Single-frame pose extraction (IMAGE mode) for live server."""
    if frame is None:
        return None
    try:
        img_rgb  = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        mp_image = mp.Image(image_format=mp.ImageFormat.SRGB, data=img_rgb)
        result   = _get_image_landmarker().detect(mp_image)
        kp       = extract_waypoints(result)
        if draw:
            draw_landmarks_on_frame(frame, result)
        return kp
    except Exception as e:
        print(f"[VISION imgpose ERROR] {e}")
        return None


def extract_flow_features(flow: np.ndarray) -> np.ndarray:
    """
    Extract 44 features from a dense optical flow field.
    flow: (H, W, 2) from cv2.calcOpticalFlowFarneback
    Returns (44,): 4 global stats + 8 direction bins + 16 grid mag + 16 grid ang
    """
    fx, fy = flow[..., 0], flow[..., 1]
    mag    = np.sqrt(fx**2 + fy**2)
    angle  = np.arctan2(fy, fx)

    stats   = np.array([mag.mean(), mag.std(), mag.max(),
                        np.percentile(mag, 75)], dtype=np.float32)
    hist, _ = np.histogram(angle, bins=FLOW_BINS,
                           range=(-np.pi, np.pi), weights=mag)
    hist    = hist.astype(np.float32)
    if hist.sum() > 0:
        hist /= hist.sum()

    H, W     = mag.shape
    cell_h   = H // GRID_ROWS
    cell_w   = W // GRID_COLS
    grid_mag = np.zeros(GRID_ROWS * GRID_COLS, dtype=np.float32)
    grid_ang = np.zeros(GRID_ROWS * GRID_COLS, dtype=np.float32)

    for r in range(GRID_ROWS):
        for c in range(GRID_COLS):
            r0, r1 = r * cell_h, (r + 1) * cell_h
            c0, c1 = c * cell_w, (c + 1) * cell_w
            cm = mag[r0:r1, c0:c1]
            ca = angle[r0:r1, c0:c1]
            idx = r * GRID_COLS + c
            grid_mag[idx] = cm.mean()
            grid_ang[idx] = np.arctan2(
                (np.sin(ca) * cm).mean(),
                (np.cos(ca) * cm).mean()
            )

    return np.concatenate([stats, hist, grid_mag, grid_ang])


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
    ], dtype=np.float32)


def compute_distances(kp: np.ndarray) -> np.ndarray:
    k = kp.reshape(33, 3)
    pairs = [(11, 12), (13, 14), (15, 16), (23, 24), (27, 28)]
    return np.array([np.linalg.norm(k[a] - k[b]) for a, b in pairs],
                    dtype=np.float32)

def compute_velocity(curr, prev):
    if prev is None:
        return np.zeros_like(curr)
    return curr - prev

def draw_landmarks_on_frame(frame, detection_result):
    if not detection_result.pose_landmarks:
        return frame
    h, w, _ = frame.shape
    for pose_landmarks in detection_result.pose_landmarks:
        for start_idx, end_idx in POSE_CONNECTIONS:
            s  = pose_landmarks[start_idx]
            e  = pose_landmarks[end_idx]
            cv2.line(frame,
                     (int(s.x * w), int(s.y * h)),
                     (int(e.x * w), int(e.y * h)),
                     (0, 255, 0), 2)
        for lm in pose_landmarks:
            cv2.circle(frame, (int(lm.x * w), int(lm.y * h)),
                       4, (0, 0, 255), -1)
    return frame


def data2numpy(data, h, w):
    try:
        return np.frombuffer(data, dtype=np.uint8).reshape((h, w, 3))
    except Exception as e:
        print(f"[VISION data2numpy ERROR] {e}")
        return None