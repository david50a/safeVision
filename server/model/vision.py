import numpy as np
import cv2
import mediapipe as mp
from mediapipe.tasks.python.vision import PoseLandmarker
import atexit
import os
import logging
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'
logging.getLogger('mediapipe').setLevel(logging.ERROR)

# Patch mediapipe's broken __del__ to suppress Windows shutdown crash
PoseLandmarker.__del__ = lambda self: None

BaseOptions = mp.tasks.BaseOptions
PoseLandmarkerOptions = mp.tasks.vision.PoseLandmarkerOptions
VisionRunningMode = mp.tasks.vision.RunningMode

options = PoseLandmarkerOptions(
    base_options=BaseOptions(model_asset_path='pose_landmarker_lite.task'),
    running_mode=VisionRunningMode.IMAGE,
)

pose_landmarker = PoseLandmarker.create_from_options(options)

def _cleanup():
    try:
        pose_landmarker.close()
    except Exception:
        pass

atexit.register(_cleanup)

LANDMARKS = 33
KEYPOINT_SIZE = LANDMARKS * 3

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

def draw_landmarks_on_frame(frame, detection_result):
    if not detection_result.pose_landmarks:
        return frame

    h, w, _ = frame.shape

    for pose_landmarks in detection_result.pose_landmarks:
        for start_idx, end_idx in POSE_CONNECTIONS:
            start = pose_landmarks[start_idx]
            end = pose_landmarks[end_idx]
            x1, y1 = int(start.x * w), int(start.y * h)
            x2, y2 = int(end.x * w), int(end.y * h)
            cv2.line(frame, (x1, y1), (x2, y2), (0, 255, 0), 2)

        for lm in pose_landmarks:
            x, y = int(lm.x * w), int(lm.y * h)
            cv2.circle(frame, (x, y), 4, (0, 0, 255), -1)

    return frame

def data2numpy(data, h, w):
    try:
        frame = np.frombuffer(data, dtype=np.uint8)
        frame = frame.reshape((h, w, 3))
        return frame
    except Exception as e:
        print("[VISION data2numpy ERROR]", e)
        return None


def extract_waypoints(detection_result):
    if not detection_result.pose_landmarks:
        return np.zeros(KEYPOINT_SIZE, dtype=np.float32)
    keypoints = []
    for lm in detection_result.pose_landmarks[0]:
        keypoints.extend([lm.x, lm.y, lm.z])
    return np.array(keypoints, dtype=np.float32)


def imgpose(frame, draw=False):
    if frame is None:
        return None

    try:
        img_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        mp_image = mp.Image(
            image_format=mp.ImageFormat.SRGB,
            data=img_rgb
        )
        detection_result = pose_landmarker.detect(mp_image)
        keypoints = extract_waypoints(detection_result)

        if draw:
            draw_landmarks_on_frame(frame, detection_result)
        return keypoints
    except Exception as e:
        print("[VISION imgpose ERROR]", e)
        return None