import numpy as np
import mediapipe as mp
import cv2

mp_pose = mp.solutions.pose
mp_drawing = mp.solutions.drawing_utils

pose = mp_pose.Pose(
    static_image_mode=False,
    model_complexity=1,
    min_detection_confidence=0.5,
    min_tracking_confidence=0.5,
)

def data2numpy(data, h, w):
    frame = np.frombuffer(data, dtype=np.uint8)
    return frame.reshape((h, w, 3))

def extract_waypoints(results):
    if not results.pose_landmarks:
        return np.zeros(99)

    keypoints = []
    for lm in results.pose_landmarks.landmark:
        keypoints.extend([lm.x, lm.y, lm.z])

    return np.array(keypoints)

def imgpose(frame, pose, draw=False):
    img_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
    results = pose.process(img_rgb)
    waypoints = extract_waypoints(results)

    if draw and results.pose_landmarks:
        mp_drawing.draw_landmarks(
            frame,
            results.pose_landmarks,
            mp_pose.POSE_CONNECTIONS
        )

    return waypoints
