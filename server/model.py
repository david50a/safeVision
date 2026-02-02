import torch
import torch.nn as nn
import torch.optim as optim
import torch.nn.functional as F

import collections
import numpy as np
import mediapipe as mp
import cv2 # remove after adaptation
def extract_keypoints(results):
    keypoints = []
    if results.pose_landmarks:
        for landmark in results.pose_landmarks.landmark:
            keypoints.extend([landmark.x, landmark.y, landmark.z])
    else: keypoints=[0]*99
    return np.array(keypoints)
mp_pose=mp.solutions.pose
mp_drawing = mp.solutions.drawing_utils

pose=mp_pose.Pose(
    static_image_mode=False,
    model_complexity=1,
    enable_segmentation=False,
    min_detection_confidence=0.5,
    min_tracking_confidence=0.5,
)
# from here
sequence=collections.deque(maxlen=30)
cap=cv2.VideoCapture(0)
while cap.isOpened():
    ret,frame=cap.read()
    if not ret:
        break
    img_rbg=cv2.cvtColor(frame,cv2.COLOR_BGR2RGB)
    results=pose.process(img_rbg)
    keypoints=extract_keypoints(results)
    sequence.append(keypoints)
    if results.pose_landmarks:
        mp_drawing.draw_landmarks(
            frame,
            results.pose_landmarks,
            mp_pose.POSE_CONNECTIONS,
        )
    cv2.imshow("pose estimation",frame)
    if cv2.waitKey(1) & 0xFF == ord('q'):
        break
cap.release()
cv2.destroyAllWindows()
# here