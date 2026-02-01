import torch
import torch.nn as nn
import torch.optim as optim
import torch.nn.functional as F

import mediapipe as mp

mp_pose=mp.solutions.pose
mp_drawing=mp.solutions.drawings_utils

pose=mp_pose.Pose(
    static_image_mode=False,
    model_complexity=1,
    enable_segmentation=False,
    min_detection_confidence=0.5,
    min_tracking_confidence=0.5,
)