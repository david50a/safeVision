import cv2
import config
from client import client, send_packet
from utils import FPSLimiter
from datetime import datetime

print('[INFO] Connected to server')
import os
from pathlib import Path

# Try to find a valid video source
root_dir = Path(__file__).resolve().parent.parent
video_source = r"C:\Users\meir\Documents\datasets\UCF_CRIME\FightingA_Part2\Fighting\Fighting033_x264A.mp4"



if not os.path.exists(video_source):
    video_source = str(root_dir / "safe.mp4")
    if not os.path.exists(video_source):
        video_source = 0 # Default to webcam

print(f'[INFO] Using video source: {video_source}')
camera = cv2.VideoCapture(video_source)


limiter = FPSLimiter(config.FPS)

while True:
    ret, frame = camera.read()
    if not ret:
        print("[ERROR] Camera read failed")
        break

    # Do NOT resize here — server does one clean resize to 320x240 before
    # computing optical flow. Double-resizing adds blur and distorts flow values.

    # Quality 95 — quality 70 introduces JPEG block artifacts that optical flow
    # mistakes for motion, corrupting every feature vector the model receives.
    success, encoded = cv2.imencode(".jpg", frame, [int(cv2.IMWRITE_JPEG_QUALITY), 95])
    if not success:
        continue

    data = encoded.tobytes()
    metadata = {
        'timestamp':  str(datetime.utcnow()),
        'camera_id':  config.CAMERA_ID,
        'location':   config.LOCATION,
        'resolution': f'{frame.shape[1]}x{frame.shape[0]}',  # actual native resolution
        'fps':        config.FPS,
        'frame_size': len(data),
        'file_name':  f'image_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.jpg'
    }
    send_packet(metadata, data)

    if config.DEBUG:
        cv2.imshow("Frame", frame)
        if cv2.waitKey(1) & 0xFF == ord('q'):
            break

    limiter.wait()


camera.release()
cv2.destroyAllWindows()
print('[INFO] Connection closed')
client.close()