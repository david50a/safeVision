import cv2
import config
from client import client,send_packet
from utils import FPSLimiter
from datetime import datetime

print('[INFO] Connected to server')
camera = cv2.VideoCapture(0)
limiter=FPSLimiter(config.FPS)
while True:
    ret, frame = camera.read()
    if not ret:
        print("[ERROR] Camera read failed")
        break
    frame=cv2.resize(frame,(config.FRAME_WIDTH,config.FRAME_HEIGHT))
    encode_params=[int(cv2.IMWRITE_JPEG_QUALITY),config.JPEG_QUALITY]
    success,encoded = cv2.imencode(".jpg", frame, [int(cv2.IMWRITE_JPEG_QUALITY), 70])
    if not success:
        continue
    data=encoded.tobytes()
    metadata = {
        "camera_id": config.CAMERA_ID,
        "location": config.LOCATION,
        'resolution': f'{config.FRAME_WIDTH}x{config.FRAME_HEIGHT}',
        'fps':config.FPS,
        'frame_size': len(data),
        'file_name': f'image_{datetime.now().strftime("%Y%m%d_%H%M%S")}.jpg'
    }
    send_packet(metadata,data)
    if config.DEBUG:
        cv2.imshow("Frame", frame)
        if cv2.waitKey(1)& 0xFF==ord('q'):
            break
    limiter.wait()
camera.release()
cv2.destroyAllWindows()
print('[INFO] Connection closed')
client.close()
