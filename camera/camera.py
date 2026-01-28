import cv2
import socket
import config
from protocol import send_packet
from utils import FPSLimiter

client=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
client.connect((config.IP,config.PORT))
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
        'frame_size': len(data)
    }
    send_packet(client,metadata,data)
    if config.DEBUG:
        cv2.imshow("Frame", frame)
        if cv2.waitKey(1)& 0xFF==ord('q'):
            break
    limiter.wait()
camera.release()
cv2.destroyAllWindows()
client.close()

