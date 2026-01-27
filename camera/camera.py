import cv2
import socket
import config
import struct
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
    cv2.imshow('Camera', frame)
    _, buffer = cv2.imencode(".jpg", frame, [int(cv2.IMWRITE_JPEG_QUALITY), 70])
    data = buffer.tobytes()
    client.sendall(struct.pack("!I", len(data)))
    client.sendall(data)
    if cv2.waitKey(1) & 0xFF == ord('q'):
        break
camera.release()
cv2.destroyAllWindows()
client.close()

