import cv2
import socket
import const
import struct
client=socket.socket()
client.connect((const.IP,const.PORT))
camera = cv2.VideoCapture(0)

while True:
    ret, frame = camera.read()
    if not ret:
        print("Failed to grab frame")
        break
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

