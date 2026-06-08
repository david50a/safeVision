import sys
import os
import time
import cv2
import numpy as np
from pathlib import Path

# Add server to path so we can import StreamBroadcaster
sys.path.append(os.path.abspath("server"))
from stream_broadcaster import StreamBroadcaster

def mock_sender():
    print("Initializing Broadcaster...")
    broadcaster = StreamBroadcaster(port=5555)
    
    # Create a dummy image to send
    width, height = 640, 480
    image = np.zeros((height, width, 3), dtype=np.uint8)
    
    print(f"Sending real encrypted mock frames for CAM_01 to 127.0.0.1:5555...")
    i = 0
    while True:
        # Update image with text to show animation
        img_copy = image.copy()
        cv2.putText(img_copy, f"MOCK LIVE FEED - Frame {i}", (50, 240), 
                    cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 255, 0), 2)
        
        # Broadcast real encrypted frame
        broadcaster.broadcast_frame("CAM_01", img_copy)
        
        time.sleep(0.1) # 10 FPS
        i += 1
    print("Done sending mock stream.")

if __name__ == "__main__":
    mock_sender()
