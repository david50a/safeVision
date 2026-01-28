import json
import os
import socket
import struct
from encyption import gcm_lib
import random
gcm=gcm_lib.GCM()
gcm.setKey()

def send_packet(sock:socket,metadata:dict,frame:bytes)->None:
    x=random.randint(1,100001)
    iv=os.urandom(12)
    aad=b"safeVision_"+str(x).encode('utf-8')
    frame,frame_tag=gcm.encrypt(frame,iv,aad)
    meta_json=json.dumps(metadata).encode('utf-8')
    meta_json=gcm.encrypt(meta_json,iv,aad)
    sock.sendall(iv)
    sock.sendall(frame_tag)
    sock.sendall(struct.pack('!I',len(meta_json)))
    sock.sendall(meta_json)
    sock.sendall(struct.pack('!I',len(frame)))
    sock.sendall(frame)