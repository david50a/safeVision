import json
import socket
import struct

def send_packet(sock:socket,metadata:dict,frame:bytes)->None:
    meta_json=json.dumps(metadata).encode('utf-8')
    sock.sendall(struct.pack('!I',len(meta_json)))
    sock.sendall(meta_json)
    sock.sendall(struct.pack('!I',len(frame)))
    sock.sendall(frame)