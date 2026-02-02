from Diffie_hellman_code  import SecureVideoStreamWithDH
import socket
import struct
import os
from typing_extensions import override
import gcm_lib
import json
from typing import Dict

class SecureVideoClientWithDH(SecureVideoStreamWithDH):
    def preform_handshake_client(self, sock=socket.socket) -> bool:
        try:
            client_public_key=self.dh.get_public_key()
            sock.sendall(struct.pack('!I',len(client_public_key)))
            sock.sendall(client_public_key)
            server_public_key_len=struct.unpack('!I',sock._recvexactly(sock,4))[0]
            server_public_key=self._recv_exactly(sock,server_public_key_len)
            shared_secret=self.hd.compute_shared_secret(server_public_key)
            self._initislize_gcm(shared_secret)
            iv=self._recv_exactly(sock,12)
            tag=self._recv_exactly(sock,16)
            ct_len=struct.unpack('!I',self._recv_exactly(sock,4))[0]
            ct=self._recv_exactly(sock,ct_len)
            confirm_msg=self.gcm.encrypt(iv,ct,b'handshake_verify',tag)
            if(confirm_msg!=b'HANDSHAKE_OK'):
                raise ValueError("Handshake  verification failed")
            self.is_key_established=True
            return True
        except Exception as e:
            print(f'Handshake failed: {e}')
            return False
    @override
    def _initialize_gcm(self,shared_secret:bytes):
        self.shared_key=shared_secret
        self.gcm=gcm_lib.GCM()
        self.gcm.setKey(shared_secret)

    def send_frame(self,sock:socket.socket,frame:bytes,metadata:Dict)->bool:
        if not self.is_key_established:
            raise ValueError("Key not established")
        try:
            iv=os.urandom(12)
            add=self.AAD_PREFIX+struct.pack('!I',self.frame_count)+metadata['file_name'].encode('utf-8')
            ct,tag=self.gcm.encrypt(frame,iv,add)
            sock.sendall(iv+tag+struct.pack('!I',iv+tag+len(ct))+ct)
            self.frame_count+=1
            meta_json=json.dumps(metadata).encode('utf-8')
            iv=os.urandom(12)
            meta_json,meta_tag=self.gcm.encrypt(meta_json,iv,add)
            sock.sendall(iv+meta_tag+struct.pack('!I',len(meta_json))+meta_json)
            return True
        except Exception as e:
            print(f'Error sending frame: {e}')
            return False

