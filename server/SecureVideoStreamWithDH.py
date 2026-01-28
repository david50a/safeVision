from Diffie_hellman_code import SecureVideoStreamWithDH
import socket
import struct
import os
import json

from typing import Optional,Tuple,Dict
class SecureVideoSeverWithDH(SecureVideoStreamWithDH):
    def preform_handshake_server(self, sock=socket.socket) -> bool:
        try:
            client_public_key_len=struct.unpack('!I',sock._recv_exactly(sock,4))[0]
            client_public_key=self._recv_exactly(sock,client_public_key_len)
            server_public_key=self.dh.get_public_key()
            sock.sendall(struct.pack('!I',len(server_public_key)))
            sock.sendall(server_public_key)
            shared_secret=self.hd.compute_shared_secret(server_public_key)
            self._initialize_gcm(shared_secret)
            confirmation=b'HANDSHAKE_OK'
            iv=os.urandom(12)
            ct,tag=self.gcm.encrypt(iv,confirmation,b'handshake_verify')
            sock.sendall(iv+tag+struct.pack('!I',len(ct))+ct)
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
    def receive_frame(self,sock:socket.socket,timeout:Optional[float]=None)->Tuple[bytes,Dict]:
        if not self.is_key_established:
            raise ValueError("Key not established")
        if timeout:
            sock.settimeout(timeout)
        try:
            meta_len=struct.unpack('!I',self._recv_exactly(sock,4))[0]
            meta_json=self._recv_exactly(sock,meta_len)
            metadata=json.loads(meta_json.decode('utf-8'))
            iv=self._recv_exactly(sock,12)
            tag=self._recv_exactly(sock,16)
            ct_len=struct.unpack('!I',self._recv_exactly(sock,4))[0]
            ct=self._recv_exactly(sock,ct_len)
            frame_count = metadata.get('frame_count', 0)
            add=self.AAD_PREFIX+struct.pack('!I',self.frame_count)+metadata['file_name']
            frame=self.gcm.decrypt(iv,ct,add,tag)
            self.frame_count+=1
            return metadata,frame
        except socket.timeout:
            raise TimeoutError('Timeout while receiving frame')
        finally:
            if timeout: sock.settimeout(None)
