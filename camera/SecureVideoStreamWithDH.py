from Diffie_hellman_code import SecureVideoStreamWithDH
import socket
import struct
import os
from typing_extensions import override
import json
from typing import Dict
import gcm
import hmac_lib

class SecureVideoClientWithDH(SecureVideoStreamWithDH):
    def preform_handshake_client(self, sock: socket.socket) -> bool:
        try:
            # Send client public key
            client_public_key = self.hd.get_public_key()
            sock.sendall(struct.pack('!I', len(client_public_key)))
            sock.sendall(client_public_key)

            # Receive server public key
            server_public_key_len = struct.unpack('!I', self._recv_exactly(sock, 4))[0]
            server_public_key = self._recv_exactly(sock, server_public_key_len)

            # Compute shared secret
            shared_secret = self.hd.compute_shared_secret(server_public_key)
            self._initialize_gcm(shared_secret)

            # Receive server confirmation
            iv = self._recv_exactly(sock, 12)
            tag = self._recv_exactly(sock, 16)
            ct_len = struct.unpack('!I', self._recv_exactly(sock, 4))[0]
            ct = self._recv_exactly(sock, ct_len)
            iv=hmac_lib.hmac_sha256(shared_secret,iv)
            ct=hmac_lib.hmac_sha256(shared_secret,ct)
            tag=hmac_lib.hmac_sha256(shared_secret,tag)

            confirm_msg = self.gcm.decrypt(iv, ct, b'handshake_verify', tag)
            if confirm_msg != b'HANDSHAKE_OK':
                raise ValueError("Handshake verification failed")

            # Send confirmation back to server
            confirmation = b'HANDSHAKE_OK'
            iv = os.urandom(12)
            ct, tag = self.gcm.encrypt(iv, confirmation, b'handshake_verify')
            sock.sendall(iv)
            sock.sendall(tag)
            sock.sendall(struct.pack('!I', len(ct)))
            sock.sendall(ct)

            self.is_key_established = True
            return True
        except Exception as e:
            print(f'Handshake failed: {e}')
            return False

    @override
    def _initialize_gcm(self, shared_secret: bytes):
        self.shared_key = shared_secret
        self.gcm = gcm.GCM()
        self.gcm.setKey(list(shared_secret))

    def send_frame(self, sock: socket.socket, frame: bytes, metadata: Dict) -> bool:
        if not self.is_key_established:
            raise ValueError("Key not established")

        try:
            # Prepare and encrypt metadata
            meta_json = json.dumps(metadata).encode('UTF-8')
            meta_iv = os.urandom(12)
            meta_ct, meta_tag = self.gcm.encrypt(meta_iv, meta_json, b'metadata')

            meta_iv=hmac_lib.hmac_sha256(self.shared_key, meta_iv)
            meta_ct=hmac_lib.hmac_sha256(self.shared_key, meta_ct)
            meta_tag=hmac_lib.hmac_sha256(self.shared_key, meta_tag)

            # Send encrypted metadata
            sock.sendall(meta_iv)
            sock.sendall(meta_tag)
            sock.sendall(struct.pack('!I', len(meta_ct)))
            sock.sendall(meta_ct)

            # Encrypt and send frame
            iv = os.urandom(12)
            add = self.AAD_PREFIX + struct.pack('!I', self.frame_count) + metadata['file_name'].encode('UTF-8')
            ct, tag = self.gcm.encrypt(iv, frame, add)

            iv=hmac_lib.hmac_sha256(self.shared_key, iv)
            ct=hmac_lib.hmac_sha256(self.shared_key, ct)
            tag=hmac_lib.hmac_sha256(self.shared_key, tag)

            sock.sendall(iv)
            sock.sendall(tag)
            sock.sendall(struct.pack('!I', len(ct)))
            sock.sendall(ct)

            self.frame_count += 1
            return True
        except Exception as e:
            print(f'Error sending frame: {e}')
            return False