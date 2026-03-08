from Diffie_hellman_code import SecureVideoStreamWithDH
import socket
import struct
import os
import json
from typing import Optional, Tuple, Dict
import hmac_lib
class SecureVideoServerWithDH(SecureVideoStreamWithDH):
    def preform_handshake_server(self, sock: socket.socket) -> bool:
        try:
            # Receive client public key
            client_public_key_len = struct.unpack('!I', self._recv_exactly(sock, 4))[0]
            client_public_key = self._recv_exactly(sock, client_public_key_len)

            # Send server public key
            server_public_key = self.hd.get_public_key()
            sock.sendall(struct.pack('!I', len(server_public_key)))
            sock.sendall(server_public_key)

            # Compute shared secret
            shared_secret = self.hd.compute_shared_secret(client_public_key)
            self._initialize_gcm(shared_secret)

            # Send confirmation to client
            confirmation = b'HANDSHAKE_OK'
            iv = os.urandom(12)
            ct, tag = self.gcm.encrypt(iv, confirmation, b'handshake_verify')
            iv=hmac_lib.hmac_sha256(shared_secret, iv)
            ct=hmac_lib.hmac_sha256(shared_secret, ct)
            tag=hmac_lib.hmac_sha256(shared_secret, tag)
            sock.sendall(iv)
            sock.sendall(tag)
            sock.sendall(struct.pack('!I', len(ct)))
            sock.sendall(ct)

            # Receive confirmation from client (UNCOMMENTED)
            iv = self._recv_exactly(sock, 12)
            tag = self._recv_exactly(sock, 16)
            ct_len = struct.unpack('!I', self._recv_exactly(sock, 4))[0]
            ct = self._recv_exactly(sock, ct_len)
            iv=hmac_lib.hmac_sha256(shared_secret, iv)
            ct=hmac_lib.hmac_sha256(shared_secret, ct)
            tag=hmac_lib.hmac_sha256(shared_secret, tag)
            confirm_msg = self.gcm.decrypt(iv, ct, b'handshake_verify', tag)

            if confirm_msg != b'HANDSHAKE_OK':
                raise ValueError("Handshake verification failed")

            self.is_key_established = True
            return True
        except Exception as e:
            print(f'Handshake failed: {e}')
            return False

    def receive_frame(self, sock: socket.socket, timeout: Optional[float] = None) -> Tuple[Dict, bytes]:
        if not self.is_key_established:
            raise ValueError("Key not established")

        if timeout:
            sock.settimeout(timeout)

        try:
            # Receive and decrypt metadata
            meta_iv = self._recv_exactly(sock, 12)
            meta_tag = self._recv_exactly(sock, 16)
            meta_ct_len = struct.unpack('!I', self._recv_exactly(sock, 4))[0]
            meta_ct = self._recv_exactly(sock, meta_ct_len)
            meta_tag=hmac_lib.hmac_sha256(self.shared_secret, meta_tag)
            meta_iv=hmac_lib.hmac_sha256(self.shared_secret, meta_iv)
            meta_ct=hmac_lib.hmac_sha256(self.shared_secret, meta_ct)
            meta_json = self.gcm.decrypt(meta_iv, meta_ct, b'metadata', meta_tag)
            metadata = json.loads(meta_json.decode('utf-8'))

            # Receive encrypted frame
            iv = self._recv_exactly(sock, 12)
            tag = self._recv_exactly(sock, 16)
            ct_len = struct.unpack('!I', self._recv_exactly(sock, 4))[0]
            ct = self._recv_exactly(sock, ct_len)
            iv=hmac_lib.hmac_sha256(self.shared_secret, iv)
            ct=hmac_lib.hmac_sha256(self.shared_secret, ct)
            tag=hmac_lib.hmac_sha256(self.shared_secret, tag)
            # Construct AAD exactly as client does
            add = self.AAD_PREFIX + struct.pack('!I', self.frame_count) + metadata['file_name'].encode('utf-8')
            frame = self.gcm.decrypt(iv, ct, add, tag)

            self.frame_count += 1
            return metadata, frame
        except socket.timeout:
            raise TimeoutError('Timeout while receiving frame')
        except Exception as e:
            print(f"[ERROR] Decryption failed: {e}")
            import traceback
            traceback.print_exc()
            raise
        finally:
            if timeout:
                sock.settimeout(None)