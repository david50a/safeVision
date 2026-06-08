from Diffie_hellman_code import SecureVideoStreamWithDH
import socket
import struct
import os
import json
from typing import Optional, Tuple, Dict

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
            iv_with_hmac = iv + self._hmac(shared_secret, iv)
            tag_with_hmac = tag + self._hmac(shared_secret, tag)
            ct_with_hmac = ct + self._hmac(shared_secret, ct)
            
            sock.sendall(iv_with_hmac)
            sock.sendall(tag_with_hmac)
            sock.sendall(struct.pack('!I', len(ct_with_hmac)))
            sock.sendall(ct_with_hmac)

            # Receive confirmation from client
            iv_with_hmac = self._recv_exactly(sock, 44)
            tag_with_hmac = self._recv_exactly(sock, 48)
            ct_len = struct.unpack('!I', self._recv_exactly(sock, 4))[0]
            ct_with_hmac = self._recv_exactly(sock, ct_len)
            
            iv, iv_hmac = iv_with_hmac[:12], iv_with_hmac[12:]
            tag, tag_hmac = tag_with_hmac[:16], tag_with_hmac[16:]
            ct, ct_hmac = ct_with_hmac[:-32], ct_with_hmac[-32:]

            if self._hmac(shared_secret, iv) != iv_hmac or \
               self._hmac(shared_secret, tag) != tag_hmac or \
               self._hmac(shared_secret, ct) != ct_hmac:
                raise ValueError("Handshake verification failed")
            
            confirm_msg = self.gcm.decrypt(iv, ct, b'handshake_verify', tag)

            if confirm_msg != b'HANDSHAKE_OK':
                raise ValueError("Handshake verification failed")

            self.is_key_established = True
            self.shared_key = shared_secret
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
            meta_iv_with_hmac = self._recv_exactly(sock, 44)
            meta_tag_with_hmac = self._recv_exactly(sock, 48)
            meta_ct_len = struct.unpack('!I', self._recv_exactly(sock, 4))[0]
            meta_ct_with_hmac = self._recv_exactly(sock, meta_ct_len)
            
            meta_iv, meta_iv_hmac = meta_iv_with_hmac[:12], meta_iv_with_hmac[12:]
            meta_tag, meta_tag_hmac = meta_tag_with_hmac[:16], meta_tag_with_hmac[16:]
            meta_ct, meta_ct_hmac = meta_ct_with_hmac[:-32], meta_ct_with_hmac[-32:]

            if self._hmac(self.shared_key, meta_iv) != meta_iv_hmac or \
               self._hmac(self.shared_key, meta_tag) != meta_tag_hmac or \
               self._hmac(self.shared_key, meta_ct) != meta_ct_hmac:
                raise ValueError("Metadata authentication failed")

            meta_json = self.gcm.decrypt(meta_iv, meta_ct, b'metadata', meta_tag)
            metadata = json.loads(meta_json.decode('utf-8'))

            # Receive encrypted frame
            iv_with_hmac = self._recv_exactly(sock, 44)
            tag_with_hmac = self._recv_exactly(sock, 48)
            ct_len = struct.unpack('!I', self._recv_exactly(sock, 4))[0]
            ct_with_hmac = self._recv_exactly(sock, ct_len)

            iv, iv_hmac = iv_with_hmac[:12], iv_with_hmac[12:]
            tag, tag_hmac = tag_with_hmac[:16], tag_with_hmac[16:]
            ct, ct_hmac = ct_with_hmac[:-32], ct_with_hmac[-32:]

            if self._hmac(self.shared_key, iv) != iv_hmac or \
               self._hmac(self.shared_key, tag) != tag_hmac or \
               self._hmac(self.shared_key, ct) != ct_hmac:
                raise ValueError("Frame authentication failed")

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