from Diffie_hellman_code import SecureVideoStreamWithDH
import socket
import ssl
import struct
import os
from typing_extensions import override
import json
from typing import Dict
import gcm

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

            # Send confirmation back to server
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

            meta_iv_with_hmac = meta_iv + self._hmac(self.shared_key, meta_iv)
            meta_tag_with_hmac = meta_tag + self._hmac(self.shared_key, meta_tag)
            meta_ct_with_hmac = meta_ct + self._hmac(self.shared_key, meta_ct)

            # Send encrypted metadata
            sock.sendall(meta_iv_with_hmac)
            sock.sendall(meta_tag_with_hmac)
            sock.sendall(struct.pack('!I', len(meta_ct_with_hmac)))
            sock.sendall(meta_ct_with_hmac)

            # Encrypt and send frame
            iv = os.urandom(12)
            add = self.AAD_PREFIX + struct.pack('!I', self.frame_count) + metadata['file_name'].encode('UTF-8')
            ct, tag = self.gcm.encrypt(iv, frame, add)

            iv_with_hmac = iv + self._hmac(self.shared_key, iv)
            tag_with_hmac = tag + self._hmac(self.shared_key, tag)
            ct_with_hmac = ct + self._hmac(self.shared_key, ct)

            sock.sendall(iv_with_hmac)
            sock.sendall(tag_with_hmac)
            sock.sendall(struct.pack('!I', len(ct_with_hmac)))
            sock.sendall(ct_with_hmac)

            self.frame_count += 1
            return True
        except ssl.SSLError as e:
            print(f'Error sending frame (SSL): {e}')
            return False
        except socket.timeout:
            print(f'Error sending frame: Socket timeout')
            return False
        except BrokenPipeError:
            print(f'Error sending frame: Connection closed by peer')
            return False
        except Exception as e:
            print(f'Error sending frame: {e}')
            return False