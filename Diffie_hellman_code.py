import hashlib
import secrets
import os
from typing import Tuple,Dict,Optional
class DiffieHellmanKeyExchange:
    P = int(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
        "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
        "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
        "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16
    )
    G = 5
    def __init__(self, private_key):
        self.private_key = secrets.randbelow(self.P-2)+2
        self.public_key=pow(self.G,self.private_key,self.P)
        self.shared_secret=None

    def get_public_key(self)->bytes:
        return self.public_key.to_bytes(256,'big')

    def generate_shared_secret(self, peer_public_key:bytes)->bytes:
        peer_public_key=int.from_bytes(peer_public_key,'big')
        if peer_public_key<2 or peer_public_key>=self.P:
            raise ValueError("Invalid peer public key")
        shared_secret=pow(peer_public_key,self.private_key,self.P)
        shared_secret_bytes=shared_secret.to_bytes(256,byteorder='big')
        self.shared_secret=hashlib.sha256(shared_secret_bytes).digest()
        return self.shared_secret
    def get_shared_secret(self)->bytes:
        if self.shared_secret is None:
            raise ValueError("Shared secret not generated")
        return self.shared_secret

