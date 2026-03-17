import hashlib
import os
import json
import hmac_lib
import base64
import uuid
import stat
import time
import struct
import getpass
import argparse
from pathlib import Path
from datetime import datetime,timedelta
from typing import Optional

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import padding,rsa

CRYPTO_AVAILABLE = True
R='\033[91M'
G='\033[92m'
C='\033[96m'
W='\033[97m'
Y='\033[93m'
B='\033[94m'
M='\033[95m'
DIM='\033[2m'
BOLD = '\033[1m'
RESET = '\033[0m'

class FileEncryptor:
    MAGIC=B'PROT1'
    SALT_LEN=16
    def _derive_key(self,password:str,salt:bytes)->bytes:
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("install cryptography: pip install cryptography")
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480_000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key

    def encrypt_file(self,src:str,dest:str,password:str)->dict:
        salt=os.urandom(self.SALT_LEN)
        key=self._derive_key(password,salt)
        f=Fernet(key)
        data=Path(src).read_bytes()
        enc=f.encrypt(data)
        checksum=hashlib.sha256(data).hexdigest()

        with open(dest,'wb') as f:
            f.write(self.MAGIC)
            f.write(salt)
            f.write(enc)

        meta={
            'original':src,
            'encrypted':dest,
            'checksum_sha256':checksum,
            'size_original':len(data),
            'size_encrypted':len(enc),
            'timestamp':datetime.utcnow().isoformat()+"Z"
        }

        return meta

    def decrypt_file(self,src:str,dest:str,password:str)->bool:
        raw=Path(src).read_bytes()
        if not raw.startswith(self.MAGIC):
            print(f'not a protected file {RESET}')
            return False
        salt=raw[len(self.MAGIC):len(self.MAGIC)+self.SALT_LEN]
        enc=raw[len(self.MAGIC)+self.SALT_LEN:]
        key=self._derive_key(password,salt)
        try:
            data=Fernet(key).decrypt(enc)
        except:
            print(f"{R}✗ Wrong password or corrupted file{RESET}")
            return False
        Path(dest).write_bytes(data)
        print(f"{G}✓ Decrypted:{RESET} {src} to {dest}")
        return True
    def encrypt_model_weights(self,model_path:str,password:str)->str:
        out_path=model_path+'.enc'
        self.encrypt_file(model_path,out_path,password)
        return out_path

class AccessControl:
    MODES={
        'readonly':0o444,
        'restricted':0o640,
        'private':0o600,
        'public':0o644,
        'immutable':0o444
    }
    def set_permissions(self,path:str,mode:str='restricted')->None:
        bits=self.MODES.get(mode,0o600)
        os.chmod(path,bits)
        print('f{G} Permissions set [{mode}]{RESET} {path} ({oct(bits)})')

    def lock_directory(self,path:str)->None:
        d=Path(path)
        for item in d.rglob('*'):
            if item.is_dir():
                item.chmod(0o700)
            else:
                item.chmod(0o600)
        d.chmod(0o700)
        print(f'{G} Directory locked:{RESET} {path}')

    def get_permissions_report(self,path:str)->dict:
        s=os.stat(path)
        mode=stat.filemode(s.st_mode)
        return {
            'path':path,
            'mode_symbolic':mode,
            'mode_octal': oct(s.st_mode&0o777),
            'uid':s.st_uid,
            'gid':s.st_gid,
            'size':s.st_size,
            'modified':datetime.fromtimestamp(s.st_mtime).isoformat()
        }
    def save_acl(self,registry_path:str,acl:dict)->None:
        with open(registry_path,'w') as f:
            json.dump(acl,f,indent=2)
        os.chmod(registry_path,0o600)
        print(f'{G} ACL saved:{RESET} {registry_path}')

class AuthManager:
    SECRET_ENV='PROT_SECRET'
    def _secret(self)->bytes:
        secret=os.environ.get(self.SECRET_ENV)
        if not secret:
            raise RuntimeError(f'Set env variable {self.SECRET_ENV}')
        return secret.encode()

    def generate_token(self,user_id:str,ttl_hours:int=24)->str:
        expiry=int(time.time())+ttl_hours*3600
        payload=f'{user_id}:{expiry}'
        sig=hmac_lib.hmac_sha256(self._secret(),payload)
        raw=f'{payload}:{sig}'
        return base64.urlsafe_b64encode(raw.encode()).decode()

    def verify_token(self,token:str)->Optional[str]:
        try:
            raw=base64.urlsafe_b64decode(token).decode()
            user_id,expiry_str,sig=raw.split(':',2)
            expiry=int(expiry_str)
            payload=f'{user_id}:{expiry}'
            expected_sig=hmac_lib.hmac_sha256(self._secret(),payload)
            if sig!=expected_sig:
                return None
            if expiry<time.time():
                return None
            return user_id
        except Exception:
            return None
    def hash_password(self,password:str)->str:
        salt=os.urandom(16)
        kdf=hashlib.pbkdf2_hmac('sha256',password.encode(),salt,480_000)
        return base64.urlsafe_b64encode(salt+kdf).decode()
    def verify_password(self,password:str,hashed:str)->bool:
        raw=base64.b64decode(hashed.encode())
        salt=raw[:16]
        kdf=raw[16:]
        new_kdf=hashlib.pbkdf2_hmac('sha256',password.encode(),salt,480_000)
        return new_kdf==kdf
    def create_user_db(self,path:str,users:dict)->None:
        db={u:self.hash_password(p) for u,p in users.items}
        with open(path,'w') as f:
            json.dump(db,f)
        os.chmod(path,0o600)
        print(f'{G} User database created:{RESET} {path}')
    def authenticate(self,path:str,username,password:str)->bool:
        if not os.path.exists(path):
            return False
        with open(path,'r') as f:
            db=json.load(f)
        hashed=db.get(username)
        if not hashed:
            return False
        return self.verify_password(password,hashed)

class DRMProtector:
    def generate_fingerprint(path:str, owner:str)->dict:
        data=Path(path).read_bytes()
        fingerprint={
            'onwer':owner,
            'file':path,
            'size':len(data),
            'md5':hashlib.md5(data).hexdigest(),
            'sha256':hashlib.sha256(data).hexdigest(),
            'sha512':hashlib.sha512(data).hexdigest()[:32]+'...',
            'fingerprint':hashlib.blake2b(data,digest_size=16).hexdigest(),
            'issued_at':datetime.utcnow().isoformat()+"Z",
            'license_id':str(uuid.uuid4())
        }
        print(f'{G} Fingerprint generated:{RESET} {fingerprint['fingerprint']} owner={owner}')
        return fingerprint

    def verify_integrity(self,fingerprint:dict,path:str,fingerprint_path:str)->bool:
        with open(fingerprint_path)as f:
            fp=json.load(f)
        data=Path(path).read_bytes()
        current=hashlib.sha256(data).hexdigest()
        ok=current==fingerprint['sha256']
        if not ok:
            print(f'{R} INTEGRITY FAILURE:{RESET} {path}')
            print(f' Expected: {fp['sha256'][:32]}...')
            print(f' Actual:   {current[:32]}...')
        else:
            print(f'{G} OK, integrity verified:{RESET} {path}')
        return ok

    def save_fingerprint(self,fingerprint:dict,out_path:str)->None:
        with open(out_path,'w') as f:
            json.dump(fingerprint,f,indent=2)
        os.chmod(out_path,0o644)
        print(f'{G} Fingerprint saved:{RESET} {out_path}')

    def text_watermark(self,text:str,path:str,owner:str)->str:
        mark_bits=owner.encode().hex()
        zwsp='\u200b'
        zwnj='\u200c'
        hidden=''.join(zwsp if b=='0' else zwnj for b in bin(int(mark_bits,16))[2:])
        idx=text.find('. ')
        if idx==-1:
            return text+hidden
        return text[:idx+2]+hidden+text[idx+2:]
    def generate_license(self,owner:str,path:str,allowed_uses:int=1,expiry_days:int=365)->dict:
        expiry=datetime.utcnow()+timedelta(days=expiry_days).isoformat()+"Z"
        lic={
            'license_id':str(uuid.uuid4()),
            'onwer':owner,
            'allowed_uses':allowed_uses,
            'expires':expiry,
            'file':path,
            'issued_at':datetime.utcnow().isoformat()+"Z",
            'uses_remaining':allowed_uses
        }
        sig_data=json.dumps({k:lic[k] for k in ['license_id','owner','file','expires']},sort_keys=True)
        lic['signature']=hashlib.sha256(sig_data.encode()).hexdigest()
        return lic

def cmd_encrypt(args):
    pwd=getpass.getpass(prompt='Password: ')
    FileEncryptor().encrypt_file(args.src,args.dest or args.src+'.enc',pwd)

def cmd_decrypt(args):
    pwd=getpass.getpass(prompt='Password: ')
    FileEncryptor().decrypt_file(args.src,args.dest or args.src.removesuffix('.enc'),pwd)

def cmd_fingerprint(args):
    drm=DRMProtector()
    fingerprint=drm.generate_fingerprint(args.file,args.owner)
    out=args.out or args.file+'.fingerprint.json'
    drm.save_fingerprint(fingerprint,out)

def cmd_verify(args):
    DRMProtector().verify_integrity(args.file,args.fingerprint)

def cmd_lock(args):
    AccessControl().lock_directory(args.path)

def cmd_permissions(args):
    AccessControl().set_permissions(args.path,args.mode)

def cmd_token(args):
    auth=AuthManager()
    token=auth.generate_token(args.user,args.till)

def cmd_verify_token(args):
    auth=AuthManager()
    user_id=auth.verify_token(args.token)
    if user_id:
        print(f'{G} Token verified:{RESET} {user_id}')
    else:
        print(f'{R} Invalid token:{RESET} {args.token}')


def cmd_license(args):
    drm=DRMProtector()
    lic=drm.generate_license(args.owner,args.file,int(args.uses),int(args.days))
    out=args.out or args.file+'.license.json'
    with open(out,'w') as f:
        json.dump(lic,f,indent=2)
    print(f'{G} License saved:{RESET} {out}')
    print(f'    ID: {lic['license_id']}')
    print(f'    Expires: {lic['expires']}')


def main():
    parser = argparse.ArgumentParser(
        description=" Model & File Protection System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # encrypt
    p = sub.add_parser("encrypt", help="Encrypt a file (AES-256)")
    p.add_argument("src")
    p.add_argument("--dst", default=None)
    p.set_defaults(func=cmd_encrypt)

    # decrypt
    p = sub.add_parser("decrypt", help="Decrypt a protected file")
    p.add_argument("src")
    p.add_argument("--dst", default=None)
    p.set_defaults(func=cmd_decrypt)

    # fingerprint
    p = sub.add_parser("fingerprint", help="Generate file fingerprint (DRM)")
    p.add_argument("file")
    p.add_argument("--owner", required=True)
    p.add_argument("--out", default=None)
    p.set_defaults(func=cmd_fingerprint)

    # verify integrity
    p = sub.add_parser("verify", help="Verify file integrity")
    p.add_argument("file")
    p.add_argument("fingerprint")
    p.set_defaults(func=cmd_verify)

    # lock directory
    p = sub.add_parser("lock", help="Lock a directory (restrictive perms)")
    p.add_argument("dir")
    p.set_defaults(func=cmd_lock)

    # set permissions
    p = sub.add_parser("chmod", help="Set named permission mode on file")
    p.add_argument("file")
    p.add_argument("--mode", default="restricted",
                   choices=["readonly", "restricted", "private", "immutable", "public"])
    p.set_defaults(func=cmd_permissions)

    # generate token
    p = sub.add_parser("token", help="Generate HMAC auth token")
    p.add_argument("user")
    p.add_argument("--ttl", type=int, default=24)
    p.set_defaults(func=cmd_token)

    # verify token
    p = sub.add_parser("verify-token", help="Verify an auth token")
    p.add_argument("token")
    p.set_defaults(func=cmd_verify_token)

    # generate license
    p = sub.add_parser("license", help="Generate DRM license for a file")
    p.add_argument("file")
    p.add_argument("--owner", required=True)
    p.add_argument("--uses", default=1)
    p.add_argument("--days", default=365)
    p.set_defaults(func=cmd_license)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main() 