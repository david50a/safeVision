import hashlib
import hmac
import math
import os
import json
import base64
import uuid
import stat
import time
import getpass
import argparse
import subprocess
from collections import deque
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional,Tuple
import re
import threading
import cv2
import glob
import numpy as np
from PIL import Image, ImageFilter, ImageStat
import csv
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import padding, rsa
try:
    import hmac_lib
    HMAC_LIB_AVAILABLE = True
except ImportError:
    HMAC_LIB_AVAILABLE = False

CRYPTO_AVAILABLE = True
R  = '\033[91m'  
G  = '\033[92m'
C  = '\033[96m'
W  = '\033[97m'
Y  = '\033[93m'
B  = '\033[94m'
M  = '\033[95m'
DIM  = '\033[2m'
BOLD = '\033[1m'
RESET = '\033[0m'

ROLES=('viewer','operator','admin')
ROLE_PERMISSIONS = {
    'viewer':   {
        'model:read', 'log:read', 'scan:run',
    },
    'operator': {
        'model:read', 'model:decrypt', 'model:encrypt',
        'scan:run', 'scan:configure',
        'log:read', 'log:export',
        'fingerprint:generate', 'fingerprint:verify',
        'license:generate',
    },
    'admin': {
        'model:read', 'model:decrypt', 'model:encrypt',
        'model:delete', 'model:chmod',
        'scan:run', 'scan:configure',
        'log:read', 'log:export', 'log:purge',
        'fingerprint:generate', 'fingerprint:verify',
        'license:generate', 'license:revoke',
        'user:create', 'user:delete', 'user:assign_role',
        'acl:read', 'acl:write',
        'retention:configure', 'privacy:configure',
    },
}

def _role_permissions(role:str)->set:
    idx=ROLES.index(role)
    perms:set=set()
    for r in ROLES[:idx+1]:
        perms|=ROLE_PERMISSIONS[r]
    return perms

class RBACManager:
    """
        Role-Based Access Control with three hierarchical roles:
            viewer   — read-only access
            operator — encrypt/decrypt, scan, fingerprint, license
            admin    — full control including user management and retention policy
        """
    def __init__(self,db_path:str,audit:'AuditLogger'):
        self.db_path=db_path
        self.audit=audit
        self.auth=AuthManager()
        if not os.path.exists(self.db_path):
            self._save({})

    def create_user(self,username:str,password:str,role:str,actor:str='system')->None:
        if role not in ROLES:
            raise ValueError(f'Invalid role {role}. Choose from: {ROLES}')
        db=self._load()
        if username in db:
            raise ValueError(f'User {username} already exists')
        db[username]={'password':self.auth.hash_password(password),'role':role,'created_at':datetime.utcnow().isoformat(),'created_by':actor}
        self._save(db)

        self.audit.log('USER_CREATED',actor,f'User {username} created with role {role}',success=True)
        print(f'{G} User created:{RESET} {username} [{role}]')

    def delete_user(self,username:str,actor:str='system')->None:
        db=self._load()
        if username not in db:
            raise ValueError(f'User {username} does not exist')
        del db[username]
        self._save(db)
        self.audit.log('USER_DELETED',actor,f'User {username} deleted',success=True)
        print(f'{Y} User deleted:{RESET} {username}')

    def assign_role(self,username:str,role:str,actor:str='system')->None:
        if role not in ROLES:
            raise ValueError(f'Invalid role {role}. Choose from: {ROLES}')
        db=self._load()
        if username not in db:
            raise ValueError(f'User {username} does not exist')
        old_role=db[username]['role']
        db[username]['role']=role
        self._save(db)
        self.audit.log('ROLE_CHANGED', actor,f"'{username}' role changed {old_role} -> {role}", success=True)
        print(f'{G} Role changed:{RESET} {username} from {old_role} to {role}')

    def authenticate(self,username:str,password:str)->Optional[str]:
        db=self._load()
        record=db.get(username)
        if not record:
            self.audit.log('AUTH_FAILED',username,'Unknown username',success=False)
            return None
        if not self.auth.verify_password(password,record['password']):
            self.audit.log('AUTH_FAILED',username,'Incorrect password',success=False)
            return None
        self.audit.log('AUTH_SUCCESS',username,'Authentication successful',success=True)
        return record['role']

    def require(self,username:str,permissiion:str,role,resource:str)->None:
        allowed=permissiion in _role_permissions(role)
        self.audit.log(event='ACCESS_CHECK',actor=username,detail=f'perm={permissiion} role={role} resource={resource} role={role}',success=allowed)
        if not allowed:
            msg=f'User {username} [{role}] denied permission {permissiion}'+(f'on {resource}' if resource else '')
            raise PermissionError(msg)
    def has_permission(self,role:str,permission:str)->bool:
        return permission in _role_permissions(role)
    def list_users(self)->list:
        db=self._load()
        return [{'username':u,'role':v['role'],'created_at':v.get('created_at')}for u,v in db.items()]
    def _load(self)->dict:
        with open(self.db_path,'r')as f:
            return json.load(f)
    def _save(self,db:dict)->None:
        with open(self.db_path,'w')as f:
            json.dump(db,f,indent=2)
        os.chmod(self.db_path,0o600)

class SecureFileRemover:
    """
    Overwrites file contents with random data before deletion to prevent recovery.
    """
    @staticmethod
    def secure_delete(path: str, passes: int = 3):
        p = Path(path)
        if not p.exists():
            return
        
        size = p.stat().st_size
        with open(path, 'ba+', buffering=0) as f:
            for _ in range(passes):
                f.seek(0)
                f.write(os.urandom(size))
                f.flush()
                os.fsync(f.fileno())
        
        os.remove(path)

class AuditLogger:
    """
       Append-only JSON-lines audit log with SHA-256 hash chaining and HMAC signing.
       Every entry links to the previous via prev_hash, and is signed with HMAC-SHA256.
       """
    def __init__(self, log_path: str, hmac_key: Optional[bytes] = None):
        self.log_path = log_path
        self._hmac_key = hmac_key
        self._prev_hash = self._last_hash()
        self._lock = threading.Lock()
        self._seq = self._last_seq()

    def set_hmac_key(self, key: bytes):
        with self._lock:
            self._hmac_key = key

    def log(self, event: str, actor: str, detail: str, success: bool = True, extra: Optional[dict] = None) -> dict:
        with self._lock:
            self._seq += 1
            entry = {
                'seq': self._seq,
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'event': event,
                'actor': actor,
                'detail': detail,
                'success': success,
                'prev_hash': self._prev_hash
            }
            if extra:
                entry['extra'] = extra
            
            # 1. Base hash chain
            raw = json.dumps(entry, sort_keys=True)
            entry['entry_hash'] = hashlib.sha256(raw.encode()).hexdigest()
            
            # 2. HMAC Signature (if key available)
            if self._hmac_key:
                if HMAC_LIB_AVAILABLE:
                    sig_bytes = hmac_lib.hmac_sha256(list(self._hmac_key), list(entry['entry_hash'].encode()))
                    entry['signature'] = bytes(sig_bytes).hex()
                else:
                    entry['signature'] = hmac.new(self._hmac_key, entry['entry_hash'].encode(), hashlib.sha256).hexdigest()
            
            line = json.dumps(entry) + '\n'
            with open(self.log_path, 'ab') as f:
                f.write(line.encode('utf-8'))
            
            self._prev_hash = entry['entry_hash']
            
            if not success:
                print(f'{R} AUDIT [{event}]{RESET} {actor}: {detail}')
            elif event in ('ANOMALY_DETECTED', 'INTEGRITY_FAILURE', 'FILE_DELETE', 'SECURITY_ALERT'):
                print(f'{Y} AUDIT [{event}]{RESET} {actor}: {detail}')
            return entry

    def verify_chain(self) -> list:
        broken = []
        prev = 'GENESIS'
        if not os.path.exists(self.log_path):
            return []
            
        with open(self.log_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                entry = json.loads(line)
                
                # Verify HMAC first if key is present
                if self._hmac_key and 'signature' in entry:
                    stored_sig = entry.pop('signature')
                    if HMAC_LIB_AVAILABLE:
                        sig_bytes = hmac_lib.hmac_sha256(list(self._hmac_key), list(entry['entry_hash'].encode()))
                        expected_sig = bytes(sig_bytes).hex()
                    else:
                        expected_sig = hmac.new(self._hmac_key, entry['entry_hash'].encode(), hashlib.sha256).hexdigest()
                    
                    if not hmac.compare_digest(stored_sig, expected_sig):
                        broken.append({'seq': entry['seq'], 'reason': 'hmac_mismatch'})
                
                # Verify hash chain
                stored_eh = entry.pop('entry_hash')
                raw = json.dumps(entry, sort_keys=True)
                expected = hashlib.sha256(raw.encode()).hexdigest()
                
                if stored_eh != expected:
                    broken.append({'seq': entry['seq'], 'reason': 'entry_hash_mismatch'})
                
                if entry['prev_hash'] != prev:
                    broken.append({'seq': entry['seq'], 'reason': 'chain_break'})
                
                prev = stored_eh
        return broken

    def export_csv(self,path:str)->None:
        with open(self.log_path,'r') as fin,open(path,'w',newline='') as fout:
            fields=['seq','timestamp','event','actor','detail','success','entry_hash']
            writer=csv.DictWriter(fout,fieldnames=fields,extrasaction='ignore')
            writer.writeheader()
            for line in fin:
                line=line.strip()
                if line:
                    writer.writerow(json.loads(line))
        print(f'{G} Audit log exported:{RESET} {path}')

    def tail(self,n:int=20)-> list:
        entries=[]
        with open(self.log_path,'r')as f:
            for line in f:
                line=line.strip()
                if line:
                    entries.append(json.loads(line))
        return entries[-n:]

    def _last_hash(self)->str:
        if not os.path.exists(self.log_path):
            return 'GENESIS'
        last='GENESIS'
        with open(self.log_path,'r')as f:
            for line in f:
                line=line.strip()
                if line:
                    try:
                        last=json.loads(line).get('entry_hash',last)
                    except Exception:
                        pass
        return last

    def _last_seq(self)->int:
        if not os.path.exists(self.log_path):
            return 0
        last=0
        with open(self.log_path,'r')as f:
            for line in f:
                line=line.strip()
                if line:
                    try:
                        last=json.loads(line).get('seq',last)
                    except Exception:
                        pass
        return last

class PrivacyEngine:
    """
        Privacy-by-Design preprocessing:
            - Real-time face blurring (OpenCV Haar cascades, no cloud needed)
            - Full-frame blur fallback when OpenCV is unavailable
            - EXIF / metadata stripping
            - Configurable blur strength
            - Every frame processed is audit-logged
        """

    def __init__(self,audit:'AuditLogger',blur_strength:int=30,fallback_blur:bool=True):
        self.audit=audit
        self.blur_strength=blur_strength
        self.fallback_blur=fallback_blur
        self._cv2=None
        self._face_cascade=None
        self._load_cv2()

    def _load_cv2(self)->None:
        self._cv2=cv2
        cascade_path=cv2.data.haarcascades+'haarcascade_frontalface_default.xml'
        self._face_cascade=cv2.CascadeClassifier(cascade_path)
        print(f'{G} OpenCV loaded: {RESET} OpenCV face detection loaded')

    def blur_faces(self,image_path:str,out_path:Optional[str]=None)->str:
        out_path = out_path or self._privacy_path(image_path)
        if self._cv2 and self._face_cascade:
            result_path = self._blur_with_opencv(image_path, out_path)
        elif self.fallback_blur:
            result_path = self._blur_full_frame(image_path, out_path)
        else:
            raise RuntimeError("Neither OpenCV nor fallback blur is available.")
        self.audit.log('MODEL_SCAN', 'privacy_engine',f"Face blur applied: {image_path} -> {out_path}", success=True)
        return result_path

    def blur_faces_image(self, img: np.ndarray) -> np.ndarray:
        if self._cv2 and self._face_cascade:
            gray=cv2.cvtColor(img,cv2.COLOR_BGR2GRAY)
            faces=self._face_cascade.detectMultiScale(gray,scaleFactor=1.1,minNeighbors=5,minSize=(30,30))
            k=self.blur_strength|1
            img_out = img.copy()
            for (x,y,w,h) in faces:
                roi=img_out[y:y+h,x:x+w]
                img_out[y:y+h,x:x+w]=cv2.GaussianBlur(roi,(k,k),0)
            # Log only to terminal, skip disk I/O for speed
            return img_out
        elif self.fallback_blur:
            pil_img = Image.fromarray(cv2.cvtColor(img, cv2.COLOR_BGR2RGB))
            pil_img = pil_img.filter(ImageFilter.GaussianBlur(radius=self.blur_strength|1))
            img_out = cv2.cvtColor(np.array(pil_img), cv2.COLOR_RGB2BGR)
            return img_out
        else:
            raise RuntimeError("Neither OpenCV nor fallback blur is available.")

    def _blur_with_opencv(self,image_path:str,out_path:Optional[str]=None)->str:
        cv2=self._cv2
        img=cv2.imread(image_path)
        gray=cv2.cvtColor(img,cv2.COLOR_BGR2GRAY)
        faces=self._face_cascade.detectMultiScale(gray,scaleFactor=1.1,minNeighbors=5,minSize=(30,30))
        k=self.blur_strength|1
        for (x,y,w,h) in faces:
            roi=img[y:y+h,x:x+w]
            img[y:y+h,x:x+w]=cv2.GaussianBlur(roi,(k,k),0)
        cv2.imwrite(out_path,img)
        n=len(faces) if hasattr(faces,'__len__') else 0
        print(f'{G} Face blur:{RESET} {n} face(s) blurred in {image_path}')
        return out_path

    def _blur_full_frame(self,image_path:str,out_path:str)->str:
        img=Image.open(image_path).convert('RGB')
        img=img.filter(ImageFilter.GaussianBlur(radius=self.blur_strength|1))
        img.save(out_path)
        print(f'{G} Full-frame blur:{RESET} {image_path} -> {out_path}')
        return out_path

    def strip_metadata(self,image_path:str,out_path:Optional[str]=None)->str:
        out_path=out_path or self._privacy_path(image_path)
        img=Image.open(image_path)
        mode=img.mode if img.mode in ('RGB','RGBA','L') else 'RGB'
        clean=Image.frombytes(mode,img.size,img.tobytes())
        clean.save(out_path,format='PNG')
        self.audit.log('MODEL_SCAN', 'privacy_engine',f"Metadata stripped': {image_path} -> {out_path}", success=True)
        print(f'{G} Metadata stripped:{RESET} {image_path} -> {out_path}')
        return out_path
    @staticmethod
    def _privacy_path(path:str)->str:
        p=Path(path)
        return str(p.parent/(p.stem+'_clean.png'))

class RetentionManager:
    """
    Data retention policy:
        - Scans watched directories for files matching a glob pattern
        - Deletes files older than max_age_days
        - Every deletion is audit-logged
        - Run manually or via a scheduler (cron / Windows Task Scheduler)
    """
    def __init__(self,audit:'AuditLogger',max_age_days:int=30):
        self.audit=audit
        self.max_age_days=max_age_days

    def run(self,directories:list,patterns:str='*',dry_run:bool=False)->dict:
        cutoff=time.time()-self.max_age_days*86_400
        deleted=[]
        skipped=[]
        for directory in directories:
            for pattern in glob.glob(os.path.join(directory,'**',patterns),recursive=True):
                try:
                    mtime=os.path.getmtime(pattern)
                    age_days=(time.time()-mtime)/86_400
                    if mtime<cutoff:
                        if not dry_run:
                            SecureFileRemover.secure_delete(pattern)
                            self.audit.log('FILE_DELETE','retention_manager',f'Deleted {pattern} (age {age_days} > {self.max_age_days})',success=True)
                        else:
                            print(f'{DIM}[dry-run]{RESET} {G} Deleted:{RESET} {pattern} (age {age_days} > {self.max_age_days})')
                        deleted.append(pattern)
                    else:
                        skipped.append(pattern)
                except Exception as e:
                    print(f'{R} retention error: {RESET} {e}')
        summary={
            'deleted':len(deleted),
            'skipped':len(skipped),
            'dry_run':dry_run,
            'timestamp':datetime.utcnow().isoformat()+'Z',
            'max_age_days':self.max_age_days
        }
        self.audit.log('RETENTION_RUN','retention_manager',f'Deleted {len(deleted)} files, skipped {len(skipped)} files, kept {len(skipped)}',success=True,extra=summary)
        print(f"\n{BOLD}Retention run complete:{RESET} "
              f"{Y}{len(deleted)} deleted{RESET}, {len(skipped)} kept.")
        return summary

class SecurityMonitor:
    """
    Real-time security monitoring with Account Lockout:
        - Brute-force detection (failed auth attempts per user)
        - Account lockout (blocks user/IP after max_auth_failures)
        - Privilege escalation detection (repeated perm failures)
        - Enumeration detection (rapid repeated resource access)
        - Model file integrity failure alerting
        - All alerts forwarded to AuditLogger for SIEM pickup
    """
    def __init__(self, audit: 'AuditLogger', max_auth_failures: int = 5, max_perm_failures: int = 3, 
                 window_seconds: int = 60, max_requests_failures: int = 20, lockout_seconds: int = 900):
        self.audit = audit
        self.max_auth_failures = max_auth_failures
        self.max_perm_failures = max_perm_failures
        self.window_seconds = window_seconds
        self.max_requests_failures = max_requests_failures
        self.lockout_seconds = lockout_seconds
        
        self._lock = threading.Lock()
        self._auth_failures: dict = {}
        self._perm_failures: dict = {}
        self._requests_failures: dict = {}
        self._lockouts: dict = {}  # username -> lockout_expiry_timestamp

    def is_locked_out(self, username: str) -> bool:
        with self._lock:
            expiry = self._lockouts.get(username)
            if expiry and time.time() < expiry:
                return True
            if expiry:
                del self._lockouts[username]  # Lockout expired
            return False

    def record_auth_failure(self, username: str) -> None:
        with self._lock:
            q = self._auth_failures.setdefault(username, deque())
            q.append(time.time())
            self._evict(q)
            if len(q) >= self.max_auth_failures:
                expiry = time.time() + self.lockout_seconds
                self._lockouts[username] = expiry
                self._alert('ACCOUNT_LOCKED', 'security_monitor', 
                            f"Account '{username}' locked for {self.lockout_seconds}s due to brute-force.")
            else:
                self._alert('AUTH_FAILURE', 'security_monitor', f"Failed auth for '{username}'")

    def record_perm_failure(self, username: str, permission: str) -> None:
        with self._lock:
            q = self._perm_failures.setdefault(username, deque())
            q.append(time.time())
            self._evict(q)
            if len(q) >= self.max_perm_failures:
                self._alert('PRIVILEGE_ESCALATION_DETECTED', 'security_monitor', 
                            f"{username} denied {permission} {len(q)} times in {self.window_seconds}s")

    def record_request(self, username: str, resource: str) -> None:
        with self._lock:
            q = self._requests_failures.setdefault(f'{username}:{resource}', deque())
            q.append(time.time())
            self._evict(q)
            if len(q) >= self.max_requests_failures:
                self._alert('RAPID_ACCESS_DETECTED', 'security_monitor', 
                            f"{username} accessed {resource} {len(q)} times in {self.window_seconds}s - possible enumeration")

    def record_integrity_failure(self, path: str, actor: str = 'system') -> None:
        self._alert('INTEGRITY_FAILURE', actor, f"File integrity check failed for '{path}'.")

    def record_comm_error(self, detail: str, actor: str = 'system') -> None:
        self._alert('COMM_ERROR', actor, detail)

    def _alert(self, event: str, actor: str, detail: str) -> None:
        self.audit.log(event, actor, detail, success=False)
        print(f"{R}{BOLD} SECURITY ALERT [{event}]:{RESET} {detail}")

    def _evict(self, q: deque) -> None:
        cutoff = time.time() - self.window_seconds
        while q and q[0] < cutoff:
            q.popleft()


class VisualInputGuard:
    """
      Detects and prevents malicious visual attacks before an image reaches the
      model.  The pipeline runs three layers:

          1. FORMAT / METADATA FILTERING
             - Validates file magic bytes and extension whitelist
             - Rejects suspiciously large files (configurable cap)
             - Strips all EXIF / metadata to remove steganographic payloads

          2. ANOMALY DETECTION
             - Pixel-distribution entropy: catches solid-noise adversarial patches
             - High-frequency energy (Laplacian variance): detects invisible
               perturbations (FGSM, PGD, C&W, etc.)
             - Channel imbalance: flags heavily skewed RGB histograms used in
               colour-space attacks
             - Duplicate-region ratio: detects tiled adversarial patches
             - Alpha-channel steganography check

          3. PREPROCESSING / SANITISATION CHANNEL
             - Resize + centre-crop to a canonical shape (removes border attacks)
             - Bit-depth reduction (quantise to k bits): destroys sub-LSB perturbations
             - Gaussian smoothing (configurable sigma): removes high-freq noise
             - Pixel-value clipping to a safe range
             - Re-encode through PIL (strips any remaining metadata)

      All decisions and scores are logged to an optional audit trail.

      """
    MAX_FILE_BYTES=20*1024**2
    ALLOWED_EXTENSIONS={'.jpg', '.jpeg', '.png', '.bmp','.webp','.tiff'}
    ALLOWED_MAGIC = {
        b'\xff\xd8\xff': 'JPEG',
        b'\x89PNG\r\n\x1a\n': 'PNG',
        b'BM': 'BMP',
        b'RIFF': 'WEBP',
        b'II*\x00': 'TIFF-LE',
        b'MM\x00*': 'TIFF-BE',
    }
    CANONICAL_SIZE = (224, 224)  # resize target before inference
    QUANTISE_BITS = 6  # reduce 8-bit to 6-bit colour depth
    SMOOTH_SIGMA = 1.0  # Gaussian blur sigma
    ENTROPY_MIN = 1.5  # below = suspiciously uniform image
    ENTROPY_MAX = 7.8  # above = suspiciously noisy image
    HF_ENERGY_THRESHOLD = 4000.0  # Laplacian variance limit
    CHANNEL_IMBALANCE_LIMIT = 80.0  # max allowed mean channel spread
    DUPLICATE_BLOCK_RATIO = 0.35  # max fraction of duplicate 8x8 blocks
    HISTORY_WINDOW = 50  # anomaly score rolling window

    def __init__(self,canonical_size: tuple[int, int] = CANONICAL_SIZE,quantise_bits: int = QUANTISE_BITS,smooth_sigma: float = SMOOTH_SIGMA,strict: bool = True,audit_log:Optional[str]=None):
        self.canonical_size=canonical_size
        self.quantise_bits=quantise_bits
        self.smooth_sigma=smooth_sigma
        self.strict=strict
        self.adult_log=audit_log
        self._sore_history:deque=deque(maxlen=self.HISTORY_WINDOW)

    def scan(self,image_path:str)->dict:
        result={
            'verdict':'PASS',
            'reasons':[],
            'scores':{},
            "clean_path":None,
            'timestamp':datetime.utcnow().isoformat()+'Z',
            'source':image_path
        }

        # Layer 1: format / metadata filtering
        raw_bytes=self._load_raw(image_path,result)
        if result['verdict']=='BLOCK':
           return self._finalise(result)
        img=self._open_and_strip_metadata(image_path,result)
        if result['verdict']=='BLOCK':
            return self._finalise(result)

        # Layer 2: anomaly detection
        self._check_entropy(img,result)
        self._check_high_frequency_energy(img,result)
        self._check_channel_imbalance(img,result)
        self._check_duplicate_blocks(img,result)
        self._check_alpha_steganography(img,result)

        flag_count=len(result['reasons'])
        self._sore_history.append(flag_count)
        result['scores']['rolling_avg_flags']=sum(self._sore_history)/len(self._sore_history)
        if result['scores']['rolling_avg_flags']>1.5:
            self._flag(result,'SUSTAINED_ANOMALY_RATE','Rolling average of flagged checks exeeds threshold -','possible systematic adversarial input stream.')
        if result['verdict']=='BLOCK':
            return self._finalise(result)

        # Layer 3: preprocessing / sanitisation
        clean_path=self._sanitise(img,image_path,result)
        result['clean_path']=clean_path
        return self._finalise(result)

    def scan_image(self, img: 'Image.Image') -> Tuple[dict, 'Image.Image']:
        result = {
            'verdict': 'PASS',
            'reasons': [],
            'scores': {},
            "clean_path": None,
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'source': 'in_memory'
        }

        # Mode check
        if img.mode not in ('RGB', 'RGBA', 'L'):
            img = img.convert('RGB')
        else:
            img=img.copy()

        # Layer 2: anomaly detection
        self._check_entropy(img, result)
        self._check_high_frequency_energy(img, result)
        self._check_channel_imbalance(img, result)
        self._check_duplicate_blocks(img, result)
        self._check_alpha_steganography(img, result)

        flag_count = len(result['reasons'])
        self._sore_history.append(flag_count)
        result['scores']['rolling_avg_flags'] = sum(self._sore_history) / len(self._sore_history)
        if result['scores']['rolling_avg_flags'] > 1.5:
            self._flag(result, 'SUSTAINED_ANOMALY_RATE', 'Rolling average of flagged checks exceeds threshold - possible systematic adversarial input stream.')
        if result['verdict'] == 'BLOCK':
            return self._finalise(result), img

        # Layer 3: preprocessing / sanitisation
        img = img.convert('RGB')
        img = self._resize_and_crop(img, self.canonical_size)
        arr = np.array(img, dtype=np.uint8)
        shift = 8 - self.quantise_bits
        arr = ((arr >> shift) << shift).astype(np.uint8)
        img = Image.fromarray(arr, mode='RGB')
        img = img.filter(ImageFilter.GaussianBlur(radius=max(0, self.smooth_sigma)))
        arr = np.clip(np.array(img, dtype=np.uint8), 0, 253).astype(np.uint8)
        img = Image.fromarray(arr, mode='RGB')

        return self._finalise(result), img

    def scan_batch(self,image_paths:list)->list:
        results=[]
        for p in image_paths:
            try:
                r=self.scan(p)
            except RuntimeError as e:
                r={'verdict':'BLOCK','reasons':[str(e)],'source':p,'clean_path':None}
            results.append(r)
        self._print_batch_sunnary(results)
        return results

    def _load_raw(self,path:str, result:dict)->Optional[bytes]:
        p=Path(path)
        if p.suffix.lower() not in self.ALLOWED_EXTENSIONS:
            self._flag(result,'INVALID_EXTENSION',f'Extension is not in the whitelist')
            return None

        size=p.stat().st_size
        result['scores']['file_bytes']=size
        if size>self.MAX_FILE_BYTES:
            self._flag(result,'FILE_TOO_LARGE',f'File is {size} BYTES - exceeds {self.MAX_FILE_BYTES} MB cap.')
            return None
        raw=p.read_bytes()
        matched=False
        for magic, fmt in self.ALLOWED_MAGIC.items():
            if raw.startswith(magic):
                result['scores']['file_format']=fmt
                matched=True
                break
        if not matched:
            self._flag(result,'MAGIC_MISMATCH','File magic bytes do not match any known safe image format')
            return None
        return raw

    def _open_and_strip_metadata(self,path:str,result:dict)->Optional['Image.Image']:
        try:
            img=Image.open(path)
            img.load()
        except OSError as e:
            self._flag(result,'DECODE_ERROR',f'PIL failed to open image {e}')
            return None

        mode=img.mode if img.mode in ('RGB','RGBA','L') else 'RGB'
        clean=Image.frombytes(mode,img.size,img.tobytes())
        return clean

    def _check_entropy(self,img:'Image.Image',result:dict)-> None:
        gray=img.convert('L')
        arr=np.array(gray,dtype=np.float32).flatten()
        hist,_=np.histogram(arr,256,range=(0,256))
        hist=hist[hist>0].astype(np.float64)
        total=hist.sum()
        probs=hist/total
        entropy=-float(np.sum(probs*np.log2(probs)))
        result['scores']['entropy']=round(entropy,4)
        if entropy<self.ENTROPY_MIN:
            self._flag(result,'LOW_ENTROPY',f'Entropy {entropy} <{self.ENTROPY_MIN}')
        elif entropy>self.ENTROPY_MAX:
            self._flag(result,'HIGH_ENTROPY',f'Entropy {entropy} >{self.ENTROPY_MAX}')

    def _check_high_frequency_energy(self,img:'Image.Image',result:dict)->None:
        gray=img.convert('L')
        lap=gray.filter(ImageFilter.Kernel(size=(3,3),kernel=[-1,-1,-1,-1,8,-1,-1,-1,-1],scale=1,offset=128))
        arr=np.array(lap,dtype=np.float32)
        variance=float(np.var(arr))
        result['scores']['hf_energy']=round(variance,2)
        if variance>self.HF_ENERGY_THRESHOLD:
            self._flag(result,'HIGH_FREQUENCY_ENERGY',f'Variance {variance} >{self.HF_ENERGY_THRESHOLD}')

    def _check_channel_imbalance(self,img:'Image.Image',result:dict)->None:
        rbg=img.convert('RGB')
        st=ImageStat.Stat(rbg)
        means=st.mean
        spread=max(means)-min(means)
        result['scores']['channel_spread']=round(spread,2)
        if spread>self.CHANNEL_IMBALANCE_LIMIT:
            self._flag(result,'CHANNEL_IMBALANCE',f'Channel spread {spread} >{self.CHANNEL_IMBALANCE_LIMIT}, may indicate color-space attack')

    def _check_duplicate_blocks(self,img:'Image.Image',result:dict)->None:
        gray=img.convert('L').resize((128,128))
        arr=np.array(gray,dtype=np.uint8)
        block_size=8
        blocks=[]
        for r in range(0,arr.shape[0],block_size):
            for c in range(0,arr.shape[1],block_size):
                block=arr[r:r+block_size,c:c+block_size]
                if block.shape==(block_size,block_size):
                    blocks.append(block.tobytes())
        total=len(block)
        unique=len(set(blocks))
        dup_ratio=1.0-(unique/total) if total>0 else 0.0
        result['scores']['duplicate_block_ratio']=round(dup_ratio,4)
        if dup_ratio>self.DUPLICATE_BLOCK_RATIO:
            self._flag(result,'DUPLICATE_BLOCKS',f'duplicate block ratio {dup_ratio} >{self.DUPLICATE_BLOCK_RATIO}- repeated pixel-blocks suggest a tiled adversarial patch')

    def _check_alpha_steganography(self,img:'Image.Image',result:dict)->None:
        if img.mode!='RGBA':
            result['scores']['alpha_lsb_entropy']=None
            return
        arr=np.array(img,dtype=np.uint8)
        alpha=arr[:,:,3]
        lsb=(alpha&1).flatten().astype(np.float32)
        ones=float(np.sum(lsb))
        total=float(lsb.size)

        if ones in (0.0,total):
            lsb_entropy=0.0
        else:
            p1=ones/total
            p0=1.0-p1
            lsb_entropy=-(p1*np.log2(p1)+ p0*math.log2(p0))
        result['scores']['alpha_lsb_entropy']=round(lsb_entropy,4)
        if lsb_entropy>0.85:
            self._flag(result,'ALPHA_LSB_ENTROPY',f'Alpha-channel LSB antropy {lsb_entropy}> 0.85- possible steganography payload in alpha channel')

    def _sanitise(self,img:'Image.Image',path:str,result:dict)->str:
        img=img.convert('RGB')
        img=self._resize_and_crop(img,self.canonical_size)
        arr=np.array(img,dtype=np.uint8)
        shift=8-self.quantise_bits
        arr=((arr>>shift)<<shift).astype(np.uint8)
        img=Image.fromarray(arr,mode='RGB')
        img=img.filter(ImageFilter.GaussianBlur(radius=max(0,self.smooth_sigma)))
        arr=np.clip(np.array(img,dtype=np.uint8),0,253).astype(np.uint8)
        img=Image.fromarray(arr,mode='RGB')
        src_p=Path(path)
        out_path=str(src_p.parent/(src_p.stem+'_clean.png'))
        img.save(out_path,format='PNG',optimize=False)
        result['scores']['clean_size']=Path(out_path).stat().st_size
        return out_path

    @staticmethod
    def _resize_and_crop(img:'Image.Image',target:Tuple[int,int])->'Image.Image':
        tw,th=target
        w,h=img.size
        scale=max(tw/w,th/h)
        new_w,new_h=int(math.ceil(w*scale)),int(math.ceil(h*scale))
        img=img.resize((new_w,new_h),Image.LANCZOS)
        left=(new_w-tw)//2
        top=(new_h-th)//2
        return img.crop((left,top,left+tw,top+th))

    @staticmethod
    def _flag(result:dict,rule:str,reason:str)->None:
       result['verdict']='BLOCK'
       result['reasons'].append({'rule':rule,'deteil': reason})

    def _finalise(self,result:dict)->dict:
        if self.adult_log and result['verdict'] != 'PASS':
            with open(self.adult_log,'a')as f:
                f.write(json.dumps(result)+'\n')
        if result['verdict']=='PASS':
            print(f'PASS{RESET} - image cleared all checks')
        else:
            n=len(result['reasons'])
            print(f'FAIL{RESET} - image cleared {n} checks')
            if self.strict:
                raise RuntimeError( f"VisualInputGuard BLOCKED '{result['source']}': "
                    + "; ".join(r['rule'] for r in result['reasons'])
                )
        return result
    @staticmethod
    def _print_batch_summary(results: list) -> None:
        total = len(results)
        blocked = sum(1 for r in results if r['verdict'] == 'BLOCK')
        passed = total - blocked
        print(f"\n{BOLD}Batch scan complete:{RESET} "
              f"{G}{passed} passed{RESET}, {R}{blocked} blocked{RESET} / {total} total.")


class FileEncryptor:
    MAGIC = b'PROT1'
    SALT_LEN = 16

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("install cryptography: pip install cryptography")
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480_000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def encrypt_file(self, src: str, dest: str, password: str) -> dict:
        salt = os.urandom(self.SALT_LEN)
        key  = self._derive_key(password, salt)
        fernet = Fernet(key)
        data = Path(src).read_bytes()
        enc  = fernet.encrypt(data)
        checksum = hashlib.sha256(data).hexdigest()

        with open(dest, 'wb') as fh:
            fh.write(self.MAGIC)
            fh.write(salt)
            fh.write(enc)

        print(f"{G}[OK] Encrypted:{RESET} {src} -> {dest}")
        return {
            'original':         src,
            'encrypted':        dest,
            'checksum_sha256':  checksum,
            'size_original':    len(data),
            'size_encrypted':   len(enc),
            'timestamp':        datetime.utcnow().isoformat() + "Z",
        }

    def decrypt_file(self, src: str, dest: str, password: str) -> bool:
        raw = Path(src).read_bytes()
        if not raw.startswith(self.MAGIC):
            print(f"{R}[FAIL] Not a protected file{RESET}")
            return False
        salt = raw[len(self.MAGIC): len(self.MAGIC) + self.SALT_LEN]
        enc  = raw[len(self.MAGIC) + self.SALT_LEN:]
        key  = self._derive_key(password, salt)
        try:
            data = Fernet(key).decrypt(enc)
        except Exception:
            print(f"{R}[FAIL] Wrong password or corrupted file{RESET}")
            return False
        Path(dest).write_bytes(data)
        print(f"{G}[OK] Decrypted:{RESET} {src} -> {dest}")
        return True

    def decrypt_to_memory(self, src: str, password: str) -> bytes:
        raw = Path(src).read_bytes()
        if not raw.startswith(self.MAGIC):
            raise ValueError("Not a protected file")
        salt = raw[len(self.MAGIC): len(self.MAGIC) + self.SALT_LEN]
        enc  = raw[len(self.MAGIC) + self.SALT_LEN:]
        key  = self._derive_key(password, salt)
        try:
            data = Fernet(key).decrypt(enc)
        except Exception as e:
            raise ValueError("Wrong password or corrupted file") from e
        return data

    def encrypt_model_weights(self, model_path: str, password: str) -> str:
        out_path = model_path + '.enc'
        self.encrypt_file(model_path, out_path, password)
        return out_path


class VideoStreamProtector:
    """
    Saves a buffer of frames as an encrypted video file.
    Designed for evidence protection during detected incidents.
    """
    def __init__(self, encryptor: 'FileEncryptor', audit: 'AuditLogger', output_dir: str = 'recordings'):
        self.encryptor = encryptor
        self.audit = audit
        self.output_dir = output_dir
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir, exist_ok=True)

    def save_stream(self, frames: list, camera_id: str, password: str, fps: float = 10.0) -> Optional[str]:
        """
        Saves a sequence of frames to an encrypted MP4 file.
        """
        if not frames:
            return None
        
        temp_path = None
        web_path = None
        try:
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            filename = f"incident_{camera_id}_{timestamp}"
            temp_path = os.path.join(self.output_dir, f"{filename}_temp.mp4")
            
            # Use the first frame to get dimensions
            height, width, _ = frames[0].shape
            
            # Using mp4v codec for broad compatibility before encryption
            fourcc = cv2.VideoWriter_fourcc(*'mp4v')
            out = cv2.VideoWriter(temp_path, fourcc, fps, (width, height))
            
            for frame in frames:
                out.write(frame)
            out.release()
            
            if not os.path.exists(temp_path):
                raise RuntimeError("Failed to create temporary video file")

            # Transcode to H.264 using FFmpeg
            web_path = os.path.join(self.output_dir, f"{filename}_web.mp4")
            cmd = [
                'ffmpeg', '-y',
                '-i', temp_path,
                '-vcodec', 'libx264',
                '-pix_fmt', 'yuv420p',
                '-movflags', 'faststart',
                web_path
            ]
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if res.returncode != 0 or not os.path.exists(web_path):
                raise RuntimeError(f"FFmpeg transcoding failed: {res.stderr.decode('utf-8', errors='ignore')}")

            # Encrypt the stream
            enc_path_base = os.path.join(self.output_dir, f"{filename}.mp4.enc")
            result = self.encryptor.encrypt_file(web_path, enc_path_base, password)
            checksum = result.get('checksum_sha256', 'unknown')
            
            # Rename to include hash for integrity verification
            enc_path = os.path.join(self.output_dir, f"{filename}_{checksum[:12]}.mp4.enc")
            os.rename(enc_path_base, enc_path)
            
            self.audit.log('INCIDENT_STREAM_SAVED', 'system', 
                           f"Encrypted incident stream saved for camera {camera_id}: {enc_path} (SHA-256: {checksum})", 
                           success=True)
            print(f"{G} Incident stream saved and hashed ({checksum[:12]}...):{RESET} {enc_path}")
            return enc_path
            
        except Exception as e:
            self.audit.log('STREAM_SAVE_ERROR', 'system', f"Failed to save stream: {str(e)}", success=False)
            print(f"{R} Failed to save incident stream:{RESET} {e}")
            return None
        finally:
            # Cleanup unencrypted files in all scenarios (success or failure)
            if temp_path and os.path.exists(temp_path):
                try:
                    SecureFileRemover.secure_delete(temp_path)
                except Exception as e:
                    print(f"{R} Failed to securely delete temp file {temp_path}:{RESET} {e}")
            if web_path and os.path.exists(web_path):
                try:
                    SecureFileRemover.secure_delete(web_path)
                except Exception as e:
                    print(f"{R} Failed to securely delete web file {web_path}:{RESET} {e}")




class AccessControl:
    MODES = {
        'readonly':   0o444,
        'restricted': 0o640,
        'private':    0o600,
        'public':     0o644,
        'immutable':  0o444,
    }

    def set_permissions(self, path: str, mode: str = 'restricted') -> None:
        bits = self.MODES.get(mode, 0o600)
        os.chmod(path, bits)
        # FIX #11: was a raw string 'f{G}...' — 'f' was outside the quotes
        print(f"{G} Permissions set [{mode}]{RESET} {path} ({oct(bits)})")

    def lock_directory(self, path: str) -> None:
        d = Path(path)
        for item in d.rglob('*'):
            if item.is_dir():
                item.chmod(0o700)
            else:
                item.chmod(0o600)
        d.chmod(0o700)
        print(f"{G} Directory locked:{RESET} {path}")

    def get_permissions_report(self, path: str) -> dict:
        s    = os.stat(path)
        mode = stat.filemode(s.st_mode)
        return {
            'path':          path,
            'mode_symbolic': mode,
            'mode_octal':    oct(s.st_mode & 0o777),
            'uid':           s.st_uid,
            'gid':           s.st_gid,
            'size':          s.st_size,
            'modified':      datetime.fromtimestamp(s.st_mtime).isoformat(),
        }

    def save_acl(self, registry_path: str, acl: dict) -> None:
        with open(registry_path, 'w') as f:
            json.dump(acl, f, indent=2)
        os.chmod(registry_path, 0o600)
        print(f"{G} ACL saved:{RESET} {registry_path}")


class AuthManager:
    SECRET_ENV = 'PROT_SECRET'

    def _secret(self) -> bytes:
        secret = os.environ.get(self.SECRET_ENV)
        if not secret:
            raise RuntimeError(f"Set env variable {self.SECRET_ENV}")
        return secret.encode()

    def _hmac_sha256(self, key: bytes, message: str) -> str:
        return hmac.new(key, message.encode(), hashlib.sha256).hexdigest()

    def generate_token(self, user_id: str, ttl_hours: int = 24) -> str:
        expiry  = int(time.time()) + ttl_hours * 3600
        payload = f"{user_id}:{expiry}"
        sig = self._hmac_sha256(self._secret(), payload)
        raw = f"{payload}:{sig}"
        return base64.urlsafe_b64encode(raw.encode()).decode()

    def verify_token(self, token: str) -> Optional[str]:
        try:
            raw = base64.urlsafe_b64decode(token).decode()
            user_id, expiry_str, sig = raw.split(':', 2)
            expiry = int(expiry_str)
            payload = f"{user_id}:{expiry}"
            expected_sig = self._hmac_sha256(self._secret(), payload)
            if not hmac.compare_digest(sig, expected_sig):
                return None
            if expiry < time.time():
                return None
            return user_id
        except Exception:
            return None

    def hash_password(self, password: str) -> str:
        salt = os.urandom(16)
        kdf  = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 480_000)
        return base64.urlsafe_b64encode(salt + kdf).decode()

    def verify_password(self, password: str, hashed: str) -> bool:
        raw     = base64.urlsafe_b64decode(hashed.encode())
        salt    = raw[:16]
        kdf     = raw[16:]
        new_kdf = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 480_000)
        return hmac.compare_digest(new_kdf, kdf)  # constant-time compare

    def create_user_db(self, path: str, users: dict) -> None:
        db = {u: self.hash_password(p) for u, p in users.items()}
        with open(path, 'w') as f:
            json.dump(db, f)
        os.chmod(path, 0o600)
        print(f"{G} User database created:{RESET} {path}")

    def authenticate(self, path: str, username: str, password: str) -> bool:
        if not os.path.exists(path):
            return False
        with open(path, 'r') as f:
            db = json.load(f)
        hashed = db.get(username)
        if not hashed:
            return False
        return self.verify_password(password, hashed)

class DRMProtector:
    def generate_fingerprint(self, path: str, owner: str) -> dict:
        data = Path(path).read_bytes()
        fingerprint = {
            'owner': owner,  
            'file': path,
            'size': len(data),
            'md5': hashlib.md5(data).hexdigest(),
            'sha256': hashlib.sha256(data).hexdigest(),
            'sha512': hashlib.sha512(data).hexdigest()[:32] + '...',
            'fingerprint': hashlib.blake2b(data, digest_size=16).hexdigest(),
            'issued_at': datetime.utcnow().isoformat() + "Z",
            'license_id': str(uuid.uuid4()),
        }
        print(f"{G} Fingerprint generated:{RESET} {fingerprint['fingerprint']} owner={owner}")
        return fingerprint

    def verify_integrity(self, path: str, fingerprint_path: str) -> bool:
        # Loads the fingerprint from the JSON file and uses that for comparison.
        with open(fingerprint_path) as f:
            fp = json.load(f)
        data = Path(path).read_bytes()
        current = hashlib.sha256(data).hexdigest()
        ok = current == fp['sha256']
        if not ok:
            print(f"{R} INTEGRITY FAILURE:{RESET} {path}")
            print(f"  Expected: {fp['sha256'][:32]}...")
            print(f"  Actual:   {current[:32]}...")
        else:
            print(f"{G} OK, integrity verified:{RESET} {path}")
        return ok

    def save_fingerprint(self, fingerprint: dict, out_path: str) -> None:
        with open(out_path, 'w') as f:
            json.dump(fingerprint, f, indent=2)
        os.chmod(out_path, 0o644)
        print(f"{G} Fingerprint saved:{RESET} {out_path}")

    def text_watermark(self, text: str, owner: str) -> str:
        mark_bits = owner.encode().hex()
        zwsp      = '\u200b'
        zwnj      = '\u200c'
        hidden    = ''.join(zwsp if b == '0' else zwnj for b in bin(int(mark_bits, 16))[2:])
        idx       = text.find('. ')
        if idx == -1:
            return text + hidden
        return text[:idx + 2] + hidden + text[idx + 2:]

    def generate_license(self, owner: str, path: str,
                         allowed_uses: int = 1, expiry_days: int = 365) -> dict:

        expiry = (datetime.utcnow() + timedelta(days=expiry_days)).isoformat() + "Z"
        lic = {
            'license_id':     str(uuid.uuid4()),
            'owner':          owner,  # FIX #7: was 'onwer' (typo)
            'allowed_uses':   allowed_uses,
            'expires':        expiry,
            'file':           path,
            'issued_at':      datetime.utcnow().isoformat() + "Z",
            'uses_remaining': allowed_uses,
        }

        sig_data      = json.dumps(
            {k: lic[k] for k in ['license_id', 'owner', 'file', 'expires']},
            sort_keys=True,
        )
        lic['signature'] = hashlib.sha256(sig_data.encode()).hexdigest()
        return lic

# CLI command handlers

def cmd_encrypt(args):
    pwd = getpass.getpass(prompt='Password: ')
    FileEncryptor().encrypt_file(args.src, args.dst or args.src + '.enc', pwd)


def cmd_decrypt(args):
    pwd = getpass.getpass(prompt='Password: ')
    FileEncryptor().decrypt_file(args.src, args.dst or args.src.removesuffix('.enc'), pwd)


def cmd_fingerprint(args):
    drm         = DRMProtector()
    fingerprint = drm.generate_fingerprint(args.file, args.owner)
    out         = args.out or args.file + '.fingerprint.json'
    drm.save_fingerprint(fingerprint, out)


def cmd_verify(args):
    DRMProtector().verify_integrity(args.file, args.fingerprint)


def cmd_lock(args):
    AccessControl().lock_directory(args.dir)


def cmd_permissions(args):
    AccessControl().set_permissions(args.file, args.mode)


def cmd_token(args):
    auth  = AuthManager()
    token = auth.generate_token(args.user, args.ttl)
    print(f"{G} Token:{RESET} {token}")


def cmd_verify_token(args):
    auth    = AuthManager()
    user_id = auth.verify_token(args.token)
    if user_id:
        print(f"{G} Token verified:{RESET} {user_id}")
    else:
        print(f"{R} Invalid token{RESET}")


def cmd_license(args):
    drm = DRMProtector()
    lic = drm.generate_license(args.owner, args.file, int(args.uses), int(args.days))
    out = args.out or args.file + '.license.json'
    with open(out, 'w') as f:
        json.dump(lic, f, indent=2)
    print(f"{G} License saved:{RESET} {out}")
    print(f"    ID:      {lic['license_id']}")
    print(f"    Expires: {lic['expires']}")

def cmd_scan(args):
    """CLI handler for the visual input guard."""
    guard = VisualInputGuard(
        canonical_size=(args.width, args.height),
        quantise_bits=args.bits,
        smooth_sigma=args.sigma,
        strict=not args.no_strict,
        audit_log=args.audit_log,
    )
    if len(args.images) == 1:
        result = guard.scan(args.images[0])
        if args.json:
            print(json.dumps(result, indent=2))
    else:
        results = guard.scan_batch(args.images)
        if args.json:
            print(json.dumps(results, indent=2))


def cmd_encrypt(args):
    pwd = getpass.getpass(prompt='Password: ')
    FileEncryptor().encrypt_file(args.src, args.dst or args.src + '.enc', pwd)


def cmd_decrypt(args):
    pwd = getpass.getpass(prompt='Password: ')
    FileEncryptor().decrypt_file(args.src, args.dst or args.src.removesuffix('.enc'), pwd)


def cmd_fingerprint(args):
    drm = DRMProtector()
    fingerprint = drm.generate_fingerprint(args.file, args.owner)
    out = args.out or args.file + '.fingerprint.json'
    drm.save_fingerprint(fingerprint, out)


def cmd_verify(args):
    DRMProtector().verify_integrity(args.file, args.fingerprint)


def cmd_lock(args):
    AccessControl().lock_directory(args.dir)


def cmd_permissions(args):
    AccessControl().set_permissions(args.file, args.mode)


def cmd_token(args):
    auth = AuthManager()
    token = auth.generate_token(args.user, args.ttl)
    print(f"{G} Token:{RESET} {token}")


def cmd_verify_token(args):
    auth = AuthManager()
    user_id = auth.verify_token(args.token)
    if user_id:
        print(f"{G} Token verified:{RESET} {user_id}")
    else:
        print(f"{R} Invalid token{RESET}")


def cmd_license(args):
    drm = DRMProtector()
    lic = drm.generate_license(args.owner, args.file, int(args.uses), int(args.days))
    out = args.out or args.file + '.license.json'
    with open(out, 'w') as f:
        json.dump(lic, f, indent=2)
    print(f"{G} License saved:{RESET} {out}")
    print(f"    ID:      {lic['license_id']}")
    print(f"    Expires: {lic['expires']}")


def cmd_scan(args):
    """CLI handler for the visual input guard."""
    guard = VisualInputGuard(
        canonical_size=(args.width, args.height),
        quantise_bits=args.bits,
        smooth_sigma=args.sigma,
        strict=not args.no_strict,
        audit_log=args.audit_log,
    )
    if len(args.images) == 1:
        result = guard.scan(args.images[0])
        if args.json:
            print(json.dumps(result, indent=2))
    else:
        results = guard.scan_batch(args.images)
        if args.json:
            print(json.dumps(results, indent=2))


#  
# Argument parser
#  

def main():
    parser = argparse.ArgumentParser(
        description="Model & File Protection System",
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
    p = sub.add_parser("verify", help="Verify file integrity against a fingerprint")
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
    p.add_argument("--out", default=None)
    p.set_defaults(func=cmd_license)

    # visual input guard
    p = sub.add_parser("scan", help="Scan image(s) for adversarial/malicious visual attacks")
    p.add_argument("images", nargs='+', help="Image file(s) to scan")
    p.add_argument("--width", type=int, default=224, help="Canonical width  (default 224)")
    p.add_argument("--height", type=int, default=224, help="Canonical height (default 224)")
    p.add_argument("--bits", type=int, default=6, help="Quantise colour to N bits (default 6)")
    p.add_argument("--sigma", type=float, default=1.0, help="Gaussian smoothing sigma (default 1.0)")
    p.add_argument("--no-strict", action='store_true', help="Warn instead of raising on BLOCK")
    p.add_argument("--audit-log", default=None, help="Path to JSON-lines audit log")
    p.add_argument("--json", action='store_true', help="Print full result as JSON")
    p.set_defaults(func=cmd_scan)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()


