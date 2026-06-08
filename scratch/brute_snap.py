import sys
sys.path.insert(0, 'server')
from model.model_protection import FileEncryptor

enc = FileEncryptor()

snap_enc = 'server/database/snapshots/snap_fef85e0656234895be6b9d27af069e71.png.enc'
dest = 'test_decrypted_check.png'

passwords = [
    'admin', 'safevision', 'password', 'security', 'system', 'HISPIN', '123456',
    'd3eeae17bf968c42c55da337ac905736', 'safeVision', 'safevision1', 'meir',
    'model', 'violence', 'rwf2000', 'Rwanda', 'rwanda', 'hispin',
    'SafeVision', 'SAFEVISION', 'master', 'MASTER', 'server', 'SERVER',
    'localhost', 'guard', 'alarm', 'camera', '12345678', 'qwerty',
    'safevision123', 'sv2024', 'sv2025', 'sv2026',
]
for pwd in passwords:
    result = enc.decrypt_file(snap_enc, dest, pwd)
    if result:
        print(f'SUCCESS: password is "{pwd}"')
        break
else:
    print('None of the tested passwords worked')
