from setuptools import setup, Extension
import pybind11
import os
import sys

openssl_dir = r"C:\Program Files\OpenSSL-Win64"

include_dirs = [pybind11.get_include()]
library_dirs = []
libraries = ['libcrypto']

if sys.platform == 'win32':
    if os.path.exists(openssl_dir):
        include_dirs.append(os.path.join(openssl_dir, 'include'))
        # Using the standard MSVC dynamically linked release build library path
        library_dirs.append(os.path.join(openssl_dir, 'lib', 'VC', 'x64', 'MD'))
    else:
        print(f"Warning: OpenSSL not found at {openssl_dir}. Please install it or update setup.py.")

ext_modules = [
    Extension(
        'gcm',
        ['encryption/gcm.cpp', "encryption/aes.cpp"],
        include_dirs=include_dirs,
        library_dirs=library_dirs,
        libraries=libraries,
        language='c++',
    ),
    Extension(
        'hmac_lib',
        ['encryption/HMAC.cpp'],
        include_dirs=include_dirs,
        library_dirs=library_dirs,
        libraries=libraries,
        language='c++',
    ),
]

setup(
    name='safevision_crypto',
    version='0.1.0',
    ext_modules=ext_modules,
)
