from setuptools import setup, Extension
import pybind11
ext_modules = [
    Extension(
        'gcm',
        ['encryption/gcm.cpp',"encryption/aes.cpp"],
        include_dirs=[pybind11.get_include()],
        language='c++',
    ),
]
setup(name='gcm',ext_modules=ext_modules)