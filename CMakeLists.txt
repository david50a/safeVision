cmake_minimum_required(VERSION 3.12)
project(EncryptionProject)

# 1. Find the pybind11 package
find_package(pybind11 REQUIRED)

# 2. Define the module (Python name, then relative path to .cpp)
pybind11_add_module(gcm_lib encryption/gcm.cpp)

# 3. If your gcm.cpp needs other headers in the encryption folder:
target_include_directories(gcm_lib PRIVATE encryption)