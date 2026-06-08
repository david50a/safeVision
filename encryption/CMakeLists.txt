cmake_minimum_required(VERSION 3.15)
project(encryption_modules)

find_package(OpenSSL REQUIRED)

# Add pybind11 (located in ../extern/pybind11 based on your file structure)
add_subdirectory(../extern/pybind11 pybind11_build)

# Build the HMAC module (name must match PYBIND11_MODULE(hmac_lib, ...) in HMAC.cpp)
pybind11_add_module(hmac_lib HMAC.cpp)
target_link_libraries(hmac_lib PRIVATE OpenSSL::Crypto)

# Build the GCM module
pybind11_add_module(gcm gcm.cpp aes.cpp)
# target_link_libraries(gcm PRIVATE OpenSSL::Crypto) # Uncomment if GCM uses OpenSSL
