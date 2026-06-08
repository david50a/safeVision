#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <algorithm>
#include <random>
#include "aes.h"
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

using namespace std;
namespace py = pybind11;
using namespace pybind11::literals;  

class GCM {
private:
    AES* aes;
    
    // Fast 128-bit GF multiplication in GCM mode (bit-reflected, shifted right)
    void gf_mult(const uint8_t* x, const uint8_t* y, uint8_t* z) {
        uint64_t x_h = 0, x_l = 0;
        uint64_t y_h = 0, y_l = 0;
        
        // Pack big-endian bytes into 64-bit halves
        for (int i = 0; i < 8; ++i) {
            x_h = (x_h << 8) | x[i];
            x_l = (x_l << 8) | x[8 + i];
            y_h = (y_h << 8) | y[i];
            y_l = (y_l << 8) | y[8 + i];
        }
        
        uint64_t z_h = 0, z_l = 0;
        uint64_t v_h = y_h;
        uint64_t v_l = y_l;
        
        for (int i = 0; i < 128; ++i) {
            bool bit;
            if (i < 64) {
                bit = (x_h >> (63 - i)) & 1;
            } else {
                bit = (x_l >> (127 - i)) & 1;
            }
            
            if (bit) {
                z_h ^= v_h;
                z_l ^= v_l;
            }
            
            uint64_t lsb = v_l & 1;
            uint64_t carry = v_h & 1;
            v_h >>= 1;
            v_l = (v_l >> 1) | (carry << 63);
            
            if (lsb) {
                v_h ^= 0xE100000000000000ULL;
            }
        }
        
        // Unpack 64-bit halves back into big-endian bytes
        for (int i = 7; i >= 0; --i) {
            z[i] = z_h & 0xFF;
            z_h >>= 8;
            z[8 + i] = z_l & 0xFF;
            z_l >>= 8;
        }
    }
    
    void ghash(const uint8_t* H, const uint8_t* data, size_t len, uint8_t* Y) {
        memset(Y, 0, 16);
        size_t blocks = len / 16;
        for (size_t i = 0; i < blocks; ++i) {
            for (int j = 0; j < 16; ++j) {
                Y[j] ^= data[i * 16 + j];
            }
            uint8_t temp[16];
            gf_mult(Y, H, temp);
            memcpy(Y, temp, 16);
        }
    }
    
    void gctr(const uint8_t* icb, const uint8_t* data, size_t len, uint8_t* out) {
        if (len == 0) return;
        size_t blocks = (len + 15) / 16;
        uint8_t cb[16];
        memcpy(cb, icb, 16);
        
        for (size_t i = 0; i < blocks; ++i) {
            uint8_t encrypted_cb[16];
            memcpy(encrypted_cb, cb, 16);
            aes->encryptBlock(encrypted_cb);
            
            size_t block_size = std::min((size_t)16, len - i * 16);
            for (size_t j = 0; j < block_size; ++j) {
                out[i * 16 + j] = data[i * 16 + j] ^ encrypted_cb[j];
            }
            
            // Increment 32-bit counter (last 4 bytes of cb)
            uint32_t val = 0;
            for (int j = 12; j < 16; ++j) {
                val = (val << 8) | cb[j];
            }
            val++;
            for (int j = 15; j >= 12; --j) {
                cb[j] = val & 0xFF;
                val >>= 8;
            }
        }
    }
    
public:
    GCM();
    ~GCM();
    void setKey();
    void setKey(const std::vector<unsigned char>& key);
    
    // Wrapped for Python: Returns a pair of (ciphertext, tag)
    std::pair<py::bytes, py::bytes> encrypt_py(py::bytes iv, py::bytes plaintext, py::bytes aad) {
        std::string s_iv = iv;
        std::string s_pt = plaintext;
        std::string s_aad = aad;
        std::vector<uint8_t> ct(s_pt.size());
        std::vector<uint8_t> tag(16);
        encrypt(reinterpret_cast<const unsigned char*>(s_iv.data()), s_iv.size(),
                reinterpret_cast<const unsigned char*>(s_pt.data()), s_pt.size(),
                reinterpret_cast<const unsigned char*>(s_aad.data()), s_aad.size(),
                ct.data(), tag.data(), tag.size());

        return {py::bytes(reinterpret_cast<char*>(ct.data()), ct.size()), 
                py::bytes(reinterpret_cast<char*>(tag.data()), tag.size())};
    }
    
    // Wrapped for Python: Returns plaintext string
    py::bytes decrypt_py(py::bytes iv, py::bytes ciphertext, py::bytes aad, py::bytes tag) {
        std::string s_iv = iv;
        std::string s_ct = ciphertext;
        std::string s_aad = aad;
        std::string s_tag = tag;
        std::vector<uint8_t> pt(s_ct.size());
        decrypt(reinterpret_cast<const unsigned char*>(s_iv.data()), s_iv.size(),
                reinterpret_cast<const unsigned char*>(s_ct.data()), s_ct.size(),
                reinterpret_cast<const unsigned char*>(s_aad.data()), s_aad.size(),
                reinterpret_cast<const unsigned char*>(s_tag.data()), s_tag.size(),
                pt.data());

        return py::bytes(reinterpret_cast<char*>(pt.data()), pt.size());
    }
    
    void encrypt(const unsigned char* iv, const size_t ivlen,
                 const unsigned char* plaintext, const size_t plen,
                 const unsigned char* aad, const size_t aadlen,
                 unsigned char* ciphertext,
                 unsigned char* tag, const size_t taglen);

    void decrypt(const unsigned char* iv, const size_t ivlen,
                 const unsigned char* ciphertext, const size_t clen,
                 const unsigned char* aad, const size_t aadlen,
                 const unsigned char* tag, const size_t taglen,
                 unsigned char* plaintext);

    static std::vector<uint8_t> generate_key();
};

GCM::GCM() : aes(nullptr) {}

GCM::~GCM() {
    if (aes) delete aes;
}

void GCM::setKey() {
    if (aes) delete aes;
    aes = new AES(generate_key());
}

void GCM::setKey(const std::vector<unsigned char>& key) {
    if (aes) delete aes;
    aes = new AES(key);
}

void GCM::encrypt(const unsigned char* iv, const size_t ivlen,
                  const unsigned char* plaintext, const size_t plen,
                  const unsigned char* aad, const size_t aadlen,
                  unsigned char* ciphertext,
                  unsigned char* tag, const size_t taglen) {
    if (!aes) throw std::runtime_error("Key not set. Call setKey() first.");
    
    uint8_t H[16] = {0};
    aes->encryptBlock(H);
    
    uint8_t J0[16] = {0};
    if (ivlen == 12) {
        memcpy(J0, iv, 12);
        J0[15] = 1;
    } else {
        std::vector<uint8_t> iv_padded(iv, iv + ivlen);
        size_t remainder = ivlen % 16;
        if (remainder != 0) {
            iv_padded.insert(iv_padded.end(), 16 - remainder, 0);
        }
        uint8_t len_block[16] = {0};
        uint64_t iv_bits_len = (uint64_t)ivlen * 8;
        for (int i = 0; i < 8; ++i) {
            len_block[8 + i] = (iv_bits_len >> (56 - 8 * i)) & 0xFF;
        }
        iv_padded.insert(iv_padded.end(), len_block, len_block + 16);
        ghash(H, iv_padded.data(), iv_padded.size(), J0);
    }
    
    uint8_t J0_inc[16];
    memcpy(J0_inc, J0, 16);
    uint32_t val = 0;
    for (int j = 12; j < 16; ++j) {
        val = (val << 8) | J0_inc[j];
    }
    val++;
    for (int j = 15; j >= 12; --j) {
        J0_inc[j] = val & 0xFF;
        val >>= 8;
    }
    
    gctr(J0_inc, plaintext, plen, ciphertext);
    
    std::vector<uint8_t> combined;
    combined.reserve(((aadlen + 15) / 16) * 16 + ((plen + 15) / 16) * 16 + 16);
    
    combined.insert(combined.end(), aad, aad + aadlen);
    size_t aad_remainder = aadlen % 16;
    if (aad_remainder != 0) {
        combined.insert(combined.end(), 16 - aad_remainder, 0);
    }
    
    combined.insert(combined.end(), ciphertext, ciphertext + plen);
    size_t ct_remainder = plen % 16;
    if (ct_remainder != 0) {
        combined.insert(combined.end(), 16 - ct_remainder, 0);
    }
    
    uint8_t len_block[16] = {0};
    uint64_t aad_bits_len = (uint64_t)aadlen * 8;
    uint64_t ct_bits_len = (uint64_t)plen * 8;
    for (int i = 0; i < 8; ++i) {
        len_block[i] = (aad_bits_len >> (56 - 8 * i)) & 0xFF;
        len_block[8 + i] = (ct_bits_len >> (56 - 8 * i)) & 0xFF;
    }
    combined.insert(combined.end(), len_block, len_block + 16);
    
    uint8_t S[16];
    ghash(H, combined.data(), combined.size(), S);
    
    uint8_t T[16];
    gctr(J0, S, 16, T);
    
    memcpy(tag, T, std::min(taglen, (size_t)16));
}

void GCM::decrypt(const unsigned char* iv, const size_t ivlen,
                  const unsigned char* ciphertext, const size_t clen,
                  const unsigned char* aad, const size_t aadlen,
                  const unsigned char* tag, const size_t taglen,
                  unsigned char* plaintext) {
    if (!aes) throw std::runtime_error("Key not set. Call setKey() first.");
    
    uint8_t H[16] = {0};
    aes->encryptBlock(H);
    
    uint8_t J0[16] = {0};
    if (ivlen == 12) {
        memcpy(J0, iv, 12);
        J0[15] = 1;
    } else {
        std::vector<uint8_t> iv_padded(iv, iv + ivlen);
        size_t remainder = ivlen % 16;
        if (remainder != 0) {
            iv_padded.insert(iv_padded.end(), 16 - remainder, 0);
        }
        uint8_t len_block[16] = {0};
        uint64_t iv_bits_len = (uint64_t)ivlen * 8;
        for (int i = 0; i < 8; ++i) {
            len_block[8 + i] = (iv_bits_len >> (56 - 8 * i)) & 0xFF;
        }
        iv_padded.insert(iv_padded.end(), len_block, len_block + 16);
        ghash(H, iv_padded.data(), iv_padded.size(), J0);
    }
    
    std::vector<uint8_t> combined;
    combined.reserve(((aadlen + 15) / 16) * 16 + ((clen + 15) / 16) * 16 + 16);
    
    combined.insert(combined.end(), aad, aad + aadlen);
    size_t aad_remainder = aadlen % 16;
    if (aad_remainder != 0) {
        combined.insert(combined.end(), 16 - aad_remainder, 0);
    }
    
    combined.insert(combined.end(), ciphertext, ciphertext + clen);
    size_t ct_remainder = clen % 16;
    if (ct_remainder != 0) {
        combined.insert(combined.end(), 16 - ct_remainder, 0);
    }
    
    uint8_t len_block[16] = {0};
    uint64_t aad_bits_len = (uint64_t)aadlen * 8;
    uint64_t ct_bits_len = (uint64_t)clen * 8;
    for (int i = 0; i < 8; ++i) {
        len_block[i] = (aad_bits_len >> (56 - 8 * i)) & 0xFF;
        len_block[8 + i] = (ct_bits_len >> (56 - 8 * i)) & 0xFF;
    }
    combined.insert(combined.end(), len_block, len_block + 16);
    
    uint8_t S[16];
    ghash(H, combined.data(), combined.size(), S);
    
    uint8_t T[16];
    gctr(J0, S, 16, T);
    
    if (memcmp(T, tag, taglen) != 0) {
        throw std::runtime_error("Invalid tag - authentication failed.");
    }
    
    uint8_t J0_inc[16];
    memcpy(J0_inc, J0, 16);
    uint32_t val = 0;
    for (int j = 12; j < 16; ++j) {
        val = (val << 8) | J0_inc[j];
    }
    val++;
    for (int j = 15; j >= 12; --j) {
        J0_inc[j] = val & 0xFF;
        val >>= 8;
    }
    
    gctr(J0_inc, ciphertext, clen, plaintext);
}

std::vector<uint8_t> GCM::generate_key() {
    std::vector<uint8_t> key(32);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    for (int i = 0; i < 32; i++) {
        key[i] = dis(gen);
    }
    return key;
}

PYBIND11_MODULE(gcm, m) {
    m.doc() = "GCM AES-256 Encryption Module";
    py::class_<GCM>(m, "GCM")
        .def(py::init<>())
        .def("setKey", static_cast<void (GCM::*)()>(&GCM::setKey))
        .def("setKey", static_cast<void (GCM::*)(const std::vector<uint8_t>&)>(&GCM::setKey), "key"_a)
        .def("encrypt", &GCM::encrypt_py, "iv"_a, "plaintext"_a, "aad"_a)
        .def("decrypt", &GCM::decrypt_py, "iv"_a, "ciphertext"_a, "aad"_a, "tag"_a)
        .def_static("generate_key", &GCM::generate_key);
}