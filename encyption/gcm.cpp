#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <cmath>
#include <algorithm>
#include <functional>
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
    
    inline vector<uint8_t> pad(vector<uint8_t> data) {
        size_t remainder = data.size() % 16;
        if (remainder != 0) {
            data.insert(data.end(), 16 - remainder, 0);
        }
        return data;
    }
    
    inline std::vector<uint8_t> xor_bytes(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
        std::vector<uint8_t> r(std::min(a.size(), b.size()));
        std::transform(a.begin(), a.begin() + r.size(), b.begin(), r.begin(), std::bit_xor<uint8_t>());
        return r;
    }

    vector<uint8_t> mul(const vector<uint8_t>& X_bytes, const vector<uint8_t>& Y_bytes);
    vector<uint8_t> ghash(const vector<uint8_t>& H, const vector<uint8_t>& A);
    vector<uint8_t> inc32(const vector<uint8_t>& counter);
    vector<uint8_t> gctr(const vector<uint8_t>& icb, const vector<uint8_t>& data);
    
public:
    GCM();
    ~GCM();
    void setKey();
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
    // Original methods remain for internal use
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
    void setKey(const std::vector<unsigned char>& key) {
        if (aes) delete aes;
        aes = new AES(key);
    }
};

vector<uint8_t> GCM::mul(const vector<uint8_t>& X_bytes, const vector<uint8_t>& Y_bytes) {
    std::vector<uint8_t> x_bits;
    x_bits.reserve(128);
    for (uint8_t b : X_bytes) {
        for (int i = 7; i >= 0; --i) x_bits.push_back((b >> i) & 1);
    }
    std::vector<uint8_t> y_bits;
    y_bits.reserve(128);
    for (uint8_t b : Y_bytes) {
        for (int i = 7; i >= 0; --i) {
            y_bits.push_back((b >> i) & 1);
        }
    }
    std::vector<uint8_t> R_bits(128, 0);
    R_bits[0] = 1; R_bits[1] = 1; R_bits[2] = 1; R_bits[7] = 1;
    std::vector<uint8_t> z_bits(128, 0);
    std::vector<uint8_t> v_bits = y_bits;
    for (size_t i = 0; i < 128; ++i) {
        if (x_bits[i]) {
            for (size_t j = 0; j < 128; ++j) {
                z_bits[j] ^= v_bits[j];
            }
        }
        uint8_t lsb = v_bits[127];
        for (int j = 127; j > 0; --j) v_bits[j] = v_bits[j - 1];
        v_bits[0] = 0;
        if (lsb) for (size_t j = 0; j < 128; ++j) v_bits[j] ^= R_bits[j];
    }
    std::vector<uint8_t> Z_bytes(16, 0);
    for (int i = 0; i < 16; ++i) {
        for (int j = 0; j < 8; ++j) Z_bytes[i] |= (z_bits[i * 8 + j] << (7 - j));
    }
    return Z_bytes;
}

vector<uint8_t> GCM::ghash(const vector<uint8_t>& H, const vector<uint8_t>& A) {
    vector<uint8_t> Y(16, 0);
    size_t n = A.size() / 16;
    for (size_t i = 0; i < n; ++i) {
        vector<uint8_t> block(A.begin() + i * 16, A.begin() + (i + 1) * 16);
        Y = xor_bytes(Y, block);
        Y = mul(Y, H);
    }
    return Y;
}

vector<uint8_t> GCM::inc32(const vector<uint8_t>& counter) {
    vector<uint8_t> result = counter;
    uint32_t val = 0;
    for (int i = 12; i < 16; i++) val = (val << 8) | result[i];
    val++;
    for (int i = 15; i >= 12; i--) {
        result[i] = val & 0xff;
        val >>= 8;
    }
    return result;
}

vector<uint8_t> GCM::gctr(const vector<uint8_t>& icb, const vector<uint8_t>& data) {
    if (data.empty()) return {};
    int n = ceil((double)data.size() / 16.0);
    vector<uint8_t> cb = icb;
    std::vector<uint8_t> result;
    result.reserve(data.size());
    for (int i = 0; i < n; ++i) {
        vector<uint8_t> encrypted_cb = aes->encrypt(cb);
        size_t block_size = std::min(static_cast<size_t>(16), data.size() - i * 16);
        for (size_t j = 0; j < block_size; ++j) result.push_back(data[i * 16 + j] ^ encrypted_cb[j]);
        cb = inc32(cb);
    }
    return result;
}

GCM::GCM() : aes(nullptr) {}

GCM::~GCM() {
    if (aes) delete aes;
}

void GCM::setKey() {
    if (aes) delete aes;
    std::vector<uint8_t> key = generate_key();
    aes = new AES(key);
}

void GCM::encrypt(const unsigned char* iv, const size_t ivlen,
                  const unsigned char* plaintext, const size_t plen,
                  const unsigned char* aad, const size_t aadlen,
                  unsigned char* ciphertext,
                  unsigned char* tag, const size_t taglen) {

    if (!aes) throw std::runtime_error("Key not set. Call setKey() first.");
    std::vector<uint8_t> H = aes->encrypt(std::vector<uint8_t>(16, 0));
    std::vector<uint8_t> J0(16, 0);
    if (ivlen == 12) {
        std::copy(iv, iv + ivlen, J0.begin());
        J0[15] = 1;
    } else {
        std::vector<uint8_t> iv_vec(iv, iv + ivlen);
        iv_vec = pad(iv_vec);
        std::vector<uint8_t> len_block(16, 0);
        uint64_t iv_bits_len = ivlen * 8;
        for (int i = 0; i < 8; ++i) {
            len_block[8 + i] = (iv_bits_len >> (56 - 8 * i)) & 0xff;
        }
        iv_vec.insert(iv_vec.end(), len_block.begin(), len_block.end());
        J0 = ghash(H, iv_vec);
    }
    std::vector<uint8_t> plaintext_vec(plaintext, plaintext + plen);
    std::vector<uint8_t> ciphertext_vec = gctr(inc32(J0), plaintext_vec);
    std::copy(ciphertext_vec.begin(), ciphertext_vec.end(), ciphertext);
    std::vector<uint8_t> aad_vec(aad, aad + aadlen);
    aad_vec = pad(aad_vec);
    std::vector<uint8_t> cipher_padded = ciphertext_vec;
    cipher_padded = pad(cipher_padded);
    std::vector<uint8_t> combined = aad_vec;
    combined.insert(combined.end(), cipher_padded.begin(), cipher_padded.end());
    std::vector<uint8_t> len_block(16, 0);
    uint64_t aad_bits_len = aadlen * 8;
    uint64_t cipher_bits_len = plen * 8;
    for (int i = 0; i < 8; ++i) {
        len_block[i] = (aad_bits_len >> (56 - 8 * i)) & 0xff;
        len_block[8 + i] = (cipher_bits_len >> (56 - 8 * i)) & 0xff;
    }
    combined.insert(combined.end(), len_block.begin(), len_block.end());
    std::vector<uint8_t> S = ghash(H, combined);
    std::vector<uint8_t> T = gctr(J0, S);
    std::copy(T.begin(), T.begin() + std::min(taglen, T.size()), tag);
}

void GCM::decrypt(const unsigned char* iv, const size_t ivlen,
                  const unsigned char* ciphertext, const size_t clen,
                  const unsigned char* aad, const size_t aadlen,
                  const unsigned char* tag, const size_t taglen,
                  unsigned char* plaintext) {
    if (!aes) throw std::runtime_error("Key not set. Call setKey() first.");
    std::vector<uint8_t> H = aes->encrypt(std::vector<uint8_t>(16, 0));
    std::vector<uint8_t> J0(16, 0);
    if (ivlen == 12) {
        std::copy(iv, iv + ivlen, J0.begin());
        J0[15] = 1;
    } else {
        std::vector<uint8_t> iv_vec(iv, iv + ivlen);
        iv_vec = pad(iv_vec);
        std::vector<uint8_t> len_block(16, 0);
        uint64_t iv_bits_len = ivlen * 8;
        // FIX: Corrected bit shifting for IV length encoding
        for (int i = 0; i < 8; ++i) {
            len_block[8 + i] = (iv_bits_len >> (56 - 8 * i)) & 0xff;
        }
        iv_vec.insert(iv_vec.end(), len_block.begin(), len_block.end());
        J0 = ghash(H, iv_vec);
    }
    std::vector<uint8_t> aad_vec(aad, aad + aadlen);
    aad_vec = pad(aad_vec);
    std::vector<uint8_t> cipher_vec(ciphertext, ciphertext + clen);
    std::vector<uint8_t> cipher_padded = cipher_vec;
    cipher_padded = pad(cipher_padded);
    std::vector<uint8_t> combined = aad_vec;
    combined.insert(combined.end(), cipher_padded.begin(), cipher_padded.end());
    std::vector<uint8_t> len_block(16, 0);
    uint64_t aad_bits_len = aadlen * 8;
    uint64_t cipher_bits_len = clen * 8;
    for (int i = 0; i < 8; ++i) {
        len_block[i] = (aad_bits_len >> (56 - 8 * i)) & 0xff;
        len_block[8 + i] = (cipher_bits_len >> (56 - 8 * i)) & 0xff;
    }
    combined.insert(combined.end(), len_block.begin(), len_block.end());
    std::vector<uint8_t> S = ghash(H, combined);
    std::vector<uint8_t> T = gctr(J0, S);
    if (memcmp(T.data(), tag, taglen) != 0) throw std::runtime_error("Invalid tag - authentication failed.");
    std::vector<uint8_t> plaintext_vec = gctr(inc32(J0), cipher_vec);
    std::copy(plaintext_vec.begin(), plaintext_vec.end(), plaintext);
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

PYBIND11_MODULE(gcm_lib, m) {
    m.doc() = "GCM AES-256 Encryption Module";
    py::class_<GCM>(m, "GCM")
        .def(py::init<>())
        // For the version: void setKey()
        .def("setKey", static_cast<void (GCM::*)()>(&GCM::setKey))
        // For the version: void setKey(const std::vector<uint8_t>&)
        .def("setKey", static_cast<void (GCM::*)(const std::vector<uint8_t>&)>(&GCM::setKey), "key"_a)
        .def("encrypt", &GCM::encrypt_py, "iv"_a, "plaintext"_a, "aad"_a)
        .def("decrypt", &GCM::decrypt_py, "iv"_a, "ciphertext"_a, "aad"_a, "tag"_a)
        .def_static("generate_key", &GCM::generate_key);
}