#ifndef AES_H
#define AES_H

#include <iostream>
#include <string>
#include <vector>
#include <array>
#include <algorithm>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <cstdint>
class AES {
public:
    // AES-256 Constants
    static constexpr size_t BlockSize = 16;
    static constexpr size_t KeySize   = 32;
    static constexpr int Nb = 4;
    static constexpr int Nk = 8;
    static constexpr int Nr = 14;

    explicit AES(const std::vector<uint8_t>& key) {
        if (key.size() != KeySize) {
            throw std::invalid_argument("AES-256 requires a 32-byte key.");
        }
        keyExpansion(key.data());
    }

    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& data) {
        if (data.empty()) {
            return pkcs7Pad(data);
        }
        
        std::vector<uint8_t> state = pkcs7Pad(data);
        for (size_t i = 0; i < state.size(); i += BlockSize) {
            cipher(state.data() + i);
        }
        return state;
    }

    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& data) {
        if (data.empty() || data.size() % BlockSize != 0) {
            throw std::runtime_error("Ciphertext length must be a multiple of 16.");
        }
        std::vector<uint8_t> state = data;
        for (size_t i = 0; i < state.size(); i += BlockSize) {
            invCipher(state.data() + i);
        }
        return pkcs7Unpad(state);
    }

    static std::string toHex(const std::vector<uint8_t>& data) {
        std::ostringstream ss;
        ss << std::hex << std::setfill('0');
        for (auto b : data) ss << std::setw(2) << static_cast<int>(b);
        return ss.str();
    }

private:
    std::array<uint8_t, 240> roundKey{};
    
    // Internal AES transformations
    void cipher(uint8_t* state);
    void invCipher(uint8_t* state);
    void keyExpansion(const uint8_t* key);
    
    // Galois Field Math
    inline uint8_t xtime(uint8_t x) { return (x << 1) ^ ((x & 0x80) ? 0x1b : 0); }
    uint8_t mul(uint8_t a, uint8_t b);

    // Round steps
    void addRoundKey(uint8_t* state, int round);
    void subBytes(uint8_t* state);
    void invSubBytes(uint8_t* state);
    void shiftRows(uint8_t* state);
    void invShiftRows(uint8_t* state);
    void mixColumns(uint8_t* state);
    void invMixColumns(uint8_t* state);

    // Padding
    std::vector<uint8_t> pkcs7Pad(const std::vector<uint8_t>& data);
    std::vector<uint8_t> pkcs7Unpad(const std::vector<uint8_t>& data);

    // Lookup Tables (defined in aes.cpp)
    static const std::array<uint8_t, 256> Sbox;
    static const std::array<uint8_t, 256> InvSbox;
    static const std::array<uint8_t, 15> Rcon; 
};

#endif // AES_H