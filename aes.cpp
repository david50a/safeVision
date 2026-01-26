#include <iostream>
#include <string>
#include <vector>
#include <array>
#include <algorithm>
#include <iomanip>
#include <sstream>
#include <stdexcept>


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

    // Lookup Tables
    static const std::array<uint8_t, 256> Sbox;
    static const std::array<uint8_t, 256> InvSbox;
    static const std::array<uint8_t, 15> Rcon; 
};


const std::array<uint8_t, 256> AES::Sbox = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

const std::array<uint8_t, 256> AES::InvSbox = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

const std::array<uint8_t, 15> AES::Rcon = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d
};

// --- Implementation of Logic ---

uint8_t AES::mul(uint8_t a, uint8_t b) {
    uint8_t r = 0;
    while (b) {
        if (b & 1) r ^= a;
        a = xtime(a);
        b >>= 1;
    }
    return r;
}

void AES::keyExpansion(const uint8_t* key) {
    std::copy(key, key + KeySize, roundKey.begin());
    uint8_t temp[4];
    for (int i = Nk; i < Nb * (Nr + 1); ++i) {
        std::copy(&roundKey[4 * (i - 1)], &roundKey[4 * (i - 1)] + 4, temp);
        if (i % Nk == 0) {
            uint8_t t = temp[0];
            temp[0] = Sbox[temp[1]] ^ Rcon[i / Nk];
            temp[1] = Sbox[temp[2]];
            temp[2] = Sbox[temp[3]];
            temp[3] = Sbox[t];
        } else if (i % Nk == 4) {
            for (uint8_t & j : temp) j = Sbox[j];
        }
        for (int j = 0; j < 4; j++)
            roundKey[4 * i + j] = roundKey[4 * (i - Nk) + j] ^ temp[j];
    }
}

void AES::cipher(uint8_t* state) {
    addRoundKey(state, 0);
    for (int round = 1; round < Nr; ++round) {
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        addRoundKey(state, round);
    }
    subBytes(state);
    shiftRows(state);
    addRoundKey(state, Nr);
}

void AES::invCipher(uint8_t* state) {
    addRoundKey(state, Nr);
    for (int round = Nr - 1; round > 0; round--) {
        invShiftRows(state);
        invSubBytes(state);
        addRoundKey(state, round);
        invMixColumns(state);
    }
    invShiftRows(state);
    invSubBytes(state);
    addRoundKey(state, 0);
}

void AES::subBytes(uint8_t* s) { for (int i = 0; i < 16; i++) s[i] = Sbox[s[i]]; }
void AES::invSubBytes(uint8_t* s) { for (int i = 0; i < 16; i++) s[i] = InvSbox[s[i]]; }

void AES::addRoundKey(uint8_t* state, int round) {
    for (int i = 0; i < 16; i++) state[i] ^= roundKey[round * 16 + i];
}

void AES::shiftRows(uint8_t* s) {
    uint8_t t[16];
    std::copy(s, s + 16, t);
    s[0]=t[0]; s[4]=t[4]; s[8]=t[8];  s[12]=t[12];
    s[1]=t[5]; s[5]=t[9]; s[9]=t[13]; s[13]=t[1];
    s[2]=t[10];s[6]=t[14];s[10]=t[2]; s[14]=t[6];
    s[3]=t[15];s[7]=t[3]; s[11]=t[7]; s[15]=t[11];
}

void AES::invShiftRows(uint8_t* s) {
    uint8_t t[16];
    std::copy(s, s + 16, t);
    s[0]=t[0]; s[4]=t[4]; s[8]=t[8];  s[12]=t[12];
    s[1]=t[13];s[5]=t[1]; s[9]=t[5];  s[13]=t[9];
    s[2]=t[10];s[6]=t[14];s[10]=t[2]; s[14]=t[6];
    s[3]=t[7]; s[7]=t[11];s[11]=t[15];s[15]=t[3];
}

void AES::mixColumns(uint8_t* s) {
    for (int i = 0; i < 4; i++) {
        uint8_t a = s[4*i], b = s[4*i+1], c = s[4*i+2], d = s[4*i+3];
        s[4*i]   = mul(a,2)^mul(b,3)^c^d;
        s[4*i+1] = a^mul(b,2)^mul(c,3)^d;
        s[4*i+2] = a^b^mul(c,2)^mul(d,3);
        s[4*i+3] = mul(a,3)^b^c^mul(d,2);
    }
}

void AES::invMixColumns(uint8_t* s) {
    for (int i = 0; i < 4; i++) {
        uint8_t a = s[4*i], b = s[4*i+1], c = s[4*i+2], d = s[4*i+3];
        s[4*i]   = mul(a,14)^mul(b,11)^mul(c,13)^mul(d,9);
        s[4*i+1] = mul(a,9)^mul(b,14)^mul(c,11)^mul(d,13);
        s[4*i+2] = mul(a,13)^mul(b,9)^mul(c,14)^mul(d,11);
        s[4*i+3] = mul(a,11)^mul(b,13)^mul(c,9)^mul(d,14);
    }
}

std::vector<uint8_t> AES::pkcs7Pad(const std::vector<uint8_t>& data) {
    size_t padLen = BlockSize - (data.size() % BlockSize);
    std::vector<uint8_t> padded = data;
    padded.insert(padded.end(), padLen, static_cast<uint8_t>(padLen));
    return padded;
}

std::vector<uint8_t> AES::pkcs7Unpad(const std::vector<uint8_t>& data) {
    if (data.empty()) return {};
    uint8_t padLen = data.back();
    if (padLen == 0 || padLen > BlockSize) throw std::runtime_error("Invalid padding");
    return {data.begin(), data.end() - padLen};
}

// Example main function (commented out - uncomment to test)
/*
int main() {
    try { 
        // Generate a 32-byte key for AES-256
        std::vector<uint8_t> key(32);
        for (int i = 0; i < 32; i++) key[i] = i;
        
        AES aes(key);

        std::string plain = "Hello, C++ World!";
        std::vector<uint8_t> data(plain.begin(), plain.end());

        auto encrypted = aes.encrypt(data);
        std::cout << "Ciphertext (Hex): " << AES::toHex(encrypted) << "\n";

        auto decrypted = aes.decrypt(encrypted);
        std::string decryptedText(decrypted.begin(), decrypted.end());
        std::cout << "Decrypted: " << decryptedText << "\n";

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
    }
    return 0;
}
*/