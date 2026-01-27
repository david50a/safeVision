#ifndef AES_H
#define AES_H

#include <cstdint>
#include <vector>
#include <string>

class AES {
public:
    // AES-256 Constants
    static constexpr size_t BlockSize = 16;
    static constexpr size_t KeySize   = 32;
    static constexpr int Nb = 4;
    static constexpr int Nk = 8;
    static constexpr int Nr = 14;

    /**
     * @brief Constructor for AES cipher
     * @param key A 32-byte key for AES-256
     * @throws std::invalid_argument if key size is not 32 bytes
     */
    explicit AES(const std::vector<uint8_t>& key);

    /**
     * @brief Encrypt data using AES-256
     * @param data The plaintext to encrypt
     * @return The encrypted ciphertext
     */
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& data);

    /**
     * @brief Decrypt data using AES-256
     * @param data The ciphertext to decrypt
     * @return The decrypted plaintext
     * @throws std::runtime_error if ciphertext length is not a multiple of 16
     */
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& data);

    /**
     * @brief Convert byte data to hexadecimal string
     * @param data The byte data to convert
     * @return Hexadecimal string representation
     */
    static std::string toHex(const std::vector<uint8_t>& data);

private:
    std::array<std::array<uint32_t, 60>, 1> roundKeys;

    void keyExpansion(const uint8_t* key);
    void cipher(uint8_t* state);
    void invCipher(uint8_t* state);
    std::vector<uint8_t> pkcs7Pad(const std::vector<uint8_t>& data);
    std::vector<uint8_t> pkcs7Unpad(const std::vector<uint8_t>& data);
};

#endif // AES_H
