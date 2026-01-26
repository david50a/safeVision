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

using namespace std;

class GCM{
    private:
        unsigned char cipher[128];
        unsigned char decrypted[128];
        inline vector<uint8_t> pad(vector<uint8_t> data) {
            data.insert(data.end(), (16 - data.size() % 16) % 16, 0);
            return data;
        };
        inline std::vector<uint8_t> xor_bytes(const std::vector<uint8_t>& a,const std::vector<uint8_t>& b) {
            std::vector<uint8_t> r(min(a.size(), b.size()));
            return transform(a.begin(), a.begin() + r.size(), b.begin(), r.begin(),bit_xor<>()), r;
        }
        vector<uint8_t> mul(const vector<uint8_t>& X, const vector<uint8_t>& Y);
        vector<uint8_t> ghash(const vector<uint8_t>& H, const vector<uint8_t>& A);
        vector<uint8_t> inc32(const vector<uint8_t>& counter);
        vector<uint8_t> gctr(const vector<uint8_t>& key, const vector<uint8_t>& icb, const vector<uint8_t>& data);
    public:
        GCM();
        void setKey(const unsigned char* key, const size_t keylen);
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
};
