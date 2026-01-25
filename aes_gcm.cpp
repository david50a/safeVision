#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <stdexcept>

using namespace std;

class AES {
private:
    static const int Nb = 4;
    static const int Nk = 8;
    static const int Nr = 14;

    unsigned char roundKey[240];

    static const unsigned char Sbox[256];
    static const unsigned char InvSbox[256];
    static const unsigned char Rcon[15];

    inline unsigned char xtime(unsigned char x) {
        return (x << 1) ^ ((x & 0x80) ? 0x1b : 0);
    }

    unsigned char mul(unsigned char a, unsigned char b) {
        unsigned char r = 0;
        while (b) {
            if (b & 1) r ^= a;
            a = xtime(a);
            b >>= 1;
        }
        return r;
    }

    void KeyExpansion(const unsigned char* key) {
        memcpy(roundKey, key, 32);

        unsigned char temp[4];
        int i = Nk;

        while (i < Nb * (Nr + 1)) {
            memcpy(temp, &roundKey[4 * (i - 1)], 4);

            if (i % Nk == 0) {
                unsigned char t = temp[0];
                temp[0] = Sbox[temp[1]];
                temp[1] = Sbox[temp[2]];
                temp[2] = Sbox[temp[3]];
                temp[3] = Sbox[t];
                temp[0] ^= Rcon[i / Nk];
            }
            else if (i % Nk == 4) {
                for (int j = 0; j < 4; j++)
                    temp[j] = Sbox[temp[j]];
            }

            for (int j = 0; j < 4; j++)
                roundKey[4 * i + j] =
                    roundKey[4 * (i - Nk) + j] ^ temp[j];

            i++;
        }
    }

    void AddRoundKey(unsigned char* state, int round) {
        for (int i = 0; i < 16; i++)
            state[i] ^= roundKey[round * 16 + i];
    }

    void SubBytes(unsigned char* s) {
        for (int i = 0; i < 16; i++) s[i] = Sbox[s[i]];
    }

    void InvSubBytes(unsigned char* s) {
        for (int i = 0; i < 16; i++) s[i] = InvSbox[s[i]];
    }

    void ShiftRows(unsigned char* s) {
        unsigned char t[16];
        memcpy(t, s, 16);

        s[0]  = t[0];  s[4]  = t[4];  s[8]  = t[8];  s[12] = t[12];
        s[1]  = t[5];  s[5]  = t[9];  s[9]  = t[13]; s[13] = t[1];
        s[2]  = t[10]; s[6]  = t[14]; s[10] = t[2];  s[14] = t[6];
        s[3]  = t[15]; s[7]  = t[3];  s[11] = t[7];  s[15] = t[11];
    }

    void InvShiftRows(unsigned char* s) {
        unsigned char t[16];
        memcpy(t, s, 16);

        s[0]  = t[0];  s[4]  = t[4];  s[8]  = t[8];  s[12] = t[12];
        s[1]  = t[13]; s[5]  = t[1];  s[9]  = t[5];  s[13] = t[9];
        s[2]  = t[10]; s[6]  = t[14]; s[10] = t[2];  s[14] = t[6];
        s[3]  = t[7];  s[7]  = t[11]; s[11] = t[15]; s[15] = t[3];
    }

    void MixColumns(unsigned char* s) {
        for (int i = 0; i < 4; i++) {
            unsigned char a = s[4*i], b = s[4*i+1],
                          c = s[4*i+2], d = s[4*i+3];
            s[4*i]   = mul(a,2)^mul(b,3)^c^d;
            s[4*i+1] = a^mul(b,2)^mul(c,3)^d;
            s[4*i+2] = a^b^mul(c,2)^mul(d,3);
            s[4*i+3] = mul(a,3)^b^c^mul(d,2);
        }
    }

    void InvMixColumns(unsigned char* s) {
        for (int i = 0; i < 4; i++) {
            unsigned char a = s[4*i], b = s[4*i+1],
                          c = s[4*i+2], d = s[4*i+3];
            s[4*i]   = mul(a,14)^mul(b,11)^mul(c,13)^mul(d,9);
            s[4*i+1] = mul(a,9)^mul(b,14)^mul(c,11)^mul(d,13);
            s[4*i+2] = mul(a,13)^mul(b,9)^mul(c,14)^mul(d,11);
            s[4*i+3] = mul(a,11)^mul(b,13)^mul(c,9)^mul(d,14);
        }
    }
    void cipher(unsigned char* state){
        addRoundKey(state,0);
        for(int round=1;round<Nr;++round){
            SubBytes(state);
                ShiftRows(state);
                MixColumns(state);
                addRoundKey(state,round);
            }
            SubBytes(state);
            ShiftRows(state);
            addRoundKey(state,Nr);
        
        }
    void invCipher(unsigned char* state){
        addRoundKey(state,Nr);
        for(int round=Nr-1;round>0;round--){
            invShiftRows(state);
            invSubBytes(state);                addRoundKey(state,round);
            invMixColumns(state);
        }
        invShiftRows(state);
        invSubBytes(state);
        addRoundKey(state,0);
        }
        vector<unsigned char> pkcs7Pad(const vector<unsigned char>& data){
           int padLen = 16 - (data.size() % 16);
            if (padLen == 0) padLen = 16;
            vector<unsigned char> padded=data;
            for(int i=0;i<padLen;i++)padded.push_back(static_cast<unsigned char>(padLen));
            return padded;
        }
        vector<unsigned char> pkcs7Unpad(const vector<unsigned char>& data){
            if(data.size()==0)return data;
            int padLen=static_cast<int>(data.back());
            if(padLen<=0 || padLen>32)throw runtime_error("Invalid PKCS#7 padding length");
            if(data.size()<static_cast<size_t>(padLen))throw runtime_error("Invalid PKCS#7 padding (data too short)");
            for(int i=0;i<padLen;i++){
                if(data[data.size()-1-i]!=static_cast<unsigned char>(padLen))throw runtime_error("Invalid PKCS#7 padding bytes");
            }
            return vector<unsigned char>(data.begin(),data.end()-padLen);
        }
    public:
        AES(const vector<unsigned char>& key){
            if(key.size()!=32)throw runtime_error("Invalid key size");
            KeyExpansion(key.data());
        }
        vector<unsigned char> encrypt(const vector<unsigned char>& data){
            vector<unsigned char> padded=pkcs7Pad(data);
            vector<unsigned char> encrypted(padded.size());
            for(int i=0;i<padded.size();i+=16){
                for(int j=0;j<16;j++){
                    if(i+j<padded.size())encrypted[i+j]=padded[i+j];
                    else encrypted[i+j]=0;
                }
                cipher(encrypted.data()+i);
            }
            return encrypted;
        }
        vector<unsigned char> decrypt(const vector<unsigned char>& data){
            if(data.size()%16!=0)throw runtime_error("Invalid data size");
            vector<unsigned char> decrypted(data.size());
            for(int i=0;i<data.size();i+=16){
                for(int j=0;j<16;j++){
                    if(i+j<data.size())decrypted[i+j]=data[i+j];
                    else decrypted[i+j]=0;
                }
                invCipher(decrypted.data()+i);
            }
            return pkcs7Unpad(decrypted);
        }
            
};