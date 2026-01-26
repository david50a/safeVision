#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <cmath>

using namespace std;

class GCM{
    private:
        unsigned char cipher[128];
        unsigned char decrypted[128];
        inline vector<uint8_t> pad(vector<uint8_t> data) {
            data.insert(data.end(), (16 - data.size() % 16) % 16, 0);
            return data;
        };
        inline vector<uint8_t> xor_bytes(vector<uint8_t> a, vector<uint8_t> b) {return vector<uint8_t>(a.begin(), a.end()) ^ vector<uint8_t>(b.begin(), b.end());}
        
};