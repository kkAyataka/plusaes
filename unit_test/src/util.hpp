#ifndef PLUSAES_UNIT_TEST_UTIL_HPP__
#define PLUSAES_UNIT_TEST_UTIL_HPP__

#include <sstream>
#include <string>
#include <vector>

typedef std::vector<unsigned char> uchar_vec;

#define DATA_T(v) v
#define AADATA_T(v) v
#define KEY_T(v) v
#define IV_T(v) v
#define NONCE_T(v) v
#define OK_ENCRYPTED_T(v) v
#define OK_TAG_T(v) v

/** hex string to bytes */
inline std::vector<unsigned char> hs2b(std::string hex_string) {
    std::vector<unsigned char> bytes;

    const auto end = std::remove_if(hex_string.begin(), hex_string.end(), [](const char c) { return c == ' '; });
    hex_string.erase(end, hex_string.end());

    if (hex_string.size() % 2 == 0) {
        for (auto ite = hex_string.begin(); ite != hex_string.end(); ite += 2) {
            char hs[3] = { *ite, *(ite + 1) };
            int byte = 0;

            std::stringstream stm;
            stm << hs;
            stm >> std::hex >> byte;

            bytes.push_back(byte & 0xFF);
        }
    }
    else {
        throw std::logic_error("Invalid hex string");
    }

    return bytes;
}

#endif // PLUSAES_UNIT_TEST_UTIL_HPP__
