#include "gtest/gtest.h"

#include "plusaes/plusaes.hpp"

namespace {

void test_encrypt_decrypt_ctr(const std::string& data, const std::vector<unsigned char> key, unsigned short nonce,
    const unsigned char* ok_encrypted) {

    plusaes::Error e;

    // enctypt
    std::vector<unsigned char> crypted(data.begin(), data.end());
    e = plusaes::crypt_ctr(&crypted[0], crypted.size(), &key[0], (int)key.size(), (unsigned char*)&nonce, sizeof(nonce));
    EXPECT_EQ(e, plusaes::kErrorOk);
    EXPECT_EQ(memcmp(&crypted[0], ok_encrypted, crypted.size()), 0);

    // decript
    e = plusaes::crypt_ctr(&crypted[0], crypted.size(), &key[0], (int)key.size(), (unsigned char*)&nonce, sizeof(nonce));
    const std::string s(crypted.begin(), crypted.end());
    EXPECT_EQ(e, plusaes::kErrorOk);
    EXPECT_EQ(s, data);
}

} // no namespace

TEST(CTR, encrypt_decript) {
    const std::string data = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const auto key = plusaes::key_from_string(&"1234567890ABCDEF");
    const unsigned short nonce = 0;

    const unsigned char ok_encrypted[] = {
        0xfb, 0x48, 0x54, 0x65, 0x23, 0x91, 0x39, 0x77, 0x1b, 0x46, 0x2c, 0x01, 0xf8, 0x7a, 0x46, 0x22,
        0x8a, 0xb6, 0x48, 0x19, 0x7d, 0xff, 0xfd, 0x1f, 0xec, 0x43
    };

    test_encrypt_decrypt_ctr(data, key, nonce, ok_encrypted);
}
