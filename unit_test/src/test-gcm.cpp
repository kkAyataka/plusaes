#include "gtest/gtest.h"

#include "plusaes/plusaes.hpp"

TEST(GCM, encrypt_decript_0) {
    const std::vector<unsigned char> raw_data(16);
    const std::vector<unsigned char> aadata(0);
    const std::vector<unsigned char> key(16);
    const unsigned char iv[12] = {};
    std::vector<unsigned char> encrypted(raw_data.size());
    unsigned char tag[16] = {};

    plusaes::encrypt_gcm(
        (unsigned char*)raw_data.data(), raw_data.size(),
        0, 0,
        &key[0], key.size(), &iv,
        &encrypted[0], &tag);

    const unsigned char ok_encrypted[] = {
        0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78
    };

    const unsigned char ok_tag[] = {
        0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd, 0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd, 0xdf
    };

    EXPECT_EQ(memcmp(&encrypted[0], ok_encrypted, sizeof(ok_encrypted)), 0);
    EXPECT_EQ(memcmp(tag, ok_tag, sizeof(ok_tag)), 0);
}

TEST(GCM, encrypt_decript_1) {
    const std::string raw_data = "Hello, plusaes";
    const std::vector<unsigned char> aadata(0);
    const std::vector<unsigned char> key = plusaes::key_from_string(&"EncryptionKey128");
    const unsigned char iv[12] = {};
    std::vector<unsigned char> encrypted(raw_data.size());
    unsigned char tag[16] = {};

    plusaes::encrypt_gcm(
        (unsigned char*)raw_data.data(), raw_data.size(),
        0, 0,
        &key[0], key.size(), &iv,
        &encrypted[0], &tag);

    const unsigned char ok_encrypted[] = {
        0x7A, 0x5F, 0x32, 0xD3, 0x5F, 0x6A, 0x7D, 0x18, 0xEE, 0x22, 0x61, 0xB6, 0x2B, 0x1B
    };

    const unsigned char ok_tag[] = {
        0xB4, 0xFA, 0x52, 0xD7, 0x19, 0x24, 0x1, 0xFC, 0x6, 0xB4, 0x27, 0xF3, 0x1E, 0xBE, 0x5, 0xCD,
    };

    EXPECT_EQ(memcmp(&encrypted[0], ok_encrypted, sizeof(ok_encrypted)), 0);
    EXPECT_EQ(memcmp(tag, ok_tag, sizeof(ok_tag)), 0);
}
