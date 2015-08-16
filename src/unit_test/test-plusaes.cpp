#include "gtest/gtest.h"
#include "plusaes/plusaes.hpp"

TEST(AES, encrypt128) {
    const unsigned char data[] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
    const int data_size = sizeof(data);
    const unsigned char key[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};

    unsigned char encrypted[data_size] = {};
    plusaes::encrypt(data, sizeof(data), key, sizeof(key), plusaes::MODE_ECB, encrypted);

    unsigned char decrypted[data_size] = {};
    plusaes::decrypt(encrypted, sizeof(encrypted), key, sizeof(key), plusaes::MODE_ECB, decrypted);

    ASSERT_NE(memcmp(encrypted, decrypted, data_size), 0);
    ASSERT_EQ(memcmp(data, decrypted, data_size), 0);
}
