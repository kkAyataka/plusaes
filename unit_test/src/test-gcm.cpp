#include "gtest/gtest.h"

#include "plusaes/plusaes.hpp"

#include "util.hpp"

typedef std::vector<unsigned char> uchar_vec;
#define DATA_T(v) v
#define AADATA_T(v) v
#define KEY_T(v) v
#define IV_T(v) v
#define OK_ENCRYPTED_T(v) v
#define OK_TAG_T(v) v

struct GcmTestParam {
    std::string desc;
    uchar_vec data;
    uchar_vec aadata;
    uchar_vec key;
    uchar_vec iv;
    uchar_vec ok_encrypted;
    uchar_vec ok_tag;

    GcmTestParam(
        const std::string & desc,
        const uchar_vec & data,
        const uchar_vec & aadata,
        const uchar_vec & key,
        const uchar_vec & iv,
        const uchar_vec & ok_encrypted,
        const uchar_vec & ok_tag
    ) : desc(desc),
        data(data),
        aadata(aadata),
        key(key),
        iv(iv),
        ok_encrypted(ok_encrypted),
        ok_tag(ok_tag) {
    }

    GcmTestParam(
        const std::string & desc,
        const std::string & data,
        const uchar_vec & aadata,
        const std::string & key,
        const uchar_vec & iv,
        const uchar_vec & ok_encrypted,
        const uchar_vec & ok_tag
    ) : desc(desc),
        data(data.begin(), data.end()),
        aadata(aadata),
        key(key.begin(), key.end()),
        iv(iv),
        ok_encrypted(ok_encrypted),
        ok_tag(ok_tag) {
    }
};

std::ostream& operator<<(std::ostream& stream, const GcmTestParam & p) {
    return stream << p.desc;
}

class GcmTest : public testing::TestWithParam<GcmTestParam> {
};

TEST_P(GcmTest, encrypt_decript) {
    const auto p = GetParam();

    std::vector<unsigned char> encrypted(p.data.size());
    unsigned char tag[16] = {};

    // Encrypt
    plusaes::encrypt_gcm(
        &p.data[0], p.data.size(),
        (p.aadata.empty()) ? 0 : &p.aadata[0], p.aadata.size(),
        &p.key[0], p.key.size(), &p.iv[0], p.iv.size(),
        &encrypted[0], &tag);

    EXPECT_EQ(memcmp(&encrypted[0], &p.ok_encrypted[0], p.ok_encrypted.size()), 0);
    EXPECT_EQ(memcmp(tag, &p.ok_tag[0], p.ok_tag.size()), 0);
    
    // Decrypt
    std::vector<unsigned char> decrypted(encrypted.size());
    plusaes::decrypt_gcm(
        &encrypted[0], encrypted.size(),
        (p.aadata.empty()) ? 0 : &p.aadata[0], p.aadata.size(),
        &p.key[0], p.key.size(), &p.iv[0], p.iv.size(),
        &decrypted[0], &tag);

    EXPECT_EQ(memcmp(&decrypted[0], p.data.data(), decrypted.size()), 0);
}

INSTANTIATE_TEST_SUITE_P(Zero, GcmTest,
    testing::Values(
        GcmTestParam(
            "Zero16Bytes",
            DATA_T(uchar_vec(16)),
            AADATA_T(uchar_vec(0)),
            KEY_T(uchar_vec(16)),
            IV_T(uchar_vec(12)),
            OK_ENCRYPTED_T(hs2b("0388dace60b6a392f328c2b971b2fe78")),
            OK_TAG_T(hs2b("ab6e47d42cec13bdf53a67b21257bddf"))
        ),
        GcmTestParam(
            "LessThan16",
            DATA_T("Hello, plusaes"),
            AADATA_T(uchar_vec(0)),
            KEY_T("EncryptionKey128"),
            IV_T(uchar_vec(12)),
            OK_ENCRYPTED_T(hs2b("7A5F32D35F6A7D18EE2261B62B1B")),
            OK_TAG_T(hs2b("B4FA52D7192401FC06B427F31EBE05CD"))
        ),
        GcmTestParam(
            "Data16Aadata0Iv12",
            DATA_T(hs2b(
                "d9313225f88406e5a55909c5aff5269a"
                "86a7a9531534f7da2e4c303d8a318a72"
                "1c3c0c95956809532fcf0e2449a6b525"
                "b16aedf5aa0de657ba637b391aafd255")),
            AADATA_T(uchar_vec(0)),
            KEY_T(hs2b("feffe9928665731c6d6a8f9467308308")),
            IV_T(hs2b("cafebabefacedbaddecaf888")),
            OK_ENCRYPTED_T(hs2b(
                "42831ec2217774244b7221b784d0d49c"
                "e3aa212f2c02a4e035c17e2329aca12e"
                "21d514b25466931c7d8f6a5aac84aa05"
                "1ba30b396a0aac973d58e091473f5985")),
            OK_TAG_T(hs2b("4d5c2af327cd64a62cf35abd2ba6fab4"))
        )
    ),
    testing::PrintToStringParamName());
