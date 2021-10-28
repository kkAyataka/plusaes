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
    auto p = GetParam();

    plusaes::Error err = plusaes::kErrorOk;
    const std::vector<unsigned char> plain = p.data;
    unsigned char iv[12] = {};
    memcpy(iv, &p.iv[0], sizeof(iv));
    unsigned char tag[16] = {};

    // Encrypt
    err = plusaes::encrypt_gcm(
        &p.data[0], p.data.size(),
        (p.aadata.empty()) ? 0 : &p.aadata[0], p.aadata.size(),
        &p.key[0], p.key.size(), &iv,
        &tag);

    EXPECT_EQ(err, plusaes::kErrorOk);
    EXPECT_EQ(memcmp(&p.data[0], &p.ok_encrypted[0], p.ok_encrypted.size()), 0);
    EXPECT_EQ(memcmp(tag, &p.ok_tag[0], p.ok_tag.size()), 0);

    // Decrypt
    err = plusaes::decrypt_gcm(
        &p.data[0], p.data.size(),
        (p.aadata.empty()) ? 0 : &p.aadata[0], p.aadata.size(),
        &p.key[0], p.key.size(), iv, 12,
        tag, 16);

    EXPECT_EQ(err, plusaes::kErrorOk);
    EXPECT_EQ(memcmp(&p.data[0], &plain[0], p.data.size()), 0);
}

INSTANTIATE_TEST_SUITE_P(Zero, GcmTest,
    testing::Values(
        // data:16, aad:0, key:16, iv:12
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


//------------------------------------------------------------------------------
// Crypt GCM
//------------------------------------------------------------------------------

class GcmCryptTest : public testing::TestWithParam<GcmTestParam> {
};

TEST_P(GcmCryptTest, crypt) {
    auto p = GetParam();
    unsigned char tag[16] = {};

    plusaes::Error err = plusaes::kErrorOk;
    const std::vector<unsigned char> P = p.data;

    // Encrypt
    err = plusaes::encrypt_gcm(
        &p.data[0], p.data.size(),
        (p.aadata.empty()) ? 0 : &p.aadata[0], p.aadata.size(),
        &p.key[0], p.key.size(),
        &p.iv[0], p.iv.size(),
        tag, 16);

    EXPECT_EQ(err, plusaes::kErrorOk);
    EXPECT_EQ(memcmp(&p.data[0], &p.ok_encrypted[0], p.ok_encrypted.size()), 0);
    EXPECT_EQ(memcmp(tag, &p.ok_tag[0], p.ok_tag.size()), 0);

    // Decrypt
    err = plusaes::decrypt_gcm(
        &p.data[0], p.data.size(),
        (p.aadata.empty()) ? 0 : &p.aadata[0], p.aadata.size(),
        &p.key[0], p.key.size(),
        &p.iv[0], p.iv.size(),
        tag, 16);

    EXPECT_EQ(err, plusaes::kErrorOk);
    EXPECT_EQ(memcmp(&p.data[0], &P[0], p.data.size()), 0);
}

INSTANTIATE_TEST_SUITE_P(Crypt, GcmCryptTest,
    testing::Values(
        GcmTestParam(
            "Case3",
            DATA_T(hs2b(
                "d9313225f88406e5a55909c5aff5269a"
                "86a7a9531534f7da2e4c303d8a318a72"
                "1c3c0c95956809532fcf0e2449a6b525"
                "b16aedf5aa0de657ba637b391aafd255")),
            AADATA_T(uchar_vec(0)),
            KEY_T(hs2b(
                "feffe9928665731c6d6a8f9467308308")),
            IV_T(hs2b(
                "cafebabefacedbaddecaf888")),
            OK_ENCRYPTED_T(hs2b(
                "42831ec2217774244b7221b784d0d49c"
                "e3aa212f2c02a4e035c17e2329aca12e"
                "21d514b25466931c7d8f6a5aac84aa05"
                "1ba30b396a0aac973d58e091473f5985")),
            OK_TAG_T(hs2b(
                "4d5c2af327cd64a62cf35abd2ba6fab4"))
        ),
        GcmTestParam(
            "Case5",
            DATA_T(hs2b(
                "d9313225f88406e5a55909c5aff5269a"
                "86a7a9531534f7da2e4c303d8a318a72"
                "1c3c0c95956809532fcf0e2449a6b525"
                "b16aedf5aa0de657ba637b39")),
            AADATA_T(hs2b(
                "feedfacedeadbeeffeedfacedeadbeef"
                "abaddad2")),
            KEY_T(hs2b(
                "feffe9928665731c6d6a8f9467308308")),
            IV_T(hs2b(
                "cafebabefacedbad")),
            OK_ENCRYPTED_T(hs2b(
                "61353b4c2806934a777ff51fa22a4755"
                "699b2a714fcdc6f83766e5f97b6c7423"
                "73806900e49f24b22b097544d4896b42"
                "4989b5e1ebac0f07c23f4598")),
            OK_TAG_T(hs2b(
                "3612d2e79e3b0785561be14aaca2fccb"))
        ),
        GcmTestParam(
            "Case6",
            DATA_T(hs2b(
                "d9313225f88406e5a55909c5aff5269a"
                "86a7a9531534f7da2e4c303d8a318a72"
                "1c3c0c95956809532fcf0e2449a6b525"
                "b16aedf5aa0de657ba637b39")),
            AADATA_T(hs2b(
                "feedfacedeadbeeffeedfacedeadbeef"
                "abaddad2")),
            KEY_T(hs2b(
                "feffe9928665731c6d6a8f9467308308")),
            IV_T(hs2b(
                "9313225df88406e555909c5aff5269aa"
                "6a7a9538534f7da1e4c303d2a318a728"
                "c3c0c95156809539fcf0e2429a6b5254"
                "16aedbf5a0de6a57a637b39b")),
            OK_ENCRYPTED_T(hs2b(
                "8ce24998625615b603a033aca13fb894"
                "be9112a5c3a211a8ba262a3cca7e2ca7"
                "01e4a9a4fba43c90ccdcb281d48c7c6f"
                "d62875d2aca417034c34aee5")),
            OK_TAG_T(hs2b(
                "619cc5aefffe0bfa462af43c1699d050"))
        )
    ),
    testing::PrintToStringParamName());
