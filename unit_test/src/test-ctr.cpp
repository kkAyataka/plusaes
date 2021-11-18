#include "gtest/gtest.h"

#include "plusaes/plusaes.hpp"

#include "util.hpp"


struct CtrTestParam {
    std::string desc;
    uchar_vec data;
    uchar_vec key;
    uchar_vec nonce;
    uchar_vec ok_encrypted;
};

class CtrTest : public testing::TestWithParam<CtrTestParam> {
};

std::ostream& operator<<(std::ostream& stream, const CtrTestParam & p) {
    return stream << p.desc;
}

TEST_P(CtrTest, encrypt_decrypt) {
    auto p = GetParam();

    plusaes::Error e = plusaes::kErrorOk;
    const std::vector<unsigned char> P = p.data;
    unsigned char nonce[16] = {};
    memcpy(nonce, &p.nonce[0], p.nonce.size());

    // Encrypt
    e = plusaes::crypt_ctr(&p.data[0], p.data.size(), &p.key[0], (int)p.key.size(), &nonce);
    EXPECT_EQ(e, plusaes::kErrorOk);
    EXPECT_EQ(memcmp(&p.data[0], &p.ok_encrypted[0], p.data.size()), 0);

    // Decrypt
    e = plusaes::crypt_ctr(&p.data[0], p.data.size(), &p.key[0], (int)p.key.size(), &nonce);
    EXPECT_EQ(e, plusaes::kErrorOk);
    EXPECT_EQ(memcmp(&p.data[0], &P[0], p.data.size()), 0);
}

INSTANTIATE_TEST_SUITE_P(
    Ctr,
    CtrTest,
    testing::Values(
        CtrTestParam{
            "d24k16n16",
            DATA_T(hs2b(
                "4DCE3E2CD316107063587765D287F5D4433639F1FADE5FF3")),
            KEY_T(hs2b(
                "569131417A30BE7488B3E0C371EDCA75")),
            NONCE_T(hs2b(
                "644AABFFEDE69C7CE1633F4DAACE2412")),
            OK_ENCRYPTED_T(hs2b(
                "FFC42C1D623210AAEFC0B70EE580CA1B2DF012DD375C0CA5")),
        },
        CtrTestParam{
            "d5k32n8",
            DATA_T(hs2b(
                "1EEA1D0FE6")),
            KEY_T(hs2b(
                "8B1EE32EF529749D5D13FD04D0462A444BBCFEA35774B342A5970A5E86FD28EF")),
            NONCE_T(hs2b(
                "36536A69AF7659DD0000000000000000")),
            OK_ENCRYPTED_T(hs2b(
                "52A9E8D953")),
        },
        CtrTestParam{
            "d16k24n0",
            DATA_T(hs2b(
                "6BDD3407E09281927F3BB61B7E181CE8")),
            KEY_T(hs2b(
                "E1518E89EB578933BB21554CC6CDCCBB77DE9BB828EF77A2")),
            NONCE_T(hs2b(
                "00000000000000000000000000000000")),
            OK_ENCRYPTED_T(hs2b(
                "6F1A63A7D8B15AC905EAF3C9593EB440")),
        },
        CtrTestParam{
            "d33k24n8",
            DATA_T(hs2b(
                "FCB7696F37EAA8D9A8E4968C0E45F0042346E9C486ADF52B317CD6047A8DC0A3D7")),
            KEY_T(hs2b(
                "E147CB7AFB8B39ADAAC36452804B994F6A6BC3BA772B1024")),
            NONCE_T(hs2b(
                "4A507F726D7C183C0000000000000000")),
            OK_ENCRYPTED_T(hs2b(
                "32FA31F2399C14DB0E284BFCB44520158C0A8586BD2F7765E24A86A722510105C1")),
        },
        CtrTestParam{
            "d24k24n8",
            DATA_T(hs2b(
                "F2692384FED0D9F8E57E579A1E6318605A1B66A9531AEA2B")),
            KEY_T(hs2b(
                "494BA1E45E81A26625FA2DAE4D6E5CAC54AC3076F6D77251")),
            NONCE_T(hs2b(
                "DE0A32BCE7D1742B0000000000000000")),
            OK_ENCRYPTED_T(hs2b(
                "A5B94E482E71ACC131DBE5D26909DB1B791891F380B3FBD0")),
        },
        CtrTestParam{
            "d16k32n16",
            DATA_T(hs2b(
                "BE7740912FD45B56B382B44EEF233550")),
            KEY_T(hs2b(
                "A145F4B0A9602B25721A68AE4D12B04CB10D99E560E4027A1FD5C67574B4BCC9")),
            NONCE_T(hs2b(
                "8831305317ECA8446CFA1F0C0F03C048")),
            OK_ENCRYPTED_T(hs2b(
                "B7B58F972D87978550C99B5EBE73E112")),
        },
        CtrTestParam{
            "d16k16n8",
            DATA_T(hs2b(
                "EE8D092F78F841F21603C09BDA01B972")),
            KEY_T(hs2b(
                "22EF973B64A04602C763BFBAB82E855D")),
            NONCE_T(hs2b(
                "531E59EE35DB38F30000000000000000")),
            OK_ENCRYPTED_T(hs2b(
                "B5C4102AD41A7F6C602EB7442E01289D")),
        },
        CtrTestParam{
            "d5k16n0",
            DATA_T(hs2b(
                "E6306A6935")),
            KEY_T(hs2b(
                "16F35E8CE6747F9D746A5D34A6C32215")),
            NONCE_T(hs2b(
                "00000000000000000000000000000000")),
            OK_ENCRYPTED_T(hs2b(
                "3FC82A4917")),
        },
        CtrTestParam{
            "d33k32n0",
            DATA_T(hs2b(
                "11B271DD416790BFD1C1D09F174231E753D1A8764B22EF7B840BF2F94DF6F53AB0")),
            KEY_T(hs2b(
                "C39C9BAD49C97FDF61A74339DF866FE78CA74BD4F3677FEC3040CDAA1BCA53F7")),
            NONCE_T(hs2b(
                "00000000000000000000000000000000")),
            OK_ENCRYPTED_T(hs2b(
                "F516250E75F1CE0D3E76467C9D18CBD835DB22145E44541D45D532E7A8B2C07C02")),
        },
        CtrTestParam{
            "d5k24n16",
            DATA_T(hs2b(
                "D93D37BA02")),
            KEY_T(hs2b(
                "0CA56E572DEE7182F83CDAF210D41D83D254884CC0D5C909")),
            NONCE_T(hs2b(
                "C543FB18D12C13EB0782B4B71F6DDAE0")),
            OK_ENCRYPTED_T(hs2b(
                "1E4C8F08CD")),
        },
        CtrTestParam{
            "d24k32n0",
            DATA_T(hs2b(
                "2AB5A01288CBDB374EB04B5E4600F241C1F44203B1EE933B")),
            KEY_T(hs2b(
                "799628BCAC9C8D9B3EBD244E8560A0404671457425CE634ABED4A4DC91DD4164")),
            NONCE_T(hs2b(
                "00000000000000000000000000000000")),
            OK_ENCRYPTED_T(hs2b(
                "27542AC24690694021B647B44EC3718A67F65E74E0D96A1B")),
        },
        CtrTestParam{
            "d33k16n16",
            DATA_T(hs2b(
                "D94E2DB7FBCCDF4B29121D851F68F40539949B5E9C2E31AD13225131B4C45EAC4E")),
            KEY_T(hs2b(
                "0B3C0F0464C7973AB887B94D656938FF")),
            NONCE_T(hs2b(
                "B32CA2364A33B9C8F4CB768CB72F0F30")),
            OK_ENCRYPTED_T(hs2b(
                "A903940E679A234B2BDD0316BC4548E5649A9472411C5F75D42654FC71CE1667C1")),
        }
    ),
    testing::PrintToStringParamName()
);

//------------------------------------------------------------------------------
// Invalid parameter size
//------------------------------------------------------------------------------

class CtrInvalidSizeTestParam {
public:
    std::size_t key_size;
    plusaes::Error ok_error;
};

class CtrInvalidSizeTest : public testing::TestWithParam<CtrInvalidSizeTestParam> {
};

TEST_P(CtrInvalidSizeTest, invalid_size) {
    const auto p = GetParam();

    auto data = hs2b("00000000000000000000000000000000");
    const auto key = hs2b("00000000000000000000000000000000");
    const unsigned char nonce[16] = {};

    // encrypt
    const auto e1 = plusaes::crypt_ctr(&data[0], data.size(), &key[0], p.key_size, &nonce);
    EXPECT_EQ(e1, p.ok_error);

    // decrypt
    const auto e2 = plusaes::crypt_ctr(&data[0], data.size(), &key[0], p.key_size, &nonce);
    EXPECT_EQ(e2, p.ok_error);
}

INSTANTIATE_TEST_SUITE_P(
    InvalidSize,
    CtrInvalidSizeTest,
    testing::Values(
        CtrInvalidSizeTestParam{0, plusaes::kErrorInvalidKeySize},
        CtrInvalidSizeTestParam{15, plusaes::kErrorInvalidKeySize},
        CtrInvalidSizeTestParam{16, plusaes::kErrorOk},
        CtrInvalidSizeTestParam{17, plusaes::kErrorInvalidKeySize},
        CtrInvalidSizeTestParam{23, plusaes::kErrorInvalidKeySize},
        CtrInvalidSizeTestParam{24, plusaes::kErrorOk},
        CtrInvalidSizeTestParam{25, plusaes::kErrorInvalidKeySize},
        CtrInvalidSizeTestParam{31, plusaes::kErrorInvalidKeySize},
        CtrInvalidSizeTestParam{32, plusaes::kErrorOk},
        CtrInvalidSizeTestParam{33, plusaes::kErrorInvalidKeySize}
    )
);
