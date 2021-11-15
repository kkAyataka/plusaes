#include "gtest/gtest.h"

#include "plusaes/plusaes.hpp"

#include "util.hpp"

struct GcmTestParam {
    std::string desc;
    uchar_vec data;
    uchar_vec aadata;
    uchar_vec key;
    uchar_vec iv;
    uchar_vec ok_encrypted;
    uchar_vec ok_tag;
};

std::ostream& operator<<(std::ostream& stream, const GcmTestParam & p) {
    return stream << p.desc;
}

class GcmCryptTest : public testing::TestWithParam<GcmTestParam> {
};

TEST_P(GcmCryptTest, encrypt_decript) {
    auto p = GetParam();
    unsigned char tag[16] = {};

    plusaes::Error err = plusaes::kErrorOk;
    const std::vector<unsigned char> P = p.data;

    // Encrypt
    err = plusaes::encrypt_gcm(
        (p.data.empty()) ? 0 : &p.data[0], p.data.size(),
        (p.aadata.empty()) ? 0 : &p.aadata[0], p.aadata.size(),
        &p.key[0], p.key.size(),
        &p.iv[0], p.iv.size(),
        tag, 16);

    EXPECT_EQ(err, plusaes::kErrorOk);
    EXPECT_EQ(p.data.empty() ? 0 : memcmp(&p.data[0], &p.ok_encrypted[0], p.ok_encrypted.size()), 0);
    EXPECT_EQ(memcmp(tag, &p.ok_tag[0], p.ok_tag.size()), 0);

    // Decrypt
    err = plusaes::decrypt_gcm(
        (p.data.empty()) ? 0 : &p.data[0], p.data.size(),
        (p.aadata.empty()) ? 0 : &p.aadata[0], p.aadata.size(),
        &p.key[0], p.key.size(),
        &p.iv[0], p.iv.size(),
        tag, 16);

    EXPECT_EQ(err, plusaes::kErrorOk);
    EXPECT_EQ(p.data.empty() ? 0 : memcmp(&p.data[0], &P[0], p.data.size()), 0);
}

INSTANTIATE_TEST_SUITE_P(
    DocDef,
    GcmCryptTest,
    testing::Values(
        GcmTestParam{
            "Case1",
            DATA_T(hs2b("")),
            AADATA_T(hs2b("")),
            KEY_T(hs2b(
                "00000000000000000000000000000000")),
            IV_T(hs2b(
                "000000000000000000000000")),
            OK_ENCRYPTED_T(hs2b(
                "")),
            OK_TAG_T(hs2b(
                "58e2fccefa7e3061367f1d57a4e7455a"))
        },
        GcmTestParam{
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
        },
        GcmTestParam{
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
        },
        GcmTestParam{
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
        }
    ),
    testing::PrintToStringParamName()
);

INSTANTIATE_TEST_SUITE_P(
    LenCombo,
    GcmCryptTest,
    testing::Values(
        GcmTestParam{
            "k16d0iv16aad0",
            DATA_T(hs2b("")),
            AADATA_T(hs2b("")),
            KEY_T(hs2b(
                "794a26919d1bbc4fc1a4f3a2fa877011")),
            IV_T(hs2b(
                "3d16f008942554f46727ab615dc38598")),
            OK_ENCRYPTED_T(hs2b("")),
            OK_TAG_T(hs2b(
                "2b59f12a50e2168de0e4b2851f50b3c9"))
        },
        GcmTestParam{
            "k16d7iv33aad16",
            DATA_T(hs2b(
                "3459a93fb51b30")),
            AADATA_T(hs2b(
                "bcbd003a3d14f516de8c8bc9932c7889")),
            KEY_T(hs2b(
                "74c54dd499505e2bde37ef704f1f7e45")),
            IV_T(hs2b(
                "6dd3db2b9de5da3aa69c0ca403c75b94"
                "08a67ea5de25c67ba53f23f4e1359253"
                "67")),
            OK_ENCRYPTED_T(hs2b(
                "48e5e752f0b5ca")),
            OK_TAG_T(hs2b(
                "7c789ba46e8208e9d9791d29fcfc12c0"))
        },
        GcmTestParam{
            "k16d16iv12aad16",
            DATA_T(hs2b(
                "315de0d84154256d11c90a14b48f9ced")),
            AADATA_T(hs2b(
                "f3104bbf9effd79382a42a762314084c")),
            KEY_T(hs2b(
                "bbcfecfda1da5cbc0f4dba79b11b7585")),
            IV_T(hs2b(
                "9556febf6148a9ee3ca9b985")),
            OK_ENCRYPTED_T(hs2b(
                "a6fd641c1600f581f27bbdc16367506d")),
            OK_TAG_T(hs2b(
                "54b72ae3b09185c25e569f084d14b69a"))
        },
        GcmTestParam{
            "k16d17iv10aad11",
            DATA_T(hs2b(
                "a4f93362a6223301cf2a6b17e9c5c2da"
                "f3")),
            AADATA_T(hs2b(
                "e429b7a8f615fce1cd66c7")),
            KEY_T(hs2b(
                "626d2823172397ee3e681b4cecf4b8b0")),
            IV_T(hs2b(
                "762d5205b31d515ea558")),
            OK_ENCRYPTED_T(hs2b(
                "0fcd1af89f6a350b4daa3ad4dffb949a"
                "b6")),
            OK_TAG_T(hs2b(
                "f67cf5887f274009a8efe9c03779c365"))
        },
        GcmTestParam{
            "k16d17iv16aad65",
            DATA_T(hs2b(
                "3bb26b2156fb346a58ae45b1181a845d"
                "fc")),
            AADATA_T(hs2b(
                "6235319fc7ad12eafc97d9832f0edf5f"
                "ee25005628dda210d85222dd7d2bfc25"
                "f9386b9e3c237b20afa60e4985115533"
                "ffce36ac278dab5529ee7f181c09b213"
                "cb")),
            KEY_T(hs2b(
                "cf909231cb9a422dba0a685299755432")),
            IV_T(hs2b(
                "99487087298281eb878bf82de84ba26f")),
            OK_ENCRYPTED_T(hs2b(
                "05dfef4bcdf3c1fe017e7005f42c9352"
                "72")),
            OK_TAG_T(hs2b(
                "1b319f12cdef2596a6c55503cfc1a889"))
        },
        GcmTestParam{
            "k16d32iv33aad18",
            DATA_T(hs2b(
                "6ba4ec4fbc8437364f2b602fb22419ca"
                "cdfb339cbd656d1472b6b3640133d095")),
            AADATA_T(hs2b(
                "9e645fdc8435fd550d9828d77f5dfa58"
                "e968")),
            KEY_T(hs2b(
                "9308d4d198a5762f98996009e38ee578")),
            IV_T(hs2b(
                "e4f0f0ca596cec9337f4fd7bd4507c6b"
                "956c37e53473b3b6ab6454bd5c50eb37"
                "52")),
            OK_ENCRYPTED_T(hs2b(
                "ea3a851d01c2ef20b453c161a29666c1"
                "4b9ed9bf9c3e2e3b9986c1da03870500")),
            OK_TAG_T(hs2b(
                "3f82f1c7a010d4854a1f8c9180bc5fda"))
        },
        GcmTestParam{
            "k24d0iv10aad16",
            DATA_T(hs2b("")),
            AADATA_T(hs2b(
                "6168eab054e2cf24dd1fad1581845b03")),
            KEY_T(hs2b(
                "60f4f1e631f7ea60725446cba3eef42f"
                "9ec083d01fa5b30a")),
            IV_T(hs2b(
                "3b4d01ecbba0cf3a77fc")),
            OK_ENCRYPTED_T(hs2b("")),
            OK_TAG_T(hs2b(
                "0886f357fad5acdcd2717b93efcee00c"))
        },
        GcmTestParam{
            "k24d0iv12aad18",
            DATA_T(hs2b("")),
            AADATA_T(hs2b(
                "5c91a8b73624bc0fa5fc9ea4460a17fe"
                "4ae9")),
            KEY_T(hs2b(
                "8c89c71455f0c775530b815a8712e17b"
                "5969cb4e34538fb9")),
            IV_T(hs2b(
                "d06261ea4cf9a7f542cb2a1c")),
            OK_ENCRYPTED_T(hs2b("")),
            OK_TAG_T(hs2b(
                "1b2baaaee9cb855d9f22d35a8384acc7"))
        },
        GcmTestParam{
            "k24d0iv33aad11",
            DATA_T(hs2b("")),
            AADATA_T(hs2b(
                "7b18e4e9023c8066f26642")),
            KEY_T(hs2b(
                "9d7fc43b10322221dcbf72609573e212"
                "b4e5495987038baf")),
            IV_T(hs2b(
                "507b818aace926b643ac8715b0df3649"
                "2569078698d4d157d0ca8297c8142766"
                "a1")),
            OK_ENCRYPTED_T(hs2b("")),
            OK_TAG_T(hs2b(
                "54dad874625afb9e3f575a914730763d"))
        },
        GcmTestParam{
            "k24d7iv10aad0",
            DATA_T(hs2b(
                "9bfda82c728385")),
            AADATA_T(hs2b("")),
            KEY_T(hs2b(
                "de685d5c3299d5cd8a8ceac8773ae74e"
                "aac75ff960936008")),
            IV_T(hs2b(
                "1179f47cfe301aff3afb")),
            OK_ENCRYPTED_T(hs2b(
                "29af06288965a2")),
            OK_TAG_T(hs2b(
                "e6d3eac7bc9199957d561e0d6f748c88"))
        },
        GcmTestParam{
            "k24d7iv12aad65",
            DATA_T(hs2b(
                "705c7987a15e7e")),
            AADATA_T(hs2b(
                "dd587b4dd99310d6d3fea314452bf6a8"
                "6d8e6fb069d42682527cb3684d39d45a"
                "68c2f8b66f46e61c47ed97d1ea0d8736"
                "cec4a9b17af8f912b57d156853e61070"
                "37")),
            KEY_T(hs2b(
                "0ffce3d222855b3186503b4e152c7ccd"
                "fd827bc0a1407bcd")),
            IV_T(hs2b(
                "64bd69c9dd8c98ea1efebd6f")),
            OK_ENCRYPTED_T(hs2b(
                "0ae564a577a3d8")),
            OK_TAG_T(hs2b(
                "5ede3e0a808586f7c2a137a38917b9d5"))
        },
        GcmTestParam{
            "k24d7iv16aad11",
            DATA_T(hs2b(
                "9e364f05e802bb")),
            AADATA_T(hs2b(
                "1b9f656181e911d0893ef9")),
            KEY_T(hs2b(
                "8657ac9a960fab3aaf21b6f3baa0cee8"
                "6272e5395f86a14c")),
            IV_T(hs2b(
                "25ef6be31e241a8e57eedd6d84c07d12")),
            OK_ENCRYPTED_T(hs2b(
                "68ea75387f0412")),
            OK_TAG_T(hs2b(
                "c164672923302bad8b8f5ff5eab82ec1"))
        },
        GcmTestParam{
            "k24d16iv10aad65",
            DATA_T(hs2b(
                "4adc49c25e816681d7d78cef669aa8f5")),
            AADATA_T(hs2b(
                "b02dd6b55ce94dc93fdd775c7d86a27b"
                "f91e35292aa536fff9836854a5b402bb"
                "f98aedc1712d2e597bbcde0f10291217"
                "4ed0304813d152e5958b028b9c5da579"
                "c0")),
            KEY_T(hs2b(
                "35592d7060ea9f7943c6773d0d9311e8"
                "fce7585bbfd1a40d")),
            IV_T(hs2b(
                "9bef4e908bf0aef9d855")),
            OK_ENCRYPTED_T(hs2b(
                "863550b7427dcd5eff3e8bd4327acf9d")),
            OK_TAG_T(hs2b(
                "2c043c23afc7c69174b2e91ded975d7b"))
        },
        GcmTestParam{
            "k24d16iv16aad18",
            DATA_T(hs2b(
                "4703ee7d56654e93200164bbd36b6d0d")),
            AADATA_T(hs2b(
                "19d094e85a157e902e7bfd22b63dc277"
                "3b28")),
            KEY_T(hs2b(
                "b1b46d435499b91f3c16ae96ab891968"
                "7807abc14991bbaa")),
            IV_T(hs2b(
                "420b1b92662b70af4569f992f5ac223b")),
            OK_ENCRYPTED_T(hs2b(
                "e587332b6d9cb7f65e4556d2d6ff6a71")),
            OK_TAG_T(hs2b(
                "996786d391cfc1763e5c32b0f8c1fe38"))
        },
        GcmTestParam{
            "k24d16iv33aad0",
            DATA_T(hs2b(
                "809fe0ff16ad989956750741fb3c9d53")),
            AADATA_T(hs2b("")),
            KEY_T(hs2b(
                "6b980ca11b9e8f0ffe890534a40d96a6"
                "16e70ad2097938d5")),
            IV_T(hs2b(
                "7ae8a764e40508db870519f8f33a8977"
                "5dfa59f9c037f43f16ab11c51c394439"
                "22")),
            OK_ENCRYPTED_T(hs2b(
                "81902cbae28004e77e56d05ea8f9127a")),
            OK_TAG_T(hs2b(
                "06a5cf6f0843d87c42b337fc5599ea7b"))
        },
        GcmTestParam{
            "k24d17iv12aad16",
            DATA_T(hs2b(
                "7fd84ad0e85a1a1c21bcae28b1b8b7ef"
                "4d")),
            AADATA_T(hs2b(
                "702e595f1d26b83840fc4761eabe8742")),
            KEY_T(hs2b(
                "7760254452829ed86df5dbd2ffc5a56d"
                "711d0dad9d253552")),
            IV_T(hs2b(
                "aa3ca6df3d0b8ebc142aba24")),
            OK_ENCRYPTED_T(hs2b(
                "e7aeca51e83a46c51a91a0fec2aff411"
                "d7")),
            OK_TAG_T(hs2b(
                "01ae70706c733a8555b6da99190ef01c"))
        },
        GcmTestParam{
            "k24d17iv16aad18",
            DATA_T(hs2b(
                "102e12afaca774dd0071b9f206d869e9"
                "6b")),
            AADATA_T(hs2b(
                "b97e8955386847f299505a6496c0ae7b"
                "7e68")),
            KEY_T(hs2b(
                "ee26e686bc675e2929dc847d98edc110"
                "886a96eb37912046")),
            IV_T(hs2b(
                "032021302cf49be2e7cb0949296a4e25")),
            OK_ENCRYPTED_T(hs2b(
                "a15b100aa65d227cd55893f532e1d77e"
                "04")),
            OK_TAG_T(hs2b(
                "0484cc785199858e1db93c13bde93238"))
        },
        GcmTestParam{
            "k24d32iv10aad11",
            DATA_T(hs2b(
                "ede4b04d79bd671674b505b910129166"
                "8ae57ea52e09d8fc83d86bd0b8f66d13")),
            AADATA_T(hs2b(
                "86e2b9fa33cec59d7f7413")),
            KEY_T(hs2b(
                "551e81463728c759f9f7cb3a0f74a14b"
                "438276f5cbde4a15")),
            IV_T(hs2b(
                "9139b8263f7a304483fa")),
            OK_ENCRYPTED_T(hs2b(
                "2775d42df3b1b6cef4d9036892c007fc"
                "b35621d3ad7e4ac25247248cd95a3572")),
            OK_TAG_T(hs2b(
                "0f0b3c1b00d8aaf1f76480dbd2a59372"))
        },
        GcmTestParam{
            "k24d32iv12aad0",
            DATA_T(hs2b(
                "72f3bff273bf59b96f7eaa882ca5c816"
                "77faa6d88b5f81296213a65454bd705e")),
            AADATA_T(hs2b("")),
            KEY_T(hs2b(
                "759e2b8df14704b5ab3d2a558f959aec"
                "be3b8c8c7dd5cb59")),
            IV_T(hs2b(
                "b3bfea3f439785c8e65260e7")),
            OK_ENCRYPTED_T(hs2b(
                "8effacae1370a5f0c763b3fd2f7c7d4c"
                "b4680ffac01524177b52896014aa1cbb")),
            OK_TAG_T(hs2b(
                "7ac0f98534c8afb92a2f98180bf66597"))
        },
        GcmTestParam{
            "k32d0iv12aad65",
            DATA_T(hs2b("")),
            AADATA_T(hs2b(
                "03a6b0d2973ae7f6863592821241280d"
                "827e2565338f9b3856f070d32ef354db"
                "965cb3b28be97a0f444a376d11215a80"
                "ada5edad157ae878931c2666de53727c"
                "0a")),
            KEY_T(hs2b(
                "5c77b5b59e641162ddc9705ce0715924"
                "6b28919c5fe027fc99d186d3aa248aea")),
            IV_T(hs2b(
                "29ce13cd688c282f23df1d7b")),
            OK_ENCRYPTED_T(hs2b("")),
            OK_TAG_T(hs2b(
                "adfbeaf877fb13f00d41bead5423dd03"))
        },
        GcmTestParam{
            "k32d7iv10aad18",
            DATA_T(hs2b(
                "e79b4af7976531")),
            AADATA_T(hs2b(
                "c4caf24190fa20ed0093f22040d904b9"
                "5c9d")),
            KEY_T(hs2b(
                "9244d95081624de9b16cb0d9163bf5ab"
                "dc578dc63b6ecd54e89a075555e31c31")),
            IV_T(hs2b(
                "577c1c204f0a116eaa0c")),
            OK_ENCRYPTED_T(hs2b(
                "ba3fab0fdded51")),
            OK_TAG_T(hs2b(
                "c917e3d32c36e23f8b4f33200a868599"))
        },
        GcmTestParam{
            "k32d16iv12aad11",
            DATA_T(hs2b(
                "16ee82682068343a6d6309d3c55dc2e6")),
            AADATA_T(hs2b(
                "cd3580eaa15c2ce353c74e")),
            KEY_T(hs2b(
                "dee146363ecc04f5af0c0a79cb70b991"
                "379d4e1f658e26d041f34a67322db315")),
            IV_T(hs2b(
                "1237618d0882b3ce141b774b")),
            OK_ENCRYPTED_T(hs2b(
                "ec68bffcd69a005fef9426c8615d2fcc")),
            OK_TAG_T(hs2b(
                "6dd8cc86df717444f3043438778eea7e"))
        },
        GcmTestParam{
            "k32d17iv33aad0",
            DATA_T(hs2b(
                "d7b17105f31e51f388b586ccda6ddf68"
                "2b")),
            AADATA_T(hs2b("")),
            KEY_T(hs2b(
                "39f71c43295623807a46e6124dbca428"
                "7028513c649fde8794d3779c4c8400a1")),
            IV_T(hs2b(
                "d6381604b0d11810ef0e7da48ed0e806"
                "ec27d67153f9b14347b8c547a825d4b4"
                "4a")),
            OK_ENCRYPTED_T(hs2b(
                "261a9806b5cb584099fa71eaa5984b08"
                "83")),
            OK_TAG_T(hs2b(
                "2f4c1f269e8d84f919ec1610ffbdad4f"))
        },
        GcmTestParam{
            "k32d32iv16aad16",
            DATA_T(hs2b(
                "a6b9a2b6a8ac93807341a3dd2c32d84c"
                "42264663b33160f6cbc64219c89564a5")),
            AADATA_T(hs2b(
                "77162335fa648b1c6069149ceea70118")),
            KEY_T(hs2b(
                "fd3a3b8b032578eee7017c2b974744cb"
                "6d7643919886b5ee733358ca7e1e70f8")),
            IV_T(hs2b(
                "5df9d3d34dac1166dc186702a9730942")),
            OK_ENCRYPTED_T(hs2b(
                "2b55a8208a8a26a697c79f5f2a92a5c8"
                "7fbdd138aff75783324897da7b743ce3")),
            OK_TAG_T(hs2b(
                "96f5ec7fdf5b07bd1992a67f07ee290f"))
        },
        GcmTestParam{
            "k32d32iv33aad65",
            DATA_T(hs2b(
                "e5f8d69dfc5c4a3528a0586be4e865d6"
                "0f7cbeb30bb2323fb984fd995213cee8")),
            AADATA_T(hs2b(
                "869d73840e708145536e773fff21b09a"
                "601f436a07970626bc146aa2f7f13e14"
                "8b3277d32c2b4510ab3ab7355aff2a03"
                "649e4d02755663453df228f2e3a4bd32"
                "d3")),
            KEY_T(hs2b(
                "02fc5b6394f1b24c73cc3da6d4453659"
                "fc4150eaa1918716078ce15cc3fbd19f")),
            IV_T(hs2b(
                "4483eac0f25a07379f258e1296d089f0"
                "3d5a82825ccf80e76646164498624581"
                "9b")),
            OK_ENCRYPTED_T(hs2b(
                "a087aae7b4fd98129d01ce568a615ad7"
                "a4a1efcaabb9380cb371112f7f9ccf67")),
            OK_TAG_T(hs2b(
                "3992de4884d5d2d4824681e59091b9fe"))
        },
        GcmTestParam{
            "SmallTag",
            DATA_T(hs2b(
                "e5f8d69dfc5c4a3528a0586be4e865d6"
                "0f7cbeb30bb2323fb984fd995213cee8")),
            AADATA_T(hs2b(
                "869d73840e708145536e773fff21b09a"
                "601f436a07970626bc146aa2f7f13e14"
                "8b3277d32c2b4510ab3ab7355aff2a03"
                "649e4d02755663453df228f2e3a4bd32"
                "d3")),
            KEY_T(hs2b(
                "02fc5b6394f1b24c73cc3da6d4453659"
                "fc4150eaa1918716078ce15cc3fbd19f")),
            IV_T(hs2b(
                "4483eac0f25a07379f258e1296d089f0"
                "3d5a82825ccf80e76646164498624581"
                "9b")),
            OK_ENCRYPTED_T(hs2b(
                "a087aae7b4fd98129d01ce568a615ad7"
                "a4a1efcaabb9380cb371112f7f9ccf67")),
            OK_TAG_T(hs2b(
                "3992de4884d5d2d4824681e590"))
        }
    ),
    testing::PrintToStringParamName()
);


//------------------------------------------------------------------------------
// Fixed iv and tag size API
//------------------------------------------------------------------------------

class GcmFixedCryptTest : public testing::TestWithParam<GcmTestParam> {
};

TEST_P(GcmFixedCryptTest, encrypt_decript) {
    auto p = GetParam();
    unsigned char iv[12] = {};
    memcpy(iv, &p.iv[0], 12);
    unsigned char tag[16] = {};

    plusaes::Error err = plusaes::kErrorOk;
    const std::vector<unsigned char> P = p.data;

    // Encrypt
    err = plusaes::encrypt_gcm(
        (p.data.empty()) ? 0 : &p.data[0], p.data.size(),
        (p.aadata.empty()) ? 0 : &p.aadata[0], p.aadata.size(),
        &p.key[0], p.key.size(),
        &iv,
        &tag);

    EXPECT_EQ(err, plusaes::kErrorOk);
    EXPECT_EQ(p.data.empty() ? 0 : memcmp(&p.data[0], &p.ok_encrypted[0], p.ok_encrypted.size()), 0);
    EXPECT_EQ(memcmp(tag, &p.ok_tag[0], p.ok_tag.size()), 0);

    // Decrypt
    err = plusaes::decrypt_gcm(
        (p.data.empty()) ? 0 : &p.data[0], p.data.size(),
        (p.aadata.empty()) ? 0 : &p.aadata[0], p.aadata.size(),
        &p.key[0], p.key.size(),
        &iv,
        &tag);

    EXPECT_EQ(err, plusaes::kErrorOk);
    EXPECT_EQ(p.data.empty() ? 0 : memcmp(&p.data[0], &P[0], p.data.size()), 0);
}

INSTANTIATE_TEST_SUITE_P(
    FixedSizeIvTag,
    GcmFixedCryptTest,
    testing::Values(
        GcmTestParam{
            "P1",
            DATA_T(hs2b(
                "7aaaeeca0c61b8b4f217095d974b4c1d")),
            AADATA_T(hs2b(
                "e778698186a6f2c955fdcf6e4febd5aa")),
            KEY_T(hs2b(
                "292e34e3d951bb876a3b06c58df76797")),
            IV_T(hs2b(
                "eb66e10e80d82014ba9cb67a")),
            OK_ENCRYPTED_T(hs2b(
                "8646ceb5537e35b9598902684ee348d9")),
            OK_TAG_T(hs2b(
                "9dd18f9ba63097f2c9defa9b7f7c6ec4"))
        },
        GcmTestParam{
            "P2",
            DATA_T(hs2b("")),
            AADATA_T(hs2b(
                "2434da4edb6bef539f51515876f7e5f0"
                "a026")),
            KEY_T(hs2b(
                "3b789cea1f537cb053e3da2eb334ab8e"
                "f982f560e880d126")),
            IV_T(hs2b(
                "37dea97f367c71bf5fb067a2")),
            OK_ENCRYPTED_T(hs2b("")),
            OK_TAG_T(hs2b(
                "7b03a7fc1855881987128ffa3d105ecb"))
        },
        GcmTestParam{
            "P3",
            DATA_T(hs2b(
                "c9195de652b930")),
            AADATA_T(hs2b(
                "5c6f0be07df4b73a2166c5167f2a0552"
                "bf61d928155a7546585f1a98419e37ae"
                "b6c9a8100fcd62decf3a990095d7c34d"
                "9fed136b876fe0a3ae4960b974394e3c"
                "85")),
            KEY_T(hs2b(
                "d48145afc036de912b1418137c0f2fd5"
                "c4e782281ef81a93")),
            IV_T(hs2b(
                "d7e3a954d8edf82e16a12e80")),
            OK_ENCRYPTED_T(hs2b(
                "0d251613cd2463")),
            OK_TAG_T(hs2b(
                "837376209d5fdb7a2504042a354a38e0"))
        }
    ),
    testing::PrintToStringParamName()
);


//------------------------------------------------------------------------------
// Invalid parameter size
//------------------------------------------------------------------------------

class GcmInvalidSizeTestParam {
public:
    std::size_t key_size;
    std::size_t iv_size;
    std::size_t tag_size;
    plusaes::Error ok_error;
};

class GcmInvalidSizeTest : public testing::TestWithParam<GcmInvalidSizeTestParam> {
};

TEST_P(GcmInvalidSizeTest, invalid_size) {
    const auto p = GetParam();

    auto data = hs2b("00000000000000000000000000000000");
    const auto key = hs2b("00000000000000000000000000000000");
    const auto iv = hs2b("000000000000000000000000");
    unsigned char tag[16] = {};

    const auto ctag = hs2b("ab6e47d42cec13bdf53a67b21257bddf");
    const auto encrypted = hs2b("0388dace60b6a392f328c2b971b2fe78");

    // encrypt
    const auto e1 = plusaes::encrypt_gcm(&data[0], data.size(), 0, 0,
                                         &key[0], p.key_size, &iv[0], p.iv_size, tag, p.tag_size);
    EXPECT_EQ(e1, p.ok_error);

    // decrypt
    const auto e2 = plusaes::decrypt_gcm(&data[0], data.size(), 0, 0,
                                         &key[0], p.key_size, &iv[0], p.iv_size, tag, p.tag_size);

    EXPECT_EQ(e2, p.ok_error);
}

INSTANTIATE_TEST_SUITE_P(
    InvalidSize,
    GcmInvalidSizeTest,
    testing::Values(
        GcmInvalidSizeTestParam{0, 12, 16, plusaes::kErrorInvalidKeySize},
        GcmInvalidSizeTestParam{16, 0, 16, plusaes::kErrorInvalidIvSize},
        GcmInvalidSizeTestParam{16, 1, 16, plusaes::kErrorOk},
        GcmInvalidSizeTestParam{16, 2, 16, plusaes::kErrorOk},
        GcmInvalidSizeTestParam{16, 12, 0, plusaes::kErrorInvalidTagSize},
        GcmInvalidSizeTestParam{16, 12, 1, plusaes::kErrorInvalidTagSize},
        GcmInvalidSizeTestParam{16, 12, 2, plusaes::kErrorInvalidTagSize},
        GcmInvalidSizeTestParam{16, 12, 3, plusaes::kErrorInvalidTagSize},
        GcmInvalidSizeTestParam{16, 12, 4, plusaes::kErrorOk},
        GcmInvalidSizeTestParam{16, 12, 5, plusaes::kErrorInvalidTagSize},
        GcmInvalidSizeTestParam{16, 12, 6, plusaes::kErrorInvalidTagSize},
        GcmInvalidSizeTestParam{16, 12, 7, plusaes::kErrorInvalidTagSize},
        GcmInvalidSizeTestParam{16, 12, 8, plusaes::kErrorOk},
        GcmInvalidSizeTestParam{16, 12, 9, plusaes::kErrorInvalidTagSize},
        GcmInvalidSizeTestParam{16, 12, 10, plusaes::kErrorInvalidTagSize},
        GcmInvalidSizeTestParam{16, 12, 11, plusaes::kErrorInvalidTagSize},
        GcmInvalidSizeTestParam{16, 12, 12, plusaes::kErrorOk},
        GcmInvalidSizeTestParam{16, 12, 13, plusaes::kErrorOk},
        GcmInvalidSizeTestParam{16, 12, 14, plusaes::kErrorOk},
        GcmInvalidSizeTestParam{16, 12, 15, plusaes::kErrorOk},
        GcmInvalidSizeTestParam{16, 12, 16, plusaes::kErrorOk},
        GcmInvalidSizeTestParam{16, 12, 17, plusaes::kErrorInvalidTagSize},
        GcmInvalidSizeTestParam{16, 12, 18, plusaes::kErrorInvalidTagSize}
    )
);


//------------------------------------------------------------------------------
// Invalid parameter tag
//------------------------------------------------------------------------------

TEST(GcmInvalidTag, invalid_tag) {
    auto data = hs2b("00000000000000000000000000000000");
    const auto key = hs2b("00000000000000000000000000000000");
    unsigned char iv[12] = {};
    memcpy(iv, &hs2b("000000000000000000000000")[0], 12);
    unsigned char tag[16] = {};

    // encrypt
    const auto e1 = plusaes::encrypt_gcm(&data[0], data.size(), 0, 0,
                                         &key[0], key.size(), &iv, &tag);
    EXPECT_EQ(e1, plusaes::kErrorOk);

    // decrypt
    tag[0] += 1;
    const auto e2 = plusaes::decrypt_gcm(&data[0], data.size(), 0, 0,
                                         &key[0], key.size(), &iv, &tag);
    EXPECT_EQ(e2, plusaes::kErrorInvalidTag);
}
