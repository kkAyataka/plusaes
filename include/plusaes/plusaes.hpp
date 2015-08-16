// Copyright (C) 2015 kkAyataka
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef PLUSAES_HPP__
#define PLUSAES_HPP__

#include <stdexcept>
#include <vector>

namespace plusaes {
namespace detail {

const int kWordSize = 4;
typedef unsigned int Word;

const int kBlockSize = 4;
typedef Word State[kBlockSize];
typedef Word RoundKey[kBlockSize];
typedef std::vector<RoundKey> RoundKeys;

inline void add_round_key(const RoundKey &key, State &state) {
    for (int i = 0; i < kBlockSize; ++i) {
        state[i] ^= key[i];
    }
}

const unsigned char kSbox[] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

const unsigned char kInvSbox[] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

inline Word sub_word(const Word w) {
    return kSbox[(w >>  0) & 0xFF] <<  0 |
           kSbox[(w >>  8) & 0xFF] <<  8 |
           kSbox[(w >> 16) & 0xFF] << 16 |
           kSbox[(w >> 24) & 0xFF] << 24;
}

inline Word inv_sub_word(const Word w) {
    return kInvSbox[(w >>  0) & 0xFF] <<  0 |
           kInvSbox[(w >>  8) & 0xFF] <<  8 |
           kInvSbox[(w >> 16) & 0xFF] << 16 |
           kInvSbox[(w >> 24) & 0xFF] << 24;
}

inline void sub_bytes(State &state) {
    for (int i = 0; i < kBlockSize; ++i) {
        state[i] = sub_word(state[i]);
    }
}

inline void inv_sub_bytes(State &state) {
    for (int i = 0; i < kBlockSize; ++i) {
        state[i] = inv_sub_word(state[i]);
    }
}

inline void shift_rows(State &state) {
    const State ori = { state[0], state[1], state[2], state[3] };
    for (int r = 1; r < kWordSize; ++r) {
        const Word m2 = 0xFF << (r * 8);
        const Word m1 = ~m2;
        for (int c = 0; c < kBlockSize; ++c) {
            state[c] = (state[c] & m1) | (ori[(c + r) % kBlockSize] & m2);
        }
    }
}

inline void inv_shift_rows(State &state) {
    const State ori = { state[0], state[1], state[2], state[3] };
    for (int r = 1; r < kWordSize; ++r) {
        const Word m2 = 0xFF << (r * 8);
        const Word m1 = ~m2;
        for (int c = 0; c < kBlockSize; ++c) {
            state[c] = (state[c] & m1) | (ori[(c + kBlockSize - r) % kWordSize] & m2);
        }
    }
}

inline unsigned char mul2(const unsigned char b) {
    unsigned char m2 = b << 1;
    if (b & 0x80) {
        m2 ^= 0x011B;
    }

    return m2;
}

inline unsigned char mul(const unsigned char b, const unsigned char m) {
    unsigned char v = 0;
    unsigned char t = b;
    for (int i = 0; i < 8; ++i) { // 8-bits
        if ((m >> i) & 0x01) {
            v ^= t;
        }

        t = mul2(t);
    }

    return v;
}

inline void mix_columns(State &state) {
    for (int i = 0; i < kBlockSize; ++i) {
        const unsigned char v0_1 = (state[i] >>  0) & 0xFF;
        const unsigned char v1_1 = (state[i] >>  8) & 0xFF;
        const unsigned char v2_1 = (state[i] >> 16) & 0xFF;
        const unsigned char v3_1 = (state[i] >> 24) & 0xFF;

        const unsigned char v0_2 = mul2(v0_1);
        const unsigned char v1_2 = mul2(v1_1);
        const unsigned char v2_2 = mul2(v2_1);
        const unsigned char v3_2 = mul2(v3_1);

        const unsigned char v0_3 = v0_2 ^ v0_1;
        const unsigned char v1_3 = v1_2 ^ v1_1;
        const unsigned char v2_3 = v2_2 ^ v2_1;
        const unsigned char v3_3 = v3_2 ^ v3_1;

        state[i] =
            (v0_2 ^ v1_3 ^ v2_1 ^ v3_1) <<  0 |
            (v0_1 ^ v1_2 ^ v2_3 ^ v3_1) <<  8 |
            (v0_1 ^ v1_1 ^ v2_2 ^ v3_3) << 16 |
            (v0_3 ^ v1_1 ^ v2_1 ^ v3_2) << 24;
    }
}

inline void inv_mix_columns(State &state) {
    for (int i = 0; i < kBlockSize; ++i) {
        const unsigned char v0 = (state[i] >>  0) & 0xFF;
        const unsigned char v1 = (state[i] >>  8) & 0xFF;
        const unsigned char v2 = (state[i] >> 16) & 0xFF;
        const unsigned char v3 = (state[i] >> 24) & 0xFF;

        state[i] =
            (mul(v0, 0x0E) ^ mul(v1, 0x0B) ^ mul(v2, 0x0D) ^ mul(v3, 0x09)) <<  0 |
            (mul(v0, 0x09) ^ mul(v1, 0x0E) ^ mul(v2, 0x0B) ^ mul(v3, 0x0D)) <<  8 |
            (mul(v0, 0x0D) ^ mul(v1, 0x09) ^ mul(v2, 0x0E) ^ mul(v3, 0x0B)) << 16 |
            (mul(v0, 0x0B) ^ mul(v1, 0x0D) ^ mul(v2, 0x09) ^ mul(v3, 0x0E)) << 24;
            
    }
}

inline Word rot_word(const Word v) {
    return ((v >> 8) & 0x00FFFFFF) | ((v & 0xFF) << 24);
}

inline unsigned int get_round_count(const int key_size) {
    switch (key_size) {
    case 16:
        return 10;
    case 24:
        return 12;
    case 32:
        return 14;
    default:
        throw std::invalid_argument("Invalid key size");
    }
}

inline RoundKeys expand_key(const unsigned char *key, const int key_size) {
    if (key_size != 16 && key_size != 24 && key_size != 32) {
        throw std::invalid_argument("Invalid key size");
    }

    const Word rcon[] = {
        0x00, 0x01, 0x02, 0x04, 0x08, 0x10,
        0x20, 0x40, 0x80, 0x1b, 0x36
    };

    const int nb = kBlockSize;
    const int nk = key_size / nb;
    const int nr = get_round_count(key_size);

    std::vector<Word> w(nb * (nr + 1));
    for (int i = 0; i < nk; ++ i) {
        memcpy(&w[i], key + (i * kWordSize), kWordSize);
    }

    for (int i = nk; i < nb * (nr + 1); ++i) {
        Word t = w[i - 1];
        if (i % nk == 0) {
            auto x0 = rot_word(t);
            auto x = sub_word(rot_word(t));
            t = sub_word(rot_word(t)) ^ rcon[i / nk];
        }
        else if (nk > 6 && i % nk == 4) {
            t = sub_word(t);
        }

        w[i] = t ^ w[i - nk];
    }

    RoundKeys keys(nr + 1);
    memcpy(&keys[0], &w[0], w.size() * kWordSize);

    return keys;
}

inline void copy_bytes_to_state(const unsigned char data[16], State &state) {
    memcpy(&state[0], data +  0, kWordSize);
    memcpy(&state[1], data +  4, kWordSize);
    memcpy(&state[2], data +  8, kWordSize);
    memcpy(&state[3], data + 12, kWordSize);
}

inline void copy_state_to_bytes(const State &state, unsigned char buf[16]) {
    memcpy(buf +  0, &state[0], kWordSize);
    memcpy(buf +  4, &state[1], kWordSize);
    memcpy(buf +  8, &state[2], kWordSize);
    memcpy(buf + 12, &state[3], kWordSize);
}

inline void encrypt16(const RoundKeys &rkeys, const unsigned char data[16], unsigned char encrypted[16]) {
    State s;
    copy_bytes_to_state(data, s);

    add_round_key(rkeys[0], s);

    for (unsigned int i = 1; i < rkeys.size() - 1; ++i) {
        sub_bytes(s);
        shift_rows(s);
        mix_columns(s);
        add_round_key(rkeys[i], s);
    }

    sub_bytes(s);
    shift_rows(s);
    add_round_key(rkeys.back(), s);

    copy_state_to_bytes(s, encrypted);
}

inline void decrypt16(const RoundKeys &rkeys, const unsigned char data[16], unsigned char decrypted[16]) {
    State s;
    copy_bytes_to_state(data, s);

    add_round_key(rkeys.back(), s);
    inv_shift_rows(s);
    inv_sub_bytes(s);

    for (std::size_t i = rkeys.size() - 2; i > 0; --i) {
        add_round_key(rkeys[i], s);
        inv_mix_columns(s);
        inv_shift_rows(s);
        inv_sub_bytes(s);
    }

    add_round_key(rkeys[0], s);

    copy_state_to_bytes(s, decrypted);
}


} // namespace detail

typedef enum {
    MODE_ECB,
    MODE_CBC
} OperationMode;

inline void encrypt(
    const unsigned char* data,
    const unsigned long data_size,
    const unsigned char* key,
    const unsigned int key_size,
    const OperationMode mode,
    unsigned char *encrypted
    ) {

    const detail::RoundKeys rkeys = detail::expand_key(key, key_size);

    if (mode == MODE_ECB) {
        const int state_size = (4 * detail::kBlockSize);
        const int bc = data_size / state_size;
        for (int i = 0; i < bc; ++i) {
            detail::encrypt16(rkeys, data + (i * bc), encrypted + (i * bc));
        }

        const int rem = data_size % state_size;
        if (rem != 0) {
            std::vector<unsigned char> ib(state_size), outb(state_size);
            memcpy(&ib[0], data + data_size - rem, rem);

            detail::encrypt16(rkeys, &ib[0], &outb[0]);
            memcpy(encrypted + (data_size - rem), &outb[0], rem);
        }
    }
}

inline void decrypt(
    const unsigned char* data,
    const unsigned long data_size,
    const unsigned char* key,
    const unsigned int key_size,
    const OperationMode mode,
    unsigned char *decrypted
    ) {

    const detail::RoundKeys rkeys = detail::expand_key(key, key_size);

    if (mode == MODE_ECB) {
        const int state_size = (4 * detail::kBlockSize);
        const int rem = data_size % state_size;

        const int bc = data_size / state_size;
        for (int i = 0; i < bc; ++i) {
            detail::decrypt16(rkeys, data + (i * bc), decrypted + (i * bc));
        }

        
        if (rem != 0) {
            std::vector<unsigned char> ib(state_size), outb(state_size);
            memcpy(&ib[0], data + data_size - rem, rem);

            detail::decrypt16(rkeys, &ib[0], &outb[0]);
            memcpy(decrypted + (data_size - rem), &outb[0], rem);
        }
    }
}

} // namespace plusaes

#endif // PLUSAES_HPP__
