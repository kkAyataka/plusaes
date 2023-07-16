plusaes
=======

Header only C++ AES cipher library.

- [GitHub Repository](https://github.com/kkAyataka/plusaes)
- [API Reference](https://kkayataka.github.io/plusaes/doc/namespaceplusaes.html)


## Development Environment

- Visual Studio 16 2022 (v143)
- Xcode 14.3 (Apple clang 14.0.3)
- GCC 4.8.5 (CentOS 7)


## Supported block cipher mode

- ECB
- CBC
- GCM
- CTR


## Usage

For example, about AES-CBC 128-bit.
Encrypts by the `plusaes::encrypt_cbc` and decripts by the `plusaes::decrypt_cbc`.

You can use convenient functions like `plusaes::key_from_string` and `plusaes::get_padded_encrypted_size`.

```cpp
#include "plusaes/plusaes.hpp"

#include <string>
#include <vector>

int main() {
    // AES-CBC 128-bit

    // parameters
    const std::string raw_data = "Hello, plusaes";
    const std::vector<unsigned char> key = plusaes::key_from_string(&"EncryptionKey128"); // 16-char = 128-bit
    const unsigned char iv[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    };

    // encrypt
    const unsigned long encrypted_size = plusaes::get_padded_encrypted_size(raw_data.size());
    std::vector<unsigned char> encrypted(encrypted_size);

    plusaes::encrypt_cbc((unsigned char*)raw_data.data(), raw_data.size(), &key[0], key.size(), &iv, &encrypted[0], encrypted.size(), true);
    // fb 7b ae 95 d5 0f c5 6f 43 7d 14 6b 6a 29 15 70

    // decrypt
    unsigned long padded_size = 0;
    std::vector<unsigned char> decrypted(encrypted_size);

    plusaes::decrypt_cbc(&encrypted[0], encrypted.size(), &key[0], key.size(), &iv, &decrypted[0], decrypted.size(), &padded_size);
    // Hello, plusaes
}
```


License
-------
[Boost Software License](LICENSE_1_0.txt)
