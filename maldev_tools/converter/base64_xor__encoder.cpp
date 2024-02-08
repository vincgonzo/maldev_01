#include <iostream>
#include <vector>
#include <string>
#include <algorithm>

std::vector<uint8_t> xor_encrypt(const std::vector<uint8_t>& shell, const std::vector<uint8_t>& keyBytes) {
    std::vector<uint8_t> encrypted(shell.size());

    for (size_t i = 0; i < shell.size(); ++i) {
        encrypted[i] = shell[i] ^ keyBytes[i % keyBytes.size()];
    }

    return encrypted;
}

int main() {
    // XOR Key - It has to be the same in the Dropper for Decrypting
    std::string key = "HereisAXorKey!";

    // Convert Key into bytes
    std::vector<uint8_t> keyBytes(key.begin(), key.end());

    // Original Shellcode here (C++ format)
    std::vector<uint8_t> buf = { // [shellcode] 
    };

    // XORing byte by byte and saving into a new vector of bytes
    std::vector<uint8_t> encoded = xor_encrypt(buf, keyBytes);

    // Convert the encoded vector to a Base64 string
    std::string base64Encoded(encoded.begin(), encoded.end());
    std::cout << base64Encoded << std::endl;

    return 0;
}