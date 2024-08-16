#ifndef __SIMPLE_KEY__H__
#define __SIMPLE_KEY__H__

#include <memory>
#include <boost/unordered_map.hpp>
#include "../crypto_tools/string_tools.h"
#include "../crypto_tools/key_tools.h"

// Retrieves the stored public key.
// The public key is returned as a binary string converted from a hexadecimal representation.
std::string GetStorePublicKey() {
    // Hard-coded public key in hexadecimal format is converted to binary format.
    // This public key is typically used for cryptographic operations, such as signature verification or encryption.
    return HexAsc2ByteString("040f3a12626327a5698c5e533c6a63f15aa07588b4081c325a4cc9c4710c81ce06f9fc321884be3961b839202bc01a9be3d1bdacc9788d4d0769261e0d21cc5c2c");
}

// Retrieves the stored private key.
// The private key is returned as a binary string converted from a hexadecimal representation.
std::string GetStorePrivateKey() {
    // Hard-coded private key in hexadecimal format is converted to binary format.
    // This private key is crucial for cryptographic operations such as signing data or decrypting messages
    // that were encrypted with the corresponding public key.
    return HexAsc2ByteString("e249423fb865e4f3d74caaba2c72bf81d80dae6892a3197ed0c71c98ee43205b");
}

#endif // __SIMPLE_KEY__H__
