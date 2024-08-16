#ifndef __SIMPLE_PACKAGE__HPP__
#define __SIMPLE_PACKAGE__HPP__

#include <boost/format.hpp>
#include <iostream>
#include "../crypto_tools/key_tools.h"
#include "../crypto_tools/string_tools.h"

// Structure to hold a decoded WebSocket package
struct DecodedWebsocketPackage {
    std::string from_pubkey;  // Public key of the sender
    std::string payload;      // Decrypted payload data
};

// Encodes a package for sending over WebSocket, encrypting the payload
std::string inline EncodePackage(
    const std::string& from_pubkey,   // Public key of the sender
    const std::string& payload,       // Original payload to encrypt
    const std::string& ecdh_key       // ECDH key used for AES encryption
) {
    std::string iv = CreateAesIVKey();  // Generate a random AES initialization vector
    if (ecdh_key.empty() || iv.empty()) {
        return "";  // Return empty if no ECDH key or IV could be generated
    }
    std::string out;
    // Encrypt the payload using the ECDH key and IV
    if (AesEncode(ecdh_key, iv, payload, out)) {
        return from_pubkey + iv + out;  // Concatenate and return the public key, IV, and encrypted data
    }
    return "";  // Return empty if encryption fails
}

// Decodes an incoming package from WebSocket, decrypting the payload
bool inline DecodePackage(
    const std::string& in,            // Input encrypted string
    DecodedWebsocketPackage& out,     // Output structure to hold the decoded data
    const std::string& ecdh_key       // ECDH key for AES decryption
) {
    // Check if the input string has enough data to include a public key and IV
    if (in.size() < PUB_KEY_SIZE + AES_IV_SIZE) {
        return false;  // Return false if the data is too short
    }

    // Extract the public key and IV from the input
    std::string from_pubkey = std::string(in, 0, PUB_KEY_SIZE);
    std::string iv = std::string(in, PUB_KEY_SIZE, AES_IV_SIZE);

    // Decrypt the remaining data using the extracted IV and ECDH key
    if (!AesDecode(ecdh_key, iv, in.data() + PUB_KEY_SIZE + AES_IV_SIZE, 
                   in.size() - (PUB_KEY_SIZE + AES_IV_SIZE), out.payload)) {
        return false;  // Return false if decryption fails
    }

    out.from_pubkey = from_pubkey;  // Set the sender's public key in the output structure
    return true;  // Return true if decryption is successful
}

#endif // __SIMPLE_PACKAGE__HPP__
