#ifndef KEYTOOL_H
#define KEYTOOL_H

#include <string>
#include <array>

// Constants defining the sizes for various cryptographic parameters.
extern const uint32_t PRI_KEY_SIZE;  // Size of the private key in bytes.
extern const uint32_t PUB_KEY_SIZE;  // Size of the public key in bytes.

extern const uint32_t AES_IV_SIZE;   // Size of the AES initialization vector.
extern const uint32_t AES_KEY_SIZE;  // Size of the AES key for 256-bit encryption.

extern const uint32_t HASH_SIZE;     // Standard size of hash outputs (e.g., SHA-256).
extern const uint32_t SIGN_SIZE;     // Size of digital signatures.

// Generates a cryptographically secure random string of a specified length.
std::string CreateCustomRandom(int len);

// Functions for wallet key management
// Generates a secure private key using cryptographic random functions.
std::string CreatePrivateKey();
// Derives the public key from a given private key using ECC (Elliptic Curve Cryptography).
std::string GetPublicKeyByPrivateKey(const std::string private_key_org);
// Derives the compressed public key from a given private key.
std::string GetCompressedPublicKeyByPrivateKey(const std::string private_key_org);

// Signs a buffer using a private key and returns the signature.
std::string GetSignByPrivateKey(const uint8_t* buf, size_t length, const std::string pri_key);
// Overload of GetSignByPrivateKey to directly take a string as input.
std::string GetSignByPrivateKey(const std::string buf, const std::string pri_key);

// Generates an ECDH (Elliptic Curve Diffie-Hellman) shared secret using a public and a private key.
std::string GetEcdhKey(const std::string& pub_key, const std::string& pri_key);
// Creates a random AES Initialization Vector (IV) for use in encryption.
std::string CreateAesIVKey();

// Encrypts a string using AES-256-CBC encryption with the specified key and IV.
bool AesEncode(const std::string& key, const std::string& iv, const std::string& in, std::string& out);
// Decrypts AES-encrypted data with the given key and IV.
bool AesDecode(const std::string& key, const std::string& iv, const std::string& in, std::string& out);
// Overload of AesDecode for decryption directly from a character array.
bool AesDecode(const std::string &key, const std::string &iv, const char* in, uint32_t in_len, std::string &out);

// Validates a digital signature against a public key and a hashed buffer.
bool SignIsValidate(const uint8_t* buf, size_t length, const std::string& pub_key, const std::string& sign);

// Computes the SHA-256 hash of the input data.
std::string Sha256(const std::string& in);
// Computes the SHA-512 hash of the input data.
std::string Sha512(const std::string& in);

#endif // KEYTOOL_H
