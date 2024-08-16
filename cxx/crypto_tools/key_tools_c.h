#ifndef KEYTOOL_C_H
#define KEYTOOL_C_H

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

// Creates a new private key and returns it as a char array along with its length.
// out_len will hold the length of the returned private key.
char* CreatePrivateKey_C(size_t* out_len);

// Generates a public key from the given private key and returns it as a char array.
// private_key_org is the original private key, private_key_len is its length,
// pubkey_len will hold the length of the returned public key.
char* GetPublicKeyByPrivateKey_C(const char* private_key_org, size_t private_key_len, size_t* pubkey_len);

// Signs data using the private key and returns the signature as a char array.
// sha256_data is the data to sign, sha256_len is its length,
// pri_key_data is the private key, pri_key_len is its length,
// sign_len will hold the length of the returned signature.
char* GetSignByPrivateKey_C(const char* sha256_data, size_t sha256_len, const char* pri_key_data, size_t pri_key_len, size_t* sign_len);

// Computes ECDH key from a public and private key and returns it as a char array.
// pub_key_data is the public key, pub_key_len is its length,
// pri_key_data is the private key, pri_key_len is its length,
// ecdh_len will hold the length of the returned ECDH key.
char* GetEcdhKey_C(const char* pub_key_data, size_t pub_key_len, const char* pri_key_data, size_t pri_key_len, size_t* ecdh_len);

// Generates a new AES IV and returns it as a char array.
// iv_len will hold the length of the returned IV.
char* CreateAesIVKey_C(size_t* iv_len);

// Encrypts data using AES and returns the encrypted data as a char array.
// key_data is the encryption key, key_len is its length,
// iv_data is the initialization vector, iv_len is its length,
// in_data is the input data to encrypt, in_len is its length,
// out_size will hold the length of the encrypted data.
char* AesEncode_C(const char* key_data, size_t key_len, const char* iv_data, size_t iv_len, const char* in_data, size_t in_len, size_t* out_size);

// Decrypts AES encrypted data and returns the decrypted data as a char array.
// Parameters mirror those of AesEncode_C.
char* AesDecode_C(const char* key_data, size_t key_len, const char* iv_data, size_t iv_len, const char* in_data, size_t in_len, size_t* out_size);

// Validates a signature using the public key, returns true if valid.
bool SignIsValidate_C(const char* sha256_data, size_t sha256_len, const char* pub_key_data, size_t pub_key_size, const char* sign_data, size_t sign_len);

// Computes the SHA-256 hash of input data and returns it as a char array.
// in_data is the input data, in_len is its length,
// out_len will hold the length of the hash.
char* Sha256_C(const char* in_data, size_t in_len, size_t* out_len);

// Computes the SHA-512 hash of input data and returns it as a char array.
// Parameters mirror those of Sha256_C.
char* Sha512_C(const char* in_data, size_t in_len, size_t* out_len);

#ifdef __cplusplus
}
#endif
#endif // KEYTOOL_C_H
