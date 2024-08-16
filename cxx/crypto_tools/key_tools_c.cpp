#ifndef __SIMPLE_KEY__H__
#define __SIMPLE_KEY__H__

#include "key_tools_c.h"
#include "key_tools.h"

// Creates a new private key and returns it as a char array along with its length
char* CreatePrivateKey_C(size_t* out_len) {
    std::string rtn = CreatePrivateKey();  // Generate private key
    char* rtn_p = (char*)malloc(rtn.size());  // Allocate memory for return
    memcpy(rtn_p, rtn.data(), rtn.size());  // Copy the key into the allocated space
    *out_len = rtn.size();  // Set the output length
    return rtn_p;
}

// Generates a public key from the given private key and returns it as a char array
char* GetPublicKeyByPrivateKey_C(const char* private_key_org, size_t private_key_len, size_t* pubkey_len) {
    std::string rtn = GetPublicKeyByPrivateKey(std::string(private_key_org, private_key_len));  // Generate public key
    char* rtn_p = (char*)malloc(rtn.size());  // Allocate memory for the return value
    memcpy(rtn_p, rtn.data(), rtn.size());  // Copy the key data
    *pubkey_len = rtn.size();  // Set the length of the public key
    return rtn_p;
}

// Signs data using the private key and returns the signature as a char array
char* GetSignByPrivateKey_C(const char* sha256_data, size_t sha256_len, const char* pri_key_data, size_t pri_key_len, size_t* sign_len) {
    std::string sha256 = std::string(sha256_data, sha256_len);
    std::string private_key = std::string(pri_key_data, pri_key_len);
    std::string rtn = GetSignByPrivateKey((uint8_t*)sha256.data(), sha256_len, private_key);
    char* rtn_p = (char*)malloc(rtn.size());
    memcpy(rtn_p, rtn.data(), rtn.size());
    *sign_len = rtn.size();
    return rtn_p;
}

// Computes ECDH key from a public and private key and returns it as a char array
char* GetEcdhKey_C(const char* pub_key_data, size_t pub_key_len, const char* pri_key_data, size_t pri_key_len, size_t* ecdh_len) {
    std::string pub_key = std::string(pub_key_data, pub_key_len);
    std::string pri_key = std::string(pri_key_data, pri_key_len);
    std::string rtn = GetEcdhKey(pub_key, pri_key);
    char* rtn_p = (char*)malloc(rtn.size());
    memcpy(rtn_p, rtn.data(), rtn.size());
    *ecdh_len = rtn.size();
    return rtn_p;
}

// Generates a new AES IV and returns it as a char array
char* CreateAesIVKey_C(size_t* iv_len) {
    std::string rtn = CreateAesIVKey();
    char* rtn_p = (char*)malloc(rtn.size());
    memcpy(rtn_p, rtn.data(), rtn.size());
    *iv_len = rtn.size();
    return rtn_p;
}

// Encrypts data using AES and returns the encrypted data as a char array
char* AesEncode_C(const char* key_data, size_t key_len, const char* iv_data, size_t iv_len, const char* in_data, size_t in_len, size_t* out_size) {
    std::string key(key_data, key_len);
    std::string iv(iv_data, iv_len);
    std::string in = std::string(in_data, in_len);
    std::string rtn;
    if (!AesEncode(key, iv, in, rtn, false)) {
        return nullptr;  // Return null if encryption fails
    }
    char* rtn_p = (char*)malloc(rtn.size());
    memcpy(rtn_p, rtn.data(), rtn.size());
    *out_size = rtn.size();
    return rtn_p;
}

// Decrypts AES encrypted data and returns the decrypted data as a char array
char* AesDecode_C(const char* key_data, size_t key_len, const char* iv_data, size_t iv_len, const char* in_data, size_t in_len, size_t* out_size) {
    std::string key(key_data, key_len);
    std::string iv(iv_data, iv_len);
    std::string in = std::string(in_data, in_len);
    std::string rtn;
    if (!AesDecode(key, iv, in, rtn, false)) {
        return nullptr;  // Return null if decryption fails
    }
    char* rtn_p = (char*)malloc(rtn.size());
    memcpy(rtn_p, rtn.data(), rtn.size());
    *out_size = rtn.size();
    return rtn_p;
}

// Validates a signature using the public key, returns true if valid
bool SignIsValidate_C(const char* sha256_data, size_t sha256_len, const char* pub_key_data, size_t pub_key_size, const char* sign_data, size_t sign_len) {
    std::string pub_key = std::string(pub_key_data, pub_key_size);
    std::string sign = std::string(sign_data, sign_len);
    return SignIsValidate((uint8_t*)sha256_data, sha256_len, pub_key, sign);
}

// Computes the SHA-256 hash of input data and returns it as a char array
char* Sha256_C(const char* in_data, size_t in_len, size_t* out_len) {
    std::string in = std::string(in_data, in_len);
    std::string rtn = Sha256(in);
    char* rtn_p = (char*)malloc(rtn.size());
    memcpy(rtn_p, rtn.data(), rtn.size());
    *out_len = rtn.size();
    return rtn_p;
}

// Computes the SHA-512 hash of input data and returns it as a char array
char* Sha512_C(const char* in_data, size_t in_len, size_t* out_len) {
    std::string in = std::string(in_data, in_len);
    std::string rtn = Sha512(in);
    char* rtn_p = (char*)malloc(rtn.size());
    memcpy(rtn_p, rtn.data(), rtn.size());
    *out_len = rtn.size();
    return rtn_p;
}

#endif // __SIMPLE_KEY__H__
