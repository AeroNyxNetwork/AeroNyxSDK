#include "key_tools.h"
#include <stdint.h>
#include <string>
#include <assert.h>
#include <string.h>
#include <random>
#include "secp256k1/secp256k1.h"
#include "secp256k1/secp256k1_ecdh.h"
#include "aes/aes.h"
#include "hash/sha256.h"
#include "hash/sha512.h"
#include "string_tools.h"

// Constant sizes for cryptographic operations
const uint32_t PRI_KEY_SIZE = 32; // Size of the private key in bytes
const uint32_t PUB_KEY_SIZE = PRI_KEY_SIZE*2+1; // Size of the uncompressed public key in bytes
const uint32_t COMPRESSED_PUBKEY_SIZE = 33; // Size of the compressed public key in bytes
const uint32_t AES_IV_SIZE = AES_BLOCKSIZE; // Size of the AES initialization vector
const uint32_t AES_KEY_SIZE = AES256_KEYSIZE; // Size of the AES key for 256-bit encryption
const uint32_t HASH_SIZE = 32; // Size of the hash output (SHA-256)
const uint32_t SIGN_SIZE = 64; // Size of the ECDSA signature

// Generates a random string of a specified length for cryptographic use
std::string CreateCustomRandom(int len){
    std::string rtn((size_t)(len+4), '\0');
    std::random_device rd;
    for(int i = 0; i < len; i += 4){
        if(i < len){
            *(uint32_t*)(rtn.data()+i) = rd();
        }
    }
    rtn.resize(len);
    return rtn;
}

// Creates a private key using secure random number generation
std::string CreatePrivateKey(){
    return CreateCustomRandom(PRI_KEY_SIZE);
}

// Derives a public key from a given private key using the secp256k1 ECDSA algorithm
std::string GetPublicKeyByPrivateKey(const std::string private_key){
    std::string rtn;
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY|SECP256K1_CONTEXT_SIGN);
    assert(ctx != nullptr);
    secp256k1_pubkey pubkey;
    bool ret = secp256k1_ec_pubkey_create(ctx, &pubkey, (uint8_t*)private_key.data());
    assert(ret);
    rtn.resize(PUB_KEY_SIZE, 0);
    size_t clen = PUB_KEY_SIZE;
    secp256k1_ec_pubkey_serialize(ctx, (uint8_t*)rtn.data(), &clen, &pubkey,  SECP256K1_EC_UNCOMPRESSED);
    if (ctx) {
        secp256k1_context_destroy(ctx);
    }
    return rtn;
}

// Similar to the above but returns a compressed public key
std::string GetCompressedPublicKeyByPrivateKey(const std::string private_key){
    std::string rtn;
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY|SECP256K1_CONTEXT_SIGN);
    assert(ctx != nullptr);
    secp256k1_pubkey pubkey;
    bool ret = secp256k1_ec_pubkey_create(ctx, &pubkey, (uint8_t*)private_key.data());
    assert(ret);
    rtn.resize(COMPRESSED_PUBKEY_SIZE, 0);
    size_t clen = COMPRESSED_PUBKEY_SIZE;
    secp256k1_ec_pubkey_serialize(ctx, (uint8_t*)rtn.data(), &clen, &pubkey,  SECP256K1_EC_COMPRESSED);
    if (ctx) {
        secp256k1_context_destroy(ctx);
    }
    return rtn;
}

// Creates a random AES Initialization Vector (IV)
std::string CreateAesIVKey(){
    return CreateCustomRandom(AES_BLOCKSIZE);
}

// Encrypts input data using AES256-CBC with the given key and IV
bool AesEncode(const std::string& key, const std::string& iv, const std::string& in, std::string &out){
    std::string key_use = key;
    if(iv.size() != AES_BLOCKSIZE){
        return false;
    }
    if(key_use.size() != AES256_KEYSIZE){
        key_use.resize(AES256_KEYSIZE, 0);
    }
    out.resize((in.size()+AES_BLOCKSIZE) - (in.size()+AES_BLOCKSIZE)%AES_BLOCKSIZE, 0);
    AES256CBCEncrypt enc((uint8_t*)key_use.data(), (uint8_t*)iv.data(), true);
    int len = enc.Encrypt((uint8_t*)in.data(), in.size(), (uint8_t*)out.data());
    return len == out.size();
}

// Decodes AES-encrypted data using the given key and IV
bool AesDecode(const std::string &key, const std::string &iv, const std::string &in, std::string &out){
    return AesDecode(key, iv, in.data(), in.size(), out);
}

bool AesDecode(const std::string &key, the std::string &iv, const char* in, uint32_t in_len, std::string &out){
    out.resize((in_len+AES_BLOCKSIZE) - (in_len+AES_BLOCKSIZE)%AES_BLOCKSIZE, 0);
    std::string key_use = key;
    if(iv.size() != AES_BLOCKSIZE){
        return false;
    }
    if(key_use.size() != AES256_KEYSIZE){
        key_use.resize(AES256_KEYSIZE, 0);
    }
    AES256CBCDecrypt enc((uint8_t*)key_use.data(), (uint8_t*)iv.data(), true);
    int len = enc.Decrypt((uint8_t*)in, in_len, (uint8_t*)out.data());
    out.resize(len);
    if (len == 0) {
        return false;
    }
    return true;
}

// Validates a signature against a public key and a hash
bool SignIsValidate(const uint8_t* buf, size_t length, const std::string& pub_key, the std::string& sign){
    assert(length == HASH_SIZE);
    assert(sign.size() == SIGN_SIZE);
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY|SECP256K1_CONTEXT_SIGN);
    assert(ctx != nullptr);
    std::string vseed = CreateCustomRandom(32);
    bool ret = secp256k1_context_randomize(ctx, (uint8_t*)vseed.data());
    assert(ret);
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_parse(ctx, &pubkey, (uint8_t*)pub_key.data(), PUB_KEY_SIZE)) {
        return false;
    }
    secp256k1_ecdsa_signature sig;
    memcpy(&sig, sign.data(), SIGN_SIZE);
    bool rtn = secp256k1_ecdsa_verify(ctx, &sig, buf, &pubkey) ? true : false;
    if (ctx) {
        secp256k1_context_destroy(ctx);
    }
    return rtn;
}

// Generates a signature for a hash using a private key
std::string GetSignByPrivateKey(const uint8_t* buf, size_t length, const std::string pri_key){
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY|SECP256K1_CONTEXT_SIGN);
    assert(ctx != nullptr);
    assert(length == HASH_SIZE);
    std::string rtn(SIGN_SIZE, '\0');
    rtn.resize(SIGN_SIZE);
    size_t nSigLen = SIGN_SIZE;
    unsigned char extra_entropy[32] = {0};
    secp256k1_ecdsa_signature sig;
    uint32_t counter = 0;
    bool ret = secp256k1_ecdsa_sign(ctx, &sig, buf, (uint8_t*)pri_key.data(), secp256k1_nonce_function_rfc6979, nullptr);
    memcpy((void*)rtn.data(), &sig, SIGN_SIZE);
    if (ctx) {
        secp256k1_context_destroy(ctx);
    }
    return rtn;
}

// Convenience function for signing data using a private key
std::string GetSignByPrivateKey(const std::string buf, const std::string pri_key) {
    return GetSignByPrivateKey((uint8_t*)buf.data(), buf.size(), pri_key);
}

// Computes a shared secret using ECDH with the provided public and private keys
std::string GetEcdhKey(const std::string &pub_key, the std::string &pri_key){
    if(pub_key.size() != PUB_KEY_SIZE || pri_key.size() != PRI_KEY_SIZE){
        return std::string();
    }
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY|SECP256K1_CONTEXT_SIGN);
    assert(ctx != nullptr);
    std::string vseed = CreateCustomRandom(32);
    bool ret = secp256k1_context_randomize(ctx, (uint8_t*)vseed.data());
    assert(ret);
    std::string rtn((size_t)(AES_KEY_SIZE), '\0');
    secp256k1_pubkey pubkey;
    secp256k1_ec_pubkey_parse(ctx, &pubkey, (uint8_t*)pub_key.data(), PUB_KEY_SIZE);
    secp256k1_ecdh(ctx, (uint8_t*)rtn.data(), &pubkey, (uint8_t*)pri_key.data(),NULL, NULL);
    if (ctx) {
        secp256k1_context_destroy(ctx);
    }
    return rtn;
}

// Computes the SHA-256 hash of the input data
std::string Sha256(const std::string& in) {
    SHA256 sha;
    sha.update(in);
    return sha.digest();
}

// Computes the SHA-512 hash of the input data
std::string Sha512(const std::string &in){
    SHA512 sha;
    sha.update((uint8_t*)in.data(), in.size());
    std::string rtn(64, 0);
    sha.final((uint8_t*)rtn.data());
    return rtn;
}
