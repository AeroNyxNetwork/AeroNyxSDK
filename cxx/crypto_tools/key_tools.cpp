
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

const uint32_t PRI_KEY_SIZE = 32;
const uint32_t PUB_KEY_SIZE = PRI_KEY_SIZE*2+1;
const uint32_t COMPRESSED_PUBKEY_SIZE = 33;
const uint32_t AES_IV_SIZE = AES_BLOCKSIZE;
const uint32_t AES_KEY_SIZE = AES256_KEYSIZE;

const uint32_t HASH_SIZE = 32;
const uint32_t SIGN_SIZE = 64;

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

std::string CreatePrivateKey(){
    return CreateCustomRandom(PRI_KEY_SIZE);
}

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
std::string CreateAesIVKey(){
    return CreateCustomRandom(AES_BLOCKSIZE);
}

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

bool AesDecode(const std::string &key, const std::string &iv, const std::string &in, std::string &out){
    return AesDecode(key, iv, in.data(), in.size(), out);
}

bool AesDecode(const std::string &key, const std::string &iv, const char* in, uint32_t in_len, std::string &out){
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


bool SignIsValidate(const uint8_t* buf, size_t length, const std::string& pub_key, const std::string& sign){
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
    //memcpy(&pubkey, pub_key.data()+1, PUB_KEY_SIZE-1);
    secp256k1_ecdsa_signature sig;
    memcpy(&sig, sign.data(), SIGN_SIZE);
    //secp256k1_ecdsa_signature_normalize(ctx, &sig, &sig);
    bool rtn = secp256k1_ecdsa_verify(ctx, &sig, buf, &pubkey)?true:false;

    if (ctx) {
        secp256k1_context_destroy(ctx);
    }
    return rtn;
    //return ecdsa_verify((uint8_t*)(pub_key.data()), buf, (uint8_t*)(sign.data()));
}
// nonce32, msg32, seckey, NULL, (void*)noncedata, count
// int hash256_func(unsigned char *nonce32, const unsigned char *msg32, const unsigned char *key32, const unsigned char *algo16, void *data, unsigned int counter) {
//     return 1;
// }
std::string GetSignByPrivateKey(const uint8_t* buf, size_t length, const std::string pri_key){
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY|SECP256K1_CONTEXT_SIGN);
    assert(ctx != nullptr);
    // std::string vseed = CreateCustomRandom(32);
    // bool ret = secp256k1_context_randomize(ctx, (uint8_t*)vseed.data());
    // assert(ret);

    assert(length == HASH_SIZE);
    std::string rtn(SIGN_SIZE, '\0');
    rtn.resize(SIGN_SIZE);
    size_t nSigLen = SIGN_SIZE;
    unsigned char extra_entropy[32] = {0};
    secp256k1_ecdsa_signature sig;
    uint32_t counter = 0;
    bool ret = secp256k1_ecdsa_sign(ctx, &sig, buf, (uint8_t*)pri_key.data(), secp256k1_nonce_function_rfc6979, nullptr);

    // Grind for low R
    /*while (ret && !SigHasLowR(ctx, &sig) ) {
        WriteLE32(extra_entropy, ++counter);
        ret = secp256k1_ecdsa_sign(ctx, &sig, buf, (uint8_t*)pri_key.data(), secp256k1_nonce_function_rfc6979, extra_entropy);
    }
    assert(ret);*/
    
    // secp256k1_ecdsa_signature_serialize_compact(ctx, (unsigned char*)rtn.data(), &sig);
    // size_t uuu;
    // unsigned char xxx[100];
    // secp256k1_ecdsa_signature_serialize_der(ctx, (unsigned char*)xxx, &uuu, &sig);
    // return std::string((const char* )xxx, uuu);
    memcpy((void*)rtn.data(), &sig, SIGN_SIZE);
    if (ctx) {
        secp256k1_context_destroy(ctx);
    }

    return rtn;
}


std::string GetSignByPrivateKey(const std::string buf, const std::string pri_key) {
    return GetSignByPrivateKey((uint8_t*)buf.data(), buf.size(), pri_key);
}
std::string GetEcdhKey(const std::string &pub_key, const std::string &pri_key){
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

std::string Sha256(const std::string& in) {
    SHA256 sha;
    sha.update(in);
    return sha.digest();
}

std::string Sha512(const std::string &in){
    SHA512 sha;
    //    sha.init();
    sha.update((uint8_t*)in.data(), in.size());
    std::string rtn(64, 0);
    sha.final((uint8_t*)rtn.data());
    return rtn;
}


