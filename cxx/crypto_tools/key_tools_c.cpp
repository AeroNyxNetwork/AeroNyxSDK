
#include "key_tools_c.h"
#include "key_tools.h"

char* CreatePrivateKey_C(size_t* out_len){
    std::string rtn = CreatePrivateKey();
    char* rtn_p = (char*)malloc(rtn.size());
    memcpy(rtn_p, rtn.data(), rtn.size());
    *out_len = rtn.size();
    return rtn_p;
}

char* GetPublicKeyByPrivateKey_C(const char* private_key_org, size_t private_key_len, size_t* pubkey_len){
    std::string rtn = GetPublicKeyByPrivateKey(std::string(private_key_org, private_key_len));
    char* rtn_p = (char*)malloc(rtn.size());
    memcpy(rtn_p, rtn.data(), rtn.size());
    *pubkey_len = rtn.size();
    return rtn_p;
}

char* GetSignByPrivateKey_C(const char* sha256_data, size_t sha256_len, const char* pri_key_data, size_t pri_key_len, size_t* sign_len){
    std::string sha256 = std::string(sha256_data, sha256_len);
    std::string private_key = std::string(pri_key_data, pri_key_len);
    std::string rtn = GetSignByPrivateKey((uint8_t*)sha256_data, sha256_len, private_key);
    char* rtn_p = (char*)malloc(rtn.size());
    memcpy(rtn_p, rtn.data(), rtn.size());
    *sign_len = rtn.size();
    return rtn_p;
};


char* GetEcdhKey_C(const char* pub_key_data, size_t pub_key_len, const char* pri_key_data, size_t pri_key_len, size_t* ecdh_len) {
    std::string pub_key = std::string(pub_key_data, pub_key_len);
    std::string pri_key = std::string(pri_key_data, pri_key_len);
    std::string rtn = GetEcdhKey(pub_key, pri_key);
    char* rtn_p = (char*)malloc(rtn.size());
    memcpy(rtn_p, rtn.data(), rtn.size());
    *ecdh_len = rtn.size();
    return rtn_p;
}

char* CreateAesIVKey_C(size_t* iv_len){
    std::string rtn = CreateAesIVKey();
    char* rtn_p = (char*)malloc(rtn.size());
    memcpy(rtn_p, rtn.data(), rtn.size());
    *iv_len = rtn.size();
    return rtn_p;
}


char* AesEncode_C(const char* key_data, size_t key_len, const char* iv_data, size_t iv_len, const char* in_data, size_t in_len, size_t* out_size){
    std::string key(key_data, key_len);
    std::string iv(iv_data, iv_len);
    std::string in = std::string(in_data, in_len);
    std::string rtn;
    if (!AesEncode(key, iv, in, rtn, false)){
        return nullptr;
    }
    char* rtn_p = (char*)malloc(rtn.size());
    memcpy(rtn_p, rtn.data(), rtn.size());
    *out_size = rtn.size();
    return rtn_p;
}

char* AesDecode_C(const char* key_data, size_t key_len, const char* iv_data, size_t iv_len, const char* in_data, size_t in_len, size_t* out_size){
    std::string key(key_data, key_len);
    std::string iv(iv_data, iv_len);
    std::string in = std::string(in_data, in_len);
    std::string rtn;
    if (!AesDecode(key, iv, in, rtn, false)){
        return nullptr;
    }
    char* rtn_p = (char*)malloc(rtn.size());
    memcpy(rtn_p, rtn.data(), rtn.size());
    *out_size = rtn.size();
    return rtn_p;
}

bool SignIsValidate_C(const char* sha256_data, size_t sha256_len, const char* pub_key_data, size_t pub_key_size, const char* sign_data, size_t sign_len){
    std::string pub_key = std::string(pub_key_data, pub_key_size);
    std::string sign = std::string(sign_data, sign_len);
    return SignIsValidate((uint8_t*)sha256_data, sha256_len, pub_key, sign);
}

char* Sha256_C(const char* in_data, size_t in_len, size_t* out_len){
    std::string in = std::string(in_data, in_len);
    std::string rtn = Sha256(in);
    char* rtn_p = (char*)malloc(rtn.size());
    memcpy(rtn_p, rtn.data(), rtn.size());
    *out_len = rtn.size();
    return rtn_p;
}
char* Sha512_C(const char* in_data, size_t in_len, size_t* out_len){
    std::string in = std::string(in_data, in_len);
    std::string rtn = Sha512(in);
    char* rtn_p = (char*)malloc(rtn.size());
    memcpy(rtn_p, rtn.data(), rtn.size());
    *out_len = rtn.size();
    return rtn_p;
}

