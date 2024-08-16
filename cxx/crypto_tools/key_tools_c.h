#ifndef KEYTOOL_C_H
#define KEYTOOL_C_H
#include <stdio.h>
#ifdef __cplusplus
extern "C" {
#endif
char* CreatePrivateKey_C(size_t* out_len);
char* GetPublicKeyByPrivateKey_C(const char* private_key_org, size_t private_key_len, size_t* pubkey_len);
char* GetSignByPrivateKey_C(const char* sha256_data, size_t sha256_len, const char* pri_key_data, size_t pri_key_len, size_t* sign_len);
char* GetEcdhKey_C(const char* pub_key_data, size_t pub_key_len, const char* pri_key_data, size_t pri_key_len, size_t* ecdh_len) ;
char* CreateAesIVKey_C(size_t* iv_len);

char* AesEncode_C(const char* key_data, size_t key_len, const char* iv_data, size_t iv_len, const char* in_data, size_t in_len, size_t* out_size);
char* AesDecode_C(const char* key_data, size_t key_len, const char* iv_data, size_t iv_len, const char* in_data, size_t in_len, size_t* out_size);
bool SignIsValidate_C(const char* sha256_data, size_t sha256_len, const char* pub_key_data, size_t pub_key_size, const char* sign_data, size_t sign_len);
char* Sha256_C(const char* in_data, size_t in_len, size_t* out_len);
char* Sha512_C(const char* in_data, size_t in_len, size_t* out_len);
#ifdef __cplusplus
}
#endif
#endif // KEYTOOL_H
