
#ifndef __SIMPLE_PACKAGE__HPP__
#define __SIMPLE_PACKAGE__HPP__

#include <boost/format.hpp>
#include <iostream>
#include "../crypto_tools/key_tools.h"
#include "../crypto_tools/string_tools.h"



struct DecodedWebsocketPackage{
    std::string from_pubkey;
    std::string payload;
};



std::string inline EncodePackage(
    const std::string& from_pubkey,
    const std::string& payload,
    const std::string& ecdh_key
){
    std::string iv = CreateAesIVKey();
    if (ecdh_key == ""|| iv == "") {
        return "";
    }
    std::string out;
    if (AesEncode(ecdh_key, iv, payload, out) ){
        return from_pubkey+iv+out;
    }
    return "";
}

bool inline DecodePackage(
    const std::string& in, 
    DecodedWebsocketPackage& out, 
    const std::string& ecdh_key ){

    if ( in.size() < PUB_KEY_SIZE + AES_IV_SIZE){
        return false;
    }
    std::string from_pubkey = std::string(in, 0, PUB_KEY_SIZE);
    std::string iv = std::string(in, PUB_KEY_SIZE, AES_IV_SIZE);

    if ( !AesDecode( ecdh_key, iv, in.data() + PUB_KEY_SIZE + AES_IV_SIZE, in.size() - (PUB_KEY_SIZE + AES_IV_SIZE ), out.payload) ){
        return false;
    }
    out.from_pubkey = from_pubkey;
    return true;

}

#endif