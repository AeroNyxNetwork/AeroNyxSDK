#include <string>
#include <iostream>
#include <cassert>
#include <chrono>
#include <boost/format.hpp>
#include <boost/json.hpp>
#include "../crypto_tools/key_tools.h"
#include "../crypto_tools/string_tools.h"

#include "simple_http.h"
#include "simple_key.h"
#include "simple_client_server.h"

std::string PRI_KEY1 = "e249423fb865e4f3d74caaba2c72bf81d80dae6892a3197ed0c71c98ee43205b";
std::string PRI_KEY2 = "29427d86893863e4599d0cdcec858b6c973dc903ceabf878f31f55c3ac51e23b";

std::string GetTimestampNowStr(){
    auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(
                      std::chrono::system_clock::now().time_since_epoch()
                  ).count();
    return (boost::format("%ld")%millis).str();
}
void TestCrypto() {
    std::cout << "=============>" << std::endl;
    std::cout << "Cryptography related" << std::endl;
    std::cout << "<=============" << std::endl;

    // create random private key
    // std::string pri_key = CreatePrivateKey();

    // Load the private key from the hex string to check if the result is correct
    std::string pri_key = HexAsc2ByteString(PRI_KEY1);
    std::string pub_key = GetPublicKeyByPrivateKey(pri_key);

    std::cout << "pri key:" << Byte2HexAsc(pri_key) << std::endl;
    std::cout << "pub key:" << Byte2HexAsc(pub_key) << std::endl;

    std::string message = "123456";
    std::string sha256 = Sha256(message);
    std::string sha512 = Sha512(message);
    std::cout << "sha 256:" << Byte2HexAsc(sha256) << std::endl;
    std::cout << "sha 512:" << Byte2HexAsc(sha512) << std::endl;

    std::string sign = GetSignByPrivateKey((uint8_t*)sha256.data(), sha256.size(), pri_key);
    std::cout << "sign:" << Byte2HexAsc(sign) << std::endl;

    std::string pri_key2 = HexAsc2ByteString(PRI_KEY2);
    std::string pub_key2 = GetPublicKeyByPrivateKey(pri_key2);
    std::string share_secret1 =  GetEcdhKey(pub_key, pri_key2);
    std::string share_secret2 =  GetEcdhKey(pub_key2, pri_key);
    std::cout << "share_secret1:" << Byte2HexAsc(share_secret1) << std::endl;
    std::cout << "share_secret2:" << Byte2HexAsc(share_secret2) << std::endl;

    std::string message_ori = "hello world";
    // std::string iv = CreateAesIVKey();
    // Load the iv from the hex string to check if the result is correct
    std::string iv = HexAsc2ByteString("12345678901234567890123456789012");
    std::string message_encoded;
    assert(AesEncode(share_secret1, iv, message_ori, message_encoded));
    std::cout << "message_encoded:" << Byte2HexAsc(message_encoded) << std::endl;

    std::string message_decoded;
    assert(AesDecode(share_secret1, iv, message_encoded, message_decoded));
    std::cout << "message_decoded:" << message_decoded << std::endl;
    assert(message_decoded == "hello world");
}


void TestRegistByInvitationCode(){
    std::cout << "=============>" << std::endl;
    std::cout << "TestRegistByInvitationCode" << std::endl;
    std::cout << "<=============" << std::endl;
    std::string pubkey = Byte2HexAsc(GetStorePublicKey());
    std::string timestamp = GetTimestampNowStr();
    std::string sign = Byte2HexAsc(GetSignByPrivateKey(Sha256(timestamp), GetStorePrivateKey()));
    std::string invatation_code = "invatation_code";
    std::string target = (boost::format("/power/recv_invitation?pubkey=%s&timestamp=%d&sign=%s&code=%s")%pubkey%timestamp%sign%invatation_code).str();
    std::cout << "response" << HttpGet("node.aeronyx.network", "10113", target) << std::endl;
}

void TestGetNodeList(){
    std::cout << "=============>" << std::endl;
    std::cout << "TestGetNodeList" << std::endl;
    std::cout << "<=============" << std::endl;
    std::string pubkey = Byte2HexAsc(GetStorePublicKey());
    std::string timestamp = GetTimestampNowStr();
    std::string sign = Byte2HexAsc(GetSignByPrivateKey(Sha256(timestamp), GetStorePrivateKey()));
    std::string target = (boost::format("/power/get_node2?pubkey=%s&timestamp=%d&sign=%s")%pubkey%timestamp%sign).str();
    std::cout<< "response" << HttpGet("node.aeronyx.network", "10113", target) << std::endl;
}

std::string TestGetToken() {
    std::cout << "=============>" << std::endl;
    std::cout << "TestGetToken" << std::endl;
    std::cout << "<=============" << std::endl;
    std::string pubkey = Byte2HexAsc(GetStorePublicKey());
    std::string timestamp = GetTimestampNowStr();
    std::string sign = Byte2HexAsc(GetSignByPrivateKey(Sha256(timestamp), GetStorePrivateKey()));
    std::string target = (boost::format("/rpc/login?pubkey=%s&timestamp=%s&sign=%s")%pubkey%timestamp%sign).str();
    std::string response = HttpGet("35.201.204.72", "10003", target);
    std::cout<< "response:" << response << std::endl;
    boost::json::object json_obj = boost::json::parse(HttpGet("35.201.204.72", "10003", target)).as_object();
    if (json_obj["success"].as_int64() == 1) {
        return json_obj["data"].as_string().c_str();
    }
    return "";
}
int main(){
    TestCrypto();
    TestRegistByInvitationCode();
    TestGetNodeList();
    std::string token = HexAsc2ByteString(TestGetToken());

    boost::asio::io_service io_service;
    boost::asio::io_service::work work(io_service);


    std::vector<std::thread> threads;
    for (int i = 0; i < std::thread::hardware_concurrency(); ++i) {  
        threads.emplace_back([&io_service]() {
            io_service.run();
        });
    }

    SimpleClientServer server;
    server.StartServer(
        io_service, 
        false, 
        7788, 
        "35.201.204.72", 
        10003, 
        HexAsc2ByteString("0463d92772a201344bdc249abcb498467796c1c90869c0604bc7e5e5e01e14f06cf95d466be872bb5d46703c361b8b6fca218e76011897519ce64f5ddef429da31"), 
        token);

    for (auto& thread : threads) {
        thread.join();
    }

    return 0;
}

// "35.201.204.72", "port": "10003", "pubkey": "0463d92772a201344bdc249abcb498467796c1c90869c0604bc7e5e5e01e14f06cf95d466be872bb5d46703c361b8b6fca218e76011897519ce64f5ddef429da31", "type": 0, "country": "TW", "passcode": ""}