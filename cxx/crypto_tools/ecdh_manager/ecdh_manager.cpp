#include "ecdh_manager.h"
#include "../key_tools.h"

std::shared_ptr<EcdhManager> EcdhManager::GetInstance(){
    if(!instance){
        instance = std::make_shared<EcdhManager>();
    }
    return instance;
}

// void EcdhManager::SetEcdh(const std::pair<std::string, std::string>& key, const std::string& value) {
// //    ecdh_map[key] = value;
    
// }


std::string EcdhManager::GetEcdh(const std::pair<std::string, std::string>& key){
    auto iter = ecdh_map.find(key);
    if (iter == ecdh_map.end()) {
        std::string value = ::GetEcdhKey(key.first, key.second);
        ecdh_map.insert({key, value});
    }
    return ecdh_map[key];
}

std::shared_ptr<EcdhManager> EcdhManager::instance = nullptr;
    
