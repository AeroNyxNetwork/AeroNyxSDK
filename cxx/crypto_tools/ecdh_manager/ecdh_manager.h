#ifndef __ECDH__MANAGER__H__
#define __ECDH__MANAGER__H__

#include <memory>
#include <boost/unordered_map.hpp>
#include <functional>



class EcdhManager{
public:
    static std::shared_ptr<EcdhManager> GetInstance();
    // void SetEcdh(const std::pair<std::string, std::string>& key, const std::string& value);
    std::string GetEcdh(const std::pair<std::string, std::string>& key);
private:
    static std::shared_ptr<EcdhManager> instance;
    boost::unordered_map<std::pair<std::string, std::string>, std::string> ecdh_map ;
};
#define GetEcdhManager() EcdhManager::GetInstance()
#endif