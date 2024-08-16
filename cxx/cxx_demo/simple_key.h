#ifndef __SIMPLE_KEY__H__
#define __SIMPLE_KEY__H__

#include <memory>
#include <boost/unordered_map.hpp>
#include "../crypto_tools/string_tools.h"
#include "../crypto_tools/key_tools.h"

std::string GetStorePublicKey(){
    return HexAsc2ByteString("040f3a12626327a5698c5e533c6a63f15aa07588b4081c325a4cc9c4710c81ce06f9fc321884be3961b839202bc01a9be3d1bdacc9788d4d0769261e0d21cc5c2c");
}
std::string GetStorePrivateKey(){
    return HexAsc2ByteString("e249423fb865e4f3d74caaba2c72bf81d80dae6892a3197ed0c71c98ee43205b");
}

#endif