cmake_minimum_required (VERSION 3.0)
project(cxx_demo)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17 ") 
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O0  -DNO_QDEBUG -DAeroNxyNode")
set(BOOST_PATH /opt/boost_1_80_0)
include_directories(${BOOST_PATH})
link_directories(${BOOST_PATH}/stage/lib)

aux_source_directory(./ main_src)
aux_source_directory(../crypto_tools crypto_tools)
aux_source_directory(../crypto_tools/aes aes)
aux_source_directory(../crypto_tools/secp256k1 secp256)
aux_source_directory(../crypto_tools/ecdh_manager ecdh_manager)
aux_source_directory(../crypto_tools/hash hash)


remove(aes ../crypto_tools/aes/ctaes.c)
remove(secp256 ../crypto_tools/secp256k1/gen_context.c)
remove(net_lib ../net_lib/http_server.cpp)
remove(crypto_tools ../crypto_tools/key_tools_c.cpp)

add_executable(
    cxx_demo
    ${main_src}
    ${crypto_tools}
    ${asio_manager}
    ${aes}
    ${blake}
    ${secp256}
    ${config}
    ${keystore}
    ${mnemonics}
    ${scrypt}
    ${hash}
    ${redis}
    ${ecdh_manager}
)

target_link_libraries(cxx_demo pthread boost_json  ssl crypto)