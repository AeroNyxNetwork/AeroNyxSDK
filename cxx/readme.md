# Introduction
This is a C++ demo that shows in detail how to use AeroNyx.

In order to minimize dependencies, only one non-standard library is used here: `boost`. Its path is configured in cxx_demo/CMakeLists.txt.

# Project Structure

- `crypto_tools` The implementations of all encryption algorithms used are here
    - `aes` AES related algorithms
    - `hash` HASH related algorithms
    - `secp256k1` secp256k1 related algorithms
    - `ecdh_manager` ECDH Accelerator
    - `key_tools` Packages most of the algorithm interfaces
    
- `cxx_demo` Demo's CMakeLists.txt and implementation logic are in this folder
    - `simple_key.h` Public and private key storage
    - `simple_http.h` Http interface
    - `simple_client_server.h` Managing each proxy connection
    - `simple_client_item.h` Used for proxy traffic entering Node
    - `simple_package.h` Traffic packet-based encryption and decryption