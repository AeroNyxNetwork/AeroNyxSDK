# Introduction

This is a C++ demo that illustrates how to effectively use AeroNyx. To keep dependencies minimal, we use only one non-standard library: `boost`. Its path is configured in the `cxx_demo/CMakeLists.txt`.

# Project Structure

The project is organized into several directories, each containing specific components of the encryption and network management functionalities:

- **crypto_tools** - Contains all implementations of the encryption algorithms used in the project.
    - **aes** - Houses AES-related algorithms.
    - **hash** - Dedicated to HASH related algorithms.
    - **secp256k1** - Contains secp256k1 related algorithms.
    - **ecdh_manager** - Manages ECDH (Elliptic Curve Diffie-Hellman) operations, accelerating the process.
    - **key_tools** - Packages most of the algorithm interfaces, facilitating their use across the project.

- **cxx_demo** - This directory contains the demo's CMake configuration and the core implementation logic.
    - **simple_key.h** - Manages storage for public and private keys.
    - **simple_http.h** - Implements the Http interface for network communication.
    - **simple_client_server.h** - Handles the management of each proxy connection.
    - **simple_client_item.h** - Utilized for managing proxy traffic entering a node.
    - **simple_package.h** - Responsible for packet-based traffic encryption and decryption.

Each component is designed to be modular and reusable, making it easy to understand and integrate into larger projects.
