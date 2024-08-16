# Key System

## Overview
The Key Management System leverages the `secp256k1` elliptic curve cryptographic algorithm, utilizing key pairs that consist of a public key and a private key. The public key is shareable and used to derive wallet addresses or verify signatures, while the private key is confidential and grants complete access to the user’s assets and permissions.

## Private Key
Each private key is a 256-bit scalar, encoded as 32 bytes. In hexadecimal format, this is represented as 64 characters, exemplifying strong cryptographic security. For instance:
`0x12345678901234567890123456789012334567890123456789012345678901234`
This key must be stored securely to prevent unauthorized access to the user's digital assets.

## Public Key
The system supports the full serialization of public keys, which are 65 bytes in length. Unlike compressed public keys, which are 33 bytes, the full public keys include both the x-coordinate and the y-coordinate, providing higher security at the cost of increased data size. Our protocol mandates the use of the full public key to enhance security and interoperability within the network.

# P2P Encryption Principle

## Password Generation

The password generation process leverages Elliptic Curve Diffie-Hellman (ECDH) to ensure secure key exchange:
- A's private key and B's public key are combined via ECDH to generate the shared secret `AB`.
- Similarly, B's private key and A's public key through ECDH produce the shared secret `BA`.
- Both operations result in the identical shared secret (`AB = BA`), enabling A and B to derive a shared password \(S = AB = BA\) that only they can access.

## Encryption and Decryption

For data confidentiality, the system employs AES-256-CBC, a symmetric encryption standard:
- A encrypts the message \(M\) using the derived password \(AB\) along with a random salt via AES-256-CBC, resulting in the encrypted output \(M+\).
- B decrypts the encrypted message \(M+\) using the same password \(BA\) and salt through AES-256-CBC, recovering the original message \(M\).

# TUN Construction Process

Follow these steps to establish a secure TUN (Tunneling) protocol environment:
1. Retrieve node information including the node's IP, port, and public key from the node list.
2. Establish a WebSocket connection using `ws://ip:port/xpp`.
3. Upon successful WebSocket connection, you will immediately receive a string representing the TUN protocol's local IP.
4. Configure the local virtual network interface to complete the TUN setup.
5. Monitor the WebSocket for incoming data. Decrypt any data using the node's public key and your local private key via AES, then forward it to the TUN network card.
6. Any outgoing data read from the TUN network card should be encrypted using the node's public key and your local private key through AES, and subsequently sent over the WebSocket.


# HTTP Interface

## Register Account via Invitation Code
### URL
`http://node.aeronyx.network:10113/power/recv_invitation`

### Arguments
- `pubkey`: Requester's public key.
- `timestamp`: Current request time (ms). The request will fail if the difference with the server time exceeds 15 seconds.
- `code`: Invitation code.
- `sign`: Signature, a hexadecimal result of signing the SHA256 hash of the `timestamp` string using the private key corresponding to the public key. It's similar to `Sign(sha256(str(timestamp)))`.

### Return
```json
{
    "success": 1, // 1 indicates success, any other value indicates failure
    "data": ""    // Reason for failure
}
```

## Get Node List (GET)
### URL
`http://node.suifly.network:10113/power/get_node2`

### Arguments

- `pubkey`: The public key of the requester. This key is used to identify and authenticate the request.
- `timestamp`: The current request time in milliseconds. The request is considered valid only if the time difference between this timestamp and the server's current time does not exceed 15 seconds.
- `sign`: The signature, represented as a hexadecimal string. This is obtained by signing the SHA256 hash of the `timestamp` string with the private key corresponding to the public key provided. The signature process can be described by: `Sign(sha256(str(timestamp)))`.

### Return

The response is a JSON object with the following structure:

```json
{
    "success": 1,  // Indicates the status of the request: '1' for success, any other value indicates failure.
    "data": [      // An array of nodes is returned if the request is successful; otherwise, an error message is returned.
        {
            "name": "",      // Name of the node.
            "ip": "",        // IP address of the node.
            "port": "",      // Communication port for the node.
            "pubkey": "",    // Public key of the node, used for secure communications.
            "type": "",      // Type of the node (e.g., full, light, etc.).
            "country": ""    // Country abbreviation where the node is located.
        },
        {
            "name": "",
            "ip": "",
            "port": "",
            "pubkey": "",
            "type": "",
            "country": ""
        }
    ]
}


```
## Get Node List by Passcode (GET)

### URL
Access the API through this endpoint:
`http://node.suifly.network:10113/power/get_node_by_passcode`

### Arguments
This endpoint requires the following parameters:
- `pubkey`: The public key of the requester, used for identifying and verifying the sender.
- `passcode`: A specific passcode required to access the node list.
- `timestamp`: The current request time in milliseconds. It is critical that the client's clock is synchronized, as a timestamp difference greater than 15 seconds from the server's time will cause the request to fail.
- `sign`: A signature, provided as a hexadecimal string. This is the result of signing the SHA256 hash of the `timestamp` string using the private key associated with the provided public key. The signing process can be described as: `Sign(sha256(str(timestamp)))`.

### Return
The response format is a JSON object structured as follows:

```json
{
    "success": 1,             // '1' indicates a successful request. Any other value denotes a failure.
    "data": [                 // On success, returns an array of node details; on failure, returns an error message.
        {
            "name": "",       // The name of the node.
            "ip": "",         // IP address of the node.
            "port": "",       // Communication port number of the node.
            "pubkey": "",     // Public key of the node for secure communications.
            "type": "",       // Type of node, e.g., full, light, etc.
            "country": ""     // Country abbreviation where the node is located.
        },
        {
            "name": "",
            "ip": "",
            "port": "",
            "pubkey": "",
            "type": "",
            "country": ""
        }
    ]
}

```

## Get Protocol Text (GET)

### URL
`https://aeronyx.network/api/v1/cms/article?navigation_second_id=1&article_id=1`

### Return
```json
{
    "title": "Title", 
    "html": "Protocol HTML text"
}
```

## Login to Node (GET)

### URL
`http://[Node IP]:[Node Port]/rpc/login`

### Arguments
`pubkey`: Requester's public key.
`timestamp`: Current request time (ms). The request will fail if the difference with the server time exceeds 15 seconds.
`sign`: Signature, a hexadecimal result of signing the SHA256 hash of the `timestamp` string using the private key corresponding to the public key. It's similar to `Sign(sha256(str(timestamp)))`.

### Return
```json
{
    "success": 1, // 1 indicates success, any other value indicates failure
    "data": ""    // If failed, returns the reason for failure; if successful, returns the token
}
```

# Demo

We plan to write a series of sample codes to help developers access AeroNyx

- [CXX demo](./cxx/) Completed
- [Python demo](./cxx/) Under development...
- [Nodejs demo](./cxx/) Under development...
- [Rust demo](./cxx/) Under development...
