# Key System

## Overview
The key system uses secp256k1 key pairs, consisting of a public key and a private key. The public key can be shown to others, while the private key must be kept secret as it represents the user's full permissions.

## Private Key
The private key is composed of 32 bytes. When represented in hexadecimal, it totals 64 hexadecimal characters, for example:  
`0x1234567890123456789012345678901234567890123456789012345678901234`

## Public Key
The full public key is composed of 65 bytes, and the compressed public key is composed of 33 bytes. Our protocol uses the full public key.

# P2P Encryption Principle

## Password Generation
The generation of the encryption password relies on ECDH. The specific principles are as follows:
- A's private key + B's public key through ECDH produces AB.
- B's private key + A's public key through ECDH produces BA.
- The result is AB = BA.  
  This allows the generation of a shared password \(S = AB = BA\) between A and B that only they know.

## Encryption and Decryption
Encryption uses AES256cbc, a symmetric encryption algorithm.  
A encrypts the message \(M\) using the password \(AB\) and a random salt through AES256cbc, resulting in the encrypted message \(M+\).  
B decrypts the message \(M+\) using the password \(BA\) and the random salt through AES256cbc, obtaining the decrypted message \(M\).

# TUN Construction Process

1. Obtain node information. From the obtained node list, you can get the node's IP, port, and public key.
2. Use WebSocket to connect to `ws://ip:port/xpp`.
3. Upon a successful WebSocket connection, a string will be immediately received, representing the local IP of the TUN protocol.
4. Configure the local virtual network card, completing the tunnel setup.
5. Read from WebSocket. If information is read, it is decrypted using the node's public key and the local private key through AES, and then written to the TUN virtual network card.
6. Read from the TUN network card. If content is read, it is encrypted using the node's public key and the local private key through AES, and then sent to the WebSocket.

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
- `pubkey`: Requester's public key.
- `timestamp`: Current request time (ms). The request will fail if the difference with the server time exceeds 15 seconds.
- `sign`: Signature, a hexadecimal result of signing the SHA256 hash of the `timestamp` string using the private key corresponding to the public key. It's similar to `Sign(sha256(str(timestamp)))`.

### Return
```json
{
    "success": 1,             // 1 indicates success, any other value indicates failure
    "data": [{                // If successful, returns an array of nodes; otherwise, returns an error message
        "name": "",           // Node name
        "ip": "",             // Node IP
        "port": "",           // Node port
        "pubkey": "",         // Node public key
        "type": "",           // Node type
        "country": ""         // Node's country abbreviation
    },{
        "name": "",
        "ip": "",
        "port": "",
        "pubkey": "",
        "type": "",
        "country": ""
    }]
}

```
## Get Node List by Passcode (GET)

### URL
`http://node.suifly.network:10113/power/get_node_by_passcode`

### Arguments
`pubkey`: Requester's public key.
`passcode`: Request passcode.
`timestamp`: Current request time (ms). The request will fail if the difference with the server time exceeds 15 seconds.
`sign`: Signature, a hexadecimal result of signing the SHA256 hash of the `timestamp` string using the private key corresponding to the public key. It's similar to `Sign(sha256(str(timestamp)))`.

### Return
```json
{
    "success": 1,             // 1 indicates success, any other value indicates failure
    "data": [{                // If successful, returns an array of nodes; otherwise, returns an error message
        "name": "",           // Node name
        "ip": "",             // Node IP
        "port": "",           // Node port
        "pubkey": "",         // Node public key
        "type": "",           // Node type
        "country": ""         // Node's country abbreviation
    },{
        "name": "",
        "ip": "",
        "port": "",
        "pubkey": "",
        "type": "",
        "country": ""
    }]
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