---
layout: default
title: KEM Generic API
parent: Key Encapsulation Mechanisms
grand_parent: Post-Quantum Algorithms
nav_order: 1
---

# Key Encapsulation Mechanisms generic API overview
{: .no_toc }

<details open markdown="block">
  <summary>
    Table of contents
  </summary>
  {: .text-delta }
1. TOC
{:toc}
</details>

The Key Exchange Mechanism (KEM) algorithms use a common API that facilitates uniform interaction with all KEM algorithms included within the library.
This ensures a consistent and efficient integration process for users leveraging different KEM algorithms for their cryptographic needs.

The library is in a state of continual enhancement, reflecting the latest developments and breakthroughs in cryptographic research. 

New algorithms are periodically added to the library, expanding its functionality and versatility to adapt to evolving security requirements and technological advancements. 

Current KEM algorithms:
- [Classic McEliece 8192128f](mceliece.html)

Useful links:
- [Getting Started Guide ](../../getting_started.html)

### Key Exchange Mechanism Using Asymmetric Encryption API


#### `PQC_generate_key_pair`

Function signature:

```cpp
int PQC_generate_key_pair(   uint32_t cipher, 
                            uint8_t *public_key, 
                            size_t public_length, 
                            uint8_t *private_key, 
                            size_t private_length);
```

To begin using a post-quantum cryptography algorithm like McEliece for encrypting communications, you first need to generate a pair of public and private keys. The function `PQC_generate_key_pair` facilitates this by accepting several parameters:

*   `cipher`: This specifies the algorithm to be used. For instance, `PQC_CIPHER_MCELIECE` is used to indicate that the McEliece cipher will be utilized for the key generation process.
    
*   `public_key` and `private_key` (output parameters): These are pointers to memory locations where the generated keys will be stored. The keys are generated based on the algorithm selected with the `cipher` parameter. For McEliece, specific structures or buffers sized according to `PQC_MCELIECE_PUBLIC_KEYLEN` and `PQC_MCELIECE_PRIVATE_KEYLEN` should be used for public and private keys, respectively.
    

The function returns `PQC_OK` on successful generation, with other codes indicating various failure modes such as unsupported cipher (`PQC_BAD_CIPHER`), incorrect key size (`PQC_BAD_LEN`), or internal errors (`PQC_INTERNAL_ERROR`).

#### `PQC_init_context`

Function signature:

```cpp
CIPHER_HANDLE PQC_init_context(uint32_t cipher, const uint8_t* key, size_t key_length);
```

The `PQC_init_context` function initializes an encryption context for further operations like key encoding. The parameters include:

*   `cipher`: Identifies the encryption algorithm to be used (`PQC_CIPHER_MCELIECE` for McEliece).
    
*   `key` and `key_length`: Point to the private key and its length, respectively. The key format and length should match the requirements of the selected cipher.
    

This returns a `CIPHER_HANDLE`, a handle for the created encryption context, unless an error occurs, indicated by return codes such as `PQC_BAD_CIPHER`.

#### `PQC_kem_encode`

Function signature:

```cpp
int PQC_kem_encode(  uint32_t cipher, 
                    uint8_t* message, 
                    size_t message_length, 
                    const uint8_t* party_a_info, 
                    size_t info_length, 
                    const uint8_t* public_key, 
                    size_t key_length, 
                    uint8_t* shared_key, 
                    size_t shared_key_length);
```

This function is a part of the key encapsulation process, where a shared key for encryption is derived and a message for the other party is generated using their public key. The parameters guide the function on how to generate these items:

*   `cipher`: Selects the encryption algorithm.
    
*   `message` and `shared_key` (output parameters): Pointers to buffers where the generated message and shared key will be stored.
    
*   `public_key`: The public key of the receiving party.
    

The return code `PQC_OK` denotes success, with other codes specifying potential errors.

#### `PQC_kem_decode`

Function signature:

```cpp
int PQC_kem_decode(  CIPHER_HANDLE ctx, 
                    const uint8_t* message, 
                    size_t message_length, 
                    const uint8_t* party_a_info, 
                    size_t info_length, 
                    uint8_t* shared_key, 
                    size_t shared_key_length);
```

This complements `PQC_kem_encode`, allowing the receiver to derive the shared encryption key from the message they received.

*   `ctx`: The encryption context handle.
    
*   `message`: The message received from the sender.
    

Successful operation returns `PQC_OK`, with failure modes similarly denoted by specific return codes.

#### `PQC_kem_encode_secret`

Function signature:

```cpp
size_t PQC_API PQC_kem_encode_secret(  uint32_t cipher, 
                                       uint8_t* message, 
                                       size_t message_length, 
                                       const uint8_t * public_key, 
                                       size_t publickey_length,
                                       uint8_t * shared_secret, 
                                       size_t shared_secret_length);
```

This function generates a shared secret key using a given encryption algorithm, a message, and a pre-generated public key. The message is then intended to be sent to the second user, who owns the public key, for decryption.

*   `cipher`: An identifier for selecting the encryption algorithm. [`Cipher constants`](common_functions.html#cipher)
    
*   `uint8_t * message`, `size_t message_length`: A pointer to the memory area for the message and its length. The message, which contains ciphertext encrypted with the public key, will be written here to be sent to the other party.
    
*   `const uint8_t * public_key`, `size_t publickey_length`: A pointer to the memory area for the public key and its length. The public key must be pre-generated and will be used to encrypt the message.
*   
*   `uint8_t * shared_secret`, `size_t shared_secret_length`: A pointer to the memory area for the shared secret and its length. The shared secret, generated after executing the function, will be written here.

The return code `PQC_OK` denotes success, with other codes specifying potential errors.

#### `PQC_kem_decode_secret`

Function signature:

```cpp
size_t PQC_kem_decode_secret(  CIPHER_HANDLE ctx, 
                    const uint8_t* message, 
                    size_t message_length, 
                    uint8_t * shared_secret,
                    size_t shared_secret_length);
```

his function complements PQC_kem_encode_secret, enabling the receiver to derive the shared encryption key from the received message. It requires an already initialized encryption context.

- `ctx`: The encryption context handle.
- `message`: A pointer to the message received from the sender.
- `message_length`: The length of the received message.
- `shared_secret`: A pointer to the memory area for the shared secret.
- `shared_secret_length`: The length of the shared secret.
    

Successful operation returns `PQC_OK`, with failure modes similarly denoted by specific return codes.

#### `PQC_close_context`

Function signature:

```cpp
int PQC_close_context(CIPHER_HANDLE ctx);
```

To conclude operations and free resources, `PQC_close_context` is used.

*   `ctx`: The encryption context handle to be closed.
    

On successful closure, `PQC_OK` is returned.
