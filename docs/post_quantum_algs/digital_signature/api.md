---
layout: default
title: Signature generic API
parent: Digital Signature
grand_parent: Post-Quantum Algorithms
nav_order: 1
---

# Signature scheme generic API overview
{: .no_toc }

<details open markdown="block">
  <summary>
    Table of contents
  </summary>
  {: .text-delta }
1. TOC
{:toc}
</details>

The Digital Signature Schemes API provides a streamlined, uniform interface across diverse signature algorithms, enabling seamless and efficient integration for cryptographic applications.
Designed for consistency in use, the API simplifies the process of leveraging various signature schemes, enhancing developer productivity and application security.

The library is in a state of continual enhancement, reflecting the latest developments and breakthroughs in cryptographic research. 

New algorithms are periodically added to the library, expanding its functionality and versatility to adapt to evolving security requirements and technological advancements.


Current signature algorithms:
- [Falcon](falcon.html)

Useful links:
- [Getting Started Guide ](../../getting_started.html)

### Signature scheme API overview


#### `PQC_generate_key_pair`

Function signature:

```cpp
int PQC_generate_key_pair(   uint32_t cipher,
                            uint8_t *public_key,
                            size_t public_length,
                            uint8_t *private_key,
                            size_t private_length);
```

This function is designed to create a public-private key pair for cryptographic operations.

**Parameters**

*   `cipher`: A constant that selects the cipher algorithm to be used for the key pair generation. The only specified value here is `PQC_CIPHER_FALCON`, indicating the Falcon algorithm. Falcon is known for its security against quantum computer attacks, making it a forward-looking choice for digital security.
    
*   `private_key (out)`: This is a pointer to a memory location where the generated private key will be stored. The format of this private key must match the requirements of the chosen cipher, which, in the case of Falcon, could be a `pqc_falcon_private_key` structure or any buffer size equivalent to `PQC_FALCON_PRIVATE_KEYLEN`. The private key is critical for signing operations and must be kept securely.
    
*   `public_key (out)`: A pointer to the storage location for the generated public key, following the same format requirements as the private key relative to the chosen cipher. For the Falcon algorithm, this could mean using the `pqc_falcon_public_key` structure or an appropriately sized buffer (`PQC_FALCON_PUBLIC_KEYLEN`). The public key will be used in the verification process of signatures and can be distributed openly.
    

**Return Values**

*   `PQC_OK`: Indicates that the operation was successful and the key pair was generated as expected.
    
*   `PQC_BAD_CIPHER`: This return value suggests that the specified cipher is unknown or unsupported by the function, hinting at a potential typo or an attempt to use an algorithm not implemented in the library.
    
*   `PQC_BAD_LEN`: Returned if the sizes of the provided buffers for the private or public keys do not meet the requirements for the selected cipher algorithm. This could be due to incorrect buffer initialization prior to calling the function.
    
*   `PQC_INTERNAL_ERROR`: Signifies an error occurred during the operation of the cipher algorithm. This could be the result of a variety of issues, including, but not limited to, hardware faults, memory corruption, or bugs within the cipher's implementation.
    

#### `PQC_init_context`

Function signature:
```cpp
CIPHER_HANDLE PQC_init_context(uint32_t cipher, const uint8_t* key, size_t key_length);
```

**Purpose**

This function initializes a cryptographic context that is needed for performing encryption, decryption, or digital signing operations. The context is generated based on the provided private key and the selected cipher algorithm.

**Parameters**

*   `cipher`: A constant used to select the signature (or encryption) algorithm. The function supports specific values, one of which is `PQC_CIPHER_FALCON`, indicating the Falcon algorithm. Falcon is known for its security against quantum computer attacks, emphasizing the function's reach towards future-proof cryptography.
    
*   `key`: A pointer to the private key, which is used to initialize the cryptographic context. The format and size of this key must comply with the standards of the selected cipher. For Falcon, specifically, the key could be structured as a `pqc_falcon_private_key` or simply as a buffer of size `PQC_FALCON_PRIVATE_KEYLEN`. This parameter is critical as it directly influences the security and efficacy of the cryptographic operations executed within the context.
    
*   `key_length`: This parameter signifies the length of the private key. It's crucial that this length matches the expected size for the selected cipher algorithm to ensure proper initialization and operation of the cryptographic context. For the Falcon cipher, this length would correspond to the value of `PQC_FALCON_PRIVATE_KEYLEN`.
    

**Return Values**

*   `PQC_BAD_CIPHER`: This return code indicates an error has occurred during the context initialization process. Specifically, it signals that either the specified cipher is not supported (unknown or unsupported cipher) or the size of the provided private key does not match what is expected for the specified cipher. This error serves as a critical check to ensure that the initialization of the cryptographic operations can only proceed with valid and supported configurations.
    
*   **Otherwise (Handle of Created Encryption Context)**: If the initialization is successful, the function returns a handle to the newly created encryption context. This handle is then used for various cryptographic operations, encapsulating the specifics of the algorithm and key used during its creation. It effectively represents an operational state that can be passed to functions requiring a cryptographic context.
    

#### `PQC_sign`

Function signature:
```cpp
int PQC_sign(CIPHER_HANDLE ctx, uint8_t* buffer, size_t length, uint8_t* signature, size_t signature_len);
```

**Purpose**

To create a digital signature for a specified message using a previously initialized encryption context. This context encapsulates the cryptographic settings and keys.

**Parameters**

*   `ctx`: This is a handle to an encryption context that has been initialized earlier. The context must be set up with the correct cipher and key for signing operations. It represents the state and configurations needed for the cryptographic operation.
    
*   `buffer` (in): A pointer to the start of the message that is to be signed. This message is the input for which the digital signature will be generated. The content here is not modified by the function.
    
*   `length`: The length of the message in bytes. This specifies how much data from `buffer` should be considered for generating the signature.
    
*   `signature` (out): A pointer to a buffer where the generated signature will be stored. The capacity of this buffer needs to be sufficient to hold the signature. For the Falcon algorithm, the signature could follow a specific structure (e.g., `pqc_falcon_signature`) or occupy a buffer sized according to `PQC_FALCON_SIGNATURE_LEN`.
    
*   `signature_len`: Specifies the length of the `signature` buffer. It is critical that this length is correctly set to accommodate the signature generated by the algorithm in use.
    

**Return Values**

*   `PQC_OK`: Signifies that the operation was successful, and the message was signed without issues. The signature is now stored in the buffer pointed to by `signature`.
    
*   `PQC_BAD_CONTEXT`: Indicates an issue with the provided encryption context (`ctx`). It might not have been properly initialized, which is a prerequisite for signing operations.
    
*   `PQC_BAD_CIPHER`: This error suggests that the cryptographic algorithm (cipher) set in the context is unknown or unsupported. It's a critical error that usually requires verifying the setup of the encryption context.
    
*   `PQC_INTERNAL_ERROR`: Signifies that an internal error occurred during the signing operation. This could be due to various reasons, including failures in the cryptographic library or resources.
    
*   `PQC_BAD_LEN`: Indicates a mismatch in the expected size of the signature. The `signature_len` might not match what is expected by the used algorithm, possibly leading to partial or failed signature writes.
    

#### `PQC_verify`

Function signature:

```cpp
int PQC_verify(  uint32_t cipher,
                const uint8_t* public_key,
                size_t public_keylen,
                const uint8_t* buffer,
                size_t length,
                const uint8_t* signature,
                size_t signature_len);
```


**Purpose**

The primary purpose of `PQC_verify` is to validate a digital signature against a message using the signer's public key. Successful verification indicates that the message has not changed since it was signed and that it was signed by the holder of the corresponding private key.

**Parameters**

*   `cipher`: This parameter identifies the cryptographic algorithm used for the signature. The function supports specific ciphers, such as `PQC_CIPHER_FALCON` for the Falcon signature algorithm, designed to be secure against quantum computer attacks.
    
*   `public_key` (in): A pointer to the public key used for verification. The format and size of this public key must be compatible with the selected cipher. For Falcon, it could be a structured type (`pqc_falcon_public_key`) or a buffer of a specific size (`PQC_FALCON_PUBLIC_KEYLEN`).
    
*   `public_keylen`: The actual length of the public key in bytes. This length must correspond to the expected size for the specified cipher algorithm.
    
*   `buffer` (in): Points to the original message that was signed. The integrity of this message is what's being verified against the signature.
    
*   `length`: Specifies the length of the message in bytes. This should be the exact size of the message data that was originally signed.
    
*   `signature` (in): A pointer to the signature that will be verified against the message and public key. The signature's format and length must align with the used algorithm.
    
*   `signature_len`: Indicates how many bytes long the signature is. This length should match the expected size for signatures generated by the specified cipher.
    

**Return Values**

*   `PQC_OK`: This indicates that the signature verification was successful. Meaning, the signature is valid for the given message and public key, confirming the integrity and authenticity of the message.
    
*   `PQC_BAD_SIGNATURE`: The verification has failed; the provided signature does not match the given message when using the specified public key. This could indicate tampering or misalignment in the verification process.
    
*   `PQC_BAD_CONTEXT`: Suggests that the function encountered an improperly initialized context or parameters not set up correctly, although this specific error is less common in pure verification functions that do not require an extensive context as signing might.
    
*   `PQC_BAD_CIPHER`: The specified cipher algorithm is unknown or unsupported. This indicates that the cipher parameter was not a valid choice or the implementation does not support it.
    
*   `PQC_BAD_LEN`: The length of the public key does not match what is expected by the selected cryptographic cipher. This error might also reference an incorrect signature length in some implementations or descriptions.
    

#### `PQC_close_context`

Function signature:

```cpp
int PQC_close_context(CIPHER_HANDLE ctx);
```


**Purpose**

The primary aim of the `PQC_close_context` function is to clean up and securely release all resources associated with a given cryptographic context. This includes memory, cryptographic keys, and any other data that were allocated or initialized as part of the context.

**Parameters**

*   `ctx`: This is the handle or reference to the encryption context that needs to be closed or freed. The context represented by this handle should have been previously initialized through the library's functions, presumably after completing all required cryptographic operations.
    

**Return Values**

*   `PQC_OK`: Indicates that the operation to close and free the context was successful. This return value assures the caller that all resources have been securely released and that the context handle is no longer valid for use in cryptographic operations.