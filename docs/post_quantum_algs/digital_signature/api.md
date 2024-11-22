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


#### `PQC_keypair_generate`

Function signature:

```cpp
int PQC_keypair_generate(   uint32_t cipher, 
                            uint8_t *public_key, 
                            size_t public_length, 
                            uint8_t *private_key, 
                            size_t private_length);
```

To begin using a post-quantum cryptography algorithm like McEliece for encrypting communications, you first need to generate a pair of public and private keys. The function `PQC_keypair_generate` facilitates this by accepting several parameters:

*   `cipher`: This specifies the algorithm to be used. For instance, `PQC_CIPHER_MCELIECE` is used to indicate that the McEliece cipher will be utilized for the key generation process.
    
*   `public_key` and `private_key` (output parameters): These are pointers to memory locations where the generated keys will be stored. The keys are generated based on the algorithm selected with the `cipher` parameter. For McEliece, specific structures or buffers sized according to `PQC_MCELIECE_PUBLIC_KEYLEN` and `PQC_MCELIECE_PRIVATE_KEYLEN` should be used for public and private keys, respectively.
    
This function uses pseudo-random source provided by PQ17 algorithm with default parameters. It is recommended to use `PQC_context_keypair_generate` instead, as it allows control on source of randomness used for key generation. 


The function returns `PQC_OK` on successful generation, with other codes indicating various failure modes such as unsupported cipher (`PQC_BAD_CIPHER`), incorrect key size (`PQC_BAD_LEN`), or internal errors (`PQC_INTERNAL_ERROR`).

#### `PQC_context_init_asymmetric`

Function signature:

```cpp
CIPHER_HANDLE PQC_API PQC_context_init_asymmetric(uint32_t cipher, uint8_t * public_key, size_t public_size, uint8_t * private_key, size_t private_size);
```

The `PQC_context_init_asymmetric` function initializes an encryption context for further operations like key encoding. The parameters include:

*   `cipher`: Identifies the encryption algorithm to be used. [`Cipher constants`](common_functions.html#cipher)
    
*   `public_key` and `public_size`: Point to the public key and its length, respectively. The key format and length should match the requirements of the selected cipher. Can be null.

*   `private_key` and `private_size`: Point to the private key and its length, respectively. The key format and length should match the requirements of the selected cipher.Can be null.
    
If pointer to a key is null context will be created without corresponding key. This can be usefull when you need only one key for desired operation (i.e. only private key is required to sign document, and only public key is required to verify it). In order to generate a keypair first create a context with both keys not set, and than create a key pair in context by calling `PQC_context_keypair_generate`.

This returns a `CIPHER_HANDLE`, a handle for the created encryption context, unless an error occurs, indicated by return codes such as `PQC_BAD_CIPHER`. Handle should be closed using `PQC_context_close` when it is not required any longer.

#### `PQC_context_keypair_generate`

Function signature:

```cpp
int PQC_context_keypair_generate(CIPHER_HANDLE ctx);
```

To begin using a post-quantum cryptography algorithm like McEliece for encrypting communications, you first need to generate a pair of public and private keys. The function `PQC_context_keypair_generate` facilitates this by accepting several parameters:

*   `ctx`: The encryption context handle.
    
This function uses pseudo-random source selected for given context. If not set, it will use PQ17 algorithm with default parameters. Use `PQC_context_random_set_pq_17` or `PQC_context_random_set_external` to select desired source of randomness. Keys will be stored in context and can be used from there. Otherwise, they can be extracted with `PQC_context_get_keypair` or `PQC_context_get_public_key` functions. If context had keys set before they will be overwritten.

The function returns `PQC_OK` on successful generation, with other codes indicating various failure modes such as unsupported cipher (`PQC_BAD_CIPHER`), external random generator error (`PQC_RANDOM_FAILURE`), or internal errors (`PQC_INTERNAL_ERROR`).

#### `PQC_context_get_keypair`

Function signature:

```cpp
int PQC_context_get_keypair(CIPHER_HANDLE ctx, 
                            uint8_t *public_key, 
                            size_t public_length, 
                            uint8_t *private_key, 
                            size_t private_length);
```

This function can be used to extract both public and private keys from the context. Parameters are:

*   `ctx`: The encryption context handle.
    
*   `public_key` and `private_key` (output parameters): These are pointers to memory locations where the keys will be stored.

* 	`public_length` and `private_length`: Length of buffer available for storing public and private keys repectly. Buffer size should match key size for algorithm used by given context. 
    
The function returns `PQC_OK` on success, with other codes indicating various failure modes such as incorrect context handle (`PQC_BAD_CONTEXT`), incorrect key size (`PQC_BAD_LEN`). If public or private key is not set in context function will return `PQC_KEY_NOT_SET`.

#### `PQC_context_get_public_key`

Function signature:

```cpp
int PQC_context_get_public_key(CIPHER_HANDLE ctx, 
                               uint8_t *public_key, 
                               size_t public_length);
```

This function can be used to extract public key from the context. Parameters are:

*   `ctx`: The encryption context handle.
    
*   `public_key` (output parameter): Pointer to memory location where the public key will be stored.

* 	`public_length`: Length of buffer available for storing public keys. Buffer size should match key size for algorithm used by given context. 
    
The function returns `PQC_OK` on success, with other codes indicating various failure modes such as incorrect context handle (`PQC_BAD_CONTEXT`), incorrect key size (`PQC_BAD_LEN`). If public key is not set in context function will return `PQC_KEY_NOT_SET`.
    

#### `PQC_signature_create`

Function signature:
```cpp
int PQC_signature_create(CIPHER_HANDLE ctx, uint8_t* buffer, size_t length, uint8_t* signature, size_t signature_len);
```

**Purpose**

To create a digital signature for a specified message using a previously initialized encryption context. This context encapsulates the cryptographic settings and should have private key set.

**Parameters**

*   `ctx`: This is a handle to an encryption context that has been initialized earlier. The context must be set up with the correct cipher and private key for signing operations. It represents the state and configurations needed for the cryptographic operation.
    
*   `buffer` (in): A pointer to the start of the message that is to be signed. This message is the input for which the digital signature will be generated. The content here is not modified by the function.
    
*   `length`: The length of the message in bytes. This specifies how much data from `buffer` should be considered for generating the signature.
    
*   `signature` (out): A pointer to a buffer where the generated signature will be stored. The capacity of this buffer needs to be sufficient to hold the signature. For the Falcon algorithm, the signature could follow a specific structure (e.g., `pqc_falcon_signature`) or occupy a buffer sized according to `PQC_FALCON_SIGNATURE_LEN`.
    
*   `signature_len`: Specifies the length of the `signature` buffer. It is critical that this length is correctly set to accommodate the signature generated by the algorithm in use.
    
This function uses pseudo-random source selected for given context. If not set, it will use PQ17 algorithm with default parameters. Use `PQC_context_random_set_pq_17` or `PQC_context_random_set_external` to select desired source of randomness.

**Return Values**

*   `PQC_OK`: Signifies that the operation was successful, and the message was signed without issues. The signature is now stored in the buffer pointed to by `signature`.
    
*   `PQC_BAD_CONTEXT`: Indicates an issue with the provided encryption context (`ctx`). It might not have been properly initialized, which is a prerequisite for signing operations.
    
*   `PQC_BAD_CIPHER`: This error suggests that the cryptographic algorithm (cipher) set in the context is unknown or unsupported. It's a critical error that usually requires verifying the setup of the encryption context.
    
*   `PQC_INTERNAL_ERROR`: Signifies that an internal error occurred during the signing operation. This could be due to various reasons, including failures in the cryptographic library or resources.
    
*   `PQC_BAD_LEN`: Indicates a mismatch in the expected size of the signature. The `signature_len` might not match what is expected by the used algorithm, possibly leading to partial or failed signature writes.
    
*	`PQC_RANDOM_FAILURE`: External random source returns error.

*	`PQC_KEY_NOT_SET`: Private key was not set in context

#### `PQC_signature_verify`

Function signature:

```cpp
int PQC_signature_verify(CIPHER_HANDLE ctx,
                const uint8_t* buffer,
                size_t length,
                const uint8_t* signature,
                size_t signature_len);
```


**Purpose**

The primary purpose of `PQC_signature_verify` is to validate a digital signature against a message using the signer's public key. Successful verification indicates that the message has not changed since it was signed and that it was signed by the holder of the corresponding private key.

**Parameters**

*   `cipher`: This parameter identifies the cryptographic algorithm used for the signature. The function supports specific ciphers, such as `PQC_CIPHER_FALCON` for the Falcon signature algorithm, designed to be secure against quantum computer attacks.
    
*   `ctx`: This is a handle to an encryption context that has been initialized earlier. It should have public key set.
    
*   `buffer` (in): Points to the original message that was signed. The integrity of this message is what's being verified against the signature.
    
*   `length`: Specifies the length of the message in bytes. This should be the exact size of the message data that was originally signed.
    
*   `signature` (in): A pointer to the signature that will be verified against the message and public key. The signature's format and length must align with the used algorithm.
    
*   `signature_len`: Indicates how many bytes long the signature is. This length should match the expected size for signatures generated by the specified cipher.
    

**Return Values**

*   `PQC_OK`: This indicates that the signature verification was successful. Meaning, the signature is valid for the given message and public key, confirming the integrity and authenticity of the message.
    
*   `PQC_BAD_SIGNATURE`: The verification has failed; the provided signature does not match the given message when using the specified public key. This could indicate tampering or misalignment in the verification process.
    
*   `PQC_BAD_CONTEXT`: Suggests that the function encountered an improperly initialized context or parameters not set up correctly.
    
*	`PQC_BAD_CIPHER`: Function was called for context configured with algorithm that do not support digital signature operations.	

*   `PQC_BAD_LEN`: The length of the public key does not match what is expected by the selected cryptographic cipher. This error might also reference an incorrect signature length in some implementations or descriptions.
    
*	`PQC_KEY_NOT_SET`: Public key was not set in context	
	
*   `PQC_INTERNAL_ERROR`: Signifies that an internal error occurred during the signing operation. This could be due to various reasons, including failures in the cryptographic library or resources.	

#### `PQC_context_close`

Function signature:

```cpp
int PQC_context_close(CIPHER_HANDLE ctx);
```


**Purpose**

The primary aim of the `PQC_context_close` function is to clean up and securely release all resources associated with a given cryptographic context. This includes memory, cryptographic keys, and any other data that were allocated or initialized as part of the context.

**Parameters**

*   `ctx`: This is the handle or reference to the encryption context that needs to be closed or freed. The context represented by this handle should have been previously initialized through the library's functions, presumably after completing all required cryptographic operations.
    

**Return Values**

*   `PQC_OK`: Indicates that the operation to close and free the context was successful. This return value assures the caller that all resources have been securely released and that the context handle is no longer valid for use in cryptographic operations.