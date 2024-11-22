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
    
If pointer to a key is null context will be created without corresponding key. This can be usefull when you need only one key for desired operation (i.e. only one key is required on either side of KEM algorithms). In order to generate a keypair first create a context with both keys not set, and than create a key pair in context by calling `PQC_context_keypair_generate`.

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

#### `PQC_kem_encapsulate`

Function signature:

```cpp
int PQC_kem_encapsulate(CIPHER_HANDLE ctx, 
                    uint8_t* message, 
                    size_t message_length, 
                    const uint8_t* party_a_info, 
                    size_t info_length, 
                    uint8_t* shared_key, 
                    size_t shared_key_length);
```

This function is a part of the key encapsulation process, where a shared key for encryption is derived and a message for the other party is generated using their public key. The parameters guide the function on how to generate these items:

*   `cipher`: Selects the encryption algorithm.

*	`party_a_info` and `info_length`: Extra information to be used in encapsulation.
    
*   `message` and `shared_key` (output parameters): Pointers to buffers where the generated message and shared key will be stored.
    
*   `public_key`: The public key of the receiving party.

This function uses pseudo-random source selected for given context. If not set, it will use PQ17 algorithm with default parameters. Use `PQC_context_random_set_pq_17` or `PQC_context_random_set_external` to select desired source of randomness.
    
The return code `PQC_OK` denotes success, with other codes specifying potential errors, which can include:
*	`PQC_BAD_CONTEXT`: Wrong context (invalid value of `ctx`)
*	`PQC_BAD_CIPHER`: algorithm selected for context does not support KEM operation.
*	`PQC_KEY_NOT_SET`: Public key was not set in context
*	`PQC_BAD_LEN`: `message_length` or `shared_key_length` do not match expected length for selected algorithm
*	`PQC_RANDOM_FAILURE`: External random source returns error 
*	`PQC_INTERNAL_ERROR`: Other errors`


#### `PQC_kem_decapsulate`

Function signature:

```cpp
int PQC_kem_decapsulate(CIPHER_HANDLE ctx, 
                    const uint8_t* message, 
                    size_t message_length, 
                    const uint8_t* party_a_info, 
                    size_t info_length, 
                    uint8_t* shared_key, 
                    size_t shared_key_length);
```

This complements `PQC_kem_encapsulate`, allowing the receiver to derive the shared encryption key from the message they received. This operation requires private key to be set for context. Arguments are:

*   `ctx`: The encryption context handle.
    
*   `message` and `message_length`: The message received from the sender.

*	`party_a_info` and `info_length`: Extra information used in encapsulation.

*	`shared_key` (output parameter): Pointer to buffer where derived shared key will be saved.

*	`shared_key_length`: Length of buffer available for shared key. Should match expected key size for selected algorithm. 

Successful operation returns `PQC_OK`, with failure modes similarly denoted by specific return codes:
*	`PQC_BAD_CONTEXT`: Wrong context (invalid value of `ctx`)
*	`PQC_BAD_CIPHER`: algorithm selected for context does not support KEM operation.
*	`PQC_KEY_NOT_SET`: Private key was not set in context
*	`PQC_BAD_LEN`: `message_length` or `shared_key_length` do not match expected length for selected algorithm
*	`PQC_INTERNAL_ERROR`: Other errors

#### `PQC_kem_encapsulate_secret`

Function signature:

```cpp
size_t PQC_API PQC_kem_encapsulate_secret(CIPHER_HANDLE ctx, 
                                       uint8_t* message, 
                                       size_t message_length, 
                                       uint8_t * shared_secret, 
                                       size_t shared_secret_length);
```

This function generates a shared secret key using a given encryption algorithm, a message, and a pre-generated public key. The message is then intended to be sent to the second user, who owns the public key, for decryption.

*   `ctx`: The encryption context handle. 
    
*   `uint8_t * message`, `size_t message_length`: A pointer to the memory area for the message and its length. The message, which contains ciphertext encrypted with the public key, will be written here to be sent to the other party.
    
*   `const uint8_t * public_key`, `size_t publickey_length`: A pointer to the memory area for the public key and its length. The public key must be pre-generated and will be used to encrypt the message.
*   
*   `uint8_t * shared_secret`, `size_t shared_secret_length`: A pointer to the memory area for the shared secret and its length. The shared secret, generated after executing the function, will be written here.

This function uses pseudo-random source selected for given context. If not set, it will use PQ17 algorithm with default parameters. Use `PQC_context_random_set_pq_17` or `PQC_context_random_set_external` to select desired source of randomness.

The return code `PQC_OK` denotes success, with other codes specifying potential errors.

The return code `PQC_OK` denotes success, with other codes specifying potential errors, which can include:
*	`PQC_BAD_CONTEXT`: Wrong context (invalid value of `ctx`)
*	`PQC_BAD_CIPHER`: algorithm selected for context does not support KEM operation.
*	`PQC_KEY_NOT_SET`: Public key was not set in context
*	`PQC_BAD_LEN`: `message_length` or `shared_key_length` do not match expected length for selected algorithm
*	`PQC_RANDOM_FAILURE`: External random source returns error 
*	`PQC_INTERNAL_ERROR`: Other errors

#### `PQC_kem_decapsulate_secret`

Function signature:

```cpp
size_t PQC_kem_decapsulate_secret(  CIPHER_HANDLE ctx, 
                    const uint8_t* message, 
                    size_t message_length, 
                    uint8_t * shared_secret,
                    size_t shared_secret_length);
```

his function complements PQC_kem_encapsulate_secret, enabling the receiver to derive the shared encryption key from the received message. It requires private key to be set in encryption context.

- `ctx`: The encryption context handle.
- `message`: A pointer to the message received from the sender.
- `message_length`: The length of the received message.
- `shared_secret`: A pointer to the memory area for the shared secret.
- `shared_secret_length`: The length of the shared secret.
    
Successful operation returns `PQC_OK`, with failure modes similarly denoted by specific return codes:
*	`PQC_BAD_CONTEXT`: Wrong context (invalid value of `ctx`)
*	`PQC_BAD_CIPHER`: algorithm selected for context does not support KEM operation.
*	`PQC_KEY_NOT_SET`: Private key was not set in context
*	`PQC_BAD_LEN`: `message_length` or `shared_key_length` do not match expected length for selected algorithm
*	`PQC_INTERNAL_ERROR`: Other errors

#### `PQC_context_close`

Function signature:

```cpp
int PQC_context_close(CIPHER_HANDLE ctx);
```

To conclude operations and free resources, `PQC_context_close` is used.

*   `ctx`: The encryption context handle to be closed.
    

On successful closure, `PQC_OK` is returned.
