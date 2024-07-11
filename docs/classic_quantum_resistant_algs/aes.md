---
layout: default
title: AES-256
parent: Classic Quantum-Resistant Algorithms
nav_order: 1
---

# Overview
{: .no_toc }

<details open markdown="block">
  <summary>
    Table of contents
  </summary>
  {: .text-delta }
1. TOC
{:toc}
</details>

*   **Algorithm type**: Quantum-resistant algorithm, symmetric key encryption algorithm
    
*   **Main cryptographic assumption**: The difficulty of performing a successful brute force attack to decipher encrypted data without knowledge of the correct encryption key
    
*   **Principal submitters**: [Joan Daemen](https://en.wikipedia.org/wiki/Joan_Daemen) and [Vincent Rijmen](https://en.wikipedia.org/wiki/Vincent_Rijmen)

*   **License**: For AES ECB, AES CBC and AES CTR the following provision applies to this part of the software as an additional term to the license:
This code is based on the code of Tiny AES in C (https://github.com/kokke/tiny-AES-c). Tiny AES in C is subject to the Unlicense and released into the public domain (https://unlicense.org/).
    

AES-256 is a variant of the Advanced Encryption Standard (AES) algorithm that uses a 256-bit key length. It is one of the most secure encryption methods and is often used in government and industry applications. AES operates on a fixed block size of 128 bits and with key sizes of 128, 192, or 256 bits, but in the case of AES-256, the key size as mentioned is 256 bits.

The encryption modes are methods that describe how to repeatedly apply the cipher's single-block operation to securely transform amounts of data larger than a block. Different modes are used for different applications, offering various levels of security and efficiency based on the use case.

*  **Electronic Codebook (ECB)**: This is the simplest encryption mode. Each block of plaintext is encrypted separately. This can lead to patterns in the ciphertext when identical blocks of plaintext are encrypted, making ECB susceptible to certain attacks (e.g., pattern analysis).
    
*  **Cipher Block Chaining (CBC)**: CBC mode adds an initialization vector (IV) to the first data block before the encryption process starts. Each subsequent block of plaintext is XORed (exclusive OR) with the previous ciphertext block before being encrypted. This means that identical plain text blocks will produce different ciphertext blocks. The IV ensures that even if the same message is encrypted multiple times, it will result in different ciphertexts.
    
*  **Output Feedback (OFB)**: OFB converts a block cipher into a synchronous stream cipher. It generates keystream blocks, which are then XORed with the plaintext blocks to produce ciphertext. The same keystream blocks are used to decrypt ciphertext back to plaintext. OFB ensures that the same plaintext inputs will result in different ciphertext outputs.
    
* **Counter (CTR)**: Like OFB, CTR turns a block cipher into a stream cipher. It encrypts a set of counter values and then XORs the resulting output with the plaintext to generate the ciphertext. The counter is increased by one for every subsequent block and must be unique for each encryption operation. CTR mode is known for its ability to allow random access to the encrypted data blocks.
    

Each of these modes has a specific use case where it excels and others where it may be susceptible. Modern practices typically favor modes like CTR over ECB and CBC due to their stronger security properties and performance benefits, particularly in settings susceptible to parallel processing.

Quantum resistance
------------------

AES-256 is considered to be [quantum](https://en.wikipedia.org/wiki/Quantum_computing) resistant, as it has similar quantum resistance to AES-128's resistance against traditional, non-quantum, attacks at 128 [bits of security](\"https://en.wikipedia.org/wiki/Bits_of_security\"). AES-192 and AES-128 are not considered quantum resistant due to their smaller key sizes. AES-192 has a strength of 96 bits against quantum attacks and AES-128 has 64 bits of strength against quantum attacks, making them both insecure.

NIST
----

The NIST certification for AES (Advanced Encryption Standard) refers to the validation process overseen by the Cryptographic Algorithm Validation Program (CAVP), which is part of the NIST (National Institute of Standards and Technology). AES itself, specified under the publication FIPS (Federal Information Processing Standards) 197, is an encryption standard approved by NIST in 2001 for securing sensitive but unclassified material by U.S. government agencies and, by extension, for other organizations.

- [FIPS 197, Advanced Encryption Standard (AES)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf)
- [Advanced Encryption Standard (AES)](https://www.nist.gov/publications/advanced-encryption-standard-aes-0)


API overview
------------

Include: `pqc/aes.h`

### `PQC_init_context`

**Function signature**

```cpp
CIPHER_HANDLE PQC_init_context(uint32_t cipher, const uint8_t* key, size_t key_length);
```

**Purpose**: This function is used to initialize an encryption context for a specific cipher with a given encryption key.

**Parameters**:

*   `cipher`: Constant to select a cipher algorithm. In this case, the possible value is `PQC_CIPHER_AES` for AES-256.
    
*   `key`: Pointer to the encryption key. The key length should match the used cipher, which for AES-256 should be 32 bytes.
    
*   `key_length`: Length of the encryption key.


### `PQC_init_context_iv`

**Function signature**

```cpp
CIPHER_HANDLE PQC_init_context_iv(uint32_t cipher, const uint8_t* key, const uint8_t* iv, size_t iv_length);
```

**Purpose**: This function is similar to `PQC_init_context`, but it also allows for the initialization vector (IV) to be specified, if required by the desired operation mode.

**Parameters**:

*   `cipher`: Constant to select a cipher algorithm, same as in `PQC_init_context`.
    
*   `key`: Pointer to the encryption key, same as in `PQC_init_context`.
    
*   `iv`: Pointer to the initialization vector. IV length should match the used cipher, which for AES-256 should be 16 bytes.
    
*   `iv_length`: Length of the IV.
    

For both functions, the return values are specified as follows:

*   `PQC_BAD_CIPHER`: Indicates an unknown/unsupported cipher or incorrect size of the key/IV.
    
*   Otherwise: Returns the handle of the created encryption context.

### `PQC_set_iv`

**Function signature**

```cpp
int PQC_set_iv(CIPHER_HANDLE ctx, const uint8_t* iv, size_t iv_length);
```

**Purpose**: This function is used to set the initialization vector for an initialized encryption context if it was not provided during the initialization with `PQC_init_context_iv()`.

**Parameters**:

*   `ctx`: Handle of the initialized encryption context.
    
*   `iv`: Pointer to the initialization vector. The IV length should match the requirements of the used cipher, for example, 16 bytes for AES-256.
    
*   `iv_length`: Length of the IV.
    

The function returns the following values:

*   `PQC_OK`: Indicates that the operation was successful, and the IV was set for the encryption context.
    
*   `PQC_BAD_CONTEXT`: Indicates that the context was not properly initialized, suggesting an issue with the encryption context handle.
    
*   `PQC_BAD_CIPHER`: This return value indicates that the cipher used does not require an IV.
    
*   `PQC_BAD_LEN`: Indicates that the length of the provided IV does not match the requirements of the cipher.
    

The provided code snippet describes a function for encrypting data using an initialized encryption context. Let's break down the purpose and usage of the given function and its parameters.

### `PQC_encrypt`

**Function signature:**

```cpp
int PQC_encrypt(CIPHER_HANDLE ctx, uint32_t mode, uint8_t* buffer, size_t length);
```

**Purpose**: This function is used to encrypt data using the specified encryption context and encryption mode.

**Parameters**:

*   `ctx`: Handle of the initialized encryption context.
    
*   `mode`: Constant to select the encryption mode. The possible values depend on the selected cipher. For PQC\_CIPHER\_AES, the available modes are PQC\_AES\_M\_ECB, PQC\_AES\_M\_CBC, and PQC\_AES\_M\_OFB.
    
*   `buffer` (in/out): Pointer to the data array. The data is encrypted in place within the same buffer.
    
*   `length`: Length of the data buffer.
    

The function returns the following values:

*   `PQC_OK`: Indicates that the operation was successful, and the data was encrypted.
    
*   `PQC_BAD_CONTEXT`: Indicates that the context was not properly initialized, suggesting an issue with the encryption context handle.
    
*   `PQC_BAD_LEN`: Indicates that the length of the data does not match the requirements for the selected cipher/mode.
    
*   `PQC_NO_IV`: Indicates that an initialization vector is required for the selected cipher/mode, but it was not set.
    
*   `PQC_BAD_MODE`: Indicates that the mode parameter provided is invalid.
    
*   `PQC_BAD_CIPHER`: Indicates that the selected cipher does not support symmetric encryption.
    

### `PQC_decrypt`

**Function signature:**

```cpp
int PQC_decrypt(CIPHER_HANDLE ctx, uint32_t mode, uint8_t* buffer, size_t length);
```

**Purpose**: This function is used to decrypt data using the specified encryption context and encryption mode.

**Parameters**:

*   `ctx`: Handle of the initialized encryption context.
    
*   `mode`: Constant to select the encryption mode. The possible values depend on the selected cipher. For PQC\_CIPHER\_AES, the available modes are PQC\_AES\_M\_ECB, PQC\_AES\_M\_CBC and PQC\_AES\_M\_OFB.
    
*   `buffer` (in/out): Pointer to the data array. The data is decrypted in place within the same buffer.
    
*   `length`: Length of the data buffer.
    

The function returns the following values:

*   `PQC_OK`: Indicates that the operation was successful, and the data was decrypted.
    
*   `P_BAD_CONTEXT`: Indicates that the context was not properly initialized, suggesting an issue with the encryption context handle.
    
*   `PQC_BAD_LEN`: Indicates that the length of the data does not match the requirements for the selected cipher/mode.
    
*   `PQC_NO_IV`: Indicates that an initialization vector is required for the selected cipher/mode, but it was not set.
    
*   `PQC_BAD_MODE`: Indicates that the mode parameter provided is invalid.
    
*   `PQC_BAD_CIPHER`: Indicates that the selected cipher does not support symmetric encryption.
    

### `PQC_close_context`

**Function signature:**

```cpp
int PQC_close_context(CIPHER_HANDLE ctx);
```

**Purpose**: This function is used to release resources associated with an initialized encryption context when it is no longer needed.

**Parameters**:

*   `ctx`: Handle of the initialized encryption context.
    

The function returns the following value:

*   `PQC_OK`: Indicates that the operation to release the resources associated with the context was successful.
    

Examples
--------

### AES CBC

```cpp
{% include examples/aes/aes_cbc_example.cpp %}
```

### AES CTR

```cpp
{% include examples/aes/aes_ctr_example.cpp %}
```

### AES ECB

```cpp
{% include examples/aes/aes_ecb_example.cpp %}
```

### AES OFB

```cpp
{% include examples/aes/aes_ofb_example.cpp %}
```
