---
layout: default
title: SHA-3
parent: Classic Quantum-Resistant Algorithms
nav_order: 2
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

SHA-3 (Secure Hash Algorithm 3) is the latest member of the Secure Hash Algorithm family, released by the National Institute of Standards and Technology (NIST) on **August 5, 2015**. While belonging to the same series of standards that includes SHA-0, SHA-1, and SHA-2, SHA-3 is internally different and does not share the MD5-like structure that SHA-1 and SHA-2 have.

The SHA-3 family of hashing algorithms was developed through a public competition and is based on the Keccak algorithm, which was designed by a team led by cryptographer Guido Bertoni and includes Joan Daemen, Michaël Peeters, and Gilles Van Assche. Keccak won the NIST competition to become the SHA-3 standard.

SHA-3 functions as a cryptographic hash function that takes an input with unfixed size (or 'message') and produces a fixed-size string of bytes, which is typically a 'digest'. Hash functions are deterministic in nature, meaning the same input will always result in the same hash value. They are also designed to be one-way functions, making it computationally infeasible to reverse or to find two different inputs that produce the same hash value (resistance to collisions).

The SHA-3 standard as defined in FIPS 202 includes a variety of functions catering to different applications:

*   SHA-3-224
    
*   SHA-3-256
    
*   SHA-3-384
    
*   SHA-3-512
    
*   SHAKE128 and SHAKE256, which are extendable-output functions (XOFs)
    

Cryptographic hash functions like SHA-3 are vital in the realm of information security. They are used for data integrity checks, digital signatures, proof-of-work systems in cryptocurrencies, and in many other scenarios where a secure and reliable method of hashing is required.

NIST
----

SHA-3 was formally standardized by NIST in FIPS PUB 202 in August 2015. It is an official member of the Secure Hash Algorithm (SHA) family, which is widely recognized and used for cryptographic applications to ensure data integrity and authentication.

  - [NIST Special Publication 800-185](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf)

*   [FIPS 202](https://csrc.nist.gov/pubs/fips/202/final)
    
*   [NIST Releases SHA-3](https://www.nist.gov/news-events/news/2015/08/nist-releases-sha-3-cryptographic-hash-standard)
        

API Overview
------------

Include: pqc/sha3.h

### `PQC_init_context_hash`

**Function Signature:**


```cpp
    CIPHER_HANDLE PQC_init_context_hash(uint32_t algorithm, uint32_t mode);
```

**Purpose:**

*   The function initializes a hashing context for a specified cryptographic hash algorithm and mode.
    

**Parameters:**

*   `algorithm`: This is a constant that determines which hashing algorithm to use. In this case, the option provided is `PQC_CIPHER_SHA3`, which indicates SHA-3, a secure hash algorithm.
    
*   `mode`: parameter defines the operational mode of the algorithm. It must be assigned one of the following values to specify the desired cryptographic strength and function: PQC_SHA3_224, PQC_SHA3_256, PQC_SHA3_384, PQC_SHA3_512, with alternatives including PQC_SHAKE_128 or PQC_SHAKE_256 for variable output lengths.
    

**Return Values:**

*   `PQC_BAD_CIPHER`: This is an error code returned if an unknown, unsupported cipher is specified, or if there is another issue such as an incorrect size of a private key.
    
*   Otherwise: The function returns a "handle" to the created encryption context.
    

### `PQC_add_data`

**Function Signature:**


```cpp
    int PQC_add_data(CIPHER_HANDLE ctx, uint8_t* buffer, size_t length);
```

**Purpose:**

*   The function's purpose is to process data for hashing, using the initialized cryptographic context referred to by `ctx`.
    

**Parameters:**

*   `ctx`: This is the cryptographic context handle which would have been initialized by a previous call to a setup function (like `PQC_init_context_hash`).
    
*   `buffer` (input): This is a pointer to a block of data to be processed. The data type `uint8_t*` implies that it is a pointer to an array of bytes, since `uint8_t` is typically defined as an unsigned 8-bit integer, representing a byte.
    
*   `length`: This is the size of the `buffer` array, indicating how much data (in bytes) from the buffer should be processed by this call to `PQC_add_data`.
    

**Return Values:**

*   `PQC_OK`: The operation was successful.
    
*   `PQC_BAD_CIPHER`: An error code indicating an issue with the cryptographic context, such as an unknown or unsupported cipher algorithm. This likely means that the context referred to by `ctx` was not properly initialized with a supported cipher.
    

The caller should check the return value after each call to this function to ensure the data was processed correctly. `PQC_add_data` function is being used for hashing data with SHA-3, the typical sequence would involve initializing a context with `PQC_init_context_hash`, calling `PQC_add_data` one or multiple times to process the data chunks, and subsequently finalizing the hash computation.

### `PQC_hash_size`

**Function Signature:**

```cpp
    unsigned int PQC_hash_size(CIPHER_HANDLE ctx);
```    

**Purpose:**

*   The function is used to query the size of the hash that the cryptographic context, identified by `ctx`, is configured to produce. This is useful for determining the amount of space required to store the hash or for validating that the context is set up correctly.
    

**Parameters:**

*   `ctx`: This is a handle to the initialized encryption context. This context should have been previously set up for a hash operation, likely by a call to a function like `PQC_init_context_hash`.
    

**Return Values:**

*   `0`: This indicates an error condition. There are two scenarios where this could be returned: if the hashing context has not been initialized (meaning `ctx` does not reference a valid context), or if the `ctx` refers to an incorrect type that doesn't support the hash size retrieval operation. Additionally, in the case where the context is initialized with one of the SHAKE modes (`SHAKE128` or `SHAKE256`), the function also returns `0` to indicate that the hash size is not fixed and can be chosen by the user during the final hash output generation.
    
*   Otherwise: The function returns the size of the expected hash output in bytes if the context is set up with one of the fixed-size SHA-3 hash modes (`SHA3-224`, `SHA3-256`, `SHA3-384`, or `SHA3-512`). These figures correspond to the hash output sizes of 224 bits (28 bytes), 256 bits (32 bytes), 384 bits (48 bytes), and 512 bits (64 bytes), respectively.
    

Understanding the size of the output is crucial, especially when allocating memory to hold the hash result or when interfacing with other systems that expect a hash of a specific size. In the case of SHAKE modes, since the output size is variable, the size value returned by this function is not useful other than to indicate that the context has been correctly set up for a SHAKE mode (since it returns `0` for these modes).

### `PQC_get_hash`

**Function Signature:**

```cpp
    int PQC_get_hash(CIPHER_HANDLE ctx, uint8_t* hash, size_t hash_length);
```

**Purpose:**

*   The function finalizes the hashing process and stores the resulting hash value into a provided buffer.
    

**Parameters:**

*   `ctx`: This is the handle to an encryption context that has been previously initialized, presumably for performing hash operations.
    
*   `hash` (output): This is a pointer to a buffer where the hash value will be stored. The buffer must be allocated by the caller before this function is called.
    
*   `hash_length`: This parameter specifies the length of the hash buffer provided. If `ctx` is configured for one of the fixed-size SHA-3 hash modes, this length should match the size returned by `PQC_hash_size`. If `ctx` is configured for one of the SHAKE modes, the length can be any positive value, as these modes support variable output lengths.

**Return Values:**

*   `PQC_OK`: Indicates that the operation was successful and the hash value has been stored in the provided buffer.
    
*   `PQC_BAD_CIPHER`: The error code returned if the cipher related to the context is unknown or unsupported.
    
*   `PQC_BAD_LEN`: This error is returned if the hash buffer length (`hash_length`) does not match the expected size of the hash, as determined by the context's configuration.
    

The description clarifies that you can interleave calls to `PQC_add_data` (which adds data to be hashed) with `PQC_get_hash`. No matter how many times `PQC_add_data` has been called, each invocation of `PQC_get_hash` will produce a hash for all the data added to the context since its creation.

**Usage Notes**:

* Before calling `PQC_get_hash`, data should have been added to the context using `PQC_add_data`.
    
* The buffer pointed to by `hash` should be of appropriate size to store the hash. This means you should either:
    *   Use `PQC_hash_size` to obtain the fixed hash size for SHA-3 variants and allocate the buffer accordingly or,
    *   Choose an arbitrary positive `hash_length` for SHAKE variants, depending on how many bytes of the hash you require.
        
* You should handle the returned value by checking for errors (`PQC_BAD_CIPHER`, `PQC_BAD_LEN`) and ensuring successful operation (`PQC_OK`).
    

Each call to `PQC_get_hash` effectively gives a snapshot of the cumulative hash of the data processed by the context up to that point. The operation's correctness relies on the proper sequence of calls, correct buffer sizes, and the monitoring of return values for error handling.

### `PQC_close_context`

**Function Signature:**
```cpp
    int PQC_close_context(CIPHER_HANDLE ctx);
 ```   

**Purpose:**

*   The purpose of this function is to deallocate the encryption context referred to by `ctx`. Once a cryptographic operation is completed, it is important to properly release any dynamically allocated memory or other resources to prevent memory leaks and ensure that sensitive information is not left in memory longer than necessary.
    

**Parameters:**

*   `ctx`: This is a handle to an initialized encryption context that has been previously created and used for cryptographic operations such as hashing or encryption.
    

**Return Values:**

*   `PQC_OK`: This indicates that the operation was successful, signaling that the context has been closed and all associated resources have been freed.
    

By calling `PQC_close_context`, users ensure that their program behaves responsibly with system resources. It is a standard best practice for C, which don't have automatic garbage collection, that every resource allocated should be paired with a corresponding deallocation.

**Usage Notes**:

* You should only call `PQC_close_context` once for each initialized context. Attempting to free an already freed context can lead to undefined behavior, including crashes.
    
* After `PQC_close_context` has been called with a particular context handle, that handle should not be used again unless it is reassigned by re-initializing a new context.
    

Example
-------

### Const size SHA-3


```cpp
{% include examples/sha3/const_size_sha3_example.cpp %}
```
    
### Shake SHA-3 example

```cpp
{% include examples/sha3/shake_sha3_example.cpp %}
```
