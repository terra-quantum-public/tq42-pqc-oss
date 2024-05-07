---
layout: default
title: Randomness Source
parent: Keys Management
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

The library currently supports various sources of randomness, with plans to integrate a paid option to access a Single Photon Quantum Random Number Generator (QRNG) in a future version. This cutting-edge feature will guarantee unparalleled unpredictability derived directly from quantum phenomena. Terra Quantum offers advanced quantum security products, including the Terra Quantum Secure Network (TQSN), a novel solution for organizations looking for full security via Quantum Key Distribution (QKD), a revolutionary technology that leverages the quantum mechanical properties of light and allows for the distribution of cryptographic keys with absolute security, making decryption impossible. Terra Quantum's patented Secure Network solution (TQSN) works well over long distances with high bit rates. It is the world's first scalable, zero-trust Secure Network for global communications. Visit [terraquantum.swiss](https://terraquantum.swiss) to learn more, or contact us at info@terraquantum.swiss.


Randomness Source - PQ17
-------------------------

A PRNG, or pseudorandom number generator, is an algorithm that generates a sequence of numbers whose properties approximate the properties of sequences of random numbers. PRNG is a deterministic algorithm that uses mathematical formulas or precalculated tables to produce sequences of numbers that seem random. PRNGs are typically used in various applications, including simulation, statistics, cryptography, and in algorithm development where random number generation is required. A cryptographic PRNG, which is a specific type of PRNG, also ensures that the output is unpredictable, provided that the initial seed (starting value of the sequence) is not known, thus making it suitable for applications in security where unpredictability is essential.

Algorithm
---------

- PQ17 is a proprietary PRNG based on X9.17.

- PQ17 is a pseudorandom number generator that uses elements of the system clock, the SHA-3 cryptographic hash function, and the AES block cipher in Output Feedback (OFB) mode to generate random numbers.

- Here's a step-by-step explanation:

    * **Timestamp Extraction**: The current time is obtained from the system clock through `std::chrono::system_clock::now()`. This time point is used to acquire entropy, which is necessary to initialize the randomness.
    
    * **Timestamp Conversion**: The current time, which is a `time_point`, is converted into two 64-bit integers which are stored in the array `dt`.
    
    * **SHA-3 Hashing**: The first of these integers, `dt[0]`, is then fed into the SHA-3 hashing function. The SHA-3 algorithm processes the input and produces a hash, which is considered to have properties of good randomness due to its cryptographic nature.
    
    * **Hash Truncation and Reuse**: The resulting hash is then truncated, taking a portion of the hash and overwriting the original elements of `dt` with this truncated hash data. This step is essential to mix the entropy and reduce predictability.
    
    * **Initial AES Encryption**: The array `dt` is then encrypted using the AES block cipher in OFB mode. This mode of operation turns a block cipher into a stream cipher, producing a keystream that is then XORed with the plaintext—in this case, the data in `dt`.
    
    * **XOR with Internal State**: After the encryption, the `dt` array is XORed with an internal state array `v`. The result of this XOR is stored in a new array `r`.
    
    * **Second AES Encryption**: The `r` array is encrypted again using AES in OFB mode.
    
    * **Update Internal State**: The internal state `v` is updated by XORing `r` with the previously modified `dt`. This is an essential step for updating the state and ensuring that subsequent outputs of the PRNG are different.
    
    * **Final AES Encryption**: Lastly, the updated state `v` is encrypted again using AES in OFB mode.
    
The final output of the PRNG will be taken from one of these encrypted buffers. This mixing of entropy sources (current time and internal state), along with repeated cryptographic transformations (SHA-3 hashing and AES encryption), is designed to produce a sequence of numbers that is very difficult to predict unless the initial seed (the internal state `v` and the initial timestamp) and the cryptographic key used for AES are both known.

This approach to constructing a PRNG is considered strong due to the cryptographic operations involved, which should theoretically yield good randomness properties suitable for various applications, including cryptographic functions, assuming the implementations of SHA-3 and AES are secure and no side-channel vulnerabilities exist.

API
---
Include `pqc/random.h`


### `PQC_random_from_pq_17`

is used to select the PQ17 PRNG as the randomness source for the library:

**Function signature:**

```cpp
int PQC_random_from_pq_17(const uint8_t* key, size_t key_len, const uint8_t* iv, size_t iv_len);
```

This function initializes the PQ17 pseudo-random number generator with a specified AES (Advanced Encryption Standard) key and initialization vector (IV).

**Parameters:**

*   `key`: This is a pointer to the memory location where the AES key is stored, which the PQ17 algorithm will use. This should either point to a `pqc_aes_key` structure or a buffer of size `PQC_AES_KEYLEN`, which is defined as 32 bytes (256 bits).
    
*   `key_len`: This is the size of the AES key. For the PQ17 algorithm, this size should be `PQC_AES_KEYLEN` or 32 bytes.
    
*   `iv`: This is a pointer to the memory location of the AES initialization vector that the PQ17 algorithm will use. It should point to a `pqc_aes_iv` structure or a buffer of size `PQC_AES_IVLEN`, which is 16 bytes (128 bits).
    
*   `iv_len`: This is the size of the AES initialization vector. It should be `PQC_AES_IVLEN` or 16 bytes.
    

**Return values:**

*   `PQC_OK`: Indicates the operation was successful and the PQ17 pseudo-random generator was initialized correctly.
    
*   `PQC_BAD_LEN`: Indicates that an invalid length for either the key or the IV was passed to the function. The valid lengths are 32 bytes for the key and 16 bytes for the IV [1](\"https://www.geeksforgeeks.org/pseudo-random-number-generator-prng/\") .
    

The initialization of the PRNG with `PQC_random_from_pq_17` influences the randomness source for subsequent operations within the library that require random data.

### `PQC_random_from_external`

is used to set custom RNG as the randomness source for the library:

```cpp
void PQC_random_from_external(void (* _get_external_random)(uint8_t * buf, size_t size) get_ext_random);
```    

**Parameters:**

*   `get_ext_random`: This is a pointer to the function which will be called for random bytes generation. On each call that function should fill the provided buffer `buf` with random bytes for the specified length `size`. 


The initialization of the PRNG with `PQC_random_from_external` influences the randomness source for subsequent operations within the library that require random data.

### `PQC_random_bytes`
is used to obtain random bytes from the currently selected random number generator:

```cpp
void PQC_random_bytes(void* buffer, size_t length);
```    

**Parameters:**

*   `buffer`: This is a pointer to the buffer where the random bytes will be stored.
    
*   `length`: This indicates the number of random bytes that should be written to the buffer.
    

The function fills the provided buffer with random bytes for the specified length. These bytes could be used for various cryptographic operations requiring randomness such as key generation or nonces.

The random number generator provided by TQ42 Cryptography is not inherently thread-safe, meaning that simultaneous access by multiple threads could lead to unpredictable results. In a multi-threaded program, the caller is responsible for ensuring that access to the random number generator is properly synchronized, such as through the use of mutexes or other synchronization mechanisms.

Example
-------

**Code**

```cpp
{% include examples/prng/prng_example.cpp %}
```
    
