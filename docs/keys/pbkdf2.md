---
layout: default
title: PBKDF2
parent: Keys Management
nav_order: 4
---

Overview
--------
{: .no_toc }

<details open markdown="block">
  <summary>
    Table of contents
  </summary>
  {: .text-delta }
1. TOC
{:toc}
</details>

PBKDF2, which stands for Password-Based Key Derivation Function 2, is a cryptographic algorithm designed to transform a password into a cryptographic key. It is widely used in applications that require secure password hashing and key generation, such as password storage, encryption key derivation, and digital signing. 


NIST
----

[https://csrc.nist.gov/News/2023/proposal-to-revise-nist-sp-800-132-pbkdf](https://csrc.nist.gov/News/2023/proposal-to-revise-nist-sp-800-132-pbkdf)

PBKDF2 (Password-Based Key Derivation Function 2) is recognized and standardized by the National Institute of Standards and Technology (NIST). NIST provides guidelines and recommendations on the use of PBKDF2 for secure password storage and key derivation. The relevant standards and publications include: **Recommendation for Password-Based Key Derivation**, **Authentication and Lifecycle Management**, **Salt and Key Length**, **Iteration Count**, **Hash Function**.

PBKDF2 Implementation
-----------------------------------

**Initial Hashing**: The password and salt are concatenated and hashed using a pseudorandom function (usually HMAC-SHA-1, HMAC-SHA-256, or another HMAC-based hash function).

**Iteration Process**: The resulting hash is repeatedly fed back into the hash function along with the original password and salt for the specified number of iterations.

**Final Output**: The final output after all iterations is the derived key, which can be used for cryptographic purposes such as encryption or as a secure password hash for storage.

  
PBKDF2 is standardized in RFC 8018 and widely implemented in many cryptographic libraries and frameworks. It is a recommended practice for password hashing due to its resistance to various attack vectors and its configurability in terms of security parameters.

API
----
### `PQC_pbkdf_2`

Include `pqc/pbkdf2.h`

The `PQC_pbkdf_2` function  is used for securely deriving cryptographic keys from passwords.

**Function signature:**

```cpp
size_t PQC_API PQC_pbkdf_2(
    int mode, size_t hash_length, size_t password_length, const uint8_t * password, size_t key_length,
    uint8_t * master_key, size_t master_key_length, uint8_t * salt, size_t salt_length, size_t iterations
)
```


**Parameters:**
*   `mode`:  Additional mode specifier which should always be set to **PQC_PBKDF2_HMAC_SHA3** as per the requirement.
*   `hash_length`:  The length of the hash.
*   `password_length`: The length of the password.
*   `password`: Password used to encrypt the file for security.
*   `key_length`: The length of the key buffer.
*   `master_key`:  Buffer for storing the derived key.
*   `master_key_length`: Define the length of the master key to be derived.
*   `salt`: Salt value used in file encryption. It's recommended to use a constant specific to the application for enhanced security.
*   `salt_length`: The length of the salt.
*   `iterations`: Number of iterations, positive integer value.
    

**Return values:**

*   `PQC_OK`: This return value indicates that the operation was executed successfully. The output will be a generated key of the length you have specified.
    
*   `PQC_IO_ERROR`: This return value suggests that an unexpected error occurred during the deletion process. 
    

Example
---------

**Code**

```cpp
{% include examples/pbkdf2/pbkdf2_example.cpp %}```
