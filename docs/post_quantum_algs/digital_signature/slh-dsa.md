---
layout: default
title: SLH-DSA
parent: Digital Signature
grand_parent: Post-Quantum Algorithms
nav_order: 2
---

# **SLH-DSA Overview**
{: .no_toc }

<details open markdown="block">
  <summary>
    Table of contents
  </summary>
  {: .text-delta }
1. TOC
{:toc}
</details>

- **Algorithm type**: Digital signature scheme.
- **Main cryptographic assumption**:  Scheme based on the presumed difficulty of finding preimages for hash functions.
- **License**: [Public-Domain](https://github.com/terra-quantum-public/tq42-pqc-oss/tree/main/src/slhdsa/LICENSE.txt)


## FIPS 205 SLH-DSA

FIPS 205 is the Stateless Hash-Based Digital Signature Algorithm (SLH-DSA), developed by the National Institute of Standards and Technology (NIST) to offer a quantum-resistant digital signature mechanism. This standard outlines a method for generating digital signatures to protect binary data (commonly called a message) and to verify and validate these digital signatures effectively.

SLH-DSA is based on SPHINCS+, considered during the NIST standardization process for post-quantum cryptography. This algorithm utilizes the assumed difficulty of finding pre-images for hash functions, as well as several related properties, to ensure its security. Unlike algorithms specified in FIPS 186-5, SLH-DSA is designed to resist attacks from large-scale quantum computers.

The standard specifies the mathematical procedures required for key generation, signature creation, and signature verification, ensuring robust security across various applications.

FIPS 205 was released as a draft on August 24, 2023, and opened for public comment until November 22, 2023. NIST officially standardized SLH-DSA on August 13, 2024, establishing a crucial step in securing data against future quantum threats.
- [FIPS 205 Initial Public Draft](https://csrc.nist.gov/pubs/fips/205/final)
- [FIPS 205 Publication](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf)

## SLH-DSA CAVP Validation

The TQ42 Cryptography v0.2.2 implementations of SLH-DSA are fully compliant with the latest NIST standard, FIPS 205. The algorithm has undergone validation through the NIST Cryptographic Algorithm Validation Program (CAVP). For additional information, please visit the For further details, please visit the NIST CAVP [webpage](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/details?product=18351).

The validation process spans multiple operating systems and hardware configurations, including:

- Red Hat 9.4 
- Ubuntu 24.04 
- Windows 11 
- Windows 2022 
- IOS 17.5.1
- Android 14

### Applications:

FIPS 205 can be applied in multiple scenarios where secure digital signatures are essential, including:

-   Ensuring the integrity and authenticity of digital communications, documents, and transactions.
-   Utilizing quantum-resistant signatures within various cryptographic protocols and systems.
-   Implementing secure and verifiable signatures for sensitive and classified governmental and military communications.
-   Enhancing the security of electronic transactions, contracts, and records within financial systems.
-   Ensuring the authenticity and integrity of software updates and installations to prevent tampering and unauthorized alterations.   

## SLH-DSA advantages over classical digital signature algorithms

Stateless Hash-Based Digital Signature Algorithm (SLH-DSA), such as those based on the SPHINCS+, offer several significant advantages over classical digital signature algorithms like RSA or ECDSA (Elliptic Curve Digital Signature Algorithm). Here are some of the key benefits:

- SLH-DSA  is expected to provide resistance to attacks from a large-scale quantum computer. Classical algorithms like RSA and ECDSA can be broken by quantum algorithms (e.g., Shor's algorithm), rendering them insecure in a post-quantum world.
- SLH-DSA algorithm offer a good balance between security and performance, with efficient key generation, signing, and verification operations.
- While classical algorithms may require increasingly larger key sizes to maintain security as computational power increases, SLH-DSA algorithms typically provide strong security with more manageable key and signature sizes,
- SLH-DSA algorithms often come with different parameter sets, allowing users to choose configurations that balance security and performance based on specific needs.


## SLH-DSA - Parameter set summary

|                    | Public key size | Private key size | Signature size | Security category |
|:------------------:|:---------------:|:----------------:|:--------------:|:-----------------:|
| SLH-DSA-SHAKE-128s | 32 bytes        | 64 bytes         | 7856 bytes     | 1                 |
| SLH-DSA-SHAKE-128f | 32 bytes        | 64 bytes         | 17088 bytes    | 1                 |
| SLH-DSA-SHAKE-192s | 48 bytes        | 96 bytes         | 16224 bytes    | 3                 |
| SLH-DSA-SHAKE-192f | 48 bytes        | 96 bytes         | 35664 bytes    | 3                 |
| SLH-DSA-SHAKE-256s | 64 bytes        | 128 bytes        | 29792 bytes    | 5                 |
| SLH-DSA-SHAKE-256f | 64 bytes        | 128 bytes        | 49856 bytes    | 5                 |

## NIST's Known Answer Tests (KAT)

The TQ42 Cryptography SLH-DSA algorithm implementation has successfully passed the Known Answer Tests (KAT) provided by NIST. This confirms that the algorithm performs reliably as anticipated. For those interested in a deeper dive into the specifics of these tests, they are available [for review](https://github.com/terra-quantum-public/tq42-pqc-oss/tree/main/test/slhdsa).

## Leveraging SLH-DSA and True Entropy

The customization of the SLH-DSA algorithm within TQ42 Cryptography is designed to work in synergy with true entropy, sourced from the Single Photon Quantum Random Number Generator (QRNG). This technology ensures that the randomness required for cryptographic keys is of the highest quality, providing unparalleled security for company data. Since the effectiveness of any cryptographic algorithm heavily relies on the randomness of its keys, incorporating QRNG derived true entropy with TQ42's customized SLH-DSA algorithm ensures that your company's sensitive information is safeguarded in the most robust manner possible.

 
## API overview

To include the necessary library, please refer to the  [Getting Started Guide](../../getting_started.html).
After following the guide, include the `pqc/slh-dsa.h` header in your code.
All Signature Schemes algorithms have a unified API. For SLH-DSA you can set the algorithm to work using one of the constants: **PQC_CIPHER_SLH_DSA_SHAKE_128S**, **PQC_CIPHER_SLH_DSA_SHAKE_128F**, **PQC_CIPHER_SLH_DSA_SHAKE_192S**, **PQC_CIPHER_SLH_DSA_SHAKE_192F**, **PQC_CIPHER_SLH_DSA_SHAKE_256S**, **PQC_CIPHER_SLH_DSA_SHAKE_256F**.
To learn about all the available methods for signature algorithms, visit the [Signature Schemes Generic API Overview page](api.html).


## Example

**Code**
```cpp 
{% include examples/signature/example_signature.cpp %}```
