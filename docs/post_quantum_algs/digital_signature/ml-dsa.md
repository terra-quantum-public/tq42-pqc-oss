---
layout: default
title: ML-DSA
parent: Digital Signature
grand_parent: Post-Quantum Algorithms
nav_order: 2
---

# **ML-DSA Overview**
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
- **Main cryptographic assumption**:  Scheme based on the Module Learning With Errors problem.
- **Copyright**:  [Public Domain](https://creativecommons.org/public-domain/cc0/)
or [Apache 2.0 License](https://www.apache.org/licenses/LICENSE-2.0.html)
- [**GitHub Source](https://github.com/terra-quantum-public/tq42-pqc-oss/tree/main/src/mldsa)


## FIPS 204 ML-DSA

FIPS 204 is the Module-Lattice-Based Digital Signature Standard developed by the National Institute of Standards and Technology (NIST) to offer a quantum-resistant digital signature solution. This standard outlines the Module-Lattice-Based Digital Signature Algorithm (ML-DSA), designed to safeguard the security and integrity of digital communications and data against quantum computer threats.

Derived from the CRYSTALS-Dilithium selection of the NIST Post-Quantum Cryptography Standardization Project, ML-DSA leverages lattice-based cryptographic constructs. These constructs are highly regarded for their resilience against both classical and quantum attacks, making ML-DSA a strong option for ensuring long-term data integrity.

FIPS 204 provides comprehensive guidelines for generating, verifying, and managing digital signatures, ensuring secure and consistent implementation across diverse applications.

The standard was initially released as a draft on August 24, 2023, with a public comment period ending on November 22, 2023. NIST officially standardized ML-DSA on August 13, 2024, marking a significant step forward in enhancing cryptographic security in the quantum computing era.
- [FIPS 204 Initial Public Draft](https://csrc.nist.gov/pubs/fips/204/final)
- [FIPS 204 Publication](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf)

## ML-DSA CAVP Validation

The TQ42 Cryptography v0.2.2 implementations of ML-DSA are fully compliant with the latest NIST standard, FIPS 204. The algorithm has undergone validation through the NIST Cryptographic Algorithm Validation Program (CAVP). For additional information, please visit the For further details, please visit the NIST CAVP [webpage](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/details?product=18351).

The validation process spans multiple operating systems and hardware configurations, including:

- Red Hat 9.4 
- Ubuntu 24.04 
- Windows 11 
- Windows 2022 
- IOS 17.5.1
- Android 14

### Applications:

FIPS 204 can be applied in multiple scenarios where secure digital signatures are essential, including:

-   Ensuring the integrity and authenticity of digital communications, documents, and transactions.
-   Utilizing quantum-resistant signatures within various cryptographic protocols and systems.
-   Implementing secure and verifiable signatures for sensitive and classified governmental and military communications.
-   Enhancing the security of electronic transactions, contracts, and records within financial systems.
-   Ensuring the authenticity and integrity of software updates and installations to prevent tampering and unauthorized alterations.   

## ML-DSA advantages over classical digital signature algorithms

Module-Lattice-based Digital Signature Algorithms (ML-DSA), such as those based on the CRYSTALS-DILITHIUM framework, offer several significant advantages over classical digital signature algorithms like RSA or ECDSA (Elliptic Curve Digital Signature Algorithm). Here are some of the key benefits:

- ML-DSA algorithms are designed to be secure against quantum computer attacks. Classical algorithms like RSA and ECDSA can be broken by quantum algorithms (e.g., Shor's algorithm), rendering them insecure in a post-quantum world.
- ML-DSA algorithm offer a good balance between security and performance, with efficient key generation, signing, and verification operations.
- While classical algorithms may require increasingly larger key sizes to maintain security as computational power increases, ML-DSA algorithms typically provide strong security with more manageable key and signature sizes,
- ML-DSA algorithms often come with different parameter sets, allowing users to choose configurations that balance security and performance based on specific needs.


## ML-DSA - Parameter set summary

|           | Public key size | Private key size | Signature size | Security category |
|:---------:|:---------------:|:----------------:|:--------------:|:-----------------:|
| ML-DSA-44 | 1312 bytes      | 2560 bytes       | 2420 bytes     | 2                 |
| ML-DSA-65 | 1952 bytes      | 4032 bytes       | 3309 bytes     | 3                 |
| ML-DSA-87 | 2592 bytes      | 4896 bytes       | 4627 bytes     | 5                 |

## NIST's Known Answer Tests (KAT)
The TQ42 Cryptography ML-DSA algorithm implementation has successfully passed the Known Answer Tests (KAT) provided by NIST. This confirms that the algorithm performs reliably as anticipated. For those interested in a deeper dive into the specifics of these tests, they are available [for review](https://github.com/terra-quantum-public/tq42-pqc-oss/tree/main/test/mldsa).

## Leveraging ML-DSA and True Entropy
The customization of the ML-DSA algorithm within TQ42 Cryptography is designed to work in synergy with true entropy, sourced from the Single Photon Quantum Random Number Generator (QRNG). This technology ensures that the randomness required for cryptographic keys is of the highest quality, providing unparalleled security for company data. Since the effectiveness of any cryptographic algorithm heavily relies on the randomness of its keys, incorporating QRNG derived true entropy with TQ42's customized ML-DSA algorithm ensures that your company's sensitive information is safeguarded in the most robust manner possible.

 
## API overview

To include the necessary library, please refer to the  [Getting Started Guide](../../getting_started.html).
After following the guide, include the `pqc/ml-dsa.h` header in your code.
All Signature Schemes algorithms have a unified API. For ML-DSA you can set the algorithm to work using the constants **PQC_CIPHER_ML_DSA_44**, **PQC_CIPHER_ML_DSA_65** or **PQC_CIPHER_ML_DSA_87**.
To learn about all the available methods for signature algorithms, visit the [Signature Schemes Generic API Overview page](api.html).


## Example

**Code**

```cpp
{% include examples/signature/example_signature.cpp %}```
