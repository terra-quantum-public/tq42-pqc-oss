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

FIPS 205 is the Stateless Hash-Based Digital Signature Algorithm (SLH-DSA), which was developed by the National Institute of Standards and Technology (NIST) to provide a quantum-resistant digital signature mechanism. FIPS 205 defines a method for digital signature generation that can be used for the protection of binary data (commonly called a message) and for the verification and validation of those digital signatures  
- [FIPS 205](https://csrc.nist.gov/pubs/fips/205/ipd) 
- [Nist post quantum cryptography](https://www.infosecurity-magazine.com/news/nist-post-quantum-cryptography/)

As part of the NIST standardisation process for post-squantum cryptography, SPHINCS+ has been under consideration and is the basis for Stateless Hash-Based Digital Signature Algorithm (SLH-DSA).
- [SPHINCS+](https://sphincs.org/data/sphincs+-paper.pdf) 

The security of SLH-DSA relies on the presumed diffculty of finding preimages for hash functions as well as several related properties of the same hash functions. Unlike the algorithms specifed in FIPS 186-5, SLH-DSA is expected to provide resistance to attacks from a large-scale quantum computer.
    
The standard specifes the mathematical steps that need to be performed for key generation, signature generation, and signature verifcation.

FIPS 205 was initially published as a draft on August 24, 2023, with a public comment period that concluded on November 22, 2023. Following the public comment period, necessary revisions were made to address feedback, and NIST aims to finalize and publish the standard for use in 2024.
    

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

- SLH-DSA-SHAKE-256f -  security category **5**
- Public key size - **64** bytes
- Private key size - **128** bytes 
- Signature size - **49 856** bytes

## NIST's Known Answer Tests (KAT)

The TQ42 Cryptography SLH-DSA algorithm implementation has successfully passed the Known Answer Tests (KAT) provided by NIST. This confirms that the algorithm performs reliably as anticipated. For those interested in a deeper dive into the specifics of these tests, they are available [for review](https://github.com/terra-quantum-public/tq42-pqc-oss/tree/main/test/slhdsa).

## Leveraging SLH-DSA and True Entropy

The customization of the SLH-DSA algorithm within TQ42 Cryptography is designed to work in synergy with true entropy, sourced from the Single Photon Quantum Random Number Generator (QRNG). This technology ensures that the randomness required for cryptographic keys is of the highest quality, providing unparalleled security for company data. Since the effectiveness of any cryptographic algorithm heavily relies on the randomness of its keys, incorporating QRNG derived true entropy with TQ42's customized SLH-DSA algorithm ensures that your company's sensitive information is safeguarded in the most robust manner possible.

 
## API overview

To include the necessary library, please refer to the  [Getting Started Guide](../../getting_started.html).
After following the guide, include the `pqc/slh-dsa.h` header in your code.
All Signature Schemes algorithms have a unified API. For SLH-DSA, you can set the algorithm to work using the constant **PQC_CIPHER_SLH_DSA_SHAKE_256F_DRAFT**.
To learn about all the available methods for signature algorithms, visit the [Signature Schemes Generic API Overview page](api.html).


## Example

**Code**
```cpp 
{% include examples/signature/example_slhdsa.cpp %}```
