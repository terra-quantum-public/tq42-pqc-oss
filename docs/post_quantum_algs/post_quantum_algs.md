---
layout: default
title: Post-Quantum Algorithms
nav_order: 4
has_children: true
permalink: /post_quantum_algs/
---


## Post-quantum algorithms
 
 also known as quantum-resistant or quantum-safe algorithms, are cryptographic methods designed to secure communications against the potential threat posed by quantum computers. 
Unlike traditional cryptographic algorithms, whose security relies on the computational difficulty of problems such as integer factorization and discrete logarithms, post-quantum algorithms are based on mathematical problems believed to be resistant to quantum computing attacks. 
These algorithms aim to ensure the confidentiality, integrity, and authenticity of digital communications in a future where quantum computers could break current encryption methods. 
The development of post-quantum cryptography encompasses various types of cryptographic algorithms, including those based on structured lattices, hash functions, and other math problems that are considered hard for quantum computers to solve. 
[What is post-quantum cryptography?](https://www.technologyreview.com/2019/07/12/134211/explainer-what-is-post-quantum-cryptography/?_ga=2.237390464.1268615396.1711369775-2039649111.1711260360)

## Post-quantum encryption Federal Information Processing Standards (FIPS)

In August 2024, the National Institute of Standards and Technology (NIST) announced the release of the first set of finalized post-quantum encryption standards, designed to withstand potential future attacks by quantum computers. These new standards aim to secure a variety of electronic information, from confidential emails to e-commerce transactions    .

The finalized standards comprise three Federal Information Processing Standards (FIPS):

- **FIPS 203**: This standard is designated for general encryption purposes and is based on the CRYSTALS-Kyber algorithm, now referred to as **ML-KEM** (Module-Lattice-Based Key-Encapsulation Mechanism). It is noted for having comparatively small encryption keys and high speed, making it efficient for exchanging keys between parties.
    - [FIPS 203 Publication](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf)
    - [TQ42 NIST certified FIPS-203 implementation](kem/ml-kem.html)

- **FIPS 204**: Focused on protecting digital signatures, this standard utilizes the CRYSTALS-Dilithium algorithm, renamed ML-DSA (Module-Lattice-Based Digital Signature Algorithm). It serves as the primary standard for digital signature protection.
    - [FIPS 204 Publication](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf)
    - [TQ42 NIST certified FIPS-204 implementation](digital_signature/ml-dsa.html)

- **FIPS 205**: Another digital signature standard, this employs the Sphincs+ algorithm, now called SLH-DSA (Stateless Hash-Based Digital Signature Algorithm), which offers a different mathematical approach than the ML-DSA, intended as a backup in case ML-DSA faces vulnerabilities.
    - [FIPS 205 Publication](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf)
    - [TQ42 NIST certified FIPS-205 implementation](digital_signature/slh-dsa.html)

The development of these standards marks a significant milestone in cryptography, aiming to prepare security infrastructure for a future where quantum computing might compromise current encryption methods. The need for post-quantum cryptography arises because quantum computers, once mature, could potentially solve the complex mathematical problems that underpin current encryption, rendering them insecure.

NIST's initiative began in 2016, with a global call for algorithms resistant to quantum attacks. Out of 69 eligible submissions, four key algorithms were identified by 2022, leading to the final standardization process. The release of these standards allows organizations to begin integrating these new algorithms into their systems to ensure the confidentiality and security of electronic information in the quantum era