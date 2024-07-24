---
layout: default
title: McEliece
parent: Key Encapsulation Mechanisms
grand_parent: Post-Quantum Algorithms
nav_order: 3
---

# **Classic McEliece Overview**
{: .no_toc }

<details open markdown="block">
  <summary>
    Table of contents
  </summary>
  {: .text-delta }
1. TOC
{:toc}
</details>

- **Algorithm Type:** Key Encapsulation Mechanism (KEM)
- **Cryptographic Assumption:** Based on Niederreiter\'s dual version of McEliece\'s public key encryption using binary Goppa codes.
-    **Principal Submitters:** Daniel J. Bernstein, Tung Chou, Tanja Lange, Ingo von Maurich, Rafael Misoczki, Ruben Niederhagen,
        Edoardo Persichetti, Christiane Peters, Peter Schwabe, Nicolas
        Sendrier, Jakub Szefer, Wen Wang
-   **Authors\' Website:** Classic McEliece <https://classic.mceliece.org/>
-   **Implementation License (SPDX-Identifier):** The following provision applies to this part of the software as an additional term to the license:
This code is based on the code of the Classic McEliece project ([Classic McEliece:Implementation](https://classic.mceliece.org/impl.html)). The Classic McEliece software is in the public domain.
-   [**GitHub Source](https://github.com/terra-quantum-public/tq42-pqc-oss/tree/main/src/mceliece) 


## NIST's Known Answer Tests (KAT)
The McEliece algorithm implementation has successfully passed the Known Answer Tests (KAT) provided by NIST. This confirms that the algorithm performs reliably as anticipated. For those interested in a deeper dive into the specifics of these tests, they are available [for review](https://github.com/terra-quantum-public/tq42-pqc-oss/tree/main/test/mceliece).

## Leveraging McEliece and True Entropy
The customization of the McEliece algorithm within TQ42 Cryptography is designed to work in synergy with true entropy, sourced from the Single Photon Quantum Random Number Generator (QRNG). This technology ensures that the randomness required for cryptographic keys is of the highest quality, providing unparalleled security for company data.
Since the effectiveness of any cryptographic algorithm heavily relies on the randomness of its keys, incorporating QRNG-derived true entropy with TQ42’s customized McEliece algorithm ensures that your company’s sensitive information is safeguarded in the most robust manner possible.

## Classic McEliece 8192128f - Parameter set summary

- Security Model - **IND-CCA2**
- Claimed NIST Level - **3**
- Public key size - **1 357 824** bytes
- Secret key size - **14 080** bytes 
- Ciphertext size - **240** bytes
- Shared secret size - **32** bytes

**Classic McEliece 8192128f** is a specific variant of the McEliece cryptosystem, which is a
public-key cryptosystem based on error-correcting codes. It is often
considered a post-quantum cryptosystem, which means it is designed to be
secure against attacks by quantum computers.

The \"8192128f\" in the name refers to the key size, which is **8192**
bits. This indicates the size of the public and private keys used in the
cryptosystem. The \"f\" refers to the specific choices made in the
specific instantiation, such as the **choice of finite field** and the
particular code used.

## NIST status

<https://classic.mceliece.org/nist.html>

Classic McEliece is a round **3 finalist in the NIST Post-Quantum
Cryptography Standardization Project** and advanced to the fourth
round -
<https://csrc.nist.gov/news/2022/pqc-candidates-to-be-standardized-and-round-4>.

The latest state of the NIST standardization process for the McEliece Key Encapsulation Mechanism (KEM) as part of the ongoing effort to establish post-quantum cryptographic standards involves the evaluation of Classic McEliece among other candidates. Here are the key points regarding the current status:

- **Continuation in the Process**: Classic McEliece, a code-based KEM, is one of the algorithms that has continued to be under consideration in the later stages of the NIST Post-Quantum Cryptography (PQC) Standardization Process. Specifically, it has been included in the fourth round of evaluation ([https://csrc.nist.gov/projects/pqc-dig-sig](https://csrc.nist.gov/projects/pqc-dig-sig)).

- **Security Level**: Classic McEliece is noted for its **IND-CCA2** security level, an important characteristic for cryptographic algorithms, signifying its suitability for secure communication standards in the face of quantum computing threats (<https://www.mdpi.com/2410-387X/7/3/40>).

- **Unique Position**: Unlike some other algorithms being considered for standardization, Classic McEliece does not directly compete with many as a general-purpose KEM. Its primary competition, in terms of lattice-based approaches like ML-KEM, differs in key aspects, such as key sizes and computational efficiency. Nevertheless, NIST is evaluating Classic McEliece along with others for its potential unique benefits, such as its long-standing security assumptions resilience to certain types of attacks (<https://blog.cloudflare.com/pq-2024>).

- **Performance Considerations**: Although Classic McEliece provides certain advantages, 
including a high level of security, its performance aspects–particularly in terms of key sizes–do not directly compete 
with some of the more computationally efficient algorithms like ML-KEM. This factor is crucial as NIST also considers the 
practicality of implementing these algorithms in real-world systems.

- **A Backup KEM**: NIST has considered the possibility of standardizing additional algorithms like BIKE and HQC as backup KEMs, 
reflecting a strategy to have alternatives in the event of cryptanalytic breakthroughs against leading candidates like ML-KEM. 
This approach underscores the rigorous and comprehensive nature of the selection process, aiming to ensure a resilient cryptographic standard.




## API overview

To include the necessary library, please refer to the [Getting Started Guide](../../getting_started.html).
After following the guide, include the ``pqc/mceliece.h`` header in your code.
All Key Exchange Mechanism algorithms have a unified API. For McEliece, you can set the algorithm to work using the constant **PQC_CIPHER_MCELIECE**.
To learn about all the available methods for Key Exchange Mechanism APIs, visit the [KEM API Overview page](api.html).


## Example

**Code**

```cpp
{% include examples/key_exchange/kem_mceliece.cpp %}
```

