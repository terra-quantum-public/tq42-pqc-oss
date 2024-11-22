---
layout: default
title: Falcon
parent: Digital Signature
grand_parent: Post-Quantum Algorithms
nav_order: 3
---

# **Falcon Overview**
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
- **Main cryptographic assumption**: Hardness of NTRU lattice problems.
- **Principal submitters**: Thomas Prest.
- **Auxiliary submitters**: Pierre-Alain Fouque, Jeffrey Hoffstein, Paul Kirchner, Vadim Lyubashevsky, Thomas Pornin, Thomas Prest, Thomas Ricosset, Gregor Seiler, William Whyte, Zhenfei Zhang.
- **Authors' website**: [https://falcon-sign.info](https://falcon-sign.info)

- **Copyright**: The following provision applies to this part of the software as an additional term to the license:

Copyright (c) 2017-2019  Falcon Project

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
 
THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.


## Falcon - Parameter set summary

- Security Model - **EUF-CMA**
- Claimed NIST Level - **5**
- Public key size - **1793** bytes
- Private key size - **2305** bytes 
- Signature size - **1280** bytes


 
## Falcon-padded-1024 overview

**Falcon-padded-1024** is a variant of the Falcon digital signature algorithm, specifically designed to offer robust security features in anticipation of the quantum computing era. It builds upon the foundational lattice-based cryptographic principles, making it inherently resistant to the types of attacks that quantum computers could potentially unleash on traditional encryption mechanisms. Here are some critical aspects of Falcon-padded-1024:

- **Quantum-resistant Algorithm**: Falcon-padded-1024 is developed to secure digital communication against both current and future threats, including those posed by quantum computing advancements. [Falcon](https://falcon-sign.info/)

- **Lattice-based Cryptography**: Utilizing NTRU lattices and fast Fourier sampling, Falcon-padded-1024 is based on the cutting-edge GPV framework, ensuring its security by relying on the hardness of lattice problems considered to be secure against quantum attacks. [Falcon - a Post-Quantum Signature Scheme](https://pqshield.com/falcon-a-post-quantum-signature-scheme/)

- **Fixed-size Signatures**: The 'padded' aspect refers to its unique ability to produce fixed-size signatures, ensuring uniformity and potentially enhancing security and privacy by preventing signature size-based side-channel attacks.

- **High Security Level**: Tailored for scenarios requiring an elevated level of security, it offers significant protection against existing cryptographic attacks, making it suitable for sensitive data protection.

## NIST

NIST has recognized **Falcon 1024** as a key digital signature scheme in its Post-Quantum Cryptography (PQC) standardization process, aiming to secure cryptographic practices against future quantum computing threats. This effort includes selecting algorithms that demonstrate resilience to quantum attacks, among which Falcon 1024 stands out for its quantum resistance, based on structured lattices and hash functions. As part of the third round of the PQC standardization process, Falcon 1024, with its reliance on NTRU lattices for compact signatures, has been slated for standardization. NIST's initiative also invites public feedback to refine and finalize these standards, ensuring a broad consensus and robustness of the adopted cryptographic measures. Falcon 1024's implementation in cryptographic libraries and its selection for standardization highlight its significance in the transition towards quantum-resistant cryptography.

Links:
- [NIST to Standardize Encryption Algorithms That Can Resist Attack by Quantum Computers, August 24, 2023](https://www.nist.gov/news-events/news/2023/08/nist-standardize-encryption-algorithms-can-resist-attack-quantum-computers)
- [NIST Announces First Four Quantum-Resistant Cryptographic Algorithms, July 05, 2022](https://www.nist.gov/news-events/news/2022/07/nist-announces-first-four-quantum-resistant-cryptographic-algorithms)

## API overview

To include the necessary library, please refer to the  [Getting Started Guide](../../getting_started.html).
After following the guide, include the `pqc/falcon.h` header in your code.
All Signature Schemes algorithms have a unified API. For Falcon 1024, you can set the algorithm to work using the constant. 

**PQC_CIPHER_FALCON**.
To learn about all the available methods for signature algorithms, visit the [Signature Schemes Generic API Overview page](api.html).

## Example

**Code**

```cpp
{% include examples/signature/example_signature.cpp %}
```
