![TQ42_Cryptography_Banner.png](https://terra-quantum-public.github.io/tq42-pqc-oss/img/readme_banner.png)

<p align="center">
  <a href="https://terra-quantum-public.github.io/tq42-pqc-oss">Documentation</a> &nbsp;&bull;&nbsp;
  <a href="https://terra-quantum-public.github.io/tq42-pqc-oss/getting_started.html">Getting Started</a> &nbsp;&bull;&nbsp;
  <a href="https://terra-quantum-public.github.io/tq42-pqc-oss/use_cases.html">Use Cases</a> &nbsp;&bull;&nbsp;
  <a href="https://terra-quantum-public.github.io/tq42-pqc-oss/api_reference.html">API reference</a>
</p>

# Introduction to TQ42 Cryptography
TQ42 Cryptography by [Terra Quantum](https://terraquantum.swiss) is a comprehensive, low-level cryptography library designed to cover Encryption, Hashing, Electronic Signatures, and Key Management Systems. It is specifically crafted to help individual developers, businesses, and governmental entities prepare for the quantum era and enhance the security of their data, and expands upon the existing functionality offered in [TQ42](https://tq42.com), the quantum-as-a-service ecosystem by Terra Quantum.

This open-source C++ library offers a unified API for both post-quantum (PQ) and quantum-resistant algorithms, as well as key generation and management functions. View the [documentation](https://terra-quantum-public.github.io/tq42-pqc-oss).

The library will expand to include support for additional languages (e.g., Python, iOS, Android), additional post-quantum algorithms, and upgrade options, like the ability to purchase quantum keys generated from Terra Quantum's proprietary Single Photon Quantum Random Number Generator (QRNG), which is designed and implemented according to the latest NIST standard (SP 800-90B) and certified by METAS.

# TQ42 Cryptography Features

## Included Features
Details on the library contents can be found in the [documentation](https://terra-quantum-public.github.io/tq42-pqc-oss). Library contents are subject to change.

![TQ42_Cryptography_Infographic.png](https://terra-quantum-public.github.io/tq42-pqc-oss/img/introduction_infographic.png)

### Classic Quantum-Resistant Algorithms

Hash Function:

-   [SHA-3](https://terra-quantum-public.github.io/tq42-pqc-oss/classic_quantum_resistant_algs/sha3.html) (all modes: 224, 256, 384, 512, SHAKE-128, SHAKE-256) 

Symmetric Encryption:

-   [AES-256](https://terra-quantum-public.github.io/tq42-pqc-oss/classic_quantum_resistant_algs/aes.html) (modes: ECB, CBC, OFB, CTR) 

### Post-Quantum Algorithms

Key Encapsulation Mechanism:

-   [Classic McEliece 8192128f](https://terra-quantum-public.github.io/tq42-pqc-oss/post_quantum_algs/kem/mceliece.html)

Digital Signature:

-   [Falcon padded 1024](https://terra-quantum-public.github.io/tq42-pqc-oss/post_quantum_algs/digital_signature/falcon.html)

### Key Management

-   [Secure file removal (HDD, SSD)](https://terra-quantum-public.github.io/tq42-pqc-oss/keys/secureHDD&SSDRemoval.html)
-   [Randomness source](https://terra-quantum-public.github.io/tq42-pqc-oss/keys/PRNG.html)
-   [Key Containers](https://terra-quantum-public.github.io/tq42-pqc-oss/keys/keys_container.html)

## Security Notice
While there are no known vulnerabilities in the quantum-safe algorithms within this library, caution is crucial. These algorithms have not undergone the same level of scrutiny as currently deployed ones. The NIST Post-Quantum Cryptography Standardization project's guidance should be followed diligently. As research progresses, algorithm security may rapidly change, including potential vulnerabilities to classical and quantum computers.

TQ42 Cryptography aligns its algorithm support with the NIST PQC standardization project. Applications and protocols should rely on outcomes from this effort for post-quantum cryptography deployment.

For those considering quantum-safe cryptography before the NIST PQC standardization project concludes, we strongly recommend using hybrid cryptography. This approach combines quantum-safe public-key algorithms with existing traditional cryptography.

Terra Quantum offers advanced quantum security products, including the Terra Quantum Secure Network (TQSN), a novel solution for organizations looking for full security via Quantum Key Distribution (QKD), a revolutionary technology that leverages the quantum mechanical properties of light and allows for the distribution of cryptographic keys with absolute security, making decryption impossible. Terra Quantum's patented Secure Network solution (TQSN) works well over long distances with high bit rates. It is the world's first scalable, zero-trust Secure Network for global communications. Visit [terraquantum.swiss](https://terraquantum.swiss) to learn more, or contact us at info@terraquantum.swiss.

# Licenses
The TQ42 Cryptography library is available under two primary licensing options to accommodate the diverse needs of organizations at different stages of their post-quantum migration journeys: 
- Free Use is permitted under [AGPLv3](https://www.gnu.org/licenses/agpl-3.0.html.en) 
- A Commercial license is available by contacting Terra Quantum at info@terraquantum.swiss

Contributions will be welcomed in the near future under a Contributor license.
