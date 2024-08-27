---
layout: default
title: Introduction
nav_order: 1
---

![image](img/introduction_system_integration.png)

# Overview
{: .no_toc }

TQ42 Cryptography by Terra Quantum is a comprehensive, low-level cryptography library designed to cover Encryption, Hashing, Electronic Signatures, and Key Management Systems. It is specifically crafted to help individual developers, businesses, and governmental entities prepare for the quantum era and enhance the security of their data.

GitHub sources - [https://github.com/terra-quantum-public/tq42-pqc-oss](https://github.com/terra-quantum-public/tq42-pqc-oss)

***

<details open markdown="block">
  <summary>
    Table of contents
  </summary>
  {: .text-delta }
1. TOC
{:toc}
</details>

# Introduction

TQ42 Cryptography is an **open-source C++ library** that offers a unified API for both post-quantum (PQ) and quantum-resistant algorithms. With a focus on security and efficiency, it comes equipped with key management features and the option to upgrade with seamless integration capabilities to a Single Photon Quantum Random Number Generator (QRNG), which meets NIST standards (SP 800-90B) and is certified by METAS.

- **Unified Algorithm Support:** This library provides a cohesive platform for a diverse range of post-quantum (PQ) and quantum-resistant algorithms, streamlining development and implementation processes.
- **Enhanced Security and Efficiency:** By incorporating advanced key management functionalities, TQ42 Cryptography ensures secure and optimized encryption key handling for heightened data protection.
- **Revolutionary QRNG Integration**: Experience unmatched randomness and security by upgrading to and seamlessly integrating with Terra Quantum's Single Photon quantum random number generator (QRNG). This feature ensures superior unpredictability sourced directly from quantum phenomena. Aligned with the latest NIST standard (SP 800-90B) and certified by METAS.

The versatility of TQ42 Cryptography enables its use in critical industries such as Banking, Finance, Critical Infrastructure, Federal Operations and others, ensuring robust data protection. TQ42 Cryptography offers classical, quantum-resistant and post-quantum low-level security algorithms. See more [Use Cases](use_cases.html).

Whether safeguarding web and mobile applications, ensuring the integrity of blockchain technology, fortifying Raspberry Pi systems, securing cloud and data storage, or protecting IoT devices and servers, TQ42 Cryptography offers comprehensive security solutions. Its applicability extends to numerous other critical scenarios where robust security measures are indispensable.

# Advanced Quantum Security
Terra Quantum offers advanced quantum security products, including the Terra Quantum Secure Network (TQSN), a novel solution for organizations looking for full security via Quantum Key Distribution (QKD), a revolutionary technology that leverages the quantum mechanical properties of light and allows for the distribution of cryptographic keys with absolute security, making decryption impossible. Terra Quantum's patented Secure Network solution (TQSN) works well over long distances with high bit rates. It is the world's first scalable, zero-trust Secure Network for global communications. Visit [terraquantum.swiss](https://terraquantum.swiss) to learn more, or contact us at info@terraquantum.swiss.
[![image](img/introduction_banner.png)](https://terraquantum.swiss/news/terra-quantum-breaks-records-in-quantum-key-distribution-paving-way-to-offering-unprecedented-security-over-existing-fiber-optic-networks-globally)

# Quantum Random Number Generator

TQ42 Cryptography can seamlessly integrate into the company security pipeline when paired with the proprietary Pseudo Key Generator PQ17. For enhanced security and a top-tier solution, clients have the option to engage with Terra Quantum to secure a license for integration with true randomness via the Single Photon Quantum Random Number Generator (QRNG), which is aligned with the latest NIST standard (SP 800-90B) and certified by METAS. This cutting-edge technology, a signature offering from Terra Quantum, embodies genuine quantum randomness, guaranteeing the generation of highly secure random numbers. The foundation of this unparalleled security lies in the Heisenberg Uncertainty Principle. The device operates on a true random entropy source, enabling swift and precise generation of random numbers at remarkable speed.
## Supported Algorithms

![image](img/introduction_infographic.png)

### Classic Quantum-Resistant Algorithms

Hash Function:

-   [SHA-3](classic_quantum_resistant_algs/sha3.html) (all modes: 224, 256, 384, 512, SHAKE-128, SHAKE-256) 

Symmetric Encryption:

-   [AES-256](classic_quantum_resistant_algs/aes.html) (modes: ECB, CBC, OFB, CTR, GCM) 

### Post-Quantum Algorithms

Key Encapsulation Mechanism:

-   [ML-KEM](post_quantum_algs/kem/ml-kem.html)
-   [Classic McEliece 8192128f](post_quantum_algs/kem/mceliece.html)

Digital Signature:

-   [ML-DSA](post_quantum_algs/digital_signature/ml-dsa.html)
-   [SLH-DSA](post_quantum_algs/digital_signature/slh-dsa.html)
-   [Falcon padded 1024](post_quantum_algs/digital_signature/falcon.html)

### Key Management

-   [Secure file removal (HDD, SSD)](keys/secureHDD&SSDRemoval.html)
-   [Randomness source](keys/PRNG.html)
-   [Key Containers](keys/keys_container.html)
-   [PBKDF2](keys/pbkdf2.html)

## Enhancing Security with Post-Quantum Algorithms: Strategic Recommendations

As the field of Post-Quantum Cryptography (PQC) continues to evolve, the security algorithms under review present a potential for undiscovered vulnerabilities. Given this scenario, we strongly advise that companies proactively integrate a strategy to include alternative or backup cryptographic algorithms within their security frameworks. Doing so not only prepares your organization for any forthcoming changes in the cryptographic landscape but also enhances overall security resilience.
Moreover, transitioning to a new algorithm can be seamlessly managed with tools like TQ42 Cryptography. This solution is designed to facilitate easy integration and deployment of robust cryptographic algorithms, ensuring that your security infrastructure remains both current and flexible. By adopting TQ42 Cryptography, your company can efficiently adapt to any cryptographic advancements or requirements, maintaining a leading edge in data protection.

## Security Notice

> Quantum-Safe Algorithm Considerations

While there are no known vulnerabilities in the quantum-safe algorithms
within this library, caution is crucial. These algorithms have not
undergone the same level of scrutiny as currently deployed ones. The
**NIST Post-Quantum Cryptography Standardization** project\'s guidance
should be followed diligently. As research progresses, algorithm
security may rapidly change, including potential vulnerabilities to
classical and quantum computers.

TQ42 Cryptography aligns its algorithm support with the **NIST PQC standardization
project**. Applications and protocols should rely on outcomes from this
effort for post-quantum cryptography deployment.

For those considering **quantum-safe cryptography** before the **NIST
PQC standardization project** concludes, we strongly recommend using
hybrid cryptography. This approach combines quantum-safe public-key
algorithms with existing traditional cryptography.
