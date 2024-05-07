---
layout: default
title: Post-Quantum Algorithms
nav_order: 4
has_children: true
permalink: /post_quantum_algs/
---


**Post-quantum algorithms**, also known as quantum-resistant or quantum-safe algorithms, are cryptographic methods designed to secure communications against the potential threat posed by quantum computers. 
Unlike traditional cryptographic algorithms, whose security relies on the computational difficulty of problems such as integer factorization and discrete logarithms, post-quantum algorithms are based on mathematical problems believed to be resistant to quantum computing attacks. 
These algorithms aim to ensure the confidentiality, integrity, and authenticity of digital communications in a future where quantum computers could break current encryption methods. 
The development of post-quantum cryptography encompasses various types of cryptographic algorithms, including those based on structured lattices, hash functions, and other math problems that are considered hard for quantum computers to solve. 
[What is post-quantum cryptography?](https://www.technologyreview.com/2019/07/12/134211/explainer-what-is-post-quantum-cryptography/?_ga=2.237390464.1268615396.1711369775-2039649111.1711260360)

**The NIST Post-Quantum (PQ) Cryptography Standardization** is a comprehensive initiative aimed at future-proofing cryptographic standards against the potential threat posed by quantum computing. 
Recognizing the quantum computational power's ability to break many of the current cryptographic algorithms, NIST launched this program to solicit, evaluate, and eventually standardize one or more quantum-resistant public-key cryptographic algorithms. 
This initiative is integral to maintaining the security of digital communications and data in the coming era of quantum computing.

The standardization process involves several key phases:

- **Call for Proposals**: NIST initiated the Post-Quantum Cryptography Standardization process by inviting the global cryptographic community to submit proposals for quantum-resistant algorithms. This phase aimed to collect a broad range of solutions suitable for various cryptographic applications, including but not limited to encryption, digital signatures, and key establishment protocols.

- **Evaluation and Selection**: Submitted proposals undergo rigorous evaluation based on criteria such as security, performance, and implementation feasibility. The evaluation process is iterative, with multiple rounds allowing for refinements and optimizations. This collaborative effort involves feedback from cryptographers, industry professionals, and other stakeholders.

- **Standardization**: The final phase involves selecting the most promising algorithms and moving towards formal standardization. These new standards are intended to replace or augment existing cryptographic standards, ensuring robust defense against quantum computer attacks.

[NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)

Following the NIST Post-Quantum Cryptography (PQC) competition, three draft standards have been proposed:

- **FIPS 203**: This standard is dedicated to Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM) algorithms. These algorithms are designed for secure key generation, encapsulation, and decapsulation, critical for safeguarding cryptographic keys against quantum attacks.
- **FIPS 204**: Focuses on the Module-Lattice-Based Digital Signature Algorithm (ML-DSA), derived from CRYSTALS-Dilithium. This standard specifies the framework for digital signatures that remain secure in the quantum-computing era, ensuring the authenticity and integrity of digital communications.
- **FIPS 205**: Introduces a Stateless Hash-Based Digital Signature Standard, utilizing SPHINCS+ as its foundation. It is designed for authenticating and verifying digital signatories in a manner resistant to quantum computing threats, enhancing the security of digital signatures further.
