---
layout: default
title: Digital Signature
parent: Post-Quantum Algorithms
nav_order: 1
has_children: true
permalink: /digital_signature/
---

**Post-quantum signature schemes** are cryptographic algorithms designed to offer secure digital signatures that remain impervious to attacks by quantum computers. 
These schemes are part of the broader field of post-quantum cryptography, which aims to develop security protocols that can withstand the potential cryptographic challenges posed by quantum computing technology.
Unlike traditional digital signature schemes that rely on the computational hardness of problems such as factoring large primes or solving discrete logarithmic problems solvable by quantum algorithms, post-quantum signature schemes are based on mathematical problems expected to be resistant to quantum attacks.

The main categories of post-quantum signature schemes include:

- **Lattice-Based Schemes**: These rely on the hardness of lattice problems such as the Shortest Vector Problem (SVP) and Learning With Errors (LWE). Lattice-based schemes are known for their security and efficiency, making them a strong candidate for post-quantum cryptography.

- **Hash-Based Schemes**: Utilizing secure cryptographic hash functions, these schemes generate signatures by specifically designing a one-time signature scheme and then employing a structure to allow multiple signings. Hash-based signatures are notable for their simplicity and proven quantum resistance.

- **Multivariate Polynomial Schemes**: These schemes base their security on the difficulty of solving systems of multivariate quadratic equations over a finite field. While offering quantum resistance, they often result in larger key sizes compared to other schemes.

- **Code-Based Schemes**: Drawing upon the hardness of decoding randomly generated linear codes, code-based signatures provide a unique approach to post-quantum cryptography, although they tend to produce larger keys and signatures.
