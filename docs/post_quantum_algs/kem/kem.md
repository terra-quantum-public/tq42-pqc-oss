---
layout: default
title: Key Encapsulation Mechanisms
parent: Post-Quantum Algorithms
nav_order: 1
has_children: true
permalink: /kem/
---

The Key Encapsulation Mechanisms (KEMs) for post-quantum algorithms serve as cryptographic protocols specifically designed to securely generate and share encryption keys resilient to attacks by quantum computers. They are pivotal in the field of post-quantum cryptography, which anticipates the era of quantum computing and emphasizes secure communication protocols. KEMs play a key role in encapsulating and decapsulating keys, ensuring the confidentiality and integrity of the exchanged keys are preserved against potential quantum computational attacks.

The operational framework of a KEM in post-quantum cryptography involves three main algorithms:

1.  **Key Generation (Generate):** This algorithm is responsible for generating a pair of keys—an openly shared public key and a privately kept secret key.
    
2.  **Encapsulation (Encapsulate):** In this step, a sender utilizes the recipient's public key to encapsulate a shared secret, resulting in a pair consisting of a ciphertext (or "encapsulation") and a shared secret value, enabling the derivation of encryption keys.
    
3.  **Decapsulation (Decapsulate):** Upon receiving the encapsulated key, the recipient uses their private key to decapsulate the shared secret from the ciphertext, thereby enabling secure communication.
    

Post-quantum KEMs leverage complex mathematical problems believed to be intractable for quantum computers, such as those based on lattice structures, code-based principles, or other quantum-resistant foundations. These KEMs play a critical role in achieving secure key exchange in the next generation of cryptographic protocols, ensuring secure communications even in the presence of sophisticated quantum computing capabilities. The development and standardization of such mechanisms, as carried out by organizations like NIST, are essential steps towards maintaining global digital security standards in the post-quantum future.