---
layout: default
title: API Reference
nav_order: 8
---

# API reference 
{: .no_toc }

<details open markdown="block">
  <summary>
    Table of contents
  </summary>
  {: .text-delta }
1. TOC
{:toc}
</details>

Below you may find the reference to the all API methods or examples that exist in the library. Find the method or example you want and navigate there to see more details.

## Post-Quantum Algorithms
### KEM
- [`PQC_context_init_asymmetric`](post_quantum_algs/kem/api.html#pqc_context_init_asymmetric)
- [`PQC_context_keypair_generate`](post_quantum_algs/kem/api.html#pqc_context_keypair_generate)
- [`PQC_keypair_generate`](post_quantum_algs/kem/api.html#pqc_keypair_generate)
- [`PQC_context_get_public_key`](post_quantum_algs/kem/api.html#pqc_context_get_public_key)
- [`PQC_context_get_keypair`](post_quantum_algs/kem/api.html#pqc_context_get_keypair)
- [`PQC_kem_encapsulate`](post_quantum_algs/kem/api.html#pqc_kem_encapsulate)
- [`PQC_kem_decapsulate`](post_quantum_algs/kem/api.html#pqc_kem_decapsulate)
- [`PQC_kem_encapsulate_secret`](post_quantum_algs/kem/api.html#pqc_kem_encapsulate_secret)
- [`PQC_kem_decapsulate_secret`](post_quantum_algs/kem/api.html#pqc_kem_decapsulate_secret)
- [`PQC_context_close`](post_quantum_algs/kem/api.html#pqc_context_close)
- [McEliece Example](post_quantum_algs/kem/mceliece.html#example)
- [ML-KEM Example](post_quantum_algs/kem/ml-kem.html#example)

### Digital Signature
- [`PQC_context_init_asymmetric`](post_quantum_algs/kem/api.html#pqc_context_init_asymmetric)
- [`PQC_context_keypair_generate`](post_quantum_algs/kem/api.html#pqc_context_keypair_generate)
- [`PQC_keypair_generate`](post_quantum_algs/kem/api.html#pqc_keypair_generate)
- [`PQC_context_get_public_key`](post_quantum_algs/kem/api.html#pqc_context_get_public_key)
- [`PQC_context_get_keypair`](post_quantum_algs/kem/api.html#pqc_context_get_keypair)
- [`PQC_signature_create`](post_quantum_algs/digital_signature/api.html#pqc_signature_create)
- [`PQC_signature_verify`](post_quantum_algs/digital_signature/api.html#pqc_signature_verify)
- [`PQC_context_close`](post_quantum_algs/digital_signature/api.html#pqc_context_close)
- [Falcon Example](post_quantum_algs/digital_signature/falcon.html#example)
- [ML-DSA Example](post_quantum_algs/digital_signature/ml-dsa.html#example)

## Classic Quantum-Resistant Algorithms

### AES-256s
- [`PQC_context_init`](classic_quantum_resistant_algs/aes.html#pqc_context_init)
- [`PQC_context_init_iv`](classic_quantum_resistant_algs/aes.html#pqc_context_init_iv)
- [`PQC_context_set_iv`](classic_quantum_resistant_algs/aes.html#pqc_context_set_iv)
- [`PQC_symmetric_encrypt`](classic_quantum_resistant_algs/aes.html#pqc_symmetric_encrypt)
- [`PQC_symmetric_decrypt`](classic_quantum_resistant_algs/aes.html#pqc_symmetric_decrypt)
- [`PQC_aead_encrypt`](classic_quantum_resistant_algs/aes.html#pqc_aead_encrypt)
- [`PQC_aead_check`](classic_quantum_resistant_algs/aes.html#pqc_aead_check)
- [`PQC_aead_decrypt`](classic_quantum_resistant_algs/aes.html#pqc_aead_decrypt)
- [`PQC_context_close`](classic_quantum_resistant_algs/aes.html#pqc_context_close)
- [AES Examples](classic_quantum_resistant_algs/aes.html#examples)

### SHA-3
- [`PQC_context_init_hash`](classic_quantum_resistant_algs/sha3.html#pqc_context_init_hash)
- [`PQC_hash_update`](classic_quantum_resistant_algs/sha3.html#pqc_hash_update)
- [`PQC_hash_size`](classic_quantum_resistant_algs/sha3.html#pqc_hash_size)
- [`PQC_hash_retrieve`](classic_quantum_resistant_algs/sha3.html#pqc_hash_retrieve)
- [`PQC_context_close`](classic_quantum_resistant_algs/sha3.html#pqc_context_close)
- [SHA-3 Example](classic_quantum_resistant_algs/aes.html#examples)

## Keys
### Symmetric Key Containers
- [`PQC_symmetric_container_create`](keys/keys_container.html#pqc_symmetric_container_create)
- [`PQC_symmetric_container_size`](keys/keys_container.html#pqc_symmetric_container_size)
- [`PQC_symmetric_container_get_version`](keys/keys_container.html#pqc_symmetric_container_get_version)
- [`PQC_symmetric_container_get_creation_time`](keys/keys_container.html#pqc_symmetric_container_get_creation_time)
- [`PQC_symmetric_container_get_expiration_time`](keys/keys_container.html#pqc_symmetric_container_get_expiration_time)
- [`PQC_symmetric_container_get_data`](keys/keys_container.html#pqc_symmetric_container_get_data)
- [`PQC_symmetric_container_from_data`](keys/keys_container.html#pqc_symmetric_container_from_data)
- [`PQC_symmetric_container_save_as`](keys/keys_container.html#pqc_symmetric_container_save_as)
- [`PQC_symmetric_container_open`](keys/keys_container.html#pqc_symmetric_container_save_as)
- [`PQC_symmetric_container_get_key`](keys/keys_container.html#pqc_symmetric_container_get_key)
- [`PQC_symmetric_container_close`](keys/keys_container.html#pqc_symmetric_container_close)
- [`PQC_symmetric_container_delete`](keys/keys_container.html#pqc_symmetric_container_delete)
- [Example](keys/keys_container.html#symmetric-container-example)

### Asymmetric Key Containers
- [`PQC_asymmetric_container_create`](keys/keys_container.html#pqc_asymmetric_container_create)
- [`PQC_asymmetric_container_size`](keys/keys_container.html#pqc_asymmetric_container_size)
- [`PQC_asymmetric_container_size_special`](keys/keys_container.html#pqc_asymmetric_container_size_special)
- [`PQC_asymmetric_container_get_version`](keys/keys_container.html#pqc_asymmetric_container_get_version)
- [`PQC_asymmetric_container_get_creation_time`](keys/keys_container.html#pqc_asymmetric_container_get_creation_time)
- [`PQC_asymmetric_container_get_expiration_time`](keys/keys_container.html#pqc_asymmetric_container_get_expiration_time)
- [`PQC_asymmetric_container_get_data`](keys/keys_container.html#pqc_asymmetric_container_get_data)
- [`PQC_asymmetric_container_from_data`](keys/keys_container.html#pqc_asymmetric_container_from_data)
- [`PQC_asymmetric_container_put_keys`](keys/keys_container.html#pqc_asymmetric_container_put_keys)
- [`PQC_asymmetric_container_get_keys`](keys/keys_container.html#pqc_asymmetric_container_get_keys)
- [`PQC_asymmetric_container_save_as`](keys/keys_container.html#pqc_asymmetric_container_save_as)
- [`PQC_asymmetric_container_open`](keys/keys_container.html#pqc_asymmetric_container_open)
- [`PQC_asymmetric_container_close`](keys/keys_container.html#pqc_asymmetric_container_close)
- [`PQC_asymmetric_container_delete`](keys/keys_container.html#pqc_asymmetric_container_delete)
- [Example](keys/keys_container.html#asymmetric-container-example)

### Randomness Source
- [`PQC_context_random_set_pq_17`](keys/PRNG.html#pqc_context_random_set_pq_17)
- [`PQC_context_random_set_external`](keys/PRNG.html#pqc_context_random_set_external)
- [`PQC_context_init_randomsource`](keys/PRNG.html#pqc_context_init_randomsource)
- [`PQC_context_random_get_bytes`](keys/PRNG.html#pqc_context_random_get_bytes)
- [Example](keys/PRNG.html#example)

### Secure file removal (HDD & SSD)
- [`PQC_file_delete`](keys/secureHDD&SSDRemoval.html#pqc_file_delete)
- [Example](keys/secureHDD&SSDRemoval.html#example)

### PBKDF2
- [`PQC_pbkdf_2`](keys/pbkdf2.html#pqc_pbkdf_2)
- [Example](keys/pbkdf2.html#example)

## Common functions
- [`PQC_cipher_get_length`](common_functions.html#pqc_cipher_get_length)
- [`PQC_context_get_length`](common_functions.html#pqc_context_get_length)
- [Constants](common_functions.html#сonstants)
