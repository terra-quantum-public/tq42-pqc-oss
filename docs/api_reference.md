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
- [`PQC_generate_key_pair`](post_quantum_algs/kem/api.html#pqc_generate_key_pair)
- [`PQC_init_context`](post_quantum_algs/kem/api.html#pqc_init_context)
- [`PQC_kem_encode`](post_quantum_algs/kem/api.html#pqc_kem_encode)
- [`PQC_kem_decode`](post_quantum_algs/kem/api.html#pqc_kem_decode)
- [`PQC_kem_encode_secret`](post_quantum_algs/kem/api.html#pqc_kem_encode_secret)
- [`PQC_kem_decode_secret`](post_quantum_algs/kem/api.html#pqc_kem_decode_secret)
- [`PQC_close_context`](post_quantum_algs/kem/api.html#pqc_close_context)
- [McEliece Example](post_quantum_algs/kem/mceliece.html#example)

### Digital Signature
- [`PQC_generate_key_pair`](post_quantum_algs/digital_signature/api.html#pqc_generate_key_pair)
- [`PQC_init_context`](post_quantum_algs/digital_signature/api.html#pqc_init_context)
- [`PQC_sign`](post_quantum_algs/digital_signature/api.html#pqc_sign)
- [`PQC_verify`](post_quantum_algs/digital_signature/api.html#pqc_verify)
- [`PQC_close_context`](post_quantum_algs/digital_signature/api.html#pqc_close_context)
- [Falcon Example](post_quantum_algs/digital_signature/falcon.html#example)

## Classic Quantum-Resistant Algorithms

### AES-256
- [`PQC_init_context`](classic_quantum_resistant_algs/aes.html#pqc_init_context)
- [`PQC_init_context_iv`](classic_quantum_resistant_algs/aes.html#pqc_init_context_iv)
- [`PQC_set_iv`](classic_quantum_resistant_algs/aes.html#pqc_set_iv)
- [`PQC_encrypt`](classic_quantum_resistant_algs/aes.html#pqc_encrypt)
- [`PQC_decrypt`](classic_quantum_resistant_algs/aes.html#pqc_decrypt)
- [`PQC_close_context`](classic_quantum_resistant_algs/aes.html#pqc_close_context)
- [AES Examples](classic_quantum_resistant_algs/aes.html#examples)

### SHA-3
- [`PQC_init_context_hash`](classic_quantum_resistant_algs/sha3.html#pqc_init_context_hash)
- [`PQC_add_data`](classic_quantum_resistant_algs/sha3.html#pqc_add_data)
- [`PQC_hash_size`](classic_quantum_resistant_algs/sha3.html#pqc_hash_size)
- [`PQC_get_hash`](classic_quantum_resistant_algs/sha3.html#pqc_get_hash)
- [`PQC_close_context`](classic_quantum_resistant_algs/sha3.html#pqc_close_context)
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
- [`PQC_random_from_pq_17`](keys/PRNG.html#pqc_random_from_pq_17)
- [`PQC_random_from_external`](keys/PRNG.html#pqc_random_from_external)
- [`PQC_random_bytes`](keys/PRNG.html#pqc_random_bytes)
- [Example](keys/PRNG.html#example)

### Secure file removal (HDD & SSD)
- [`PQC_file_delete`](keys/secureHDD&SSDRemoval.html#pqc_file_delete)
- [Example](keys/secureHDD&SSDRemoval.html#example)

## Common functions
- [`PQC_get_length`](common_functions.html#pqc_get_length)
- [`PQC_context_get_length`](common_functions.html#pqc_context_get_length)
- [Constants](common_functions.html#сonstants)
