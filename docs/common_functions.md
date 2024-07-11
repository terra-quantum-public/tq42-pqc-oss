---
layout: default
title: Common functions
nav_order: 7
---

# Common functions
{: .no_toc }

<details open markdown="block">
  <summary>
    Table of contents
  </summary>
  {: .text-delta }
1. TOC
{:toc}
</details>

The section provides detailed descriptions of common functions and constants used in the TQ42 Cryptography.

## Common functions 

### `PQC_get_length`

**Function signature**

```cpp
size_t PQC_API PQC_get_length(uint32_t cipher, uint32_t type);
```

**Purpose**: This function returns the size of a specific variable in bytes for a given algorithm type.

**Parameters**:

- `cipher`: A constant used to select the cryptographic algorithm. [`Cipher constants`](common_functions.html#cipher)
- `type`: A constant used to determine the type of buffer whose length is needed: [`The length parameter`](common_functions.html#the-length-parameter)

- return values:
	- `0`: Indicates an error, such as an invalid cipher/type pairing.
	- Otherwise, the length of the specified key or buffer in bytes.

### `PQC_context_get_length`

**Function signature**

```cpp
size_t PQC_API PQC_context_get_length(CIPHER_HANDLE context, uint32_t type);
```
**Purpose**: This function returns the size of the specified algorithm based on the provided context.

**Parameters**:

`context` : A memory area allocated for a particular algorithm. This context is initialized when an algorithm is selected (space is allocated for it and a handle is obtained). This handle is then used in all related functions without direct access to the class object.
`type`: A constant specifying the type of length to be retrieved. [`The length parameter`](common_functions.html#the-length-parameter)

**Return values:**

*   `size_t`: The length of the algorithm associated with the specified context.
    
*   `0`: Indicates an error, such as an invalid context or type.
    

## Сonstants

### Cipher:

    - PQC_CIPHER_AES		(1): AES-256
	- PQC_CIPHER_FALCON		(5): Falcon
	- PQC_CIPHER_MCELIECE		(10): Classic McEliece

### The length parameter:

	- PQC_LENGTH_SYMMETRIC		(0): length of key for symmetric algorhitms
	- PQC_LENGTH_IV		  	(1): length of initialization vector
	- PQC_LENGTH_PUBLIC	  	(2): length of public key
	- PQC_LENGTH_PRIVATE	  	(3): length of private key
	- PQC_LENGTH_SIGNATURE 		(4): length of signature
	- PQC_LENGTH_MESSAGE	  	(5): length of message
	- PQC_LENGTH_SHARED	  	(6): length of shared secret

