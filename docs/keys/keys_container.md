---
layout: default
title: Key Containers
parent: Keys Management
nav_order: 1
---

Overview
--------
{: .no_toc }

<details open markdown="block">
  <summary>
    Table of contents
  </summary>
  {: .text-delta }
1. TOC
{:toc}
</details>

**Key Containers** are secure storage locations where cryptographic keys are held. These keys are used for various security purposes such as encrypting and decrypting data, digital signing, and authentication. Key containers help maintain the integrity and confidentiality of these keys, ensuring they are protected from unauthorized access.

GitHub URL:
 - [TQ Asymmetric container](https://github.com/terra-quantum-public/tq42-pqc-oss/blob/main/src/asymmetric_container.cpp)
 - [TQ Symmetric container](https://github.com/terra-quantum-public/tq42-pqc-oss/blob/main/src/container.cpp)

NIST
-----
Key Containers, developed by Terra Quantum, adhere to the comprehensive NIST guidelines specified in the:
- [NIST Key Management Guidelines](https://csrc.nist.gov/projects/key-management/key-management-guidelines) 
- [Recommendation for Key Management](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf)

These guidelines encompass best practices for the management of cryptographic keying material, including general guidance and minimum requirements for federal information systems, aimed at ensuring robust and secure key management.

Key Containers Features
------------------------------

-   **Minimize exposure**: Terra Quantum Key Containers follow best practices by limiting the time secret symmetric or asymmetric private keys remain in plaintext form to reduce the risk of exposure.
-   **Enhance confidentiality**: These containers prevent direct human access to plaintext secret keys, ensuring that keys are not viewed unintentionally or maliciously.
-   **Confirm key correctness**: Key confirmation protocols such as those outlined in SP 800-175B, SP 800-56A, and SP 800-56B are employed to verify the correct establishment of keys, enhancing security.
-   **Verify key integrity**: Terra Quantum Key Containers incorporate cryptographic integrity checks, like Message Authentication Codes (MAC) or digital signatures, to validate a key's integrity and prevent tampering.

Symmetric & Asymmetric Key Containers Distinction
---------------------------------
Please be aware that symmetric and asymmetric containers are stored in separate vectors and must not be confused with one another. Each type serves distinct cryptographic functions, yet they may share identical numerical identifiers. For example, a symmetric container and an asymmetric container could both be labeled with the number "N," but they are inherently different entities.

-   **Risk of Misuse**: Utilizing a function intended for symmetric containers on an asymmetric container (or vice versa) can result in undefined behavior, which might include data corruption, security breaches, or system crashes.



## Symmetric Key Container

### `PQC_symmetric_container_create`
**Function signature:**
```cpp
PQC_CONTAINER_HANDLE PQC_symmetric_container_create();
```
-   The function that is used to create a Symmetric Key Container.
-   This function returns a handle, denoted as  `PQC_CONTAINER_HANDLE`, which serves as a reference to the newly created container within the program's memory.

**Initialization with Random Keys**:
When the container is created, it fetches keys from a selected randomness source. This step ensures that the keys generated for the container are sufficiently random and secure for cryptographic operations.
    
**File Association Clarification**:
 It's important to note that upon creation, the new container is not automatically linked to a file on disk. This means that the container is purely in memory and needs to be saved explicitly to disk if persistent storage is required. This can be achieved using function  `PQC_symmetric_container_save_as()`.
 
**Handling Container Data**:
    If there is a need to work with the contents of the container, such as transferring it over a network or performing other operations, the data within the container can be extracted using a function like  `PQC_symmetric_container_get_data()`. This function retrieves the contents of the container in a suitable format for further processing or transmission.

### `PQC_symmetric_container_size`

**Function signature**:  
```cpp
size_t PQC_symmetric_container_size(PQC_CONTAINER_HANDLE container)     
```
- is designed to determine the size of the buffer needed to store the data extracted from the container.
- This step is crucial for ensuring that the buffer allocated for storing the container data is of the appropriate size to prevent data loss or truncation.

**Parameters**:
    
   - `container`: This parameter represents the handle of the container from which the data size is being queried. It serves as a reference to the specific container being processed.

**Return Value**:
    
   - The return value of this function is the size of the data required to store the contents of the specified container.
   - This size value is essential for allocating a buffer with sufficient capacity to accommodate the extracted container data without loss or overflow.

### `PQC_symmetric_container_get_version`

**Function signature**:  
```cpp
uint32_t PQC_symmetric_container_get_version(PQC_CONTAINER_HANDLE container)
```
- is designed to determine the container version.

**Parameters**:
    
   - `container`: This parameter represents the handle of the container from which the version is being queried. It serves as a reference to the specific container being processed.

**Return Value**:
    
   - The return value of this function is the container version.

####  `PQC_symmetric_container_get_creation_time`
**Function signature**
```cpp
uint64_t PQC_symmetric_container_get_creation_time(PQC_CONTAINER_HANDLE container);
```

-   **Parameters**:
   -   `container`: Handle of the container for which the creation timestamp (seconds since UNIX epoch) needs to be determined.
-   **Return values**:
    -   Returns the creation timestamp (seconds since UNIX epoch) of the container.

####  `PQC_symmetric_container_get_expiration_time`
**Function signature**
```cpp
uint64_t PQC_symmetric_container_get_expiration_time(PQC_CONTAINER_HANDLE container);
```

-   **Parameters**:
   -   `container`: Handle of the container for which the expiration timestamp (seconds since UNIX epoch) needs to be determined.
-   **Return values**:
    -   Returns the expiration timestamp (seconds since UNIX epoch) of the container. After this timestamp getting keys is not available.


### `PQC_symmetric_container_get_data`
**Function signature**
```cpp
int PQC_symmetric_container_get_data(PQC_CONTAINER_HANDLE container, 
                                        uint8_t* container_data, 
                                        size_t data_length, 
                                        const uint8_t* key, 
                                        size_t key_length, 
                                        const uint8_t* iv, 
                                        size_t iv_length);
```
is designed to retrieve the encrypted data from the specified container and store it in a buffer. The retrieved data can then be utilized, for instance, for transmission over a network.

**Parameters**

-   `container`: Handle of the container from which the data is to be extracted.
-   `container_data (out)`: Pointer to the buffer used to store the retrieved container data.
-   `data_length`: Length of the buffer pointed to by  `container_data`. It should be the size returned by the  `PQC_symmetric_container_size()`  function, ensuring that the buffer is appropriately sized to accommodate the retrieved data.
-   `key`: AES key used to encrypt the container. It should point to a  `pqc_aes_key`  structure or any buffer of size  `PQC_AES_KEYLEN`.
-   `key_length`: Length of the key buffer.
-   `iv`: AES initialization vector for the container encryption. It should point to a  `pqc_aes_iv`  structure or any buffer of size  `PQC_AES_IVLEN`.
-   `iv_length`: Length of the IV buffer.

**Return Values**

The function can yield the following return values:

-   `PQC_OK`: Indicates successful operation, signifying that the data retrieval was completed without any issues.
-   `PQC_BAD_CONTAINER`: Denotes an invalid container handle, suggesting the specified container is not valid or accessible.
-   `PQC_BAD_LEN`: Indicates that one of the buffers (either  `container_data`,  `key`, or  `iv`) has an incorrect length, reflecting a mismatch between the expected and actual buffer sizes.

### `PQC_symmetric_container_from_data`
**Function signature**
```cpp
PQC_CONTAINER_HANDLE PQC_symmetric_container_from_data(const uint8_t* container_data,
                                                        size_t data_length,
                                                        const uint8_t *key,
                                                        size_t key_length,
                                                        const uint8_t* iv,
                                                        size_t iv_length);
```
is designed to reconstruct a container from the extracted data, allowing for the restoration of the original container structure.

**Parameters**: 
  - `container_data`: Pointer to a buffer containing the extracted container data that needs to be reconstructed.
  - `data_length`: Length of the buffer pointed to by  `container_data`, ensuring that the data is correctly sized for the reconstruction process.
  - `key`: AES key utilized to encrypt the container. It should point to a  `pqc_aes_key`  structure or any buffer of size  `PQC_AES_KEYLEN`.
  -  `key_length`: Length of the key buffer.
  - `iv`: AES initialization vector for container encryption, pointing to a  `pqc_aes_iv`  structure or any buffer of size  `PQC_AES_IVLEN`.
  - `iv_length`: Length of the IV buffer.
  
**Return Values**:   
- `PQC_FAILED_TO_CREATE_CONTAINER`: Indicates that the container creation process failed, likely due to incorrect input buffer sizes. This return value helps to identify issues during the container reconstruction.
- Otherwise: The handle of the created container is returned upon successful reconstruction, enabling further manipulation or processing of the container.
     
**File Association Reminder**:
- It's highlighted that the new container, once reconstructed, is not automatically linked to a file on disk. It's recommended to save the container using functions like `PQC_symmetric_container_save_as()`  or  `PQC_symmetric_container_save_as_pair()`  for persistence or further utilization.

### `PQC_symmetric_container_save_as`
**Function Signature**:
```cpp
int PQC_symmetric_container_save_as(PQC_CONTAINER_HANDLE container, 
                                    const char* filename,
                                    const char* password,
                                    const char *salt);
```
- is utilized to save a container, possibly created earlier in the program, to a file.

**Parameters**:
- `container`: Handle of the container that needs to be saved to the file.
- `filename`: File name that will be used to save container.
- `client_m`: Client name used for file name generation.
- `client_k`: Client name used for file name generation.
- `password`: Password used to encrypt the file for security.
- `salt`: Salt value used in file encryption. It's recommended to use a constant specific to the application for enhanced security.

**Return Values**:
    
- `PQC_OK`: Indicates that the operation of saving the container to the file was successful.
- `PQC_BAD_CONTAINER`: Denotes an invalid container handle, signifying issues with the container reference.
- `PQC_IO_ERROR`: Indicates an error occurred during the process of saving the file, flagging potential issues with file I/O operations.

### `PQC_symmetric_container_open`
**Function signature**
```cpp
PQC_CONTAINER_HANDLE PQC_symmetric_container_open(const char* filename,
                                                    const char* password,
                                                    const char* salt);
```
- is designed to load a container from a file.

**Parameters**:    

- `filename`: File name that will be used to save container.
- `client_m`: Client name used for filename generation.
- `client_k`: Client name used for filename generation.
- `password`: Password used to encrypt the file for security.
- `salt`: Salt value used in file encryption. It's recommended to use a constant specific to the application for enhanced security.

**Return Values**:
  - `PQC_FAILED_TO_CREATE_CONTAINER`: Indicates that there was an error, most probably an I/O error, during container loading.
  - Otherwise: The return value is a handle to a container, allowing for further manipulation or processing of the loaded container.

**Additional Notes**
-   The use of password and salt during loading ensures file encryption is maintained for secure data retrieval.

### `PQC_symmetric_container_get_key`
**Function signature:**
```cpp
int PQC_symmetric_container_get_key(PQC_CONTAINER_HANDLE container, 
                                    int index, 
                                    size_t bytes_encoded,
                                    uint32_t cipher,
                                    uint32_t method,
                                    uint8_t* key,
                                    size_t key_length);
```
-   is designed to retrieve an encryption key from a container, allowing for access to the specified key for cryptographic and decryption operations.

**Parameters**:
- `container`: Container handle, representing the specific container from which the key is to be retrieved.
- `index`: The index of the key to be retrieved, currently within the range of 0 to 5.
- `bytes_encoded`: The number of bytes to be encoded with the retrieved key.
- `cipher`: The cipher to be used for encryption; currently, it should be  `PQC_CIPHER_AES`.
- `method`: The encryption method to be used, specified as one of the  `PQC_AES_M_...`  constants.
```cpp
PQC_AES_M_CBC = 2
PQC_AES_M_ECB = 3
PQC_AES_M_OFB = 4
PQC_AES_M_GCM = 5
PQC_AES_M_CTR = 6
```

- `key (out)`: Pointer to a buffer for storing the retrieved key. It should point to a  `pqc_aes_key`  structure or any buffer of length  `PQC_AES_KEYLEN`.
- `key_length`: The length of the key buffer.

**Return Values**:
- `PQC_OK`: Indicates that the operation of retrieving the key from the container was successful.
- `PQC_CONTAINER_DEPLETED`: Indicates that the key at the specified index was used above the allowed capacity, potentially exceeding the usage limits of the container.
- `PQC_CONTAINER_EXPIRED`: Indicates that the key exceeded the usage time limits of the container.
- `PQC_BAD_CONTAINER`: Denotes an invalid container handle or index out of range, highlighting issues with the container reference or index value.
- `PQC_BAD_CIPHER`: Indicates an unsupported cipher.
- `PQC_BAD_MODE`: Denotes an unsupported encryption method.
- `PQC_BAD_LEN`: Denotes the wrong length of the key buffer, reflecting a mismatch between the expected and actual buffer size.
- `PQC_IO_ERROR`: Denotes an I/O error, potentially occurring while saving the modified container.

**Automatic Update**:    
- It's highlighted that if the container is associated with a file (created using one of the  `PQC_container_open_...`  functions or saved with one of the  `PQC_container_save_...`  functions), it will be automatically updated on disk with a new use count when a key is read from the container.
The provided code snippet outlines a function designed to close a container when it's no longer in use.

Here's a breakdown of the function and its relevant components:

### `PQC_symmetric_container_close`
**Function signature:**    
```cpp
PQC_symmetric_container_close(PQC_CONTAINER_HANDLE container)
```
- This function is used to safely close a specified container, effectively releasing or finalizing resources associated with that container. Closing containers when they are no longer in use is a best practice that helps manage resources efficiently and ensures data integrity.

**Parameters:**

-   **`container`**: This parameter is the handle to the container that needs to be closed. The handle acts as a unique identifier for the container within the application or system, allowing the function to pinpoint which specific container to close.

**Return Values:**

-   **`PQC_OK`**: This return value indicates that the operation was successful, meaning the container was closed without any issues.
-   **`PQC_BAD_CONTAINER`**: This return value indicates an invalid container handle was provided, which means the function failed to find or recognize the specified container, and therefore, could not close it. This could occur if the container handle is incorrect, has already been closed, or never existed.

### `PQC_symmetric_container_delete`
**Function signature:**    
```cpp
size_t PQC_API PQC_symmetric_container_delete(const char * filename)
```

- This function deletes a file with the specified name.

**Parameters**:

- `filename`: A string representing the name of the file to be deleted.


**Return Values:**

-  **`PQC_OK`**: Indicates that the operation was successful.
-  **`PQC_IO_ERROR`**: Indicates that the operation was not performed due to an input/output error.



### Symmetric container example


```cpp
{% include examples/container/container_example_3_write_read_to_file.cpp %}
```


## Asymmetric Key Container

Include: `pqc/falcon.h`

### `PQC_asymmetric_container_create`

**Function signature**
```cpp
PQC_CONTAINER_HANDLE PQC_asymmetric_container_create(uint32_t cipher);
```

-   This function is designed for the creation of a new asymmetric cryptographic container. The type of encryption cipher used within the container is determined by the input parameter  `cipher`.

**Parameters**

-   **`cipher`**: This parameter specifies the encryption algorithm to use within the container. It's defined by integer constants that uniquely determine each cipher:
    -   **`PQC_CIPHER_FALCON (5)`**: selects the Falcon cipher, recognized for its use in digital signatures and security efficacy in post-quantum cryptographic scenarios.

**Return Value**

-   **`handle of created container`**: The function returns a handle-essentially a reference or an identifier to the newly created container. This handle can be used in subsequent operations to manipulate or query the container.

**Container Initialization**

-   **Key Fetching**: As part of the container's creation, cryptographic keys are sourced from a [specified randomness source](keys/PRNG.html). This ensures that the cryptographic keys are robust and secure, fitting the requirements for secure cryptographic operations.
-   **Memory Residency**: It is crucial to note that the container exists only in the memory when created. There's no automatic storage or file association happening during the container's creation.

**Important Note**

-   **Saving the Container**: The newly created container should be explicitly saved to disk or another storage medium to ensure it is preserved beyond the current application session. This should be done using a different function specifically intended for saving containers.

####  `PQC_asymmetric_container_size`

**Function signature**
```cpp
size_t PQC_asymmetric_container_size(PQC_CONTAINER_HANDLE container);
```

-   **Parameters**:
    -   `container`: Handle of the container for which the size of the required buffer needs to be determined.
-   **Return values**:
    -   Returns the size of the data required to store the contents of the container.

####  `PQC_asymmetric_container_size_special`
**Function signature**
```cpp
size_t PQC_asymmetric_container_size_special(uint32_t cipher, uint16_t mode);
```

-   **Parameters**:
    -   `cipher`: Constant to select the cipher algorithm. Possible values are:
        -   `PQC_CIPHER_FALCON (5)`
    -   `mode`: Additional mode specifier which should always be set to zero as per the requirement.
-   **Return values**:
    -   Returns the size of the data required to store the container, given a specific type of cipher.

####  `PQC_asymmetric_container_get_version`
**Function signature**
```cpp
uint32_t PQC_API PQC_asymmetric_container_get_version(PQC_CONTAINER_HANDLE container);
```

-   **Parameters**:
   -   `container`: Handle of the container for which the version needs to be determined.
-   **Return values**:
    -   Returns the container version.
    
####  `PQC_asymmetric_container_get_creation_time`
**Function signature**
```cpp
uint64_t PQC_API PQC_asymmetric_container_get_creation_time(PQC_CONTAINER_HANDLE container);
```

-   **Parameters**:
   -   `container`: Handle of the container for which the creation timestamp (seconds since UNIX epoch) needs to be determined.
-   **Return values**:
    -   Returns the creation timestamp (seconds since UNIX epoch) of the container.

####  `PQC_asymmetric_container_get_expiration_time`
**Function signature**
```cpp
uint64_t PQC_API PQC_asymmetric_container_get_expiration_time(PQC_CONTAINER_HANDLE container);
```

-   **Parameters**:
   -   `container`: Handle of the container for which the expiration timestamp (seconds since UNIX epoch) needs to be determined.
-   **Return values**:
    -   Returns the expiration timestamp (seconds since UNIX epoch) of the container. After this timestamp getting keys is not available.

### `PQC_asymmetric_container_get_data`
**Function signature**
```cpp
int PQC_asymmetric_container_get_data(PQC_CONTAINER_HANDLE container,
                                        uint8_t* container_data,
                                        size_t data_length,
                                        const uint8_t* key,
                                        size_t key_length,
                                        const uint8_t* iv,
                                        size_t iv_length);
```

**Parameters**:
- `container`: Handle of the container from which data is to be extracted.
- `container_data (out)`: Pointer to the buffer where the container's data will be stored.
- `data_length`: Length of the buffer pointed to by  `container_data`. This should be the size returned by  `PQC_asymmetric_container_size()`  or  `PQC_asymmetric_container_size_special()`.
- `key`: AES key used for the encryption of the container. This should point to an appropriate  `pqc_aes_key`  structure or any buffer of the correct size (`PQC_AES_KEYLEN`).
- `key_length`: Length of the key buffer.
- `iv`: AES initialization vector for container encryption. This should point to a  `pqc_aes_iv`  structure or any buffer of the appropriate size (`PQC_AES_IVLEN`).
- `iv_length`: Length of the IV buffer.

**Return values**:
 - `PQC_OK`: Indicates that the operation was successful.
 - `PQC_BAD_CONTAINER`: Indicates an invalid container handle.
 - `PQC_BAD_LEN`: Points out that one of the buffers has an incorrect length.

### `PQC_asymmetric_container_from_data`
reconstructs a container based on the extracted data, such as data received over a network.

**Function signature:**
```cpp
PQC_CONTAINER_HANDLE PQC_asymmetric_container_from_data(uint32_t cipher, 
                                                        const uint8_t* container_data, 
                                                        size_t data_length, 
                                                        const uint8_t* key, size_t key_length, 
                                                        const uint8_t* iv, 
                                                        size_t iv_length);
```

**Parameters**:
-   `cipher`: Constant used to select the cipher algorithm. Possible values are  `PQC_CIPHER_FALCON`  (5). The chosen cipher should match the cipher used for the data.
-   `container_data`: Pointer to the container data.
-   `data_length`: Length of the container data.
-   `key`: Pointer to the key used for encryption.
-   `key_length`: Length of the key buffer.
-   `iv`: Pointer to the initialization vector (IV) used for encryption.
-   `iv_length`: Length of the IV buffer.

**Return Values**
-   `PQC_FAILED_TO_CREATE_CONTAINER`: Indicates that the container was not created due to incorrect input buffer size.
-   Otherwise: Returns the handle of the created container upon successful reconstruction.

**Additional Notes**
-   The newly reconstructed container is not automatically associated with a file on disk.
-   Saving the container to a file should be done using another function.

### `PQC_asymmetric_container_put_keys`
**Function signature**
```cpp
int PQC_asymmetric_container_put_keys(uint32_t cipher, 
                                        PQC_CONTAINER_HANDLE container,
                                        uint8_t* pk, 
                                        size_t pk_length, 
                                        uint8_t* sk, 
                                        size_t sk_length);
```
 is responsible for inserting keys into an asymmetric container. It is important to note that asymmetric containers do not automatically generate keys and they need to be generated separately using the  `PQC_generate_key_pair()`  function before being inserted into the container.

**Parameters**
-   `cipher`: Constant used to select the cipher algorithm. Possible values are  `PQC_CIPHER_FALCON`  (5). The cipher selected should match the cipher used for the keys and the container.
-   `container`: Handle of the container where the keys will be inserted.
-   `sk`: Pointer to where the private key will be stored. The key format should match the chosen cipher:
    -   For  `PQC_CIPHER_FALCON`: Use  `pqc_falcon_private_key`  structure or a buffer of size  `PQC_FALCON_PRIVATE_KEYLEN`.
-   `pk`: Pointer to where the public key will be stored. The key format should match the chosen cipher:
    -   For  `PQC_CIPHER_FALCON`: Use  `pqc_falcon_public_key`  structure or a buffer of size  `PQC_FALCON_PUBLIC_KEYLEN`.
-   `pk_length`: Length of the public key.
-   `sk_length`: Length of the secret key.

**Return Values**

-   `PQC_OK`: Indicates a successful operation of inserting keys into the container.
-   `PQC_BAD_CONTAINER`: Represents an invalid container handle.
-   `PQC_BAD_CIPHER`: Indicates an incorrect cipher was provided.
-   `PQC_BAD_LEN`: Signifies an incorrect length of any parameter provided.

**Additional Notes**

-   It is essential to generate the keys using  `PQC_generate_key_pair()`  before inserting them into the container.
-   The function ensures that the keys are inserted correctly with respect to the chosen cipher within the container.

### `PQC_asymmetric_container_get_keys`

**Function signature:**
```cpp
int PQC_asymmetric_container_get_keys(uint32_t cipher, 
                                        PQC_CONTAINER_HANDLE container,
                                        uint8_t* pk,
                                        size_t pk_length,
                                        uint8_t* sk,
                                        size_t sk_length);
```
 is responsible for retrieving encryption keys from a container.

**Parameters**
-   `cipher`: A constant used to select the cipher algorithm, with possible values being  `PQC_CIPHER_FALCON`  (5). The selected cipher should match the cipher used for the keys and the container.
-   `container`: The handle of the container from which the keys will be retrieved.
-   `sk`: A pointer to where the private key will be stored. The key format should match the chosen cipher:
    -   For  `PQC_CIPHER_FALCON`: The  `pqc_falcon_private_key`  structure should be used, or any buffer of size  `PQC_FALCON_PRIVATE_KEYLEN`.
-   `pk`: A pointer to where the public key will be stored. The key format should match the chosen cipher:
    
    -   For  `PQC_CIPHER_FALCON`: The  `pqc_falcon_public_key`  structure should be used, or any buffer of size  `PQC_FALCON_PUBLIC_KEYLEN`.
-   `pk_length`: The length of the public key.    
-   `sk_length`: The length of the secret key.

**Return Values**

-   `PQC_OK`: Indicates a successful operation of retrieving keys from the container.
-   `PQC_BAD_CONTAINER`: Represents an invalid container handle or index out of range.
-   `PQC_BAD_CIPHER`: Indicates an unsupported cipher.
-   `PQC_BAD_MODE`: Indicates an unsupported encryption method.
-   `PQC_BAD_LEN`: Signifies a wrong length of the key buffer.

**Additional Notes**

-   This function serves the purpose of retrieving encryption keys from a container, ensuring that the keys are appropriately structured and matched with the chosen cipher.
-   Following the specified key formats and lengths is crucial for successful key retrieval from the container.

### `PQC_asymmetric_container_save_as`

**Function signature:**
```cpp
int PQC_asymmetric_container_save_as(uint32_t cipher, 
                                        PQC_CONTAINER_HANDLE container,
                                        const char* filename,
                                        const char* password,
                                        const char* salt);
```
is responsible for saving a container to a file.

**Parameters**
-   `cipher`: A constant used to select the cipher algorithm, with possible values being  `PQC_CIPHER_FALCON`  (5). The chosen cipher should match the cipher used for the container.
-   `container`: The handle of the container to be saved.
-   `filename`: File name that will be used to save container.
-   `password`: The password used to encrypt the file.
-   `salt`: The salt used in file encryption. It is recommended to set it to some constant string specific to the application.

**Return Values**

-   `PQC_OK`: Indicates a successful operation of saving the container to a file.
-   `PQC_BAD_CONTAINER`: Represents an invalid container handle.
-   `PQC_IO_ERROR`: Indicates an error while saving the file.

**Additional Notes**

-   This function is responsible for persisting the container to a file, it is essential to provide the unique naming of the file to avoid collisions.
-   It is essential to provide the appropriate password and salt for file encryption to ensure security.

### `PQC_asymmetric_container_open` 

**Function signature:**
```cpp
PQC_CONTAINER_HANDLE PQC_asymmetric_container_open(uint32_t cipher,
                                                    const char* filename,
                                                    const char* password,
                                                    const char* salt);
```
The function is responsible for creating a container handle based on the provided parameters and the file contents.

**Parameters**

-   `cipher`: A constant used to select the cipher algorithm, with possible values being  `PQC_CIPHER_FALCON` (5). The chosen cipher should match the cipher used for the container.
-   `filename`: File name that will be used to save container.
-   `password`: The password used to decrypt the file.
-   `salt`: The salt used in file decryption. It is recommended to set it to a constant string specific to the application.

**Return Values**

-   `PQC_FAILED_TO_CREATE_CONTAINER`: Indicates an error, most probably an I/O error, during container loading.
-   Otherwise, a handle to a container is returned.

**Additional Notes**

-   This function is responsible for loading a container from a file, it is essential to provide the unique naming of the file to avoid collisions.
-   The function requires the correct password and salt for successful decryption of the file and creation of the container handle.

### `PQC_asymmetric_container_close`
**Function signature:**
```cpp
int PQC_asymmetric_container_close(PQC_CONTAINER_HANDLE container);
```
is utilized to close a container handle when it is no longer in use.

**Parameters**

-   `container`: The container handle that is no longer in use and needs to be closed.

**Return Values**

-   `PQC_OK`: Indicates that the operation to close the container handle was successful.
-   `PQC_BAD_CONTAINER`: Represents an invalid container handle.

**Additional Notes**

-   This function is used to release the resources associated with a container handle, ensuring proper memory management and resource cleanup.
-   It is important to provide a valid container handle as a parameter to successfully close the container.

### `PQC_asymmetric_container_delete`
**Function signature:**    
```cpp
size_t PQC_API PQC_asymmetric_container_delete(const char * filename)
```
- This function deletes a file with the specified name.

**Parameters**:

- `filename`: A string representing the name of the file to be deleted.

**Return Values:**

-  **`PQC_OK`**: Indicates that the operation was successful.
-  **`PQC_IO_ERROR`**: Indicates that the operation was not performed due to an input/output error.

## Asymmetric container example

```cpp
{% include examples/asymmetric_container/asymmetric_container_example_3_write_read_to_file_falcon.cpp %}
```

