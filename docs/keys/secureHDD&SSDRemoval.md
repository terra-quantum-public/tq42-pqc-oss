---
layout: default
title: Secure File Removal (HDD, SSD)
parent: Keys Management
nav_order: 3
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

Safe deletion from both hard disk drives (HDDs) and solid state drives (SSDs) is crucial due to the sensitive nature of the data stored on these devices. When a file is "deleted" from a drive, it is typically not physically removed from the storage medium; instead, the file system marks the space occupied by the file as available for new data to be written over. This means that the deleted data can potentially be recovered using specialized software or techniques.

The importance of safe deletion is underscored by several key considerations: **Data Privacy and Security**, **Legal and Compliance Requirements**, **Data Residuals and End-of-Life Disposal**, and **Protection Against Data Recovery**.

NIST
----

[https://csrc.nist.gov/pubs/sp/800/88/r1/final](https://csrc.nist.gov/pubs/sp/800/88/r1/final)

NIST 800-88 is a standard published by the National Institute of Standards and Technology (NIST) for secure washing of storage devices. This standard is designed to help organizations meet legal and regulatory requirements for data erasure, as well as protect sensitive information. The standard outlines a process for securely erasing data based on its format, which can be used to ensure that the data cannot be recovered even if the storage device is damaged or repurposed. The NIST disk wipe standard includes a number of important considerations, such as the type of data, the storage device, and the data wiping technique used.

Secure File Deletion Implementation
-----------------------------------

The objective of this protocol is to ensure the secure deletion of files from both HDDs and SSDs through a series of meticulous operations designed to remove data beyond recovery. This process takes advantage of advanced cryptographic techniques and specific deletion strategies suited for the underlying storage technology.

**Dynamic Key Generation**

**Initialization Procedure**: Initiate the process by generating a unique encryption key and allocating it within dynamic memory.

**Key Randomization Process**

**Utilization of PQC\_random_bytes**: Deploy the cryptographic function `PQC_random_get_bytes(void*, size_t)` to infuse the key with a sequence of random values. The introduction of randomness is critical, significantly supporting the encryption key's resilience against both brute force attacks and decryption strategies.

**File Encryption Procedure**

**AES CBC Mode Application**: Once the key is duly randomized, encrypt the designated file utilizing the AES in CBC (Cipher Block Chaining) mode. The AES CBC mode is renowned for its strong security attributes, efficiently encrypting content to render it indecipherable in the absence of the specific encryption key.

**Data Elimination Strategy**

**Remove the Key**: Following the encryption phase, the dynamic memory housing the key should be immediately removed. This action is important to eliminate any residual traces that could be potentially leveraged to decrypt the encryption.

**Permanent File Removal:** The encrypted file can then be deleted.

  
This procedure underscores a critical facet of secure file deletion: without the unique encryption key, which has been securely disposed of, the encrypted file is transformed into an inaccessible data block, effectively nullifying any potential for data recovery or unauthorized access.

API
----
### `PQC_file_delete`

Include `pqc/delete.h`

The `PQC_file_delete` function is designed to securely delete a file from a storage medium.

**Function signature:**

```cpp
int PQC_file_delete(CIPHER_HANDLE handle, const char* filename);
```

**Parameters:**
* `handle`: The encryption context handle. This is used to provide random source for container creation. Use `PQC_container_create_randomsource` to create context for a sole purpose of generating random numbers.
*   `filename`: This is the input parameter, which refers to the name of the file that needs to be deleted. It can be just the file name if the file is located in the current working directory of the application, or it can be a full path to the file if located elsewhere.
    

**Return values:**

*   `PQC_OK`: This return value indicates that the operation was executed successfully. It implies that the file was found, the secure deletion process as prescribed was completed, and the file was deleted without encountering any issues.
    
*   `PQC_IO_ERROR`: This return value suggests that an unexpected error occurred during the deletion process. It covers situations such as issues with disk access or insufficient permissions.

*	`PQC_RANDOM_FAILURE`: External random source returns error 

Example
---------

**Code**

```cpp
{% include examples/ssd_hdd_removal/ssd_hdd_removal.cpp %}```
