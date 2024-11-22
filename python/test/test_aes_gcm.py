import pytest

from test import pqc

# Define the key and data
key = b'12345678901234567890123456789012'  # Replace with your AES key
iv = b'1234567890123456'  # Replace with your initialization vector
data = b'1234567890123456'  # Replace with your plaintext data
aad = b'qwertyuiopasdfghjklzxcvbnm' # Replace with your additional data

# Define the length of the data
data_len = len(data)


# Function to perform GCM encryption
@pytest.fixture
def GCM_encrypt(pqc):
    def encrypt(key, data):
        # Initialize the context
        context = pqc.PQC_context_init_iv(pqc.PQC_CIPHER_AES, key, iv)

        # Encrypt the data
        buffer, tag = pqc.PQC_aead_encrypt(context, pqc.PQC_AES_M_GCM, data, aad)

        # Close the context
        pqc.PQC_context_close(context)

        return buffer, tag

    return encrypt


# Function to check GCM tag
@pytest.fixture
def GCM_check(pqc):
    def check(key, data, tag):
        # Initialize the context
        context = pqc.PQC_context_init_iv(pqc.PQC_CIPHER_AES, key, iv)

        # Decrypt the data
        result = pqc.PQC_aead_check(context, pqc.PQC_AES_M_GCM, data, aad, tag)

        # Close the context
        pqc.PQC_context_close(context)

        return result

    return check

# Function to perform GCM decryption
@pytest.fixture
def GCM_decrypt(pqc):
    def decrypt(key, data, tag):
        # Initialize the context
        context = pqc.PQC_context_init_iv(pqc.PQC_CIPHER_AES, key, iv)

        # Decrypt the data
        buffer = pqc.PQC_aead_decrypt(context, pqc.PQC_AES_M_GCM, data, aad, tag)

        # Close the context
        pqc.PQC_context_close(context)

        return buffer

    return decrypt


def test_aes_gcm(GCM_encrypt, GCM_decrypt, GCM_check):
    # Encrypt the data
    buffer, tag = GCM_encrypt(key, data)

    assert buffer != data

    # check tag
    assert GCM_check(key, buffer, tag)

    # Decrypt the data
    buffer = GCM_decrypt(key, buffer, tag)

    assert buffer == data
