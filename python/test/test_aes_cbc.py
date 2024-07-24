import pytest

from test import pqc

# Define the key and data
key = b'12345678901234567890123456789012'  # Replace with your AES key
iv = b'1234567890123456'  # Replace with your initialization vector
data = b'1234567890123456'  # Replace with your plaintext data

# Define the length of the data
data_len = len(data)


# Function to perform CBC encryption
@pytest.fixture
def CBC_encrypt(pqc):
    def encrypt(key, data):
        # Initialize the context
        context = pqc.PQC_init_context_iv(pqc.PQC_CIPHER_AES, key, iv)

        # Encrypt the data
        buffer = pqc.PQC_encrypt(context, pqc.PQC_AES_M_CBC, data)

        # Close the context
        pqc.PQC_close_context(context)

        return buffer

    return encrypt


# Function to perform CBC decryption
@pytest.fixture
def CBC_decrypt(pqc):
    def decrypt(key, data):
        # Initialize the context
        context = pqc.PQC_init_context_iv(pqc.PQC_CIPHER_AES, key, iv)

        # Decrypt the data
        buffer = pqc.PQC_decrypt(context, pqc.PQC_AES_M_CBC, data)

        # Close the context`
        pqc.PQC_close_context(context)

        return buffer

    return decrypt


def test_aes_cbc(CBC_encrypt, CBC_decrypt):
    # Encrypt the data
    buffer = CBC_encrypt(key, data)

    assert buffer != data

    # Decrypt the data
    buffer = CBC_decrypt(key, buffer)

    assert buffer == data
