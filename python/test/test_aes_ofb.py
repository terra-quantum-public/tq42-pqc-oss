import pytest

from test import pqc

# Define the key and data
key = b'12345678901234567890123456789012'  # Replace with your AES key
iv = b'1234567890123456'  # Replace with your initialization vector
data = b'1234567890123456'  # Replace with your plaintext data

# Define the length of the data
data_len = len(data)


# Function to perform OFB encryption
@pytest.fixture
def OFB_encrypt(pqc):
    def encrypt(key, data):
        # Initialize the context
        context = pqc.PQC_context_init_iv(pqc.PQC_CIPHER_AES, key, iv)

        # Encrypt the data
        buffer = pqc.PQC_symmetric_encrypt(context, pqc.PQC_AES_M_OFB, data)

        # Close the context
        pqc.PQC_context_close(context)

        return buffer

    return encrypt


# Function to perform OFB decryption
@pytest.fixture
def OFB_decrypt(pqc):
    def decrypt(key, data):
        # Initialize the context
        context = pqc.PQC_context_init_iv(pqc.PQC_CIPHER_AES, key, iv)

        # Decrypt the data
        buffer = pqc.PQC_symmetric_decrypt(context, pqc.PQC_AES_M_OFB, data)

        # Close the context
        pqc.PQC_context_close(context)

        return buffer

    return decrypt


def test_aes_ofb(OFB_encrypt, OFB_decrypt):
    # Encrypt the data
    buffer = OFB_encrypt(key, data)

    assert buffer != data

    # Decrypt the data
    buffer = OFB_decrypt(key, buffer)

    assert buffer == data
