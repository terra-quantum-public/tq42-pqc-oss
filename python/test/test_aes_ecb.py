import pytest

from test import pqc

# Define the key and data
key = b'12345678901234567890123456789012'  # Replace with your AES key
data = b'1234567890123456'  # Replace with your plaintext data

# Define the length of the data
data_len = len(data)


# Function to perform ECB encryption
@pytest.fixture
def ECB_encrypt(pqc):
    def encrypt(key, data):
        # Initialize the context
        context = pqc.PQC_init_context(pqc.PQC_CIPHER_AES, key)

        # Encrypt the data
        buffer = pqc.PQC_encrypt(context, pqc.PQC_AES_M_ECB, data)

        # Close the context
        pqc.PQC_close_context(context)

        return buffer

    return encrypt


# Function to perform ECB decryption
@pytest.fixture
def ECB_decrypt(pqc):
    def decrypt(key, data):
        # Initialize the context
        context = pqc.PQC_init_context(pqc.PQC_CIPHER_AES, key)

        # Decrypt the data
        buffer = pqc.PQC_decrypt(context, pqc.PQC_AES_M_ECB, data)

        # Close the context`
        pqc.PQC_close_context(context)

        return buffer

    return decrypt


def test_aes_ecb(ECB_encrypt, ECB_decrypt):
    # Encrypt the data
    buffer = ECB_encrypt(key, data)

    assert buffer != data

    # Decrypt the data
    buffer = ECB_decrypt(key, buffer)

    assert buffer == data
