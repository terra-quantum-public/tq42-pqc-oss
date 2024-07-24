import pytest

from test import pqc


@pytest.fixture
def pbkdf2_params():
    """
    Provides test parameters for PBKDF2 tests, including password, salt, key length,
    hash length, iterations, and the expected derived key.
    """
    password = b"password"
    hash_length = 256
    salt_hex = "a5dcea8d0bba2f1fcfa5824085bf06e65fa1255484dafd499984323672b71fee"
    salt = bytes.fromhex(salt_hex)
    key_length = 256
    iterations = 10000
    expected_key_hex = "49f284e2fe1530736065097ef2c11815bef18a3bf1e2a372b4ce6dc5b66f6eb6"
    expected_key = bytes.fromhex(expected_key_hex)
    return password, hash_length, key_length, salt, iterations, expected_key


@pytest.fixture
def PBKDF2(pqc):
    """
    A fixture to perform the PBKDF2 operation using the C library wrapped by ctypes.
    """

    def perform_pbkdf2(password, hash_length, key_length, salt, iterations):
        derived_key = pqc.PQC_pbkdf_2(password, hash_length, key_length, salt, iterations)
        return derived_key

    return perform_pbkdf2


def test_pbkdf2_derived_key_correctness(pbkdf2_params, PBKDF2):
    """
    Tests the correctness of the derived key against an expected key.
    """
    password, hash_length, key_length, salt, iterations, expected_key = pbkdf2_params
    derived_key_bytes = PBKDF2(password, hash_length, key_length, salt, iterations)

    assert derived_key_bytes == expected_key, "Derived key does not match expected key"
