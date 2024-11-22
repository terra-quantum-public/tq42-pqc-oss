from test import pqc


def test_sign_falcon(pqc):
    info_size = 10
    data_for_signature = bytes(range(info_size))  # data to be signed

    cipher = pqc.PQC_CIPHER_FALCON

    bob = pqc.PQC_context_init_asymmetric(cipher, None, None)
    
    pqc.PQC_context_keypair_generate(bob)

    # Generate keys
    pub_bob = pqc.PQC_context_get_public_key(bob)

    # Sign data
    signature = pqc.PQC_signature_create(
        bob, data_for_signature, pqc.PQC_cipher_get_length(cipher, pqc.PQC_LENGTH_SIGNATURE)
    )

    alice = pqc.PQC_context_init_asymmetric(cipher, pub_bob, None)

    assert pqc.PQC_signature_verify(alice, data_for_signature, signature)

    pqc.PQC_context_close(bob)
    pqc.PQC_context_close(alice)

    return True
