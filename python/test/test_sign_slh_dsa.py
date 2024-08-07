from test import pqc


def test_sign_slh_dsa(pqc):
    cipher = pqc.PQC_CIPHER_SLH_DSA_SHAKE_256F
    info_size = 10
    data_for_signature = bytes(range(info_size))  # data to be signed

    # Generate keys
    pub_bob, priv_bob = pqc.PQC_generate_key_pair(cipher)

    bob = pqc.PQC_init_context(cipher, priv_bob)

    # Sign data
    signature = pqc.PQC_sign(
        bob, data_for_signature, pqc.PQC_get_length(cipher, pqc.PQC_LENGTH_SIGNATURE)
    )

    assert pqc.PQC_verify(cipher, pub_bob, data_for_signature, signature)

    pqc.PQC_close_context(bob)

    return True
