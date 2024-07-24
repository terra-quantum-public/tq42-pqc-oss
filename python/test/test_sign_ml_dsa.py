from test import pqc


def test_sign_ml_dsa(pqc):
    info_size = 10
    data_for_signature = bytes(range(info_size))  # data to be signed

    # Generate keys
    pub_bob, priv_bob = pqc.PQC_generate_key_pair(pqc.PQC_CIPHER_ML_DSA)

    bob = pqc.PQC_init_context(pqc.PQC_CIPHER_ML_DSA, priv_bob)

    # Sign data
    signature = pqc.PQC_sign(
        bob, data_for_signature, pqc.PQC_get_length(pqc.PQC_CIPHER_ML_DSA, pqc.PQC_LENGTH_SIGNATURE)
    )

    assert pqc.PQC_verify(pqc.PQC_CIPHER_ML_DSA, pub_bob, data_for_signature, signature)

    pqc.PQC_close_context(bob)

    return True
