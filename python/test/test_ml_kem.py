from test import pqc


def test_ml_kem_(pqc):
    info_size = 10
    party_a_info = bytes(range(info_size))  # additional data to be used for key derivation

    pub_bob, priv_bob = pqc.PQC_generate_key_pair(pqc.PQC_CIPHER_ML_KEM)

    # To derive shared key to be used for data encryption and message for other party call
    shared_alice, message = pqc.PQC_kem_encode(pqc.PQC_CIPHER_ML_KEM, party_a_info, pub_bob)

    # (Bob) To derive shared key from message and private key
    bob = pqc.PQC_init_context(pqc.PQC_CIPHER_ML_KEM, priv_bob)
    shared_bob = pqc.PQC_kem_decode(bob, message, party_a_info)
    assert shared_alice == shared_bob

    pqc.PQC_close_context(bob)
