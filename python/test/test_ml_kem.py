from test import pqc


def test_ml_kem(pqc):
    info_size = 10
    party_a_info = bytes(range(info_size))  # additional data to be used for key derivation
    cipher = pqc.PQC_CIPHER_ML_KEM_512

    bob = pqc.PQC_context_init_asymmetric(cipher, None, None)
    
    pqc.PQC_context_keypair_generate(bob)

    pub_bob = pqc.PQC_context_get_public_key(bob)
    
    alice = pqc.PQC_context_init_asymmetric(cipher, pub_bob, None)

    # To derive shared key to be used for data encryption and message for other party call
    shared_alice, message = pqc.PQC_kem_encapsulate(alice, party_a_info)

    # (Bob) To derive shared key from message and private key
    shared_bob = pqc.PQC_kem_decapsulate(bob, message, party_a_info)
    assert shared_alice == shared_bob

    pqc.PQC_context_close(bob)
    pqc.PQC_context_close(alice)