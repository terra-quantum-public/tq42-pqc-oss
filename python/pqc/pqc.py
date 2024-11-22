# -*- coding: utf-8 -*-

import ctypes
import os

import pqc.utils

# Load the C library
try:
    pqc_lib = ctypes.CDLL(os.path.join(os.path.dirname(__file__), pqc.utils.library))
except OSError:
    raise ImportError(
        'Failed to load the C library. Please make sure the library is available and the path is correct.'
    )

PQC_OK = 0
PQC_BAD_CONTEXT = 1
PQC_BAD_LEN = 2
PQC_BAD_MODE = 3
PQC_NO_IV = 4
PQC_INTERNAL_ERROR = 5
PQC_BAD_SIGNATURE = 6
PQC_CONTAINER_DEPLETED = 7
PQC_IO_ERROR = 8
PQC_BAD_CIPHER = 0xFFFFFFFFFFFFFFFF
PQC_AUTHENTICATION_FAILURE = 9
PQC_KEY_NOT_SET = 10
PQC_CONTAINER_EXPIRED = 11


class PQException(Exception):
    pass


class PQBadContext(PQException):
    pass


class PQBadArguments(PQException):
    pass


class PQBadLen(PQException):
    pass


class PQBadMode(PQException):
    pass


class PQNoIV(PQException):
    pass


class PQInternalError(PQException):
    pass


class PQBadSignature(PQException):
    pass


class PQContainerDepleted(PQException):
    pass


class PQContainerExpired(PQException):
    pass


class PQFailedCreateContainer(PQException):
    pass


class PQIOError(PQException):
    pass


class PQBadCipher(PQException):
    pass


class PQAuthenticationFailure(PQException):
    pass


class PQUnknownError(PQException):
    pass


def _check_return_code(retcode):
    if retcode == PQC_OK:
        return
    if retcode == PQC_BAD_CONTEXT:
        raise PQBadContext()
    if retcode == PQC_BAD_LEN:
        raise PQBadLen()
    if retcode == PQC_BAD_MODE:
        raise PQBadMode
    if retcode == PQC_NO_IV:
        raise PQNoIV()
    if retcode == PQC_INTERNAL_ERROR:
        raise PQInternalError()
    if retcode == PQC_BAD_SIGNATURE:
        raise PQBadSignature()
    if retcode == PQC_CONTAINER_DEPLETED:
        raise PQContainerDepleted()
    if retcode == PQC_CONTAINER_EXPIRED:
        raise PQContainerExpired()
    if retcode == PQC_IO_ERROR:
        raise PQIOError()
    if retcode == PQC_BAD_CIPHER or retcode == -1:
        raise PQBadCipher()
    if retcode == PQC_AUTHENTICATION_FAILURE:
        raise PQAuthenticationFailure()
    raise PQUnknownError()


PQC_CIPHER_AES = 1
PQC_CIPHER_SHA3 = 4
PQC_CIPHER_FALCON = 5
PQC_CIPHER_DILITHIUM = 6
PQC_CIPHER_MCELIECE = 10
PQC_CIPHER_KYBER_512 = 51971
PQC_CIPHER_KYBER_768 = 51972
PQC_CIPHER_KYBER_1024 = 51973
PQC_CIPHER_ML_KEM_512 = 51968
PQC_CIPHER_ML_KEM_768 = 51969
PQC_CIPHER_ML_KEM_1024 = 51970
PQC_CIPHER_RAINBOW = 11
PQC_CIPHER_ML_DSA_87 = 1687
PQC_CIPHER_ML_DSA_65 = 1665
PQC_CIPHER_ML_DSA_44 = 1644
PQC_CIPHER_SLH_DSA_SHAKE_128S = 52482
PQC_CIPHER_SLH_DSA_SHAKE_128F = 52484
PQC_CIPHER_SLH_DSA_SHAKE_192S = 52486
PQC_CIPHER_SLH_DSA_SHAKE_192F = 52488
PQC_CIPHER_SLH_DSA_SHAKE_256S = 52490
PQC_CIPHER_SLH_DSA_SHAKE_256F = 52492

# Constants for the length types
PQC_LENGTH_SYMMETRIC = 0
PQC_LENGTH_IV = 1
PQC_LENGTH_PUBLIC = 2
PQC_LENGTH_PRIVATE = 3
PQC_LENGTH_SIGNATURE = 4
PQC_LENGTH_MESSAGE = 5
PQC_LENGTH_SHARED = 6

PQC_AES_M_CBC = 2
PQC_AES_M_ECB = 3
PQC_AES_M_OFB = 4
PQC_AES_M_GCM = 5
PQC_AES_M_CTR = 6

PQC_AES_BLOCKLEN = 16

PQC_AES_KEYLEN = 32
PQC_AES_IVLEN = PQC_AES_BLOCKLEN
PQC_AES_keyExpSize = 240
PQC_AES_CTR_counterIncrement = 1

# SHA3 constants
PQC_SHA3_224 = 224
PQC_SHA3_256 = 256
PQC_SHA3_384 = 384
PQC_SHA3_512 = 512

PQC_SHAKE_256 = 32
PQC_SHAKE_128 = 16

PQC_SYMMETRIC_CONTAINER_KEY_LENGTH = 32
PQC_SYMMETRIC_CONTAINER_NUM_KEYS = 6

PQC_PBKDF2_HMAC_SHA3 = 1
PQC_PBKDF2_ITERATIONS_NUMBER = 10000
# Define C data types
PQC_AES_BLOCKLEN = 16
CIPHER_HANDLE = ctypes.c_size_t
PQC_CONTAINER_HANDLE = ctypes.c_size_t


# Python wrappers for the C functions

pqc_lib.PQC_keypair_generate.argtypes = [
    ctypes.c_uint32,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
]
pqc_lib.PQC_keypair_generate.restype = ctypes.c_int


def PQC_keypair_generate(cipher):
    private_key_length = pqc_lib.PQC_cipher_get_length(cipher, PQC_LENGTH_PRIVATE)
    public_key_length = pqc_lib.PQC_cipher_get_length(cipher, PQC_LENGTH_PUBLIC)
    private_key = (ctypes.c_uint8 * private_key_length)()
    public_key = (ctypes.c_uint8 * public_key_length)()
    result = pqc_lib.PQC_keypair_generate(cipher, public_key, public_key_length, private_key, private_key_length)
    _check_return_code(result)
    return bytes(public_key), bytes(private_key)


pqc_lib.PQC_context_keypair_generate.argtypes = [CIPHER_HANDLE]
pqc_lib.PQC_keypair_generate.restype = ctypes.c_int


def PQC_context_keypair_generate(ctx):
    result = pqc_lib.PQC_context_keypair_generate(ctx)
    _check_return_code(result)    

pqc_lib.PQC_context_init.argtypes = [ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t]
pqc_lib.PQC_context_init.restype = CIPHER_HANDLE


pqc_lib.PQC_context_get_keypair.argtypes = [
    CIPHER_HANDLE,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
]
pqc_lib.PQC_context_get_keypair.restype = ctypes.c_int


def PQC_context_get_keypair(ctx):
    private_key_length = pqc_lib.PQC_context_get_length(ctx, PQC_LENGTH_PRIVATE)
    public_key_length = pqc_lib.PQC_context_get_length(ctx, PQC_LENGTH_PUBLIC)
    private_key = (ctypes.c_uint8 * private_key_length)()
    public_key = (ctypes.c_uint8 * public_key_length)()
    result = pqc_lib.PQC_context_get_keypair(ctx, public_key, public_key_length, private_key, private_key_length)
    _check_return_code(result)
    return bytes(public_key), bytes(private_key)


pqc_lib.PQC_context_get_public_key.argtypes = [
    CIPHER_HANDLE,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t
]
pqc_lib.PQC_context_get_public_key.restype = ctypes.c_int

def PQC_context_get_public_key(ctx):
    public_key_length = pqc_lib.PQC_context_get_length(ctx, PQC_LENGTH_PUBLIC)
    public_key = (ctypes.c_uint8 * public_key_length)()
    result = pqc_lib.PQC_context_get_public_key(ctx, public_key, public_key_length)
    _check_return_code(result)
    return bytes(public_key)
    
def PQC_context_init(cipher, key):
    key_length = len(key)
    key_ptr = (ctypes.c_uint8 * key_length)(*key)
    handle = pqc_lib.PQC_context_init(cipher, key_ptr, key_length)
    if handle == PQC_BAD_CIPHER:
        raise PQBadCipher()
    return handle


pqc_lib.PQC_context_init_iv.argtypes = [
    ctypes.c_uint32,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
]
pqc_lib.PQC_context_init_iv.restype = CIPHER_HANDLE


def PQC_context_init_iv(cipher, key, iv):
    key_length = len(key)
    iv_length = len(iv)
    key_ptr = (ctypes.c_uint8 * key_length)(*key)
    iv_ptr = (ctypes.c_uint8 * iv_length)(*iv)
    handle = pqc_lib.PQC_context_init_iv(cipher, key_ptr, key_length, iv_ptr, iv_length)
    if handle == PQC_BAD_CIPHER:
        raise PQBadCipher()
    return handle


pqc_lib.PQC_context_init_hash.argtypes = [ctypes.c_uint32, ctypes.c_uint32]
pqc_lib.PQC_context_init_hash.restype = CIPHER_HANDLE


def PQC_context_init_hash(algorithm, mode):
    handle = pqc_lib.PQC_context_init_hash(algorithm, mode)
    if handle == PQC_BAD_CIPHER:
        raise PQBadCipher()
    return handle


pqc_lib.PQC_context_init_asymmetric.argtypes = [ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t]
pqc_lib.PQC_context_init_asymmetric.restype = CIPHER_HANDLE


def PQC_context_init_asymmetric(cipher, public_key, private_key):

    public_key_length = len(public_key) if public_key else 0 
    public_key_ptr = (ctypes.c_uint8 * public_key_length)(*public_key) if public_key else ctypes.POINTER(ctypes.c_uint8)()

    private_key_length = len(private_key) if private_key else 0 
    private_key_ptr = (ctypes.c_uint8 * private_key_length)(*private_key) if private_key else ctypes.POINTER(ctypes.c_uint8)()


    handle = pqc_lib.PQC_context_init_asymmetric(cipher, public_key_ptr, public_key_length, private_key_ptr, private_key_length)
    if handle == PQC_BAD_CIPHER:
        raise PQBadCipher()
    return handle
    
pqc_lib.PQC_context_init_randomsource.argtypes = []
pqc_lib.PQC_context_init_randomsource.restype = CIPHER_HANDLE


def PQC_context_init_randomsource():
    handle = pqc_lib.PQC_context_init_randomsource()
    if handle == PQC_BAD_CIPHER:
        raise PQBadCipher()
    return handle


pqc_lib.PQC_context_set_iv.argtypes = [CIPHER_HANDLE, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t]
pqc_lib.PQC_context_set_iv.restype = ctypes.c_int


def PQC_context_set_iv(ctx, iv):
    iv_length = len(iv)
    iv_ptr = (ctypes.c_uint8 * iv_length)(*iv)
    result = pqc_lib.PQC_context_set_iv(ctx, iv_ptr, iv_length)
    _check_return_code(result)


pqc_lib.PQC_symmetric_encrypt.argtypes = [CIPHER_HANDLE, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t]
pqc_lib.PQC_symmetric_encrypt.restype = ctypes.c_int


def PQC_symmetric_encrypt(ctx, mode, buffer):
    length = len(buffer)
    buffer_ptr = (ctypes.c_uint8 * length)(*buffer)
    result = pqc_lib.PQC_symmetric_encrypt(ctx, mode, buffer_ptr, length)
    _check_return_code(result)
    return bytes(buffer_ptr)


def PQC_symmetric_decrypt(ctx, mode, buffer):
    length = len(buffer)
    buffer_ptr = (ctypes.c_uint8 * length)(*buffer)
    result = pqc_lib.PQC_symmetric_decrypt(ctx, mode, buffer_ptr, length)
    _check_return_code(result)
    return bytes(buffer_ptr)


pqc_lib.PQC_aead_encrypt.argtypes = [
    CIPHER_HANDLE, 
    ctypes.c_uint32, 
    ctypes.POINTER(ctypes.c_uint8), 
    ctypes.c_size_t, 
    ctypes.POINTER(ctypes.c_uint8), 
    ctypes.c_size_t, 
    ctypes.POINTER(ctypes.c_uint8), 
    ctypes.c_size_t
]
pqc_lib.PQC_aead_encrypt.restype = ctypes.c_int


def PQC_aead_encrypt(ctx, mode, buffer, aad):
    length = len(buffer)
    buffer_ptr = (ctypes.c_uint8 * length)(*buffer)
    
    aad_length = len(aad)
    aad_ptr = (ctypes.c_uint8 * aad_length)(*aad)
    
    tag_length = PQC_AES_IVLEN
    tag_ptr = (ctypes.c_uint8 * tag_length)()
    
    result = pqc_lib.PQC_aead_encrypt(ctx, mode, buffer_ptr, length, aad_ptr, aad_length, tag_ptr, tag_length)
    _check_return_code(result)
    return bytes(buffer_ptr), bytes(tag_ptr)
    

pqc_lib.PQC_aead_decrypt.argtypes = [
    CIPHER_HANDLE, 
    ctypes.c_uint32, 
    ctypes.POINTER(ctypes.c_uint8), 
    ctypes.c_size_t, 
    ctypes.POINTER(ctypes.c_uint8), 
    ctypes.c_size_t, 
    ctypes.POINTER(ctypes.c_uint8), 
    ctypes.c_size_t
]
pqc_lib.PQC_aead_decrypt.restype = ctypes.c_int


def PQC_aead_decrypt(ctx, mode, buffer, aad, tag):
    length = len(buffer)
    buffer_ptr = (ctypes.c_uint8 * length)(*buffer)
    
    aad_length = len(aad)
    aad_ptr = (ctypes.c_uint8 * aad_length)(*aad)
    
    tag_length = PQC_AES_IVLEN
    tag_ptr = (ctypes.c_uint8 * tag_length)(*tag)
    
    result = pqc_lib.PQC_aead_encrypt(ctx, mode, buffer_ptr, length, aad_ptr, aad_length, tag_ptr, tag_length)
    _check_return_code(result)
    return bytes(buffer_ptr)
        
pqc_lib.PQC_aead_check.argtypes = [
    CIPHER_HANDLE, 
    ctypes.c_uint32, 
    ctypes.POINTER(ctypes.c_uint8), 
    ctypes.c_size_t, 
    ctypes.POINTER(ctypes.c_uint8), 
    ctypes.c_size_t, 
    ctypes.POINTER(ctypes.c_uint8), 
    ctypes.c_size_t
]
pqc_lib.PQC_aead_check.restype = ctypes.c_int

def PQC_aead_check(ctx, mode, buffer, aad, tag):
    length = len(buffer)
    buffer_ptr = (ctypes.c_uint8 * length)(*buffer)
    
    aad_length = len(aad)
    aad_ptr = (ctypes.c_uint8 * aad_length)(*aad)
    
    tag_length = PQC_AES_IVLEN
    tag_ptr = (ctypes.c_uint8 * tag_length)(*tag)
    
    result = pqc_lib.PQC_aead_check(ctx, mode, buffer_ptr, length, aad_ptr, aad_length, tag_ptr, tag_length)
    if result == PQC_AUTHENTICATION_FAILURE:
        return False
    _check_return_code(result)
    return True    
 
pqc_lib.PQC_kem_encapsulate_secret.argtypes = [
    CIPHER_HANDLE,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
]
pqc_lib.PQC_kem_encapsulate_secret.restype = ctypes.c_int


def PQC_kem_encapsulate_secret(ctx, message, shared_secret):
    message_length = len(message)
    shared_secret_length = len(shared_secret)

    message_ptr = (ctypes.c_uint8 * message_length)(*message)
    shared_secret_ptr = (ctypes.c_uint8 * shared_secret_length)(*shared_secret)

    result = pqc_lib.PQC_kem_encapsulate_secret(
        cipher, message_ptr, message_length, shared_secret_ptr, shared_secret_length
    )
    _check_return_code(result)


pqc_lib.PQC_kem_decapsulate_secret.argtypes = [
    CIPHER_HANDLE,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
]
pqc_lib.PQC_kem_decapsulate_secret.restype = ctypes.c_int


def PQC_kem_decapsulate_secret(ctx, message, shared_secret):
    message_length = len(message)
    shared_secret_length = len(shared_secret)

    message_ptr = (ctypes.c_uint8 * message_length)(*message)
    shared_secret_ptr = (ctypes.c_uint8 * shared_secret_length)(*shared_secret)

    result = pqc_lib.PQC_kem_decapsulate_secret(ctx, message_ptr, message_length, shared_secret_ptr, shared_secret_length)
    _check_return_code(result)


pqc_lib.PQC_kem_encapsulate.argtypes = [
    CIPHER_HANDLE,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
]
pqc_lib.PQC_kem_encapsulate.restype = ctypes.c_int


def PQC_kem_encapsulate(ctx, party_a_info):
    message_length = pqc_lib.PQC_context_get_length(ctx, PQC_LENGTH_MESSAGE)
    info_length = len(party_a_info)
    shared_key_length = pqc_lib.PQC_context_get_length(ctx, PQC_LENGTH_SHARED)

    message_ptr = (ctypes.c_uint8 * message_length)()
    party_a_info_ptr = (ctypes.c_uint8 * info_length)(*party_a_info)
    shared_key_ptr = (ctypes.c_uint8 * shared_key_length)()

    result = pqc_lib.PQC_kem_encapsulate(
        ctx,
        message_ptr,
        message_length,
        party_a_info_ptr,
        info_length,
        shared_key_ptr,
        shared_key_length,
    )
    _check_return_code(result)
    return bytes(shared_key_ptr), bytes(message_ptr)


pqc_lib.PQC_kem_decapsulate.argtypes = [
    CIPHER_HANDLE,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
]
pqc_lib.PQC_kem_decapsulate.restype = ctypes.c_int


def PQC_kem_decapsulate(ctx, message, party_a_info):
    message_length = len(message)
    info_length = len(party_a_info)
    shared_key_length = pqc_lib.PQC_context_get_length(ctx, PQC_LENGTH_SHARED)

    message_ptr = (ctypes.c_uint8 * message_length)(*message)
    party_a_info_ptr = (ctypes.c_uint8 * info_length)(*party_a_info)
    shared_key_ptr = (ctypes.c_uint8 * shared_key_length)()

    result = pqc_lib.PQC_kem_decapsulate(
        ctx, message_ptr, message_length, party_a_info_ptr, info_length, shared_key_ptr, shared_key_length
    )
    _check_return_code(result)
    return bytes(shared_key_ptr)


pqc_lib.PQC_kdf.argtypes = [
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
]
pqc_lib.PQC_kdf.restype = ctypes.c_int


def PQC_kdf(party_a_info, shared_secret, key_length):
    shared_length = len(shared_secret)
    info_length = len(party_a_info)
    key = (ctypes.c_uint8 * key_length)()

    shared_secret_ptr = (ctypes.c_uint8 * shared_length)(*shared_secret)
    party_a_info_ptr = (ctypes.c_uint8 * info_length)(*party_a_info)

    result = pqc_lib.PQC_kdf(party_a_info_ptr, info_length, shared_secret_ptr, shared_length, key, key_length)
    _check_return_code(result)

    return bytes(key)


pqc_lib.PQC_signature_create.argtypes = [
    CIPHER_HANDLE,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
]
pqc_lib.PQC_signature_create.restype = ctypes.c_int


def PQC_signature_create(ctx, buffer, signature_len):
    length = len(buffer)
    signature = (ctypes.c_uint8 * signature_len)()

    buffer_ptr = (ctypes.c_uint8 * length)(*buffer)

    result = pqc_lib.PQC_signature_create(ctx, buffer_ptr, length, signature, signature_len)
    _check_return_code(result)

    return bytes(signature)


pqc_lib.PQC_signature_verify.argtypes = [
    CIPHER_HANDLE,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
]
pqc_lib.PQC_signature_verify.restype = ctypes.c_int


def PQC_signature_verify(ctx, buffer, signature):
    length = len(buffer)
    buffer_ptr = (ctypes.c_uint8 * length)(*buffer)
    signature_ptr = (ctypes.c_uint8 * len(signature))(*signature)

    result = pqc_lib.PQC_signature_verify(
        ctx, buffer_ptr, length, signature_ptr, len(signature)
    )
    _check_return_code(result)

    return True  # Verification successful


pqc_lib.PQC_hash_update.argtypes = [CIPHER_HANDLE, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t]
pqc_lib.PQC_hash_update.restype = ctypes.c_int


def PQC_hash_update(ctx, data):
    length = len(data)
    data_ptr = (ctypes.c_uint8 * length)(*data)

    result = pqc_lib.PQC_hash_update(ctx, data_ptr, length)
    _check_return_code(result)


pqc_lib.PQC_hash_size.argtypes = [CIPHER_HANDLE]
pqc_lib.PQC_hash_size.restype = ctypes.c_uint


def PQC_hash_size(ctx):
    return pqc_lib.PQC_hash_size(ctx)


pqc_lib.PQC_hash_retrieve.argtypes = [CIPHER_HANDLE, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t]
pqc_lib.PQC_hash_retrieve.restype = ctypes.c_int


def PQC_hash_retrieve(ctx, hash_size):
    hash_buffer = (ctypes.c_uint8 * hash_size)()

    result = pqc_lib.PQC_hash_retrieve(ctx, hash_buffer, hash_size)
    _check_return_code(result)

    return bytes(hash_buffer)


pqc_lib.PQC_context_close.argtypes = [CIPHER_HANDLE]
pqc_lib.PQC_context_close.restype = ctypes.c_int


def PQC_context_close(ctx):
    result = pqc_lib.PQC_context_close(ctx)
    _check_return_code(result)


pqc_lib.PQC_context_random_set_pq_17.argtypes = [
    CIPHER_HANDLE,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
]
pqc_lib.PQC_context_random_set_pq_17.restype = ctypes.c_int


def PQC_context_random_set_pq_17(ctx, key, iv):
    key_len = len(key)
    iv_len = len(iv)
    key_ptr = (ctypes.c_uint8 * key_len)(*key)
    iv_ptr = (ctypes.c_uint8 * iv_len)(*iv)

    result = pqc_lib.PQC_context_random_set_pq_17(ctx, key_ptr, key_len, iv_ptr, iv_len)
    _check_return_code(result)


pqc_lib.PQC_context_random_get_bytes.argtypes = [CIPHER_HANDLE, ctypes.c_void_p, ctypes.c_size_t]
pqc_lib.PQC_context_random_get_bytes.restype = None


def PQC_context_random_get_bytes(ctx, length):
    buffer = (ctypes.c_uint8 * length)()
    pqc_lib.PQC_context_random_get_bytes(ctx, buffer, length)
    return bytes(buffer)


pqc_lib.PQC_symmetric_container_create.argtypes = [CIPHER_HANDLE]
pqc_lib.PQC_symmetric_container_create.restype = PQC_CONTAINER_HANDLE


def PQC_symmetric_container_create(ctx):
    return pqc_lib.PQC_symmetric_container_create(ctx)


pqc_lib.PQC_symmetric_container_get_data.argtypes = [
    PQC_CONTAINER_HANDLE,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
]
pqc_lib.PQC_symmetric_container_get_data.restype = ctypes.c_int


def PQC_symmetric_container_get_data(container, key, iv):
    data_length = PQC_symmetric_container_size(container)
    key_length = len(key)
    iv_length = len(iv)
    container_data = (ctypes.c_uint8 * data_length)()
    key_ptr = (ctypes.c_uint8 * key_length)(*key)
    iv_ptr = (ctypes.c_uint8 * iv_length)(*iv)

    result = pqc_lib.PQC_symmetric_container_get_data(
        container, container_data, data_length, key_ptr, key_length, iv_ptr, iv_length
    )
    _check_return_code(result)

    return bytes(container_data)


pqc_lib.PQC_symmetric_container_from_data.argtypes = [
    CIPHER_HANDLE,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
]

pqc_lib.PQC_symmetric_container_from_data.restype = PQC_CONTAINER_HANDLE


def PQC_symmetric_container_from_data(ctx, container_data, key, iv):
    data_length = len(container_data)
    key_length = len(key)
    iv_length = len(iv)
    container_data_ptr = (ctypes.c_uint8 * data_length)(*container_data)
    key_ptr = (ctypes.c_uint8 * key_length)(*key)
    iv_ptr = (ctypes.c_uint8 * iv_length)(*iv)

    container_handle = pqc_lib.PQC_symmetric_container_from_data(
        ctx, container_data_ptr, data_length, key_ptr, key_length, iv_ptr, iv_length
    )

    if container_handle == PQC_BAD_CIPHER:
        raise PQFailedCreateContainer()

    return container_handle


pqc_lib.PQC_symmetric_container_save_as.argtypes = [
    PQC_CONTAINER_HANDLE,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
]
pqc_lib.PQC_symmetric_container_save_as.restype = ctypes.c_int


def PQC_symmetric_container_save_as(container, filename, password, salt):
    result = pqc_lib.PQC_symmetric_container_save_as(
        container,
        filename.encode('utf-8'),
        password.encode('utf-8'),
        salt.encode('utf-8'),
    )
    _check_return_code(result)


pqc_lib.PQC_symmetric_container_get_key.argtypes = [
    PQC_CONTAINER_HANDLE,
    ctypes.c_int,
    ctypes.c_size_t,
    ctypes.c_uint32,
    ctypes.c_uint32,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
]
pqc_lib.PQC_symmetric_container_get_key.restype = ctypes.c_int


def PQC_symmetric_container_get_key(container, index, bytes_encoded, cipher, method):
    key_length = PQC_SYMMETRIC_CONTAINER_KEY_LENGTH
    key = (ctypes.c_uint8 * key_length)()

    result = pqc_lib.PQC_symmetric_container_get_key(container, index, bytes_encoded, cipher, method, key, key_length)
    _check_return_code(result)

    return bytes(key)


pqc_lib.PQC_symmetric_container_size.argtypes = [PQC_CONTAINER_HANDLE]
pqc_lib.PQC_symmetric_container_size.restype = ctypes.c_size_t


def PQC_symmetric_container_size(container):
    container_size = pqc_lib.PQC_symmetric_container_size(container)
    if container_size == 0:
        raise PQBadArguments()
    return container_size


pqc_lib.PQC_symmetric_container_get_version.argtypes = [PQC_CONTAINER_HANDLE]
pqc_lib.PQC_symmetric_container_get_version.restype = ctypes.c_uint32


def PQC_symmetric_container_get_version(container):
    version = pqc_lib.PQC_symmetric_container_get_version(container)
    return version


pqc_lib.PQC_symmetric_container_get_creation_time.argtypes = [PQC_CONTAINER_HANDLE]
pqc_lib.PQC_symmetric_container_get_creation_time.restype = ctypes.c_uint64


def PQC_symmetric_container_get_creation_time(container):
    creation_ts = pqc_lib.PQC_symmetric_container_get_creation_time(container)
    return creation_ts


pqc_lib.PQC_symmetric_container_get_expiration_time.argtypes = [PQC_CONTAINER_HANDLE]
pqc_lib.PQC_symmetric_container_get_expiration_time.restype = ctypes.c_uint64


def PQC_symmetric_container_get_expiration_time(container):
    expiration_ts = pqc_lib.PQC_symmetric_container_get_expiration_time(container)
    return expiration_ts


pqc_lib.PQC_symmetric_container_open.argtypes = [
    CIPHER_HANDLE,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
]
pqc_lib.PQC_symmetric_container_open.restype = PQC_CONTAINER_HANDLE


def PQC_symmetric_container_open(ctx, filename, password, salt):
    container_handle = pqc_lib.PQC_symmetric_container_open(
        ctx,
        filename.encode('utf-8'),
        password.encode('utf-8'),
        salt.encode('utf-8'),
    )
    if container_handle == PQC_BAD_CIPHER:
        raise PQFailedCreateContainer()

    return container_handle


pqc_lib.PQC_symmetric_container_close.argtypes = [PQC_CONTAINER_HANDLE]
pqc_lib.PQC_symmetric_container_close.restype = ctypes.c_int


def PQC_symmetric_container_close(container):
    result = pqc_lib.PQC_symmetric_container_close(container)
    _check_return_code(result)


pqc_lib.PQC_asymmetric_container_create.argtypes = [ctypes.c_uint32]
pqc_lib.PQC_asymmetric_container_create.restype = PQC_CONTAINER_HANDLE


def PQC_asymmetric_container_create(cipher):
    container_handle = pqc_lib.PQC_asymmetric_container_create(cipher)

    if container_handle == PQC_BAD_CIPHER:
        raise PQFailedCreateContainer()

    return container_handle


pqc_lib.PQC_asymmetric_container_size.argtypes = [PQC_CONTAINER_HANDLE]
pqc_lib.PQC_asymmetric_container_size.restype = ctypes.c_size_t


def PQC_asymmetric_container_size(container):
    container_size = pqc_lib.PQC_asymmetric_container_size(container)
    return container_size


pqc_lib.PQC_asymmetric_container_size_special.argtypes = [ctypes.c_uint32, ctypes.c_uint16]
pqc_lib.PQC_asymmetric_container_size_special.restype = ctypes.c_size_t


def PQC_asymmetric_container_size_special(cipher, mode):
    container_size = pqc_lib.PQC_asymmetric_container_size_special(cipher, mode)
    return container_size


pqc_lib.PQC_asymmetric_container_get_version.argtypes = [PQC_CONTAINER_HANDLE]
pqc_lib.PQC_asymmetric_container_get_version.restype = ctypes.c_uint32


def PQC_asymmetric_container_get_version(container):
    version = pqc_lib.PQC_asymmetric_container_get_version(container)
    return version


pqc_lib.PQC_asymmetric_container_get_creation_time.argtypes = [PQC_CONTAINER_HANDLE]
pqc_lib.PQC_asymmetric_container_get_creation_time.restype = ctypes.c_uint64


def PQC_asymmetric_container_get_creation_time(container):
    creation_ts = pqc_lib.PQC_asymmetric_container_get_creation_time(container)
    return creation_ts


pqc_lib.PQC_asymmetric_container_get_expiration_time.argtypes = [PQC_CONTAINER_HANDLE]
pqc_lib.PQC_asymmetric_container_get_expiration_time.restype = ctypes.c_uint64


def PQC_asymmetric_container_get_expiration_time(container):
    expiration_ts = pqc_lib.PQC_asymmetric_container_get_expiration_time(container)
    return expiration_ts


pqc_lib.PQC_asymmetric_container_get_data.argtypes = [
    PQC_CONTAINER_HANDLE,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
]
pqc_lib.PQC_asymmetric_container_get_data.restype = ctypes.c_int


def PQC_asymmetric_container_get_data(container, data_length, key, iv):
    container_data = (ctypes.c_uint8 * data_length)()

    result = pqc_lib.PQC_asymmetric_container_get_data(
        container,
        container_data,
        data_length,
        (ctypes.c_uint8 * len(key))(*key),
        len(key),
        (ctypes.c_uint8 * len(iv))(*iv),
        len(iv),
    )
    _check_return_code(result)

    return bytes(container_data)


pqc_lib.PQC_asymmetric_container_from_data.argtypes = [
    ctypes.c_uint32,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
]
pqc_lib.PQC_asymmetric_container_from_data.restype = PQC_CONTAINER_HANDLE


def PQC_asymmetric_container_from_data(cipher, container_data, key, iv):
    container_handle = pqc_lib.PQC_asymmetric_container_from_data(
        cipher,
        (ctypes.c_uint8 * len(container_data))(*container_data),
        len(container_data),
        (ctypes.c_uint8 * len(key))(*key),
        len(key),
        (ctypes.c_uint8 * len(iv))(*iv),
        len(iv),
    )
    if container_handle == PQC_BAD_CIPHER:
        raise PQFailedCreateContainer()

    return container_handle


pqc_lib.PQC_asymmetric_container_put_keys.argtypes = [
    ctypes.c_uint32,
    PQC_CONTAINER_HANDLE,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
]
pqc_lib.PQC_asymmetric_container_put_keys.restype = ctypes.c_int


def PQC_asymmetric_container_put_keys(cipher, container_handle, pk, sk):
    result = pqc_lib.PQC_asymmetric_container_put_keys(
        cipher, container_handle, (ctypes.c_uint8 * len(pk))(*pk), len(pk), (ctypes.c_uint8 * len(sk))(*sk), len(sk)
    )
    _check_return_code(result)


pqc_lib.PQC_asymmetric_container_get_keys.argtypes = [
    ctypes.c_uint32,
    PQC_CONTAINER_HANDLE,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
]
pqc_lib.PQC_asymmetric_container_get_keys.restype = ctypes.c_int


def PQC_asymmetric_container_get_keys(cipher, container_handle):
    pk_length = pqc_lib.PQC_cipher_get_length(cipher, PQC_LENGTH_PUBLIC)
    pk = (ctypes.c_uint8 * pk_length)()
    sk_length = pqc_lib.PQC_cipher_get_length(cipher, PQC_LENGTH_PRIVATE)
    sk = (ctypes.c_uint8 * sk_length)()

    result = pqc_lib.PQC_asymmetric_container_get_keys(cipher, container_handle, pk, pk_length, sk, sk_length)
    _check_return_code(result)

    return bytes(sk), bytes(pk)


pqc_lib.PQC_asymmetric_container_save_as.argtypes = [
    ctypes.c_uint32,
    PQC_CONTAINER_HANDLE,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
]
pqc_lib.PQC_asymmetric_container_save_as.restype = ctypes.c_int


def PQC_asymmetric_container_save_as(cipher, container_handle, filename, password, salt):
    result = pqc_lib.PQC_asymmetric_container_save_as(
        cipher, container_handle, filename.encode(), password.encode(), salt.encode()
    )
    _check_return_code(result)


pqc_lib.PQC_asymmetric_container_open.argtypes = [
    ctypes.c_uint32,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
]
pqc_lib.PQC_asymmetric_container_open.restype = PQC_CONTAINER_HANDLE


def PQC_asymmetric_container_open(cipher, filename, password, salt):
    container_handle = pqc_lib.PQC_asymmetric_container_open(
        cipher, filename.encode(), password.encode(), salt.encode()
    )
    if container_handle == PQC_BAD_CIPHER:
        raise PQFailedCreateContainer()

    return container_handle


pqc_lib.PQC_asymmetric_container_close.argtypes = [PQC_CONTAINER_HANDLE]
pqc_lib.PQC_asymmetric_container_close.restype = ctypes.c_int


def PQC_asymmetric_container_close(container_handle):
    result = pqc_lib.PQC_asymmetric_container_close(container_handle)
    _check_return_code(result)


pqc_lib.PQC_cipher_get_length.argtypes = [ctypes.c_uint32, ctypes.c_uint32]
pqc_lib.PQC_cipher_get_length.restype = ctypes.c_size_t


def PQC_cipher_get_length(cipher, length_type):
    length = pqc_lib.PQC_cipher_get_length(cipher, length_type)
    if length == 0:
        raise PQBadArguments()
    return length


pqc_lib.PQC_context_get_length.argtypes = [ctypes.c_uint32, ctypes.c_uint32]
pqc_lib.PQC_context_get_length.restype = ctypes.c_size_t


def PQC_context_get_length(context, length_type):
    length = pqc_lib.PQC_context_get_length(context, length_type)
    if length == 0:
        raise PQBadArguments()
    return length


pqc_lib.PQC_file_delete.argtypes = [ctypes.c_char_p]
pqc_lib.PQC_file_delete.restype = ctypes.c_int


def PQC_file_delete(filename):
    result = pqc_lib.PQC_file_delete(filename.encode())
    _check_return_code(result)


pqc_lib.PQC_symmetric_container_delete.argtypes = [CIPHER_HANDLE, ctypes.c_char_p]
pqc_lib.PQC_symmetric_container_delete.restype = ctypes.c_int


def PQC_symmetric_container_delete(ctx, filename):
    _check_return_code(pqc_lib.PQC_symmetric_container_delete(ctx, filename.encode('utf-8')))


pqc_lib.PQC_asymmetric_container_delete.argtypes = [CIPHER_HANDLE, ctypes.c_char_p]
pqc_lib.PQC_asymmetric_container_delete.restype = ctypes.c_int


def PQC_asymmetric_container_delete(ctx, filename):
    _check_return_code(pqc_lib.PQC_asymmetric_container_delete(ctx, filename.encode('utf-8')))


pqc_lib.PQC_pbkdf_2.argtypes = [
    ctypes.c_int,
    ctypes.c_size_t,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.c_size_t,
]
pqc_lib.PQC_pbkdf_2.restype = ctypes.c_size_t


def PQC_pbkdf_2(password, hash_length, key_length, salt, iterations):
    password_length = len(password)
    password_array = (ctypes.c_uint8 * password_length)(*password)
    salt_length = len(salt)
    salt_array = (ctypes.c_uint8 * salt_length)(*salt)
    derived_key_length = key_length // 8
    derived_key = (ctypes.c_uint8 * derived_key_length)()

    result = pqc_lib.PQC_pbkdf_2(
        PQC_PBKDF2_HMAC_SHA3,
        hash_length,
        password_length,
        password_array,
        key_length,
        derived_key,
        derived_key_length,
        salt_array,
        salt_length,
        iterations,
    )

    if result != 0:
        raise ValueError(f"Key derivation failed with error code: {result}")

    return bytes(derived_key)
