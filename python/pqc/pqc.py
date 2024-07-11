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
PQC_NO_AUT_TAG = 9
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


class PQNoAutTag(PQException):
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
    if retcode == PQC_BAD_CIPHER:
        raise PQBadCipher()
    if retcode == PQC_NO_AUT_TAG:
        raise PQNoAutTag()
    raise PQUnknownError()


PQC_CIPHER_AES = 1
PQC_CIPHER_SHA3 = 4
PQC_CIPHER_MCELIECE = 10
PQC_CIPHER_RAINBOW = 11
PQC_CIPHER_FALCON = 5

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


# Define C data types
PQC_AES_BLOCKLEN = 16
CIPHER_HANDLE = ctypes.c_size_t
PQC_CONTAINER_HANDLE = ctypes.c_size_t


# Python wrappers for the C functions

pqc_lib.PQC_generate_key_pair.argtypes = [
    ctypes.c_uint32,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
]
pqc_lib.PQC_generate_key_pair.restype = ctypes.c_int


def PQC_generate_key_pair(cipher):
    private_key_length = pqc_lib.PQC_get_length(cipher, PQC_LENGTH_PRIVATE)
    public_key_length = pqc_lib.PQC_get_length(cipher, PQC_LENGTH_PUBLIC)
    private_key = (ctypes.c_uint8 * private_key_length)()
    public_key = (ctypes.c_uint8 * public_key_length)()
    result = pqc_lib.PQC_generate_key_pair(cipher, public_key, public_key_length, private_key, private_key_length)
    _check_return_code(result)
    return bytes(public_key), bytes(private_key)


pqc_lib.PQC_init_context.argtypes = [ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t]
pqc_lib.PQC_init_context.restype = CIPHER_HANDLE


def PQC_init_context(cipher, key):
    key_length = len(key)
    key_ptr = (ctypes.c_uint8 * key_length)(*key)
    handle = pqc_lib.PQC_init_context(cipher, key_ptr, key_length)
    if handle == PQC_BAD_CIPHER:
        raise PQBadCipher()
    return handle


pqc_lib.PQC_init_context_iv.argtypes = [
    ctypes.c_uint32,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
]
pqc_lib.PQC_init_context_iv.restype = CIPHER_HANDLE


def PQC_init_context_iv(cipher, key, iv):
    key_length = len(key)
    iv_length = len(iv)
    key_ptr = (ctypes.c_uint8 * key_length)(*key)
    iv_ptr = (ctypes.c_uint8 * iv_length)(*iv)
    handle = pqc_lib.PQC_init_context_iv(cipher, key_ptr, key_length, iv_ptr, iv_length)
    if handle == PQC_BAD_CIPHER:
        raise PQBadCipher()
    return handle


pqc_lib.PQC_init_context_hash.argtypes = [ctypes.c_uint32, ctypes.c_uint32]
pqc_lib.PQC_init_context_hash.restype = CIPHER_HANDLE


def PQC_init_context_hash(algorithm, mode):
    handle = pqc_lib.PQC_init_context_hash(algorithm, mode)
    if handle == PQC_BAD_CIPHER:
        raise PQBadCipher()
    return handle


pqc_lib.PQC_set_iv.argtypes = [CIPHER_HANDLE, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t]
pqc_lib.PQC_set_iv.restype = ctypes.c_int


def PQC_set_iv(ctx, iv):
    iv_length = len(iv)
    iv_ptr = (ctypes.c_uint8 * iv_length)(*iv)
    result = pqc_lib.PQC_set_iv(ctx, iv_ptr, iv_length)
    _check_return_code(result)


pqc_lib.PQC_encrypt.argtypes = [CIPHER_HANDLE, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t]
pqc_lib.PQC_encrypt.restype = ctypes.c_int


def PQC_encrypt(ctx, mode, buffer):
    length = len(buffer)
    buffer_ptr = (ctypes.c_uint8 * length)(*buffer)
    result = pqc_lib.PQC_encrypt(ctx, mode, buffer_ptr, length)
    _check_return_code(result)
    return bytes(buffer_ptr)



def PQC_decrypt(ctx, mode, buffer):
    length = len(buffer)
    buffer_ptr = (ctypes.c_uint8 * length)(*buffer)
    result = pqc_lib.PQC_decrypt(ctx, mode, buffer_ptr, length)
    _check_return_code(result)
    return bytes(buffer_ptr)


pqc_lib.PQC_kem_encode_secret.argtypes = [
    ctypes.c_uint32,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
]
pqc_lib.PQC_kem_encode_secret.restype = ctypes.c_int


def PQC_kem_encode_secret(cipher, message, public_key, shared_secret):
    message_length = len(message)
    shared_secret_length = len(shared_secret)
    key_length = len(public_key)

    message_ptr = (ctypes.c_uint8 * message_length)(*message)
    shared_secret_ptr = (ctypes.c_uint8 * shared_secret_length)(*shared_secret)
    public_key_ptr = (ctypes.c_uint8 * key_length)(*public_key)

    result = pqc_lib.PQC_kem_encode_secret(
        cipher, message_ptr, message_length, public_key_ptr, key_length, shared_secret_ptr, shared_secret_length
    )
    _check_return_code(result)


pqc_lib.PQC_kem_decode_secret.argtypes = [
    CIPHER_HANDLE,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
]
pqc_lib.PQC_kem_decode_secret.restype = ctypes.c_int


def PQC_kem_decode_secret(ctx, message, shared_secret):
    message_length = len(message)
    shared_secret_length = len(shared_secret)

    message_ptr = (ctypes.c_uint8 * message_length)(*message)
    shared_secret_ptr = (ctypes.c_uint8 * shared_secret_length)(*shared_secret)

    result = pqc_lib.PQC_kem_decode_secret(ctx, message_ptr, message_length, shared_secret_ptr, shared_secret_length)
    _check_return_code(result)


pqc_lib.PQC_kem_encode.argtypes = [
    ctypes.c_uint32,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
]
pqc_lib.PQC_kem_encode.restype = ctypes.c_int


def PQC_kem_encode(cipher, party_a_info, public_key):
    message_length = pqc_lib.PQC_get_length(cipher, PQC_LENGTH_MESSAGE)
    info_length = len(party_a_info)
    shared_key_length = pqc_lib.PQC_get_length(cipher, PQC_LENGTH_SHARED)
    key_length = len(public_key)

    message_ptr = (ctypes.c_uint8 * message_length)()
    party_a_info_ptr = (ctypes.c_uint8 * info_length)(*party_a_info)
    shared_key_ptr = (ctypes.c_uint8 * shared_key_length)()
    public_key_ptr = (ctypes.c_uint8 * key_length)(*public_key)

    result = pqc_lib.PQC_kem_encode(
        cipher,
        message_ptr,
        message_length,
        party_a_info_ptr,
        info_length,
        public_key_ptr,
        key_length,
        shared_key_ptr,
        shared_key_length,
    )
    _check_return_code(result)
    return bytes(shared_key_ptr), bytes(message_ptr)


pqc_lib.PQC_kem_decode.argtypes = [
    CIPHER_HANDLE,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
]
pqc_lib.PQC_kem_decode.restype = ctypes.c_int


def PQC_kem_decode(ctx, message, party_a_info):
    message_length = len(message)
    info_length = len(party_a_info)
    shared_key_length = pqc_lib.PQC_context_get_length(ctx, PQC_LENGTH_SHARED)

    message_ptr = (ctypes.c_uint8 * message_length)(*message)
    party_a_info_ptr = (ctypes.c_uint8 * info_length)(*party_a_info)
    shared_key_ptr = (ctypes.c_uint8 * shared_key_length)()

    result = pqc_lib.PQC_kem_decode(
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


pqc_lib.PQC_sign.argtypes = [
    CIPHER_HANDLE,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
]
pqc_lib.PQC_sign.restype = ctypes.c_int


def PQC_sign(ctx, buffer, signature_len):
    length = len(buffer)
    signature = (ctypes.c_uint8 * signature_len)()

    buffer_ptr = (ctypes.c_uint8 * length)(*buffer)

    result = pqc_lib.PQC_sign(ctx, buffer_ptr, length, signature, signature_len)
    _check_return_code(result)

    return bytes(signature)


pqc_lib.PQC_verify.argtypes = [
    ctypes.c_uint32,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
]
pqc_lib.PQC_verify.restype = ctypes.c_int


def PQC_verify(cipher, public_key, buffer, signature):
    public_keylen = len(public_key)
    length = len(buffer)

    buffer_ptr = (ctypes.c_uint8 * length)(*buffer)
    public_key_ptr = (ctypes.c_uint8 * public_keylen)(*public_key)
    signature_ptr = (ctypes.c_uint8 * len(signature))(*signature)

    result = pqc_lib.PQC_verify(cipher, public_key_ptr, public_keylen, buffer_ptr, length, signature_ptr, len(signature))
    _check_return_code(result)

    return True  # Verification successful


pqc_lib.PQC_add_data.argtypes = [CIPHER_HANDLE, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t]
pqc_lib.PQC_add_data.restype = ctypes.c_int


def PQC_add_data(ctx, data):
    length = len(data)
    data_ptr = (ctypes.c_uint8 * length)(*data)

    result = pqc_lib.PQC_add_data(ctx, data_ptr, length)
    _check_return_code(result)


pqc_lib.PQC_hash_size.argtypes = [CIPHER_HANDLE]
pqc_lib.PQC_hash_size.restype = ctypes.c_uint


def PQC_hash_size(ctx):
    return pqc_lib.PQC_hash_size(ctx)


pqc_lib.PQC_get_hash.argtypes = [CIPHER_HANDLE, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t]
pqc_lib.PQC_get_hash.restype = ctypes.c_int


def PQC_get_hash(ctx, hash_size):
    hash_buffer = (ctypes.c_uint8 * hash_size)()

    result = pqc_lib.PQC_get_hash(ctx, hash_buffer, hash_size)
    _check_return_code(result)

    return bytes(hash_buffer)


pqc_lib.PQC_close_context.argtypes = [CIPHER_HANDLE]
pqc_lib.PQC_close_context.restype = ctypes.c_int


def PQC_close_context(ctx):
    result = pqc_lib.PQC_close_context(ctx)
    _check_return_code(result)


pqc_lib.PQC_random_from_pq_17.argtypes = [
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
]
pqc_lib.PQC_random_from_pq_17.restype = ctypes.c_int


def PQC_random_from_pq_17(key, iv):
    key_len = len(key)
    iv_len = len(iv)
    key_ptr = (ctypes.c_uint8 * key_len)(*key)
    iv_ptr = (ctypes.c_uint8 * iv_len)(*iv)

    result = pqc_lib.PQC_random_from_pq_17(key_ptr, key_len, iv_ptr, iv_len)
    _check_return_code(result)


pqc_lib.PQC_random_bytes.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
pqc_lib.PQC_random_bytes.restype = None


def PQC_random_bytes(length):
    buffer = (ctypes.c_uint8 * length)()
    pqc_lib.PQC_random_bytes(buffer, length)
    return bytes(buffer)


pqc_lib.PQC_symmetric_container_create.argtypes = []
pqc_lib.PQC_symmetric_container_create.restype = PQC_CONTAINER_HANDLE


def PQC_symmetric_container_create():
    return pqc_lib.PQC_symmetric_container_create()


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
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
]

pqc_lib.PQC_symmetric_container_from_data.restype = PQC_CONTAINER_HANDLE


def PQC_symmetric_container_from_data(container_data, key, iv):
    data_length = len(container_data)
    key_length = len(key)
    iv_length = len(iv)
    container_data_ptr = (ctypes.c_uint8 * data_length)(*container_data)
    key_ptr = (ctypes.c_uint8 * key_length)(*key)
    iv_ptr = (ctypes.c_uint8 * iv_length)(*iv)

    container_handle = pqc_lib.PQC_symmetric_container_from_data(
        container_data_ptr, data_length, key_ptr, key_length, iv_ptr, iv_length
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
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
]
pqc_lib.PQC_symmetric_container_open.restype = PQC_CONTAINER_HANDLE


def PQC_symmetric_container_open(filename, password, salt):
    container_handle = pqc_lib.PQC_symmetric_container_open(
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
    pk_length = pqc_lib.PQC_get_length(cipher, PQC_LENGTH_PUBLIC)
    pk = (ctypes.c_uint8 * pk_length)()
    sk_length = pqc_lib.PQC_get_length(cipher, PQC_LENGTH_PRIVATE)
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


pqc_lib.PQC_get_length.argtypes = [ctypes.c_uint32, ctypes.c_uint32]
pqc_lib.PQC_get_length.restype = ctypes.c_size_t


def PQC_get_length(cipher, length_type):
    length = pqc_lib.PQC_get_length(cipher, length_type)
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


pqc_lib.PQC_symmetric_container_delete.argtypes = [ctypes.c_char_p]
pqc_lib.PQC_symmetric_container_delete.restype = ctypes.c_int


def PQC_symmetric_container_delete(filename):
    _check_return_code(
        pqc_lib.PQC_symmetric_container_delete(filename.encode('utf-8'))
    )


pqc_lib.PQC_asymmetric_container_delete.argtypes = [ctypes.c_char_p]
pqc_lib.PQC_asymmetric_container_delete.restype = ctypes.c_int


def PQC_asymmetric_container_delete(filename):
    _check_return_code(
        pqc_lib.PQC_asymmetric_container_delete(filename.encode('utf-8'))
    )
