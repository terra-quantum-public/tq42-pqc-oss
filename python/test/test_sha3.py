from dataclasses import dataclass
from types import ModuleType

import pytest

from test import pqc

# SHA3 is a hash-function. Input data - message of any size.
# Hash of fixed size is saved into hash array.
# Look test_shake_sha3.cpp for use of arbitary sized hash.


@dataclass
class sha3_test_data:
    message: bytes
    sha_len: callable
    expected: bytes


def test_sha3(sha3_data: sha3_test_data, pqc: ModuleType):
    sha3 = pqc.PQC_context_init_hash(pqc.PQC_CIPHER_SHA3, sha3_data.sha_len())

    pqc.PQC_hash_update(sha3, sha3_data.message)
    # PQC_hash_update adds message content to context.

    hash_size: int = pqc.PQC_hash_size(sha3)

    hash = pqc.PQC_hash_retrieve(sha3, hash_size)  # PQC_hash_retrieve gets hash from message

    pqc.PQC_context_close(sha3)

    assert hash == sha3_data.expected


# Message is a data to get hash from.
message = b'\xa3' * 200


@pytest.fixture(
    params=[
        sha3_test_data(
            message=message,
            sha_len=lambda: pqc.__wrapped__().PQC_SHA3_512,
            expected=b'\xe7m\xfa\xd2 \x84\xa8\xb1F\x7f\xcf/\xfaX6\x1b\xecv(\xed\xf5\xf3\xfd\xc0\xe4\x80]\xc4\x8c\xae\xec\xa8\x1b|\x13\xc3\n\xdfR\xa3e\x95\x84s\x9a-\xf4k\xe5\x89\xc5\x1c\xa1\xa4\xa8Am\xf6TZ\x1c\xe8\xba\x00',
        ),
        sha3_test_data(
            message=message,
            sha_len=lambda: pqc.__wrapped__().PQC_SHA3_224,
            expected=b'\x93v\x81j\xbaP?r\xf9l\xe7\xebe\xac\t]\xee\xe3\xbeK\xf9\xbb\xc2\xa1\xcb~\x11\xe0',
        ),
        sha3_test_data(
            message=message,
            sha_len=lambda: pqc.__wrapped__().PQC_SHA3_256,
            expected=b'y\xf3\x8a\xde\xc5\xc2\x03\x07\xa9\x8e\xf7n\x83$\xaf\xbf\xd4l\xfd\x81\xb2.9s\xc6_\xa1\xbd\x9d\xe3\x17\x87',
        ),
        sha3_test_data(
            message=message,
            sha_len=lambda: pqc.__wrapped__().PQC_SHA3_384,
            expected=b'\x18\x81\xde,\xa7\xe4\x1e\xf9]\xc4s+\x8f_\x00+\x18\x9c\xc1\xe4+t\x16\x8e\xd1s&I\xce\x1d\xbc\xddv\x19z1\xfdU\xee\x98\x9f-pP\xddG>\x8f',
        ),
    ]
)
def sha3_data(request):
    return request.param
