from dataclasses import dataclass
from types import ModuleType

import pytest

from test import pqc


# The hash taking mechanism SHAKE is the mechanism of the sha 3 hash function, but with a variable output size.
# Simply put, you can take hash with any hash size.
# The SHAKE function exists in two instances: SHAKE 128 and SHAKE 256. They differ somewhat in their internal
# structure. In particular, SHAKE 256 will do more permutations with larger output hash sizes, which means it
# will have higher reliability. However, this does not significantly affect the quality of hash functions. And
# it has absolutely no effect on the interface to use.

# In this example, we will create a message with data, take a hash from it and compare it with the default cache
# that should be received.

hash_size = 500  # Output hash size we want to have


@dataclass
class shake_test_data:
    message: bytes
    shake_algorithm: int
    expected: bytes


message = b'1234567890'


@pytest.fixture(
    params=[
        shake_test_data(
            message=message,
            shake_algorithm=lambda: pqc.__wrapped__().PQC_SHAKE_256,
            expected=b'\xcde\xa4\xe5S@[P\xc2\xf3p\x01\xea\x81\x90_6\xd6P\xccw_\xda\xd8\x98\xb2\xe3CdL\xb3\xdb%k\xc0\xe9\xb3\x01\xf7\xf2\x1a\xdb\xaa\xfa\xd9y1\xbf)\x0b3\xd69\x16\x86\xba\x11?\xa3\xfe\x98\xa7\xaa\xf5}\xd8\x9e3J\x80\x13\xd4u.e\xdb\x9c5\x0c\x804\x1d399`Ob\xdd\xed\xf1\xfa>\xc9\xbd\xec\xb9\x04I\x02,\x8aOo\xff\xc7z\xdcz\xa4#\xb0r^*\xdb\xac\x82\xab\x07)\xb5\x92D\x10\x19$\xffI\xaa\xf5g*\x05\xd0\x10\xfc\xa4\xd3\xc4\xad\xb4T\xd8\x89\x10\xd6\xb2\xd9\xfe\xa2\x85\x997J\xac\xa1\x9d\x8b\xc9dO\x80D\xaa\x94\x08\x94\xbe\x05\x92\xb0s\xae\xd5K\xbdl\xc0\xa6\xc5\x9b\xb6\xbe\xd0\x1d\xf1\x8f\xd3\xe8t\xe6!\xa1\xc7\x16\x153\xf2\xf0\xaf\xa6\xee\xbd\xc1{\xba\xb9\xb1\xb0nB\n\x1fr6T4\xc4\xe5\x87\xd5C\xfa\xf6^\xcf\x87\x8a\xaeQ]F\xca@\x10j{\xa0\x87K\x87\xddZJ\xb4\xdcG \xb9\x88\t\xcd\xd7VnfE\xc0\xc4\xab\xdd=n3\xc9\xc8\xc8\x07\xbc\xa2\x1d\x98>\xb7#\xa1U\x14\x9e\xacFdq\'\xc0k\xad\x03\xba\xa0\x1dFO\r\x08\xa8v5\xd7?\x85\xbfG\xb5:\x83V\x02\xe52NG\xaex\xa7|Ed\xcb&\x04~x7\xbe\x98y\xd9\xcc\xb9\x80D\x92\xc4\xa8>\xc1\xc2B=\xc8\xb3>\r\xb9u\x17[Bj\xb5\xb5\xd2\xbef\n\xd3^\xbeI\x1b\xfcQ\xfd\x96y3\xc6\xb0;\x94\xc6\xd1@r\n\x82a\x85\xf0\x85c0\x94\xb2X\x11\x90o\xdc\xdb\xd5\xe8\x18\xf2\xd4m\xee\xfc\xa7\xfa{rA\xfdv\xa0\xdb\xa8d\x00~\xa2\xd6\xd0\xe3\x82+\xff\xf7\xd7\xe6\xe2\x947\xcc\x88;\xddy\xd2\x13@\xc8\xe8\xd64h\x8d\xc6\xde\xf4\xefi\xec\xc2\x7f\xd6\xceO\')\xf2`J\xd2Qv6]\x82P\xb8S%\xd47\x04\n\xe9\xc4\xfd3"\x9eA\n\xa2\x07\xef\x93s+\xfd#j\xb7\xa0Sh?xN\xf2\x00H[\x160',
        ),
        shake_test_data(
            message=message,
            shake_algorithm=lambda: pqc.__wrapped__().PQC_SHAKE_128,
            expected=b'\x1c\xd2\xc7\x1aR\xe3\xf2\xa6 \x17>\x91_\x17d\x8d\xccCD>\xf7\x87T0,kD\xcfG\xda\xf5\'\x12\x07\xc6\xc5?\xcc\x01|\x81O\x99#\xfb\x8d\x87\xd6,R\x9cfq\xae#\xef<\xb5)U\xd2\x1d\xc8ud\xb6\xfc-\xbcj\xa2\x14\x87v\x15\x0f\xb5l\x86\x9b\xaa\xae\xf6\x9e\xc0\x11\x9c\xb1}\xd1\xf7\xa2Nmm\xd2,\xcdTk\xe4Kx\xf6\xb4\x11|,\n\x01"F\x0b\xb1\x94\x16\xff\xa3\xc3\xf1\xeb\xaeJC\xf4NR\xc6\x11:\xc9].`\x08>]z\'Z0\xe3\xde\xc2c\x08\x99\xbd`\xef\x9f\x8e\xc6\xcd\xf3\xb5\xcfI\xa9\xa8i\xe4\x12\xac\x93G\xd3[\xfe\xb6\xe4n\x18\';HJ\xc5\xaeh\xc7T\xb4:/\xc7V\xa7\xd9\x13\x94#\xc2 ?\x98\xe2\xdbG\xc3\xde\xe0\xd7\xa5P\xbe\xc6\xf4\xdaQ\x1d\xfer)\xee\xe3\x04\xc3D\x01\xb7a\xd0\x03\xb5\x1egj\xe4\x92V\x04\xdb\x9e7,\xfcR\xc3}\x00\xe8\r\xde\x00Z\x1d\xc1\xd2#\x0f\x97\t\x8f\x806C\xe9g\xa4\xc0S9%<\x9aV\xe0k\xbc\xf1\xadg+\xda\xe8\xd2%\xe3\x16r\xb8\xdb`\xb1\x1e\xd7\x9e\x17\xed\xa0\x97d\xd5\xcd\xdb\x7f=\x9dd\x00\xf8\x1dL3\x1d\xf5\x1c\xc2hY\'\x80\xb4P\xf3\xdb\xa7\xedot\x7f\x9e$~\xba j\x98\x95W\xba\xf9\xab\xee#\x14n%\x90\xb2\xf9\xee\xc0\xc2\xfd\x9c\x11\xdf\xf5\x82\xe1n\xaf\xef\xac\xd0\xb4;\x183,\r6q\x9f\xe2}\x01"\xd4)\xa5\x89\xe0\xe5\x9e\xdf\xe7\xe6\xb5}Y+\x89B+\xf3\xc5&*3\xe7\xba\x05\x0c\xc8\xa0\xf8\xf0\xa88\xd4\xef\xbf\xbf\xf8q\x8bDG\x0e\xe2c\xdd\xdeZDs7\x106#\xad\x14\xc6\xcf+\xb8\xc9\x85/\xdc\x9d<\x1f\xbc)B\xccmTBu5\xa8\xcd\xb94MP\xd4\'\x0f2\\0\xbdQj\x1dQ\x17C\xb1\xed\x1e)\xe7\xab\x03\xf1\xc0\x7fKF)\xa7\xf9\xa2\x12\xf3\xb1<\xbafR\xf5\xbb\x91\xfaP\xf9\x8c\x99\xed\xa9t\xaa\x88',
        ),
    ]
)
def shake_data(request):
    return request.param


def test_sha3_shake_partial(shake_data: shake_test_data, pqc: ModuleType):
    # Init context of sha3 SHAKE hash function using library API
    sha3 = pqc.PQC_init_context_hash(pqc.PQC_CIPHER_SHA3, shake_data.shake_algorithm())

    # In detail. There is a function PQC_add_data(). It allows you to add data to the buffer from which the hash is taken.
    # It is important to understand that this function can be applied to one hash function object many times. That is, if
    # you need to take a hash from data of this type "1234567890", then you can add "1234" first, and then additionally add
    # "567890" and take the hash. And it won't be any different from taking the hash from "1234567890". Moreover, you can
    # first add "1234", take the hash from this data, and then add "567890" and again take the hash from the added data. And
    # the resulting hash will be equivalent to the hash from "1234567890".

    # In the example, we will first add "1234", then we will take a hash from this data, show that it is NOT equal to our default
    # message. Then add "567890", take the hash again. And show that it is equal to our default message. After that, we will create
    # a new hash function object and take the hash from "1234567890". And let's show that it is also equal to our default message.

    pqc.PQC_add_data(sha3, shake_data.message[: len(shake_data.message) // 2])
    out = pqc.PQC_get_hash(sha3, hash_size)

    # So, now in out is hash of SHAKE256 from half of the data. It should not be equal to expected size

    assert out != shake_data.expected

    pqc.PQC_add_data(sha3, shake_data.message[len(shake_data.message) // 2 :])
    actual = pqc.PQC_get_hash(sha3, hash_size)

    # `actual` is a hash of "1234567890" and should equal expected value

    assert actual == shake_data.expected

    pqc.PQC_close_context(sha3)


def test_sha3_shake(shake_data: shake_test_data, pqc: ModuleType):
    sha3_new = pqc.PQC_init_context_hash(pqc.PQC_CIPHER_SHA3, shake_data.shake_algorithm())
    pqc.PQC_add_data(sha3_new, shake_data.message)
    actual = pqc.PQC_get_hash(sha3_new, hash_size)

    assert actual == shake_data.expected

    pqc.PQC_close_context(sha3_new)
