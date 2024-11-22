#include "crypto_hash.h"

#include <buffer.h>
#include <sha3.h>


void sha_3_hash_256(const BufferView & res, const ConstBufferView & input)
{
    SHA3 sha3El(PQC_SHAKE_256);
    sha3El.update(input);
    sha3El.retrieve_shake(res);
}
