#pragma once

#include <buffer.h>

namespace slh_dsa
{

// Algorithm 13: Generate a FORS private-key value
void fors_SKgen(
    const BufferView & sk, const ConstBufferView & skseed, const ConstBufferView & pkseed, const BufferView & addr,
    size_t idx, size_t mode
);

// Algorithm 14: Compute the root of a Merkle subtree of FORS public values
void fors_node(
    const BufferView & node, const ConstBufferView & skseed, const ConstBufferView & pkseed, size_t i, size_t z,
    const BufferView & addr, size_t mode
);

// Algorithm 15: Generate a FORS signature
void fors_sign(
    const BufferView & sig_fors, const ConstBufferView & md, const ConstBufferView & skseed,
    const ConstBufferView & pkseed, const BufferView & addr, size_t mode
);

// Algorithm 16: Compute a FORS public key from a FORS signature
void fors_pkFromSig(
    const BufferView & pk, const ConstBufferView & sig_fors, const ConstBufferView & md, const ConstBufferView & pkseed,
    const BufferView & addr, size_t mode
);

} // namespace slh_dsa
