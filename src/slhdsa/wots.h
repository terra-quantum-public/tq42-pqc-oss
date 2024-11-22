#pragma once

#include <buffer.h>

namespace slh_dsa
{

// Algorithm 5: Generate a WOTS+ public key
void wots_PKgen(
    const BufferView & pk, const ConstBufferView & pkseed, const ConstBufferView & skseed, const BufferView & addr,
    size_t mode
);

// Algorithm 6: Generate a WOTS+ signature on an n-byte message.
void wots_sign(
    const BufferView & sig, const ConstBufferView & m, const ConstBufferView & pkseed, const ConstBufferView & skseed,
    const BufferView & addr, size_t mode
);

// Algorithm 7: Compute a WOTS+ public key from a message and its signature
void wots_PKFromSig(
    const BufferView & pk, const ConstBufferView & sig, const ConstBufferView & m, const ConstBufferView & pkseed,
    const BufferView & addr, size_t mode
);

} // namespace slh_dsa
