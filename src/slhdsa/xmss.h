#pragma once

#include <buffer.h>

namespace slh_dsa
{

// Algorithm 8: Chaining function used in WOTS
void xmss_node(
    const BufferView & node, const ConstBufferView & skseed, size_t i, size_t z, const ConstBufferView & pkseed,
    const BufferView & addr, size_t mode
);

// Algorithm 9: Generate an XMSS signature
void xmss_sign(
    const BufferView & sig_xmss, const ConstBufferView & m, const ConstBufferView & skseed, size_t idx,
    const ConstBufferView & pkseed, const BufferView & addr, size_t mode
);

// Algorithm 10: Compute an XMSS public key from an XMSS signature
void xmss_PKFromSig(
    const BufferView & pk, size_t idx, const ConstBufferView & sig_xmss, const ConstBufferView & m,
    const ConstBufferView & pkseed, const BufferView & addr, size_t mode
);

} // namespace slh_dsa
