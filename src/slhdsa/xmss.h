#pragma once

#include <buffer.h>

namespace slh_dsa
{

// Algorithm 8: Chaining function used in WOTS
void xmss_node(
    const BufferView & node, const ConstBufferView & skseed, int i, int z, const ConstBufferView & pkseed,
    const BufferView & addr
);

// Algorithm 9: Generate an XMSS signature
void xmss_sign(
    const BufferView & sig_xmss, const ConstBufferView & m, const ConstBufferView & skseed, int idx,
    const ConstBufferView & pkseed, const BufferView & addr
);

// Algorithm 10: Compute an XMSS public key from an XMSS signature
void xmss_PKFromSig(
    const BufferView & pk, int idx, const ConstBufferView & sig_xmss, const ConstBufferView & m,
    const ConstBufferView & pkseed, const BufferView & addr
);

} // namespace slh_dsa
