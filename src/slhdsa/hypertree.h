#pragma once

#include <buffer.h>

namespace slh_dsa
{

// Algorithm 11: Generate a hypertree signature
void ht_sign(
    const BufferView & sig_ht, const ConstBufferView & m, const ConstBufferView & skseed,
    const ConstBufferView & pkseed, size_t idx_tree, int idx_leaf
);

// Algorithm 12: Verify a hypertree signature
bool ht_verify(
    const ConstBufferView & m, const ConstBufferView & sig_ht, const ConstBufferView & pkseed, size_t idx_tree,
    int idx_leaf, const ConstBufferView & pkroot
);

} // namespace slh_dsa
