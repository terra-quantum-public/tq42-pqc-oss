#include "hypertree.h"

#include <algorithm>
#include <cassert>
#include <core.h>

#include "address.h"
#include "converter.h"
#include "params.h"
#include "xmss.h"

namespace slh_dsa
{

// Algorithm 11: Generate a hypertree signature
void ht_sign(
    const BufferView & sig_ht, const ConstBufferView & m, const ConstBufferView & skseed,
    const ConstBufferView & pkseed, size_t idx_tree, int idx_leaf
)
{
    assert(sig_ht.size() == (PQC_SLH_DSA_H + PQC_SLH_DSA_D * PQC_SLH_DSA_LEN) * PQC_SLH_DSA_N);
    assert(m.size() == PQC_SLH_DSA_N);
    assert(skseed.size() == PQC_SLH_DSA_N);
    assert(pkseed.size() == PQC_SLH_DSA_N);

    Address addr;
    BufferView layer_address = address::layer_address(addr);
    BufferView tree_address = address::tree_address(addr);
    Converter::toByte(tree_address, idx_tree);

    const size_t SIGTMP_SIZE = (PQC_SLH_DSA_LEN + PQC_SLH_DSA_H_PRIME) * PQC_SLH_DSA_N;
    BufferView sigtmp0 = sig_ht.mid(0, SIGTMP_SIZE);
    xmss_sign(sigtmp0, m, skseed, idx_leaf, pkseed, addr);
    StackBuffer<PQC_SLH_DSA_N> root;
    xmss_PKFromSig(root, idx_leaf, sigtmp0, m, pkseed, addr);

    for (int j = 1; j < PQC_SLH_DSA_D; ++j)
    {
        idx_leaf = (int)(idx_tree % (unsigned long)(1 << PQC_SLH_DSA_H_PRIME));
        idx_tree >>= PQC_SLH_DSA_H_PRIME;

        Converter::toByte(layer_address, j);
        Converter::toByte(tree_address, idx_tree);

        BufferView sigtmp = sig_ht.mid(j * SIGTMP_SIZE, SIGTMP_SIZE);
        xmss_sign(sigtmp, root, skseed, idx_leaf, pkseed, addr);

        if (j < PQC_SLH_DSA_D - 1)
        {
            xmss_PKFromSig(root, idx_leaf, sigtmp, root, pkseed, addr);
        }
    }
}

// Algorithm 12: Verify a hypertree signature
bool ht_verify(
    const ConstBufferView & m, const ConstBufferView & sig_ht, const ConstBufferView & pkseed, size_t idx_tree,
    int idx_leaf, const ConstBufferView & pkroot
)
{
    assert(m.size() == PQC_SLH_DSA_N);
    assert(sig_ht.size() == (PQC_SLH_DSA_H + PQC_SLH_DSA_D * PQC_SLH_DSA_LEN) * PQC_SLH_DSA_N);
    assert(pkseed.size() == PQC_SLH_DSA_N);
    assert(pkroot.size() == PQC_SLH_DSA_N);

    Address addr;
    BufferView layer_address = address::layer_address(addr);
    BufferView tree_address = address::tree_address(addr);
    Converter::toByte(tree_address, idx_tree);

    const size_t SIGTMP_SIZE = (PQC_SLH_DSA_LEN + PQC_SLH_DSA_H_PRIME) * PQC_SLH_DSA_N;
    ConstBufferView sigtmp0 = sig_ht.mid(0, SIGTMP_SIZE);
    StackBuffer<PQC_SLH_DSA_N> node;
    xmss_PKFromSig(node, idx_leaf, sigtmp0, m, pkseed, addr);

    for (int j = 1; j < PQC_SLH_DSA_D; ++j)
    {
        idx_leaf = (int)(idx_tree % (unsigned long)(1 << PQC_SLH_DSA_H_PRIME));
        idx_tree >>= PQC_SLH_DSA_H_PRIME;

        Converter::toByte(layer_address, j);
        Converter::toByte(tree_address, idx_tree);

        ConstBufferView sigtmp = sig_ht.mid(j * SIGTMP_SIZE, SIGTMP_SIZE);
        xmss_PKFromSig(node, idx_leaf, sigtmp, node, pkseed, addr);
    }

    return std::equal(node.const_data(), node.const_data() + node.size(), pkroot.const_data());
}

} // namespace slh_dsa
