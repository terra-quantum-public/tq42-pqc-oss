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
    const ConstBufferView & pkseed, size_t idx_tree, size_t idx_leaf, size_t mode
)
{
    assert(
        sig_ht.size() ==
        (ParameterSets[mode].H + ParameterSets[mode].D * ParameterSets[mode].LEN) * ParameterSets[mode].N
    );
    assert(m.size() == ParameterSets[mode].N);
    assert(skseed.size() == ParameterSets[mode].N);
    assert(pkseed.size() == ParameterSets[mode].N);

    Address addr;
    BufferView layer_address = address::layer_address(addr);
    BufferView tree_address = address::tree_address(addr);
    Converter::toByte(tree_address, idx_tree);

    const size_t SIGTMP_SIZE = (ParameterSets[mode].LEN + ParameterSets[mode].H_PRIME) * ParameterSets[mode].N;
    BufferView sigtmp0 = sig_ht.mid(0, SIGTMP_SIZE);
    xmss_sign(sigtmp0, m, skseed, idx_leaf, pkseed, addr, mode);
    std::vector<uint8_t> v_root(ParameterSets[mode].N);
    BufferView root(v_root);
    xmss_PKFromSig(root, idx_leaf, sigtmp0, m, pkseed, addr, mode);

    for (size_t j = 1; j < ParameterSets[mode].D; ++j)
    {
        idx_leaf = (idx_tree % (size_t)((size_t)1 << ParameterSets[mode].H_PRIME));
        idx_tree >>= ParameterSets[mode].H_PRIME;

        Converter::toByte(layer_address, j);
        Converter::toByte(tree_address, idx_tree);

        BufferView sigtmp = sig_ht.mid(j * SIGTMP_SIZE, SIGTMP_SIZE);
        xmss_sign(sigtmp, root, skseed, idx_leaf, pkseed, addr, mode);

        if (j < ParameterSets[mode].D - 1)
        {
            xmss_PKFromSig(root, idx_leaf, sigtmp, root, pkseed, addr, mode);
        }
    }
}

// Algorithm 12: Verify a hypertree signature
bool ht_verify(
    const ConstBufferView & m, const ConstBufferView & sig_ht, const ConstBufferView & pkseed, size_t idx_tree,
    size_t idx_leaf, const ConstBufferView & pkroot, size_t mode
)
{
    assert(m.size() == ParameterSets[mode].N);
    assert(
        sig_ht.size() ==
        (ParameterSets[mode].H + ParameterSets[mode].D * ParameterSets[mode].LEN) * ParameterSets[mode].N
    );
    assert(pkseed.size() == ParameterSets[mode].N);
    assert(pkroot.size() == ParameterSets[mode].N);

    Address addr;
    BufferView layer_address = address::layer_address(addr);
    BufferView tree_address = address::tree_address(addr);
    Converter::toByte(tree_address, idx_tree);

    const size_t SIGTMP_SIZE = (ParameterSets[mode].LEN + ParameterSets[mode].H_PRIME) * ParameterSets[mode].N;
    ConstBufferView sigtmp0 = sig_ht.mid(0, SIGTMP_SIZE);
    std::vector<uint8_t> v_node(ParameterSets[mode].N);
    BufferView node(v_node);
    xmss_PKFromSig(node, idx_leaf, sigtmp0, m, pkseed, addr, mode);

    for (size_t j = 1; j < ParameterSets[mode].D; ++j)
    {
        idx_leaf = (idx_tree % (size_t)((size_t)1 << ParameterSets[mode].H_PRIME));
        idx_tree >>= ParameterSets[mode].H_PRIME;

        Converter::toByte(layer_address, j);
        Converter::toByte(tree_address, idx_tree);

        ConstBufferView sigtmp = sig_ht.mid(j * SIGTMP_SIZE, SIGTMP_SIZE);
        xmss_PKFromSig(node, idx_leaf, sigtmp, node, pkseed, addr, mode);
    }

    return std::equal(node.const_data(), node.const_data() + node.size(), pkroot.const_data());
}

} // namespace slh_dsa
