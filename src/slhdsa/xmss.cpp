#include "xmss.h"

#include <cassert>
#include <core.h>

#include "address.h"
#include "converter.h"
#include "params.h"
#include "wots.h"

namespace slh_dsa
{

// Algorithm 8: Compute the root of a Merkle subtree of WOTS+ public keys
void xmss_node(
    const BufferView & node, const ConstBufferView & skseed, size_t i, size_t z, const ConstBufferView & pkseed,
    const BufferView & addr, size_t mode
)
{
    assert(node.size() == ParameterSets[mode].N);
    assert(skseed.size() == ParameterSets[mode].N);
    assert(pkseed.size() == ParameterSets[mode].N);
    assert(addr.size() == ADDRESS_SIZE);

    if (z > ParameterSets[mode].H_PRIME || i >= ((size_t)1 << (ParameterSets[mode].H_PRIME - z)))
        throw InternalError();

    if (z == 0)
    {
        address::setTypeAndClear(addr, WOTS_HASH);
        BufferView keypair_addr = address::keypair_address(addr);
        Converter::toByte(keypair_addr, i);
        wots_PKgen(node, pkseed, skseed, addr, mode);
    }
    else
    {
        std::vector<uint8_t> node_data(ParameterSets[mode].N * 2);
        BufferView lr_nodes(node_data);
        auto [lnode, rnode] = lr_nodes.split(ParameterSets[mode].N, ParameterSets[mode].N);

        xmss_node(lnode, skseed, 2 * i, z - 1, pkseed, addr, mode);
        xmss_node(rnode, skseed, 2 * i + 1, z - 1, pkseed, addr, mode);

        address::setTypeAndClear(addr, TREE);
        BufferView tree_height = address::tree_height(addr);
        Converter::toByte(tree_height, z);
        BufferView tree_index = address::tree_index(addr);
        Converter::toByte(tree_index, i);

        function_H(pkseed, addr, lnode, rnode, node);
    }
}

// Algorithm 9: Generate an XMSS signature
void xmss_sign(
    const BufferView & sig_xmss, const ConstBufferView & m, const ConstBufferView & skseed, size_t idx,
    const ConstBufferView & pkseed, const BufferView & addr, size_t mode
)
{
    assert(
        sig_xmss.size() ==
        ParameterSets[mode].LEN * ParameterSets[mode].N + ParameterSets[mode].H_PRIME * ParameterSets[mode].N
    );
    assert(m.size() == ParameterSets[mode].N);
    assert(pkseed.size() == ParameterSets[mode].N);
    assert(skseed.size() == ParameterSets[mode].N);
    assert(addr.size() == ADDRESS_SIZE);

    BufferView sig = sig_xmss.mid(0, ParameterSets[mode].LEN * ParameterSets[mode].N);
    BufferView auth = sig_xmss.mid(
        ParameterSets[mode].LEN * ParameterSets[mode].N, ParameterSets[mode].H_PRIME * ParameterSets[mode].N
    );

    for (size_t j = 0; j < ParameterSets[mode].H_PRIME; ++j)
    {
        size_t k = (idx / (size_t)((size_t)1 << j)) ^ (size_t)1;
        BufferView authj = auth.mid(j * ParameterSets[mode].N, ParameterSets[mode].N);
        xmss_node(authj, skseed, k, j, pkseed, addr, mode);
    }

    address::setTypeAndClear(addr, WOTS_HASH);
    BufferView keypair_addr = address::keypair_address(addr);
    Converter::toByte(keypair_addr, idx);
    wots_sign(sig, m, pkseed, skseed, addr, mode);
}

// Algorithm 10: Compute an XMSS public key from an XMSS signature
void xmss_PKFromSig(
    const BufferView & pk, size_t idx, const ConstBufferView & sig_xmss, const ConstBufferView & m,
    const ConstBufferView & pkseed, const BufferView & addr, size_t mode
)
{
    assert(pk.size() == ParameterSets[mode].N);
    assert(
        sig_xmss.size() ==
        ParameterSets[mode].LEN * ParameterSets[mode].N + ParameterSets[mode].H_PRIME * ParameterSets[mode].N
    );
    assert(m.size() == ParameterSets[mode].N);
    assert(pkseed.size() == ParameterSets[mode].N);
    assert(addr.size() == ADDRESS_SIZE);

    address::setTypeAndClear(addr, WOTS_HASH);
    BufferView keypair_addr = address::keypair_address(addr);
    Converter::toByte(keypair_addr, idx);

    ConstBufferView sig = sig_xmss.mid(0, ParameterSets[mode].LEN * ParameterSets[mode].N);
    ConstBufferView auth = sig_xmss.mid(
        ParameterSets[mode].LEN * ParameterSets[mode].N, ParameterSets[mode].H_PRIME * ParameterSets[mode].N
    );

    wots_PKFromSig(pk, sig, m, pkseed, addr, mode);

    address::setTypeAndClear(addr, TREE);
    BufferView tree_index = address::tree_index(addr);
    Converter::toByte(tree_index, idx);
    BufferView tree_height = address::tree_height(addr);

    for (size_t k = 0; k < ParameterSets[mode].H_PRIME; ++k)
    {
        Converter::toByte(tree_height, k + 1);
        ConstBufferView authk = auth.mid(k * ParameterSets[mode].N, ParameterSets[mode].N);
        if ((idx / (size_t)((size_t)1 << k)) % 2 == 0)
        {
            Converter::toByte(tree_index, Converter::toInteger(tree_index) / 2);
            function_H(pkseed, addr, pk, authk, pk);
        }
        else
        {
            Converter::toByte(tree_index, (Converter::toInteger(tree_index) - 1) / 2);
            function_H(pkseed, addr, authk, pk, pk);
        }
    }
}

} // namespace slh_dsa
