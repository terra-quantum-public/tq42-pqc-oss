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
    const BufferView & node, const ConstBufferView & skseed, int i, int z, const ConstBufferView & pkseed,
    const BufferView & addr
)
{
    assert(node.size() == PQC_SLH_DSA_N);
    assert(skseed.size() == PQC_SLH_DSA_N);
    assert(pkseed.size() == PQC_SLH_DSA_N);
    assert(addr.size() == ADDRESS_SIZE);

    if (z > PQC_SLH_DSA_H_PRIME || i >= (1 << (PQC_SLH_DSA_H_PRIME - z)))
        throw InternalError();

    if (z == 0)
    {
        address::setTypeAndClear(addr, WOTS_HASH);
        BufferView keypair_addr = address::keypair_address(addr);
        Converter::toByte(keypair_addr, i);
        wots_PKgen(node, pkseed, skseed, addr);
    }
    else
    {
        HeapBuffer<PQC_SLH_DSA_N + ADDRESS_SIZE + PQC_SLH_DSA_N * 2> joined; // pkseed || ADRS || lnode || rnode
        joined.mid(0, PQC_SLH_DSA_N).store(pkseed);
        BufferView trAddr = joined.mid(PQC_SLH_DSA_N, ADDRESS_SIZE);
        trAddr.store(addr);

        xmss_node(joined.mid(PQC_SLH_DSA_N + ADDRESS_SIZE, PQC_SLH_DSA_N), skseed, 2 * i, z - 1, pkseed, addr); // lnode
        xmss_node(
            joined.mid(PQC_SLH_DSA_N + ADDRESS_SIZE + PQC_SLH_DSA_N, PQC_SLH_DSA_N), skseed, 2 * i + 1, z - 1, pkseed,
            addr
        ); // rnode

        address::setTypeAndClear(trAddr, TREE);
        BufferView tree_height = address::tree_height(trAddr);
        Converter::toByte(tree_height, z);
        BufferView tree_index = address::tree_index(trAddr);
        Converter::toByte(tree_index, i);

        function_H(joined, node);
    }
}

// Algorithm 9: Generate an XMSS signature
void xmss_sign(
    const BufferView & sig_xmss, const ConstBufferView & m, const ConstBufferView & skseed, int idx,
    const ConstBufferView & pkseed, const BufferView & addr
)
{
    assert(sig_xmss.size() == PQC_SLH_DSA_LEN * PQC_SLH_DSA_N + PQC_SLH_DSA_H_PRIME * PQC_SLH_DSA_N);
    assert(m.size() == PQC_SLH_DSA_N);
    assert(pkseed.size() == PQC_SLH_DSA_N);
    assert(skseed.size() == PQC_SLH_DSA_N);
    assert(addr.size() == ADDRESS_SIZE);

    BufferView sig = sig_xmss.mid(0, PQC_SLH_DSA_LEN * PQC_SLH_DSA_N);
    BufferView auth = sig_xmss.mid(PQC_SLH_DSA_LEN * PQC_SLH_DSA_N, PQC_SLH_DSA_H_PRIME * PQC_SLH_DSA_N);

    for (int j = 0; j < PQC_SLH_DSA_H_PRIME; ++j)
    {
        int k = (idx / (int)(1 << j)) ^ 1;
        BufferView authj = auth.mid(j * PQC_SLH_DSA_N, PQC_SLH_DSA_N);
        xmss_node(authj, skseed, k, j, pkseed, addr);
    }

    address::setTypeAndClear(addr, WOTS_HASH);
    BufferView keypair_addr = address::keypair_address(addr);
    Converter::toByte(keypair_addr, idx);
    wots_sign(sig, m, pkseed, skseed, addr);
}

// Algorithm 10: Compute an XMSS public key from an XMSS signature
void xmss_PKFromSig(
    const BufferView & pk, int idx, const ConstBufferView & sig_xmss, const ConstBufferView & m,
    const ConstBufferView & pkseed, const BufferView & addr
)
{
    assert(pk.size() == PQC_SLH_DSA_N);
    assert(sig_xmss.size() == PQC_SLH_DSA_LEN * PQC_SLH_DSA_N + PQC_SLH_DSA_H_PRIME * PQC_SLH_DSA_N);
    assert(m.size() == PQC_SLH_DSA_N);
    assert(pkseed.size() == PQC_SLH_DSA_N);
    assert(addr.size() == ADDRESS_SIZE);

    address::setTypeAndClear(addr, WOTS_HASH);
    BufferView keypair_addr = address::keypair_address(addr);
    Converter::toByte(keypair_addr, idx);

    ConstBufferView sig = sig_xmss.mid(0, PQC_SLH_DSA_LEN * PQC_SLH_DSA_N);
    ConstBufferView auth = sig_xmss.mid(PQC_SLH_DSA_LEN * PQC_SLH_DSA_N, PQC_SLH_DSA_H_PRIME * PQC_SLH_DSA_N);

    wots_PKFromSig(pk, sig, m, pkseed, addr);

    StackBuffer<PQC_SLH_DSA_N + ADDRESS_SIZE + PQC_SLH_DSA_N + PQC_SLH_DSA_N> joined; // PKseed || ADDR || node || authk
    joined.mid(0, PQC_SLH_DSA_N).store(pkseed);
    BufferView joined_addr = joined.mid(PQC_SLH_DSA_N, ADDRESS_SIZE);

    address::setTypeAndClear(addr, TREE);
    BufferView tree_index = address::tree_index(addr);
    Converter::toByte(tree_index, idx);
    BufferView tree_height = address::tree_height(addr);

    for (int k = 0; k < PQC_SLH_DSA_H_PRIME; ++k)
    {
        Converter::toByte(tree_height, k + 1);
        ConstBufferView authk = auth.mid(k * PQC_SLH_DSA_N, PQC_SLH_DSA_N);
        if ((idx / (int)(1 << k)) % 2 == 0)
        {
            Converter::toByte(tree_index, Converter::toInteger(tree_index) / 2);
            joined_addr.store(addr);
            joined.mid(PQC_SLH_DSA_N + ADDRESS_SIZE, PQC_SLH_DSA_N).store(pk);
            joined.mid(PQC_SLH_DSA_N + ADDRESS_SIZE + PQC_SLH_DSA_N, PQC_SLH_DSA_N).store(authk);
            function_H(joined, pk);
        }
        else
        {
            Converter::toByte(tree_index, (Converter::toInteger(tree_index) - 1) / 2);
            joined_addr.store(addr);
            joined.mid(PQC_SLH_DSA_N + ADDRESS_SIZE, PQC_SLH_DSA_N).store(authk);
            joined.mid(PQC_SLH_DSA_N + ADDRESS_SIZE + PQC_SLH_DSA_N, PQC_SLH_DSA_N).store(pk);
            function_H(joined, pk);
        }
    }
}

} // namespace slh_dsa
