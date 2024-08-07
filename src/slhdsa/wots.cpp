#include "wots.h"

#include <cassert>
#include <core.h>

#include "address.h"
#include "converter.h"
#include "params.h"

namespace slh_dsa
{

// Algorithm 4: Chaining function used in WOTS
void chain(
    const BufferView & out, const ConstBufferView & X, int i, int s, const ConstBufferView & pkseed,
    const BufferView & addr
)
{
    assert(out.size() == PQC_SLH_DSA_N);
    assert(pkseed.size() == PQC_SLH_DSA_N);
    assert(addr.size() == ADDRESS_SIZE);

    if (i + s > PQC_SLH_DSA_W || i < 0 || s < 0)
        throw InternalError();

    StackBuffer<PQC_SLH_DSA_N + ADDRESS_SIZE + PQC_SLH_DSA_N> joined; // PKseed || ADRS || tmp
    BufferView local_pkseed = joined.mid(0, PQC_SLH_DSA_N);
    local_pkseed.store(pkseed);
    BufferView local_addr = joined.mid(PQC_SLH_DSA_N, ADDRESS_SIZE);
    local_addr.store(addr);
    BufferView local_hash = joined.mid(PQC_SLH_DSA_N + ADDRESS_SIZE, PQC_SLH_DSA_N);
    local_hash.store(X);

    for (int j = i; j < i + s; ++j)
    {
        BufferView hash_addr = address::hash_address(local_addr);
        Converter::toByte(hash_addr, j);
        function_F(joined, local_hash);
    }

    out.store(local_hash);
    addr.store(local_addr);
}

// Algorithm 5: Generate a WOTS+ public key
void wots_PKgen(
    const BufferView & pk, const ConstBufferView & pkseed, const ConstBufferView & skseed, const BufferView & addr
)
{
    assert(pk.size() == PQC_SLH_DSA_N);
    assert(pkseed.size() == PQC_SLH_DSA_N);
    assert(skseed.size() == PQC_SLH_DSA_N);
    assert(addr.size() == ADDRESS_SIZE);

    HeapBuffer<PQC_SLH_DSA_N + ADDRESS_SIZE + PQC_SLH_DSA_LEN * PQC_SLH_DSA_N> pk_joined; // PK.seed, wotspkADRS, tmp
    BufferView tmp = pk_joined.mid(PQC_SLH_DSA_N + ADDRESS_SIZE, PQC_SLH_DSA_LEN * PQC_SLH_DSA_N);
    StackBuffer<PQC_SLH_DSA_N> sk{};

    StackBuffer<PQC_SLH_DSA_N + ADDRESS_SIZE + PQC_SLH_DSA_N> sk_joined; // PK.seed, skADRS, SK.seed
    sk_joined.mid(0, PQC_SLH_DSA_N).store(pkseed);
    sk_joined.mid(PQC_SLH_DSA_N + ADDRESS_SIZE, PQC_SLH_DSA_N).store(skseed);
    BufferView skAddr = sk_joined.mid(PQC_SLH_DSA_N, ADDRESS_SIZE);
    skAddr.store(addr);
    address::setTypeAndClear(skAddr, WOTS_PRF);
    address::keypair_address(skAddr).store(address::keypair_address(addr));

    BufferView chain_addr = address::chain_address(addr);
    BufferView sk_chain_addr = address::chain_address(skAddr);

    for (int i = 0; i < PQC_SLH_DSA_LEN; ++i)
    {
        Converter::toByte(sk_chain_addr, i);
        function_PRF(sk_joined, sk);
        Converter::toByte(chain_addr, i);
        BufferView tmpi = tmp.mid(i * PQC_SLH_DSA_N, PQC_SLH_DSA_N);
        chain(tmpi, sk, 0, PQC_SLH_DSA_W - 1, pkseed, addr);
    }

    pk_joined.mid(0, PQC_SLH_DSA_N).store(pkseed);
    BufferView wotspkAddr = pk_joined.mid(PQC_SLH_DSA_N, ADDRESS_SIZE);
    wotspkAddr.store(addr);
    address::setTypeAndClear(wotspkAddr, WOTS_PK);
    address::keypair_address(wotspkAddr).store(address::keypair_address(addr));
    function_Tl(pk_joined, pk);
}

// Algorithm 6: Generate a WOTS+ signature on an n-byte message.
void wots_sign(
    const BufferView & sig, const ConstBufferView & m, const ConstBufferView & pkseed, const ConstBufferView & skseed,
    const BufferView & addr
)
{
    assert(sig.size() == PQC_SLH_DSA_LEN * PQC_SLH_DSA_N);
    assert(m.size() == PQC_SLH_DSA_N);
    assert(pkseed.size() == PQC_SLH_DSA_N);
    assert(skseed.size() == PQC_SLH_DSA_N);
    assert(addr.size() == ADDRESS_SIZE);

    StackBuffer<PQC_SLH_DSA_N> sk{};
    std::array<int, PQC_SLH_DSA_LEN> msg{};
    int csum = 0;
    Converter::base_2b(msg.data(), PQC_SLH_DSA_LEN_1, m, PQC_SLH_DSA_LGW);
    for (int i = 0; i < PQC_SLH_DSA_LEN_1; ++i)
        csum += PQC_SLH_DSA_W - 1 - msg[i];

    csum <<= 4;

    StackBuffer<PQC_SLH_DSA_CSUM_LEN> csum_m{};
    BufferView csum_buf(csum_m);
    Converter::toByte(csum_buf, csum);
    Converter::base_2b(msg.data() + PQC_SLH_DSA_LEN_1, PQC_SLH_DSA_LEN_2, csum_buf, PQC_SLH_DSA_LGW);

    StackBuffer<PQC_SLH_DSA_N + ADDRESS_SIZE + PQC_SLH_DSA_N> sk_joined; // PK.seed || skADRS || SK.seed
    sk_joined.mid(0, PQC_SLH_DSA_N).store(pkseed);
    sk_joined.mid(PQC_SLH_DSA_N + ADDRESS_SIZE, PQC_SLH_DSA_N).store(skseed);
    BufferView skAddr = sk_joined.mid(PQC_SLH_DSA_N, ADDRESS_SIZE);
    skAddr.store(addr);
    address::setTypeAndClear(skAddr, WOTS_PRF);
    address::keypair_address(skAddr).store(address::keypair_address(addr));

    BufferView chain_addr = address::chain_address(addr);
    BufferView sk_chain_addr = address::chain_address(skAddr);

    for (int i = 0; i < PQC_SLH_DSA_LEN; ++i)
    {
        Converter::toByte(sk_chain_addr, i);
        function_PRF(sk_joined, sk);
        Converter::toByte(chain_addr, i);
        BufferView sigi = sig.mid(i * PQC_SLH_DSA_N, PQC_SLH_DSA_N);
        chain(sigi, sk, 0, msg[i], pkseed, addr);
    }
}

// Algorithm 7: Compute a WOTS+ public key from a message and its signature
void wots_PKFromSig(
    const BufferView & pk, const ConstBufferView & sig, const ConstBufferView & m, const ConstBufferView & pkseed,
    const BufferView & addr
)
{
    assert(pk.size() == PQC_SLH_DSA_N);
    assert(sig.size() == PQC_SLH_DSA_LEN * PQC_SLH_DSA_N);
    assert(m.size() == PQC_SLH_DSA_N);
    assert(pkseed.size() == PQC_SLH_DSA_N);
    assert(addr.size() == ADDRESS_SIZE);

    HeapBuffer<PQC_SLH_DSA_N + ADDRESS_SIZE + PQC_SLH_DSA_LEN * PQC_SLH_DSA_N> pk_joined; // PK.seed, wotspkADRS, tmp
    BufferView tmp = pk_joined.mid(PQC_SLH_DSA_N + ADDRESS_SIZE, PQC_SLH_DSA_LEN * PQC_SLH_DSA_N);

    std::array<int, PQC_SLH_DSA_LEN> msg{};
    int csum = 0;
    Converter::base_2b(msg.data(), PQC_SLH_DSA_LEN_1, m, PQC_SLH_DSA_LGW);
    for (int i = 0; i < PQC_SLH_DSA_LEN_1; ++i)
        csum += PQC_SLH_DSA_W - 1 - msg[i];

    csum <<= 4;

    StackBuffer<PQC_SLH_DSA_CSUM_LEN> csum_m{};
    BufferView csum_buf(csum_m);
    Converter::toByte(csum_buf, csum);
    Converter::base_2b(msg.data() + PQC_SLH_DSA_LEN_1, PQC_SLH_DSA_LEN_2, csum_buf, PQC_SLH_DSA_LGW);

    BufferView chain_addr = address::chain_address(addr);
    for (int i = 0; i < PQC_SLH_DSA_LEN; ++i)
    {
        Converter::toByte(chain_addr, i);
        BufferView tmpi = tmp.mid(i * PQC_SLH_DSA_N, PQC_SLH_DSA_N);
        ConstBufferView sigi = sig.mid(i * PQC_SLH_DSA_N, PQC_SLH_DSA_N);
        chain(tmpi, sigi, msg[i], PQC_SLH_DSA_W - 1 - msg[i], pkseed, addr);
    }

    pk_joined.mid(0, PQC_SLH_DSA_N).store(pkseed);
    BufferView wotspkAddr = pk_joined.mid(PQC_SLH_DSA_N, ADDRESS_SIZE);
    wotspkAddr.store(addr);
    address::setTypeAndClear(wotspkAddr, WOTS_PK);
    address::keypair_address(wotspkAddr).store(address::keypair_address(addr));
    function_Tl(pk_joined, pk);
}

} // namespace slh_dsa
