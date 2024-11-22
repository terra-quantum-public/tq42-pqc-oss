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
    const BufferView & out, const ConstBufferView & X, size_t i, size_t s, const ConstBufferView & pkseed,
    const BufferView & addr, size_t mode
)
{
    assert(out.size() == ParameterSets[mode].N);
    assert(pkseed.size() == ParameterSets[mode].N);
    assert(addr.size() == ADDRESS_SIZE);

    if (i + s > ParameterSets[mode].W)
        throw InternalError();

    out.store(X);
    for (size_t j = i; j < i + s; ++j)
    {
        BufferView hash_addr = address::hash_address(addr);
        Converter::toByte(hash_addr, j);
        function_F(pkseed, addr, out, out);
    }
}

// Algorithm 5: Generate a WOTS+ public key
void wots_PKgen(
    const BufferView & pk, const ConstBufferView & pkseed, const ConstBufferView & skseed, const BufferView & addr,
    size_t mode
)
{
    assert(pk.size() == ParameterSets[mode].N);
    assert(pkseed.size() == ParameterSets[mode].N);
    assert(skseed.size() == ParameterSets[mode].N);
    assert(addr.size() == ADDRESS_SIZE);

    std::vector<uint8_t> v_tmp(ParameterSets[mode].LEN * ParameterSets[mode].N);
    BufferView tmp(v_tmp);
    std::vector<uint8_t> v_sk(ParameterSets[mode].N);
    BufferView sk(v_sk);

    Address skAddr;
    skAddr.store(addr);
    address::setTypeAndClear(skAddr, WOTS_PRF);
    address::keypair_address(skAddr).store(address::keypair_address(addr));

    BufferView chain_addr = address::chain_address(addr);
    BufferView sk_chain_addr = address::chain_address(skAddr);

    for (size_t i = 0; i < ParameterSets[mode].LEN; ++i)
    {
        Converter::toByte(sk_chain_addr, i);
        function_PRF(pkseed, skAddr, skseed, sk);
        Converter::toByte(chain_addr, i);
        BufferView tmpi = tmp.mid(i * ParameterSets[mode].N, ParameterSets[mode].N);
        chain(tmpi, sk, 0, ParameterSets[mode].W - 1, pkseed, addr, mode);
    }

    Address wotspkAddr;
    wotspkAddr.store(addr);
    address::setTypeAndClear(wotspkAddr, WOTS_PK);
    address::keypair_address(wotspkAddr).store(address::keypair_address(addr));
    function_Tl(pkseed, wotspkAddr, tmp, pk);
}

// Algorithm 6: Generate a WOTS+ signature on an n-byte message.
void wots_sign(
    const BufferView & sig, const ConstBufferView & m, const ConstBufferView & pkseed, const ConstBufferView & skseed,
    const BufferView & addr, size_t mode
)
{
    assert(sig.size() == ParameterSets[mode].LEN * ParameterSets[mode].N);
    assert(m.size() == ParameterSets[mode].N);
    assert(pkseed.size() == ParameterSets[mode].N);
    assert(skseed.size() == ParameterSets[mode].N);
    assert(addr.size() == ADDRESS_SIZE);

    std::vector<int> msg(ParameterSets[mode].LEN);
    size_t csum = 0;
    Converter::base_2b(msg.data(), ParameterSets[mode].LEN_1, m, (int)ParameterSets[mode].LGW);
    for (size_t i = 0; i < ParameterSets[mode].LEN_1; ++i)
        csum += ParameterSets[mode].W - 1 - (size_t)msg[i];

    csum <<= 4;

    std::vector<uint8_t> csum_m(ParameterSets[mode].CSUM_LEN);
    BufferView csum_buf(csum_m);
    Converter::toByte(csum_buf, csum);
    Converter::base_2b(
        msg.data() + ParameterSets[mode].LEN_1, ParameterSets[mode].LEN_2, csum_buf, (int)ParameterSets[mode].LGW
    );

    Address skAddr;
    skAddr.store(addr);
    address::setTypeAndClear(skAddr, WOTS_PRF);
    address::keypair_address(skAddr).store(address::keypair_address(addr));

    BufferView chain_addr = address::chain_address(addr);
    BufferView sk_chain_addr = address::chain_address(skAddr);

    std::vector<uint8_t> v_sk(ParameterSets[mode].N);
    BufferView sk(v_sk);
    for (size_t i = 0; i < ParameterSets[mode].LEN; ++i)
    {
        Converter::toByte(sk_chain_addr, i);
        function_PRF(pkseed, skAddr, skseed, sk);
        Converter::toByte(chain_addr, i);
        BufferView sigi = sig.mid(i * ParameterSets[mode].N, ParameterSets[mode].N);
        chain(sigi, sk, 0, msg[i], pkseed, addr, mode);
    }
}

// Algorithm 7: Compute a WOTS+ public key from a message and its signature
void wots_PKFromSig(
    const BufferView & pk, const ConstBufferView & sig, const ConstBufferView & m, const ConstBufferView & pkseed,
    const BufferView & addr, size_t mode
)
{
    assert(pk.size() == ParameterSets[mode].N);
    assert(sig.size() == ParameterSets[mode].LEN * ParameterSets[mode].N);
    assert(m.size() == ParameterSets[mode].N);
    assert(pkseed.size() == ParameterSets[mode].N);
    assert(addr.size() == ADDRESS_SIZE);

    std::vector<uint8_t> v_tmp(ParameterSets[mode].LEN * ParameterSets[mode].N);
    BufferView tmp(v_tmp);

    std::vector<int> msg(ParameterSets[mode].LEN);
    size_t csum = 0;
    Converter::base_2b(msg.data(), ParameterSets[mode].LEN_1, m, (int)ParameterSets[mode].LGW);
    for (size_t i = 0; i < ParameterSets[mode].LEN_1; ++i)
        csum += ParameterSets[mode].W - 1 - (size_t)msg[i];

    csum <<= 4;

    std::vector<uint8_t> csum_m(ParameterSets[mode].CSUM_LEN);
    BufferView csum_buf(csum_m);
    Converter::toByte(csum_buf, csum);
    Converter::base_2b(
        msg.data() + ParameterSets[mode].LEN_1, ParameterSets[mode].LEN_2, csum_buf, (int)ParameterSets[mode].LGW
    );

    BufferView chain_addr = address::chain_address(addr);
    for (size_t i = 0; i < ParameterSets[mode].LEN; ++i)
    {
        Converter::toByte(chain_addr, i);
        BufferView tmpi = tmp.mid(i * ParameterSets[mode].N, ParameterSets[mode].N);
        ConstBufferView sigi = sig.mid(i * ParameterSets[mode].N, ParameterSets[mode].N);
        chain(tmpi, sigi, msg[i], ParameterSets[mode].W - 1 - msg[i], pkseed, addr, mode);
    }

    Address wotspkAddr;
    wotspkAddr.store(addr);
    address::setTypeAndClear(wotspkAddr, WOTS_PK);
    address::keypair_address(wotspkAddr).store(address::keypair_address(addr));
    function_Tl(pkseed, wotspkAddr, tmp, pk);
}

} // namespace slh_dsa
