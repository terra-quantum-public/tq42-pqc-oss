#pragma once

#include <array>
#include <buffer.h>
#include <cstddef>
#include <cstdint>

using std::size_t;
using std::uint32_t;

namespace slh_dsa
{

#define ADDRESS_SIZE 32

using address_type = std::array<std::uint8_t, 4>;
static const address_type WOTS_HASH = {0x00, 0x00, 0x00, 0x00};
static const address_type WOTS_PK = {0x00, 0x00, 0x00, 0x01};
static const address_type TREE = {0x00, 0x00, 0x00, 0x02};
static const address_type FORS_TREE = {0x00, 0x00, 0x00, 0x03};
static const address_type FORS_ROOTS = {0x00, 0x00, 0x00, 0x04};
static const address_type WOTS_PRF = {0x00, 0x00, 0x00, 0x05};
static const address_type FORS_PRF = {0x00, 0x00, 0x00, 0x06};

using Address = StackBuffer<ADDRESS_SIZE>;

namespace address
{
static const std::array<std::uint8_t, 12> padding12{};

inline BufferView layer_address(const BufferView & addr) { return addr.mid(0, 4); }
inline BufferView tree_address(const BufferView & addr) { return addr.mid(4, 12); }
inline BufferView type_address(const BufferView & addr) { return addr.mid(16, 4); }
inline BufferView keypair_address(const BufferView & addr) { return addr.mid(20, 4); }
inline BufferView chain_address(const BufferView & addr) { return addr.mid(24, 4); }
inline BufferView hash_address(const BufferView & addr) { return addr.mid(28, 4); }
inline BufferView tree_height(const BufferView & addr) { return addr.mid(24, 4); }
inline BufferView tree_index(const BufferView & addr) { return addr.mid(28, 4); }
inline void setTypeAndClear(const BufferView & addr, const address_type & type)
{
    type_address(addr).store(type);
    addr.mid(20, 12).store(padding12);
}
} // namespace address

} // namespace slh_dsa
