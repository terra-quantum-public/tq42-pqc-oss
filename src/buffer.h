#pragma once

#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <optional>
#include <stdexcept>
#include <tuple>
#include <vector>


template <typename StorageType> class MemoryRange
{
public:
    MemoryRange(StorageType * data, size_t size) : data_(data), size_(size) {}

    StorageType * data() const { return data_; }
    size_t size() const { return size_; }

private:
    StorageType * const data_;
    const size_t size_;
};

template <size_t N> class Array
{
public:
    Array(std::initializer_list<uint8_t> data)
    {
        if (data.size() > N)
        {
            throw std::invalid_argument("Array::Array() initilizer list too long");
        }
        memcpy(data_, data.begin(), data.size());
        memset(data_ + data.size(), 0, N - data.size());
    }

    uint8_t * data() const { return const_cast<uint8_t *>(&data_[0]); }
    size_t size() const { return N; }

private:
    uint8_t data_[N];
};

template <typename StorageType, class ViewType> class ConstBufferViewCore
{
public:
    using value_type = uint8_t;

    ConstBufferViewCore(const StorageType & memory) : memory_(memory) {}
    ConstBufferViewCore(std::initializer_list<uint8_t> data) : memory_(data) {}

    ViewType mid(size_t start_pos, std::optional<size_t> length) const
    {
        size_t len = length.value_or(size() - start_pos);

#ifndef NDEBUG
        if (start_pos >= size() || start_pos + len > size())
        {
            throw std::out_of_range("ConstBufferViewCore::mid() index out of range");
        }
#endif
        return ViewType(const_cast<uint8_t *>(const_data() + start_pos), len);
    }


    size_t size() const { return memory_.size(); }
    const uint8_t * const_data() const { return memory_.data(); }

    uint16_t load_16(size_t index) const
    {
        index *= 2;
#ifndef NDEBUG
        if (index + 1 >= size())
        {
            throw std::out_of_range("ConstBufferViewCore::load_16() index out of range");
        }
#endif
        const uint8_t * data = memory_.data();
        return (uint16_t)data[index] + ((uint16_t)data[index + 1] << 8);
    }

    uint32_t load_32(size_t index) const
    {
        index *= 4;
#ifndef NDEBUG
        if (index + 3 >= size())
        {
            throw std::out_of_range("ConstBufferViewCore::load_32() index out of range");
        }
#endif
        const uint8_t * data = memory_.data();
        return (uint32_t)data[index] + ((uint32_t)data[index + 1] << 8) + ((uint32_t)data[index + 2] << 16) +
               ((uint32_t)data[index + 3] << 24);
    }

    uint64_t load_64(size_t index) const { return load_64_offset(index << 3); }

    /// `offset` — byte offset
    uint64_t load_64_offset(size_t offset) const
    {
#ifndef NDEBUG
        if (offset + 7 >= size())
        {
            throw std::out_of_range("ConstBufferViewCore::load_64() offset out of range");
        }
#endif
        const uint8_t * data = memory_.data();

        return (uint64_t)data[offset] + ((uint64_t)data[offset + 1] << 8) + ((uint64_t)data[offset + 2] << 16) +
               ((uint64_t)data[offset + 3] << 24) + ((uint64_t)data[offset + 4] << 32) +
               ((uint64_t)data[offset + 5] << 40) + ((uint64_t)data[offset + 6] << 48) +
               ((uint64_t)data[offset + 7] << 56);
    }

    template <typename... Args> auto split(Args... sizes) const
    {
#ifndef NDEBUG
        if ((sizes + ...) != size())
        {
            throw std::out_of_range("BufferViewCore::split() sum of blocks to split does not equal to buffer size");
        }
#endif // _DEBUG

        return make_split(0, sizes...);
    }

private:
    std::tuple<ViewType> make_split(size_t from, size_t size) const
    {
        return std::make_tuple(ViewType(const_cast<uint8_t *>(const_data() + from), size));
    }

    template <typename... Args> auto make_split(size_t from, size_t first_size, Args... next_sizes) const
    {
        return std::tuple_cat(make_split(from, first_size), make_split(from + first_size, next_sizes...));
    }

protected:
    const StorageType memory_;
};

class ConstBufferView : public ConstBufferViewCore<MemoryRange<const uint8_t>, ConstBufferView>
{
public:
    ConstBufferView(const void * data, size_t size)
        : ConstBufferViewCore(MemoryRange(static_cast<const uint8_t *>(data), size))
    {
    }

    template <class T>
    ConstBufferView(const T & arr) : ConstBufferView(arr.data(), arr.size() * sizeof(typename T::value_type))
    {
    }

    template <typename T> static ConstBufferView from_single(const T & data)
    {
        return ConstBufferView(&data, sizeof(T));
    }
};

template <typename StorageType, typename ViewType>
class BufferViewCore : public ConstBufferViewCore<StorageType, ViewType>
{
public:
    using value_type = uint8_t;

    template <typename T> BufferViewCore(const T & memory) : ConstBufferViewCore<StorageType, ViewType>(memory) {}

    uint8_t * data() const { return const_cast<uint8_t *>(this->memory_.data()); }

    uint8_t & operator[](size_t index) const
    {
#ifndef NDEBUG
        if (index >= this->size())
        {
            throw std::out_of_range("Buffer::operator [] index out of range");
        }
#endif
        return const_cast<uint8_t *>(this->memory_.data())[index];
    }

    void store(const ConstBufferView & other) const
    {
#ifndef NDEBUG
        if (this->size() != other.size())
        {
            throw std::out_of_range("Buffer::copy_from() called for incompatible sizes");
        }
#endif
        memcpy(data(), other.const_data(), this->size());
    }

    void store_16(size_t index, uint16_t value) const
    {
        index *= 2;
#ifndef NDEBUG
        if (index + 1 >= this->size())
        {
            throw std::out_of_range("Buffer::store_16() index out of range");
        }
#endif
        uint8_t * data = const_cast<uint8_t *>(this->memory_.data());

        data[index + 0] = (value >> 0x00) & 0xFF;
        data[index + 1] = (value >> 0x08) & 0xFF;
    }

    void store_32(size_t index, uint32_t value) const
    {
        index *= 4;
#ifndef NDEBUG
        if (index + 3 >= this->size())
        {
            throw std::out_of_range("Buffer::store_32() index out of range");
        }
#endif
        uint8_t * data = const_cast<uint8_t *>(this->memory_.data());
        data[index + 0] = (value >> 0x00) & 0xFF;
        data[index + 1] = (value >> 0x08) & 0xFF;
        data[index + 2] = (value >> 0x10) & 0xFF;
        data[index + 3] = (value >> 0x18) & 0xFF;
    }

    void store_64(size_t index, uint64_t value) const { store_64_offset(index << 3, value); }

    /// `offset` — byte offset
    void store_64_offset(size_t offset, uint64_t value) const
    {
#ifndef NDEBUG
        if (offset + 7 >= this->size())
        {
            throw std::out_of_range("Buffer::store_64_offset() offset out of range");
        }
#endif
        uint8_t * data = const_cast<uint8_t *>(this->memory_.data());
        data[offset + 0] = (value >> 0x00) & 0xFF;
        data[offset + 1] = (value >> 0x08) & 0xFF;
        data[offset + 2] = (value >> 0x10) & 0xFF;
        data[offset + 3] = (value >> 0x18) & 0xFF;
        data[offset + 4] = (value >> 0x20) & 0xFF;
        data[offset + 5] = (value >> 0x28) & 0xFF;
        data[offset + 6] = (value >> 0x30) & 0xFF;
        data[offset + 7] = (value >> 0x38) & 0xFF;
    }
};

class BufferView : public BufferViewCore<MemoryRange<uint8_t>, BufferView>
{
public:
    BufferView(void * data, size_t size)
        : BufferViewCore<MemoryRange<uint8_t>, BufferView>(MemoryRange(static_cast<uint8_t *>(data), size))
    {
    }

    template <class T> BufferView(T & arr) : BufferView((void *)arr.data(), arr.size() * sizeof(typename T::value_type))
    {
    }

    template <typename T> static BufferView from_single(T & data) { return BufferView(&data, sizeof(T)); }
};

template <size_t N> class StackBuffer : public BufferViewCore<Array<N>, BufferView>
{
public:
    StackBuffer() : BufferViewCore<Array<N>, BufferView>(std::initializer_list<uint8_t>{}) {}
    StackBuffer(std::initializer_list<uint8_t> data) : BufferViewCore<Array<N>, BufferView>(data) {}
};

template <size_t N> class HeapBuffer : public BufferViewCore<std::vector<uint8_t>, BufferView>
{
public:
    HeapBuffer() : BufferViewCore<std::vector<uint8_t>, BufferView>(std::vector<uint8_t>(N)) {}
    HeapBuffer(std::initializer_list<uint8_t> data)
        : BufferViewCore<std::vector<uint8_t>, BufferView>(make_vector(data))
    {
    }

private:
    static std::vector<uint8_t> make_vector(std::initializer_list<uint8_t> data)
    {
        if (data.size() > N)
        {
            throw std::invalid_argument("HeapBuffer: initilizer list too long");
        }
        if (data.size() == N)
        {
            return std::vector<uint8_t>(data);
        }
        std::vector<uint8_t> vec(N);
        std::copy(data.begin(), data.end(), vec.begin());
        return vec;
    }
};
