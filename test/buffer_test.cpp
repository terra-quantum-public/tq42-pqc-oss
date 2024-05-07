#include <array>

#include <gtest/gtest.h>

#include <buffer.h>


TEST(BUFFER, CONST_BUFFER_VIEW_ACCESS_DATA)
{
    std::array<uint8_t, 16> data = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF};

    ConstBufferView buffer = data;

    EXPECT_EQ(buffer.size(), data.size());
    EXPECT_EQ(buffer.size(), data.size());
    EXPECT_EQ(buffer.const_data(), data.data());

    EXPECT_EQ(buffer.load_16(1), 0x0302);
    EXPECT_EQ(buffer.load_32(1), 0x07060504u);
    EXPECT_EQ(buffer.load_64(1), 0x0F0E0D0C0B0A0908ull);
}

TEST(BUFFER, CONST_BUFFER_VIEW_MID)
{
    std::array<uint8_t, 8> data = {0, 1, 2, 3, 4, 5, 6, 7};

    ConstBufferView buffer = data;

    ConstBufferView first = buffer.mid(0, 4);
    EXPECT_EQ(first.size(), 4);
    EXPECT_EQ(first.const_data(), data.data());
    EXPECT_EQ(first.load_16(0), 0x0100);

    ConstBufferView second = buffer.mid(4, 4);
    EXPECT_EQ(second.size(), 4);
    EXPECT_EQ(second.const_data(), data.data() + 4);
    EXPECT_EQ(second.load_16(0), 0x0504);

    ConstBufferView till_end = buffer.mid(4, std::nullopt);
    EXPECT_EQ(till_end.size(), 4);
    EXPECT_EQ(till_end.const_data(), data.data() + 4);
}

TEST(BUFFER, CONST_BUFFER_VIEW_SPLIT)
{
    std::array<uint8_t, 8> data = {0, 1, 2, 3, 4, 5, 6, 7};

    ConstBufferView buffer = data;

    auto [part1, part2, part3] = buffer.split(2u, 2u, 4u);

    EXPECT_EQ(part1.size(), 2);
    EXPECT_EQ(part1.load_16(0), 0x0100);

    EXPECT_EQ(part2.size(), 2);
    EXPECT_EQ(part2.load_16(0), 0x0302);

    EXPECT_EQ(part3.size(), 4);
    EXPECT_EQ(part3.load_32(0), 0x07060504u);
}


TEST(BUFFER, BUFFER_VIEW_ACCESS_DATA)
{
    std::array<uint8_t, 16> data = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF};

    BufferView buffer = data;

    EXPECT_EQ(buffer.size(), data.size());
    EXPECT_EQ(buffer.size(), data.size());
    EXPECT_EQ(buffer.const_data(), data.data());
    EXPECT_EQ(buffer.data(), data.data());

    for (size_t i = 0; i < data.size(); ++i)
    {
        EXPECT_EQ(buffer[i], data[i]);
    }

    EXPECT_EQ(buffer.load_16(1), 0x0302);
    EXPECT_EQ(buffer.load_32(1), 0x07060504u);
    EXPECT_EQ(buffer.load_64(1), 0x0F0E0D0C0B0A0908ull);
}

TEST(BUFFER, BUFFER_VIEW_MID)
{
    std::array<uint8_t, 8> data = {0, 1, 2, 3, 4, 5, 6, 7};

    BufferView buffer = data;

    BufferView first = buffer.mid(0, 4);
    EXPECT_EQ(first.size(), 4);
    EXPECT_EQ(first.const_data(), data.data());
    EXPECT_EQ(first.load_16(0), 0x0100);

    BufferView second = buffer.mid(4, 4);
    EXPECT_EQ(second.size(), 4);
    EXPECT_EQ(second.const_data(), data.data() + 4);
    EXPECT_EQ(second.load_16(0), 0x0504);

    BufferView till_end = buffer.mid(4, std::nullopt);
    EXPECT_EQ(till_end.size(), 4);
    EXPECT_EQ(till_end.const_data(), data.data() + 4);
}

TEST(BUFFER, BUFFER_VIEW_STORE_DATA)
{
    std::array<uint8_t, 16> data = {0};

    BufferView buffer = data;


    buffer.store_16(1, 0x0302);

    {
        std::array<uint8_t, 16> expected({0, 0, 2, 3});
        EXPECT_EQ(data, expected);
    }

    buffer.store_32(1, 0x07060504u);

    {
        std::array<uint8_t, 16> expected({0, 0, 2, 3, 4, 5, 6, 7});
        EXPECT_EQ(data, expected);
    }


    buffer.store_64(1, 0x0F0E0D0C0B0A0908ull);

    {
        std::array<uint8_t, 16> expected({0, 0, 2, 3, 4, 5, 6, 7, 8, 9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF});
        EXPECT_EQ(data, expected);
    }

    for (size_t i = 0; i < data.size(); ++i)
    {
        buffer[i] = static_cast<uint8_t>(data.size() - i - 1);
    }

    {
        std::array<uint8_t, 16> expected({0xF, 0xE, 0xD, 0xC, 0xB, 0xA, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0});
        EXPECT_EQ(data, expected);
    }
}

TEST(BUFFER, BUFFER_VIEW_SPLIT)
{
    std::array<uint8_t, 8> data = {0, 1, 2, 3, 4, 5, 6, 7};

    BufferView buffer = data;

    auto [part1, part2, part3] = buffer.split(2u, 2u, 4u);

    EXPECT_EQ(part1.size(), 2);
    EXPECT_EQ(part1.load_16(0), 0x0100);

    EXPECT_EQ(part2.size(), 2);
    EXPECT_EQ(part2.load_16(0), 0x0302);

    EXPECT_EQ(part3.size(), 4);
    EXPECT_EQ(part3.load_32(0), 0x07060504u);
}


TEST(BUFFER, STACK_BUFFER_BUFFER_ACCESS_DATA)
{
    std::initializer_list<uint8_t> data = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF};
    StackBuffer<16> buffer = data;

    EXPECT_EQ(buffer.size(), data.size());
    EXPECT_EQ(buffer.size(), data.size());
    EXPECT_EQ(buffer.const_data()[0], 0);
    EXPECT_EQ(buffer.const_data()[1], 1);
    EXPECT_EQ(buffer.data()[0], 0);
    EXPECT_EQ(buffer.data()[1], 1);

    for (size_t i = 0; i < data.size(); ++i)
    {
        EXPECT_EQ(buffer[i], i);
    }

    EXPECT_EQ(buffer.load_16(1), 0x0302);
    EXPECT_EQ(buffer.load_32(1), 0x07060504u);
    EXPECT_EQ(buffer.load_64(1), 0x0F0E0D0C0B0A0908ull);
}


TEST(BUFFER, STACK_BUFFER_BUFFER_STORE_DATA)
{
    StackBuffer<16> buffer;

    buffer.store_16(1, 0x0302);

    EXPECT_EQ(buffer.load_16(1), 0x0302);

    buffer.store_32(1, 0x07060504u);

    EXPECT_EQ(buffer.load_32(1), 0x07060504u);

    buffer.store_64(1, 0x0F0E0D0C0B0A0908ull);

    EXPECT_EQ(buffer.load_64(1), 0x0F0E0D0C0B0A0908ull);

    for (size_t i = 0; i < buffer.size(); ++i)
    {
        buffer[i] = static_cast<uint8_t>(buffer.size() - i - 1);
    }

    for (size_t i = 0; i < buffer.size(); ++i)
    {
        EXPECT_EQ(buffer[i], static_cast<uint8_t>(buffer.size() - i - 1));
    }
}

TEST(BUFFER, STACK_BUFFER_BUFFER_MID)
{
    StackBuffer<8> buffer{0, 1, 2, 3, 4, 5, 6, 7};

    BufferView first = buffer.mid(0, 4);
    EXPECT_EQ(first.size(), 4);
    EXPECT_EQ(first.load_16(0), 0x0100);

    BufferView second = buffer.mid(4, 4);
    EXPECT_EQ(second.size(), 4);
    EXPECT_EQ(second.load_16(0), 0x0504);

    BufferView till_end = buffer.mid(4, std::nullopt);
    EXPECT_EQ(till_end.size(), 4);
    EXPECT_EQ(second.load_16(0), 0x0504);
}

TEST(BUFFER, STACK_BUFFER_INITIALIZER_LIST_TOO_LONG)
{
    bool have_exception = false;

    try
    {
        StackBuffer<2> buffer{0, 1, 2, 3, 4};
    }
    catch (std::invalid_argument &)
    {
        have_exception = true;
    }

    EXPECT_TRUE(have_exception);
}

TEST(BUFFER, STACK_BUFFER_INITIALIZER_LIST_SHORT)
{
    StackBuffer<6> buffer{0, 1, 2, 3};

    EXPECT_EQ(buffer.load_16(0), 0x0100);
    EXPECT_EQ(buffer.load_16(1), 0x0302);
    EXPECT_EQ(buffer.load_16(2), 0x0000);
}

TEST(BUFFER, STACK_BUFFER_SPLIT)
{
    StackBuffer<8> buffer{0, 1, 2, 3, 4, 5, 6, 7};

    auto [part1, part2, part3] = buffer.split(2u, 2u, 4u);

    EXPECT_EQ(part1.size(), 2);
    EXPECT_EQ(part1.load_16(0), 0x0100);

    EXPECT_EQ(part2.size(), 2);
    EXPECT_EQ(part2.load_16(0), 0x0302);

    EXPECT_EQ(part3.size(), 4);
    EXPECT_EQ(part3.load_32(0), 0x07060504u);
}

TEST(BUFFER, HEAP_BUFFER_BUFFER_ACCESS_DATA)
{
    std::initializer_list<uint8_t> data = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF};
    HeapBuffer<16> buffer = data;

    EXPECT_EQ(buffer.size(), data.size());
    EXPECT_EQ(buffer.size(), data.size());
    EXPECT_EQ(buffer.const_data()[0], 0);
    EXPECT_EQ(buffer.const_data()[1], 1);
    EXPECT_EQ(buffer.data()[0], 0);
    EXPECT_EQ(buffer.data()[1], 1);

    for (size_t i = 0; i < data.size(); ++i)
    {
        EXPECT_EQ(buffer[i], i);
    }

    EXPECT_EQ(buffer.load_16(1), 0x0302);
    EXPECT_EQ(buffer.load_32(1), 0x07060504u);
    EXPECT_EQ(buffer.load_64(1), 0x0F0E0D0C0B0A0908ull);
}


TEST(BUFFER, HEAP_BUFFER_BUFFER_STORE_DATA)
{
    HeapBuffer<16> buffer;

    buffer.store_16(1, 0x0302);

    EXPECT_EQ(buffer.load_16(1), 0x0302);

    buffer.store_32(1, 0x07060504u);

    EXPECT_EQ(buffer.load_32(1), 0x07060504u);

    buffer.store_64(1, 0x0F0E0D0C0B0A0908ull);

    EXPECT_EQ(buffer.load_64(1), 0x0F0E0D0C0B0A0908ull);

    for (size_t i = 0; i < buffer.size(); ++i)
    {
        buffer[i] = static_cast<uint8_t>(buffer.size() - i - 1);
    }

    for (size_t i = 0; i < buffer.size(); ++i)
    {
        EXPECT_EQ(buffer[i], static_cast<uint8_t>(buffer.size() - i - 1));
    }
}

TEST(BUFFER, HEAP_BUFFER_BUFFER_MID)
{
    HeapBuffer<8> buffer{0, 1, 2, 3, 4, 5, 6, 7};

    BufferView first = buffer.mid(0, 4);
    EXPECT_EQ(first.size(), 4);
    EXPECT_EQ(first.load_16(0), 0x0100);

    BufferView second = buffer.mid(4, 4);
    EXPECT_EQ(second.size(), 4);
    EXPECT_EQ(second.load_16(0), 0x0504);

    BufferView till_end = buffer.mid(4, std::nullopt);
    EXPECT_EQ(till_end.size(), 4);
    EXPECT_EQ(second.load_16(0), 0x0504);
}

TEST(BUFFER, HEAP_BUFFER_INITIALIZER_LIST_TOO_LONG)
{
    bool have_exception = false;

    try
    {
        HeapBuffer<2> buffer{0, 1, 2, 3, 4};
    }
    catch (std::invalid_argument &)
    {
        have_exception = true;
    }

    EXPECT_TRUE(have_exception);
}

TEST(BUFFER, HEAP_BUFFER_INITIALIZER_LIST_SHORT)
{
    HeapBuffer<6> buffer{0, 1, 2, 3};

    EXPECT_EQ(buffer.load_16(0), 0x0100);
    EXPECT_EQ(buffer.load_16(1), 0x0302);
    EXPECT_EQ(buffer.load_16(2), 0x0000);
}

TEST(BUFFER, HEAP_BUFFER_SPLIT)
{
    HeapBuffer<8> buffer{0, 1, 2, 3, 4, 5, 6, 7};

    auto [part1, part2, part3] = buffer.split(2u, 2u, 4u);

    EXPECT_EQ(part1.size(), 2);
    EXPECT_EQ(part1.load_16(0), 0x0100);

    EXPECT_EQ(part2.size(), 2);
    EXPECT_EQ(part2.load_16(0), 0x0302);

    EXPECT_EQ(part3.size(), 4);
    EXPECT_EQ(part3.load_32(0), 0x07060504u);
}
