// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TEST_UTIL_BIGUINT_H
#define BITCOIN_TEST_UTIL_BIGUINT_H

#include <cstddef>
#include <cstdint>
#include <vector>

// Byte-wise references for BigUint tests. Values are little-endian.

/** value shifted up by bits, truncated or zero-extended to result_size bytes. */
inline std::vector<unsigned char> ShiftLeftFixed(const std::vector<unsigned char>& value, uint64_t bits, size_t result_size)
{
    std::vector<unsigned char> result(result_size, 0);
    const size_t byte_shift{static_cast<size_t>(bits / 8)};
    const unsigned int bit_shift{static_cast<unsigned int>(bits % 8)};
    for (size_t i{0}; i < value.size() && i + byte_shift < result.size(); ++i) {
        const uint16_t shifted{static_cast<uint16_t>(static_cast<uint16_t>(value[i]) << bit_shift)};
        result[i + byte_shift] |= static_cast<unsigned char>(shifted);
        if (bit_shift != 0 && i + byte_shift + 1 < result.size()) {
            result[i + byte_shift + 1] |= static_cast<unsigned char>(shifted >> 8);
        }
    }
    return result;
}

/** value shifted down by bits, as result_size bytes. value must hold
 *  result_size bytes above the whole bytes shifted out. */
inline std::vector<unsigned char> ShiftRightFixed(const std::vector<unsigned char>& value, uint64_t bits, size_t result_size)
{
    std::vector<unsigned char> result(result_size, 0);
    const size_t byte_shift{static_cast<size_t>(bits / 8)};
    const unsigned int bit_shift{static_cast<unsigned int>(bits % 8)};
    for (size_t i{0}; i < result.size(); ++i) {
        const size_t source{i + byte_shift};
        uint16_t shifted{static_cast<uint16_t>(static_cast<uint16_t>(value[source]) >> bit_shift)};
        if (bit_shift != 0 && source + 1 < value.size()) {
            shifted |= static_cast<uint16_t>(value[source + 1]) << (8 - bit_shift);
        }
        result[i] = static_cast<unsigned char>(shifted);
    }
    return result;
}

/** value without its trailing zero bytes. */
inline std::vector<unsigned char> TrimTrailingZeros(std::vector<unsigned char> value)
{
    while (!value.empty() && value.back() == 0) value.pop_back();
    return value;
}

#endif // BITCOIN_TEST_UTIL_BIGUINT_H
