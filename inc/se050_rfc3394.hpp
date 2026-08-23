/**
 * @file se050_rfc3394.hpp
 * @brief RFC 3394 AES Key Wrap / Unwrap with a caller-supplied AES-128 block.
 *
 * @details The wrapping key never needs to exist in MCU RAM: the 16-byte
 *          encrypt/decrypt callbacks may be SE050 `CipherOneShot` AES-ECB
 *          (AN12413 P1_CIPHER / P2_ENCRYPT_ONESHOT|P2_DECRYPT_ONESHOT) or a
 *          host software AES. AES-256 CEK wrap is 40 bytes (4 × 8-byte
 *          semiblocks plus the 8-byte integrity IV).
 *
 * @copyright Copyright (c) 2026 HardFOC. All rights reserved.
 */
#pragma once

#include "se050_types.hpp"

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace se050::rfc3394 {

inline constexpr std::uint64_t kIntegrityIv = 0xA6A6A6A6A6A6A6A6ULL;
inline constexpr std::size_t kAes256CekLen = 32U;
inline constexpr std::size_t kAes256WrappedLen = 40U;

/** @brief AES-ECB encrypt or decrypt of one 16-byte block (KEK size is the oracle's). */
using AesBlockFn = Error (*)(const std::uint8_t in[16], std::uint8_t out[16], void* ctx);

[[nodiscard]] inline std::uint64_t LoadBe64(const std::uint8_t* p) noexcept {
    return (static_cast<std::uint64_t>(p[0]) << 56) | (static_cast<std::uint64_t>(p[1]) << 48) |
           (static_cast<std::uint64_t>(p[2]) << 40) | (static_cast<std::uint64_t>(p[3]) << 32) |
           (static_cast<std::uint64_t>(p[4]) << 24) | (static_cast<std::uint64_t>(p[5]) << 16) |
           (static_cast<std::uint64_t>(p[6]) << 8) | static_cast<std::uint64_t>(p[7]);
}

inline void StoreBe64(std::uint8_t* p, std::uint64_t v) noexcept {
    p[0] = static_cast<std::uint8_t>(v >> 56);
    p[1] = static_cast<std::uint8_t>(v >> 48);
    p[2] = static_cast<std::uint8_t>(v >> 40);
    p[3] = static_cast<std::uint8_t>(v >> 32);
    p[4] = static_cast<std::uint8_t>(v >> 24);
    p[5] = static_cast<std::uint8_t>(v >> 16);
    p[6] = static_cast<std::uint8_t>(v >> 8);
    p[7] = static_cast<std::uint8_t>(v);
}

/**
 * @brief RFC 3394 unwrap. @p wrapped_len must be 8*(n+1) with n >= 2.
 * @param decrypt AES-1 of the wrapping key (KEK).
 */
[[nodiscard]] inline Error Unwrap(const std::uint8_t* wrapped, std::size_t wrapped_len, std::uint8_t* out,
                                  std::size_t out_cap, std::size_t* out_len, AesBlockFn decrypt,
                                  void* ctx) noexcept {
    if (out_len == nullptr) {
        return Error::InvalidArgument;
    }
    *out_len = 0;
    if (wrapped == nullptr || out == nullptr || decrypt == nullptr) {
        return Error::InvalidArgument;
    }
    if ((wrapped_len < 24U) || ((wrapped_len % 8U) != 0U)) {
        return Error::InvalidArgument;
    }
    const std::size_t n = (wrapped_len / 8U) - 1U;
    const std::size_t plain_len = n * 8U;
    if (out_cap < plain_len) {
        return Error::BufferTooSmall;
    }
    std::uint64_t a = LoadBe64(wrapped);
    std::uint64_t r[8]{};
    if (n > 8U) {
        return Error::InvalidArgument;
    }
    for (std::size_t i = 0; i < n; ++i) {
        r[i] = LoadBe64(wrapped + 8U * (i + 1U));
    }
    for (int j = 5; j >= 0; --j) {
        for (std::size_t i = n; i >= 1U; --i) {
            const std::uint64_t t = static_cast<std::uint64_t>(n) * static_cast<std::uint64_t>(j) + i;
            a ^= t;
            std::uint8_t block[16]{};
            StoreBe64(block, a);
            StoreBe64(block + 8, r[i - 1U]);
            std::uint8_t outb[16]{};
            const Error e = decrypt(block, outb, ctx);
            if (e != Error::Ok) {
                return e;
            }
            a = LoadBe64(outb);
            r[i - 1U] = LoadBe64(outb + 8);
        }
    }
    if (a != kIntegrityIv) {
        return Error::Protocol;
    }
    for (std::size_t i = 0; i < n; ++i) {
        StoreBe64(out + 8U * i, r[i]);
    }
    *out_len = plain_len;
    return Error::Ok;
}

/**
 * @brief RFC 3394 wrap. @p plain_len must be 8*n with n >= 2.
 * @param encrypt AES of the wrapping key (KEK).
 */
[[nodiscard]] inline Error Wrap(const std::uint8_t* plain, std::size_t plain_len, std::uint8_t* out,
                                std::size_t out_cap, std::size_t* out_len, AesBlockFn encrypt,
                                void* ctx) noexcept {
    if (out_len == nullptr) {
        return Error::InvalidArgument;
    }
    *out_len = 0;
    if (plain == nullptr || out == nullptr || encrypt == nullptr) {
        return Error::InvalidArgument;
    }
    if ((plain_len < 16U) || ((plain_len % 8U) != 0U)) {
        return Error::InvalidArgument;
    }
    const std::size_t n = plain_len / 8U;
    const std::size_t wrapped_len = (n + 1U) * 8U;
    if (n > 8U) {
        return Error::InvalidArgument;
    }
    if (out_cap < wrapped_len) {
        return Error::BufferTooSmall;
    }
    std::uint64_t a = kIntegrityIv;
    std::uint64_t r[8]{};
    for (std::size_t i = 0; i < n; ++i) {
        r[i] = LoadBe64(plain + 8U * i);
    }
    for (int j = 0; j <= 5; ++j) {
        for (std::size_t i = 1U; i <= n; ++i) {
            std::uint8_t block[16]{};
            StoreBe64(block, a);
            StoreBe64(block + 8, r[i - 1U]);
            std::uint8_t outb[16]{};
            const Error e = encrypt(block, outb, ctx);
            if (e != Error::Ok) {
                return e;
            }
            a = LoadBe64(outb);
            const std::uint64_t t = static_cast<std::uint64_t>(n) * static_cast<std::uint64_t>(j) + i;
            a ^= t;
            r[i - 1U] = LoadBe64(outb + 8);
        }
    }
    StoreBe64(out, a);
    for (std::size_t i = 0; i < n; ++i) {
        StoreBe64(out + 8U * (i + 1U), r[i]);
    }
    *out_len = wrapped_len;
    return Error::Ok;
}

}  // namespace se050::rfc3394
