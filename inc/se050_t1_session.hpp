/**
 * @file se050_t1_session.hpp
 * @brief ISO/IEC 7816-3 **T=1** block protocol for NXP SE050 **T=1 over I²C** (EDC = CRC-16).
 *
 * @details This layer sits on top of @ref I2cTransceiveInterface and implements:
 *          - NAD discipline (`0x5A` host → SE, `0xA5` SE → host),
 *          - I-block send/receive with **chaining** (M bit, `0x20`),
 *          - R-block **ACK** between chained blocks (`0x80` family),
 *          - minimal **S-block** requests used during bring-up (`0xC6` warm reset, `0xC7` GET ATR),
 *          - CRC-16 EDC via @ref se050::crc.
 *
 * @note Field firmware may require tuning @ref SetInterFrameDelayMs. Align behaviour with
 *       NXP UM11225 / UM1225 and validate on-target (logic analyser / golden traces).
 *
 * @copyright Copyright (c) 2026 HardFOC. All rights reserved.
 */
#pragma once

#include "se050_crc.hpp"
#include "se050_types.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace se050 {

/** @brief T=1 constants and small helpers for SE050 on I²C. */
namespace t1 {

/** @brief NAD value used by the host for command blocks. */
inline constexpr std::uint8_t kNadHostToSe = 0x5AU;
/** @brief NAD value returned by the SE in response blocks. */
inline constexpr std::uint8_t kNadSeToHost = 0xA5U;
/** @brief Maximum information field size per block (ISO 7816-3 typical upper bound). */
inline constexpr std::size_t kMaxInformationField = 254U;
/** @brief Raw block buffer high water: prologue + INF + EDC. */
inline constexpr std::size_t kMaxRawBlockBytes = 3U + kMaxInformationField + 2U;

/** @brief S-block PCB used by NXP stacks for a 7816-style warm reset request (LEN = 0 INF). */
inline constexpr std::uint8_t kPcbSWarmReset = 0xC6U;
/** @brief S-block PCB used by NXP stacks for GET ATR / card profile read (LEN = 0 INF). */
inline constexpr std::uint8_t kPcbSGetAtr = 0xC7U;
/** @brief S-block request/response pair for resynchronization. */
inline constexpr std::uint8_t kPcbSResyncReq = 0xC0U;
inline constexpr std::uint8_t kPcbSResyncResp = 0xE0U;
/** @brief S-block request/response pair for waiting-time extension. */
inline constexpr std::uint8_t kPcbSWtxReq = 0xC3U;
inline constexpr std::uint8_t kPcbSWtxResp = 0xE3U;

[[nodiscard]] inline constexpr bool IsIBlock(std::uint8_t pcb) noexcept {
    return (pcb & 0x80U) == 0U;
}
[[nodiscard]] inline constexpr bool IsRBlock(std::uint8_t pcb) noexcept {
    return (pcb & 0xC0U) == 0x80U;
}
[[nodiscard]] inline constexpr bool IsSBlock(std::uint8_t pcb) noexcept {
    return (pcb & 0xC0U) == 0xC0U;
}
[[nodiscard]] inline constexpr bool IBlockMore(std::uint8_t pcb) noexcept {
    return (pcb & 0x20U) != 0U;
}
[[nodiscard]] inline constexpr std::uint8_t IBlockPcb(std::uint8_t ns_bit, bool more) noexcept {
    return static_cast<std::uint8_t>(((ns_bit & 1U) << 6) | (more ? 0x20U : 0U));
}
[[nodiscard]] inline constexpr std::uint8_t RBlockAckPcb(std::uint8_t nr_bit) noexcept {
    return static_cast<std::uint8_t>(0x80U | ((nr_bit & 1U) << 4));
}
[[nodiscard]] inline constexpr std::uint8_t IBlockSeqFromPcb(std::uint8_t pcb) noexcept {
    return static_cast<std::uint8_t>((pcb >> 6) & 1U);
}

}  // namespace t1

/**
 * @brief Stateful T=1 session bound to a concrete I²C transport.
 * @tparam TransportT CRTP transport (`I2cTransceiveInterface<TransportT>`).
 */
template <typename TransportT>
class T1Session {
public:
    explicit T1Session(TransportT& transport) noexcept : transport_(transport) {}

    /** @brief Delay between a completed @p Write and the first @p Read of the response. */
    void SetInterFrameDelayMs(std::uint32_t ms) noexcept { inter_frame_delay_ms_ = ms; }

    [[nodiscard]] std::uint32_t InterFrameDelayMs() const noexcept { return inter_frame_delay_ms_; }

    /** @brief Number of retry attempts for retryable I²C read errors while waiting response blocks. */
    void SetReadRetries(std::uint8_t retries) noexcept { max_read_retries_ = retries; }

    [[nodiscard]] std::uint8_t ReadRetries() const noexcept { return max_read_retries_; }

    /** @brief Delay between retryable read attempts (transport polling interval). */
    void SetReadRetryDelayMs(std::uint32_t ms) noexcept { read_retry_delay_ms_ = ms; }

    [[nodiscard]] std::uint32_t ReadRetryDelayMs() const noexcept { return read_retry_delay_ms_; }

    /** @brief Upper bound of tolerated WTX request/response cycles within a single exchange. */
    void SetMaxWtxRequests(std::uint8_t max_wtx_requests) noexcept { max_wtx_requests_ = max_wtx_requests; }

    [[nodiscard]] std::uint8_t MaxWtxRequests() const noexcept { return max_wtx_requests_; }

    TransportT& Transport() noexcept { return transport_; }
    const TransportT& Transport() const noexcept { return transport_; }

    /**
     * @brief Send an S-block warm-reset style request (PCB = @ref t1::kPcbSWarmReset, empty INF).
     * @param timeout_ms I²C segment timeout.
     */
    [[nodiscard]] Error ChipWarmReset(std::uint32_t timeout_ms) noexcept {
        const Error se = SendSBlock(t1::kPcbSWarmReset, timeout_ms);
        if (se != Error::Ok) {
            return se;
        }
        std::uint8_t raw[t1::kMaxRawBlockBytes]{};
        std::size_t raw_len = 0;
        const Error re = RecvT1Block(raw, sizeof(raw), &raw_len, timeout_ms);
        ResetSequenceState();
        return re;
    }

    /**
     * @brief Retrieve the SE050 **T=1oI2C** profile / ATR-like byte string (S-block GET ATR).
     * @param buf Destination buffer for the **information field** bytes (ATR payload only).
     * @param cap Capacity of @p buf.
     * @param len_out Written INF length on success.
     */
    [[nodiscard]] Error GetAnswerToReset(std::uint8_t* buf, std::size_t cap, std::size_t* len_out,
                                         std::uint32_t timeout_ms) noexcept {
        if (len_out == nullptr) {
            return Error::InvalidArgument;
        }
        *len_out = 0;
        ResetSequenceState();
        const Error se = SendSBlock(t1::kPcbSGetAtr, timeout_ms);
        if (se != Error::Ok) {
            return se;
        }
        std::uint8_t raw[t1::kMaxRawBlockBytes]{};
        std::size_t raw_len = 0;
        const Error re = RecvT1Block(raw, sizeof(raw), &raw_len, timeout_ms);
        if (re != Error::Ok) {
            return re;
        }
        if (raw_len < 5U) {
            return Error::Protocol;
        }
        if (!t1::IsSBlock(raw[1])) {
            return Error::Protocol;
        }
        const std::uint8_t ln = raw[2];
        if (3U + static_cast<std::size_t>(ln) + 2U != raw_len) {
            return Error::Protocol;
        }
        if (static_cast<std::size_t>(ln) > cap) {
            return Error::BufferTooSmall;
        }
        if (ln > 0U) {
            std::memcpy(buf, raw + 3U, ln);
        }
        *len_out = ln;
        ResetSequenceState();
        return Error::Ok;
    }

    /**
     * @brief Exchange a raw **information field** payload (APDU bytes) with the SE using I-blocks.
     *
     * Performs chained transmission/reception per ISO 7816-3 (R-block ACK between chained blocks).
     *
     * @param cmd Command INF (typically a full C-APDU).
     * @param cmd_len Length of @p cmd (may exceed @ref t1::kMaxInformationField; chaining used).
     * @param rsp Buffer for concatenated response INF (typically R-APDU body + status).
     * @param rsp_cap Capacity of @p rsp.
     * @param rsp_len Total INF bytes stored into @p rsp.
     *
     * @note If this returns any error other than @ref Error::Ok, call @ref ResetSequenceState
     *       (or perform a warm / electrical reset) before the next exchange — `N(S)` / `N(R)`
     *       state may no longer match the SE.
     */
    [[nodiscard]] Error ExchangeInformation(const std::uint8_t* cmd, std::size_t cmd_len, std::uint8_t* rsp,
                                            std::size_t rsp_cap, std::size_t* rsp_len,
                                            std::uint32_t timeout_ms) noexcept {
        if (rsp_len == nullptr) {
            return Error::InvalidArgument;
        }
        *rsp_len = 0;
        if (!transport_.EnsureInitialized()) {
            return Error::NotInitialized;
        }

        std::size_t off = 0;
        std::uint8_t ns_host = host_ns_;
        while (off < cmd_len) {
            const std::size_t chunk =
                std::min(cmd_len - off, static_cast<std::size_t>(t1::kMaxInformationField));
            const bool more_chain = (off + chunk) < cmd_len;
            const std::uint8_t pcb = t1::IBlockPcb(ns_host, more_chain);
            const Error w = SendRawBlock(pcb, cmd + off, static_cast<std::uint8_t>(chunk), timeout_ms);
            if (w != Error::Ok) {
                return w;
            }
            ns_host ^= 1U;
            off += chunk;
            if (more_chain) {
                const Error rr = ExpectRBlockFromCard(timeout_ms);
                if (rr != Error::Ok) {
                    return rr;
                }
            }
        }
        host_ns_ = ns_host;

        std::size_t total_rx = 0;
        std::uint8_t wtx_count = 0;
        for (int guard = 0; guard < 64; ++guard) {
            std::uint8_t raw[t1::kMaxRawBlockBytes]{};
            std::size_t raw_len = 0;
            const Error rb = RecvT1Block(raw, sizeof(raw), &raw_len, timeout_ms);
            if (rb != Error::Ok) {
                return rb;
            }
            if (raw_len < 5U) {
                return Error::Protocol;
            }
            if (raw[0] != t1::kNadSeToHost) {
                return Error::Protocol;
            }
            if (t1::IsSBlock(raw[1])) {
                const Error sb = HandleSBlock(raw, raw_len, timeout_ms, &wtx_count);
                if (sb != Error::Ok) {
                    return sb;
                }
                continue;
            }
            if (!t1::IsIBlock(raw[1])) {
                return Error::Protocol;
            }
            const std::uint8_t seq = t1::IBlockSeqFromPcb(raw[1]);
            if (seq != card_ns_) {
                return Error::Sequence;
            }
            const std::uint8_t ln = raw[2];
            if (3U + static_cast<std::size_t>(ln) + 2U != raw_len) {
                return Error::Protocol;
            }
            if (total_rx + static_cast<std::size_t>(ln) > rsp_cap) {
                return Error::BufferTooSmall;
            }
            if (ln > 0U) {
                std::memcpy(rsp + total_rx, raw + 3U, ln);
                total_rx += ln;
            }
            card_ns_ ^= 1U;
            if (!t1::IBlockMore(raw[1])) {
                *rsp_len = total_rx;
                return Error::Ok;
            }
            const Error ack = SendRBlockAck(t1::RBlockAckPcb(card_ns_), timeout_ms);
            if (ack != Error::Ok) {
                return ack;
            }
        }
        return Error::Protocol;
    }

    /** @brief Reset sequence counters (call after electrical / protocol reset). */
    void ResetSequenceState() noexcept {
        host_ns_ = 0;
        card_ns_ = 0;
    }

private:
    [[nodiscard]] Error SendSBlock(std::uint8_t pcb, std::uint32_t timeout_ms) noexcept {
        if (!transport_.EnsureInitialized()) {
            return Error::NotInitialized;
        }
        return SendRawBlock(pcb, nullptr, 0, timeout_ms);
    }

    [[nodiscard]] Error SendRawBlock(std::uint8_t pcb, const std::uint8_t* inf, std::uint8_t inf_len,
                                     std::uint32_t timeout_ms) noexcept {
        if (static_cast<std::size_t>(inf_len) > t1::kMaxInformationField) {
            return Error::InvalidArgument;
        }
        std::uint8_t frame[t1::kMaxRawBlockBytes]{};
        frame[0] = t1::kNadHostToSe;
        frame[1] = pcb;
        frame[2] = inf_len;
        if (inf_len > 0 && inf != nullptr) {
            std::memcpy(frame + 3U, inf, inf_len);
        }
        crc::AppendEdc(frame, 3U + inf_len);
        const Error e = transport_.Write(frame, 3U + inf_len + 2U, timeout_ms);
        if (e != Error::Ok) {
            return e;
        }
        transport_.delay_ms(inter_frame_delay_ms_);
        return Error::Ok;
    }

    [[nodiscard]] Error SendRBlockAck(std::uint8_t pcb, std::uint32_t timeout_ms) noexcept {
        return SendRawBlock(pcb, nullptr, 0, timeout_ms);
    }

    [[nodiscard]] Error RecvT1Block(std::uint8_t* out, std::size_t cap, std::size_t* total_len,
                                    std::uint32_t timeout_ms) noexcept {
        if (cap < 5U) {
            return Error::BufferTooSmall;
        }
        Error e = ReadWithRetry(out, 3U, timeout_ms);
        if (e != Error::Ok) {
            return e;
        }
        const std::uint8_t ln = out[2];
        if (3U + static_cast<std::size_t>(ln) + 2U > cap) {
            return Error::BufferTooSmall;
        }
        if (ln + 2U > 0U) {
            e = ReadWithRetry(out + 3U, ln + 2U, timeout_ms);
            if (e != Error::Ok) {
                return e;
            }
        }
        const std::size_t tot = 3U + ln + 2U;
        if (!crc::VerifyFrameCrc(out, tot)) {
            return Error::Crc;
        }
        *total_len = tot;
        return Error::Ok;
    }

    [[nodiscard]] Error ExpectRBlockFromCard(std::uint32_t timeout_ms) noexcept {
        std::uint8_t wtx_count = 0;
        for (int guard = 0; guard < 16; ++guard) {
            std::uint8_t raw[t1::kMaxRawBlockBytes]{};
            std::size_t raw_len = 0;
            const Error e = RecvT1Block(raw, sizeof(raw), &raw_len, timeout_ms);
            if (e != Error::Ok) {
                return e;
            }
            if (raw_len < 5U || raw[0] != t1::kNadSeToHost) {
                return Error::Protocol;
            }
            if (t1::IsSBlock(raw[1])) {
                const Error sb = HandleSBlock(raw, raw_len, timeout_ms, &wtx_count);
                if (sb != Error::Ok) {
                    return sb;
                }
                continue;
            }
            if (!t1::IsRBlock(raw[1])) {
                return Error::Protocol;
            }
            return Error::Ok;
        }
        return Error::Protocol;
    }

    [[nodiscard]] static constexpr bool IsRetryableReadError(Error e) noexcept {
        return e == Error::Transport || e == Error::Timeout;
    }

    [[nodiscard]] Error ReadWithRetry(std::uint8_t* rx, std::size_t rx_len, std::uint32_t timeout_ms) noexcept {
        for (std::uint8_t attempt = 0; attempt <= max_read_retries_; ++attempt) {
            const Error e = transport_.Read(rx, rx_len, timeout_ms);
            if (e == Error::Ok) {
                return Error::Ok;
            }
            if (!IsRetryableReadError(e) || attempt == max_read_retries_) {
                return e;
            }
            transport_.delay_ms(read_retry_delay_ms_);
        }
        return Error::Transport;
    }

    [[nodiscard]] Error HandleSBlock(const std::uint8_t* raw, std::size_t raw_len, std::uint32_t timeout_ms,
                                     std::uint8_t* wtx_count) noexcept {
        if (raw == nullptr || raw_len < 5U) {
            return Error::Protocol;
        }
        const std::uint8_t ln = raw[2];
        if (3U + static_cast<std::size_t>(ln) + 2U != raw_len) {
            return Error::Protocol;
        }
        if (raw[1] == t1::kPcbSWtxReq) {
            if (wtx_count == nullptr || *wtx_count >= max_wtx_requests_) {
                return Error::Protocol;
            }
            ++(*wtx_count);
            return SendRawBlock(t1::kPcbSWtxResp, (ln > 0U) ? (raw + 3U) : nullptr, ln, timeout_ms);
        }
        if (raw[1] == t1::kPcbSResyncReq) {
            ResetSequenceState();
            return SendRawBlock(t1::kPcbSResyncResp, nullptr, 0U, timeout_ms);
        }
        return Error::Protocol;
    }

    TransportT& transport_;
    std::uint32_t inter_frame_delay_ms_{2};
    std::uint8_t max_read_retries_{6};
    std::uint32_t read_retry_delay_ms_{2};
    std::uint8_t max_wtx_requests_{8};
    std::uint8_t host_ns_{0};
    std::uint8_t card_ns_{0};
};

}  // namespace se050
