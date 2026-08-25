/**
 * @file se050_scp03.hpp
 * @brief GlobalPlatform SCP03 session over an existing T=1 I²C link.
 *
 * @details Protects on-board APDUs against an I²C probe (the MitM that can
 *          forge "signature valid"). This is **not** the HMI channel — HMI
 *          trust remains SE-backed TLS 1.3. Host crypto is in
 *          @ref se050_scp03_crypto.hpp (AES-CMAC / CBC). Compiled-in NXP
 *          default ENC/MAC/DEK values are forbidden; @ref OpenSecureChannel
 *          returns @ref Error::NotSupported when static keys are absent.
 *
 *          Wrap/unwrap uses caller-owned buffers (CM4: D2 `.se_apdu_scratch`).
 *          Live T=1 exchanges stay plaintext until unique ENC/MAC keys exist.
 *
 * @copyright Copyright (c) 2026 HardFOC. All rights reserved.
 */
#pragma once

#include "se050_apdu.hpp"
#include "se050_scp03_crypto.hpp"
#include "se050_t1_session.hpp"
#include "se050_types.hpp"

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace se050::scp03 {

inline constexpr std::uint8_t kClaGp = 0x80U;
inline constexpr std::uint8_t kClaGpSecure = 0x84U;
inline constexpr std::uint8_t kInsInitializeUpdate = 0x50U;
inline constexpr std::uint8_t kInsExternalAuthenticate = 0x82U;
inline constexpr std::uint8_t kDefaultKeyVersion = 0x0BU;
inline constexpr std::uint8_t kSecLevelCmacCencRmacRenc = 0x33U;
inline constexpr std::size_t kInitUpdateRspMin = 10U + 3U + 8U + 8U + 2U;
inline constexpr std::uint8_t kClaSmBit = 0x04U;
inline constexpr std::size_t kMacFieldLen = 8U;
/** @brief Short-APDU wrap workspace (CM4: D2 `.se_apdu_scratch`, not task stack). */
inline constexpr std::size_t kWrapScratchBytes = 320U;

/** @brief Runtime static keys (never compiled-in NXP defaults). */
struct StaticKeys {
    const std::uint8_t* host_static_key_enc{nullptr};
    std::size_t host_static_key_enc_len{0};
    const std::uint8_t* host_static_key_cmac{nullptr};
    std::size_t host_static_key_cmac_len{0};
    const std::uint8_t* host_challenge{nullptr};
    std::size_t host_challenge_len{0};
    std::uint8_t key_version{kDefaultKeyVersion};
};

/** @brief Live SCP03 session state after a successful handshake. */
struct ChannelState {
    bool open{false};
    std::uint8_t senc[crypto::kAes128KeyLen]{};
    std::uint8_t smac[crypto::kAes128KeyLen]{};
    std::uint8_t srmac[crypto::kAes128KeyLen]{};
    std::uint8_t mcv[16]{};
    std::uint8_t counter[16]{};
};

/**
 * @brief C-MAC + C-ENC wrap of a short C-APDU (this C2 rejects extended Lc).
 * @details Caller owns @p out. On CM4 put @p out in D2 `.se_apdu_scratch`.
 *          Updates MCV. Does not increment the command counter (host
 *          increments in @ref UnwrapResponse after the card replies).
 */
[[nodiscard]] inline Error WrapCommand(ChannelState& st, const std::uint8_t* capdu,
                                       std::size_t capdu_len, std::uint8_t* out,
                                       std::size_t out_cap, std::size_t* out_len) noexcept {
    if (out_len == nullptr) {
        return Error::InvalidArgument;
    }
    *out_len = 0;
    if (!st.open) {
        return Error::NotSupported;
    }
    if (capdu == nullptr || out == nullptr || capdu_len < 4U) {
        return Error::InvalidArgument;
    }

    const std::uint8_t cla = static_cast<std::uint8_t>(capdu[0] | kClaSmBit);
    const std::uint8_t ins = capdu[1];
    const std::uint8_t p1 = capdu[2];
    const std::uint8_t p2 = capdu[3];
    std::size_t data_len = 0;
    const std::uint8_t* data = nullptr;
    if (capdu_len > 4U) {
        data_len = capdu[4];
        if (data_len > 0U) {
            if (capdu_len < (5U + data_len)) {
                return Error::Protocol;
            }
            data = capdu + 5U;
        }
    }

    std::size_t enc_len = 0;
    if (data_len > 0U) {
        if ((5U + data_len + 16U + kMacFieldLen) > out_cap) {
            return Error::BufferTooSmall;
        }
        std::memcpy(out + 5U, data, data_len);
        enc_len = data_len;
        if (!crypto::IsoPad80(out + 5U, &enc_len, out_cap - 5U - kMacFieldLen)) {
            return Error::BufferTooSmall;
        }
        std::uint8_t icv[16]{};
        crypto::CommandIcv(st.senc, st.counter, icv);
        if (!crypto::Aes128CbcEncrypt(st.senc, icv, out + 5U, out + 5U, enc_len)) {
            return Error::InvalidArgument;
        }
    }

    const std::size_t lc = enc_len + kMacFieldLen;
    if (lc > 255U || (5U + lc) > out_cap) {
        return Error::BufferTooSmall;
    }
    out[0] = cla;
    out[1] = ins;
    out[2] = p1;
    out[3] = p2;
    out[4] = static_cast<std::uint8_t>(lc);

    crypto::Cmac cm{};
    crypto::CmacStart(cm, st.smac);
    crypto::CmacUpdate(cm, st.mcv, 16U);
    crypto::CmacUpdate(cm, out, 5U + enc_len);
    std::uint8_t mac_full[16]{};
    crypto::CmacFinish(cm, mac_full);
    std::memcpy(out + 5U + enc_len, mac_full, kMacFieldLen);
    std::memcpy(st.mcv, mac_full, 16);
    *out_len = 5U + lc;
    return Error::Ok;
}

/**
 * @brief R-MAC + R-ENC unwrap. Increments the command counter on R-MAC Ok.
 * @details A short error R-APDU (< 10 bytes) passes SW through without MAC.
 *          MAC failure closes the channel.
 */
[[nodiscard]] inline Error UnwrapResponse(ChannelState& st, const std::uint8_t* rapdu,
                                          std::size_t rapdu_len, std::uint8_t* out,
                                          std::size_t out_cap, std::size_t* out_len) noexcept {
    if (out_len == nullptr) {
        return Error::InvalidArgument;
    }
    *out_len = 0;
    if (!st.open) {
        return Error::NotSupported;
    }
    if (rapdu == nullptr || out == nullptr || rapdu_len < 2U) {
        return Error::InvalidArgument;
    }

    const std::uint8_t sw1 = rapdu[rapdu_len - 2U];
    const std::uint8_t sw2 = rapdu[rapdu_len - 1U];

    if (rapdu_len < (kMacFieldLen + 2U)) {
        if (out_cap < 2U) {
            return Error::BufferTooSmall;
        }
        out[0] = sw1;
        out[1] = sw2;
        *out_len = 2U;
        crypto::IncCommandCounter(st.counter);
        return Error::Ok;
    }

    crypto::Cmac cm{};
    crypto::CmacStart(cm, st.srmac);
    crypto::CmacUpdate(cm, st.mcv, 16U);
    crypto::CmacUpdate(cm, rapdu, rapdu_len - kMacFieldLen - 2U);
    crypto::CmacUpdate(cm, rapdu + rapdu_len - 2U, 2U);
    std::uint8_t mac_full[16]{};
    crypto::CmacFinish(cm, mac_full);
    if (std::memcmp(mac_full, rapdu + rapdu_len - kMacFieldLen - 2U, kMacFieldLen) != 0) {
        st.open = false;
        return Error::Protocol;
    }

    const std::size_t enc_len = rapdu_len - kMacFieldLen - 2U;
    if (enc_len == 0U) {
        if (out_cap < 2U) {
            return Error::BufferTooSmall;
        }
        out[0] = sw1;
        out[1] = sw2;
        *out_len = 2U;
        crypto::IncCommandCounter(st.counter);
        return Error::Ok;
    }
    if ((enc_len % 16U) != 0U || enc_len > out_cap) {
        st.open = false;
        return Error::Protocol;
    }

    std::uint8_t icv[16]{};
    crypto::ResponseIcv(st.senc, st.counter, icv);
    if (!crypto::Aes128CbcDecrypt(st.senc, icv, rapdu, out, enc_len)) {
        st.open = false;
        return Error::Protocol;
    }
    std::size_t plain_len = 0;
    if (!crypto::IsoUnpad80(out, enc_len, &plain_len)) {
        st.open = false;
        return Error::Protocol;
    }
    if ((plain_len + 2U) > out_cap) {
        return Error::BufferTooSmall;
    }
    out[plain_len] = sw1;
    out[plain_len + 1U] = sw2;
    *out_len = plain_len + 2U;
    crypto::IncCommandCounter(st.counter);
    return Error::Ok;
}

/**
 * @brief SCP03 session bound to a T=1 transport.
 * @tparam TransportT CRTP I²C transport type used by @ref T1Session.
 */
template <typename TransportT>
class Session {
public:
    Session() noexcept = default;

    /**
     * @brief `INITIALIZE UPDATE` / `EXTERNAL AUTHENTICATE`.
     * @details Returns @ref Error::NotSupported when static keys or the
     *          8-byte host challenge are missing. Never returns Ok for a
     *          plaintext stand-in.
     */
    [[nodiscard]] Error OpenSecureChannel(T1Session<TransportT>& t1, const StaticKeys& keys,
                                          std::uint32_t timeout_ms) noexcept {
        using crypto::kAes128KeyLen;
        using crypto::kChallengeLen;
        using crypto::kCryptogramLen;
        st_.open = false;
        if (!crypto::StaticKeysUsable(keys.host_static_key_enc, keys.host_static_key_enc_len,
                                      keys.host_static_key_cmac, keys.host_static_key_cmac_len) ||
            keys.host_challenge == nullptr || keys.host_challenge_len != kChallengeLen) {
            return Error::NotSupported;
        }

        std::uint8_t capdu[16]{};
        std::size_t capdu_len = 0;
        Error e = apdu::BuildCaseShort(kClaGp, kInsInitializeUpdate, keys.key_version, 0x00U,
                                       keys.host_challenge, static_cast<std::uint8_t>(kChallengeLen),
                                       false, 0x00U, capdu, sizeof(capdu), &capdu_len);
        if (e != Error::Ok) {
            return e;
        }

        std::uint8_t rapdu[48]{};
        std::size_t rapdu_len = 0;
        e = t1.ExchangeInformation(capdu, capdu_len, rapdu, sizeof(rapdu), &rapdu_len, timeout_ms);
        if (e != Error::Ok) {
            return e;
        }
        if (rapdu_len < kInitUpdateRspMin) {
            return Error::Protocol;
        }
        const std::uint8_t sw1 = rapdu[rapdu_len - 2U];
        const std::uint8_t sw2 = rapdu[rapdu_len - 1U];
        if (sw1 != 0x90U || sw2 != 0x00U) {
            return Error::Protocol;
        }

        const std::uint8_t* card_challenge = rapdu + 13U;
        const std::uint8_t* card_cryptogram = rapdu + 21U;

        std::uint8_t senc[kAes128KeyLen]{};
        std::uint8_t smac[kAes128KeyLen]{};
        std::uint8_t srmac[kAes128KeyLen]{};
        if (!crypto::DeriveSessionKey(keys.host_static_key_enc, crypto::kDeriveSenc,
                                      keys.host_challenge, card_challenge, senc) ||
            !crypto::DeriveSessionKey(keys.host_static_key_cmac, crypto::kDeriveSmac,
                                      keys.host_challenge, card_challenge, smac) ||
            !crypto::DeriveSessionKey(keys.host_static_key_cmac, crypto::kDeriveSrmac,
                                      keys.host_challenge, card_challenge, srmac)) {
            return Error::InvalidArgument;
        }

        std::uint8_t expect_card[kCryptogramLen]{};
        if (!crypto::ComputeCryptogram(smac, crypto::kDeriveCardCryptogram, keys.host_challenge,
                                       card_challenge, expect_card) ||
            std::memcmp(expect_card, card_cryptogram, kCryptogramLen) != 0) {
            return Error::Protocol;
        }

        std::uint8_t host_cryptogram[kCryptogramLen]{};
        if (!crypto::ComputeCryptogram(smac, crypto::kDeriveHostCryptogram, keys.host_challenge,
                                       card_challenge, host_cryptogram)) {
            return Error::InvalidArgument;
        }

        std::uint8_t ext[32]{};
        ext[0] = kClaGpSecure;
        ext[1] = kInsExternalAuthenticate;
        ext[2] = kSecLevelCmacCencRmacRenc;
        ext[3] = 0x00U;
        ext[4] = 0x10U;
        std::memcpy(ext + 5, host_cryptogram, kCryptogramLen);

        std::uint8_t mcv[16]{};
        std::uint8_t mac_in[16 + 13]{};
        std::memcpy(mac_in, mcv, 16);
        std::memcpy(mac_in + 16, ext, 13);
        std::uint8_t mac_full[16]{};
        crypto::Aes128Cmac(smac, mac_in, 16U + 13U, mac_full);
        std::memcpy(ext + 13, mac_full, kCryptogramLen);
        const std::size_t ext_len = 5U + 2U * kCryptogramLen;

        std::uint8_t ext_rapdu[16]{};
        std::size_t ext_rapdu_len = 0;
        e = t1.ExchangeInformation(ext, ext_len, ext_rapdu, sizeof(ext_rapdu), &ext_rapdu_len,
                                   timeout_ms);
        if (e != Error::Ok) {
            return e;
        }
        if (ext_rapdu_len < 2U || ext_rapdu[ext_rapdu_len - 2U] != 0x90U ||
            ext_rapdu[ext_rapdu_len - 1U] != 0x00U) {
            return Error::Protocol;
        }

        std::memcpy(st_.senc, senc, kAes128KeyLen);
        std::memcpy(st_.smac, smac, kAes128KeyLen);
        std::memcpy(st_.srmac, srmac, kAes128KeyLen);
        std::memcpy(st_.mcv, mac_full, 16);
        std::memset(st_.counter, 0, sizeof(st_.counter));
        st_.counter[15] = 0x01U;
        st_.open = true;
        return Error::Ok;
    }

    [[nodiscard]] Error Close() noexcept {
        st_.open = false;
        return Error::Ok;
    }

    [[nodiscard]] bool IsOpen() const noexcept { return st_.open; }

    [[nodiscard]] Error WrapCommand(const std::uint8_t* capdu, std::size_t capdu_len,
                                    std::uint8_t* out, std::size_t out_cap,
                                    std::size_t* out_len) noexcept {
        return se050::scp03::WrapCommand(st_, capdu, capdu_len, out, out_cap, out_len);
    }

    [[nodiscard]] Error UnwrapResponse(const std::uint8_t* rapdu, std::size_t rapdu_len,
                                       std::uint8_t* out, std::size_t out_cap,
                                       std::size_t* out_len) noexcept {
        return se050::scp03::UnwrapResponse(st_, rapdu, rapdu_len, out, out_cap, out_len);
    }

    [[nodiscard]] ChannelState& State() noexcept { return st_; }
    [[nodiscard]] const ChannelState& State() const noexcept { return st_; }

private:
    ChannelState st_{};
};

}  // namespace se050::scp03
