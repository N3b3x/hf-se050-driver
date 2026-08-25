/**
 * @file se050_scp03_crypto.hpp
 * @brief Host AES-128 / RFC 4493 CMAC / GlobalPlatform SCP03 KDF (header-only).
 *
 * @details This is the host-side primitive set the SE050 T=1 stack needs so
 *          I²C1 can run an authenticated SCP03 channel. It is **not** NXP
 *          Plug & Trust and does **not** contain NXP default platform keys.
 *
 *          Derivation layout matches GP Card Spec Amendment D (label || 00 ||
 *          L || counter || host_challenge || card_challenge).
 *
 * @copyright Copyright (c) 2026 HardFOC. All rights reserved.
 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace se050::scp03::crypto {

inline constexpr std::size_t kAes128KeyLen = 16U;
inline constexpr std::size_t kCmacLen = 16U;
inline constexpr std::size_t kChallengeLen = 8U;
inline constexpr std::size_t kCryptogramLen = 8U;
inline constexpr std::size_t kLabelLen = 12U;

inline constexpr std::uint8_t kDeriveCardCryptogram = 0x00U;
inline constexpr std::uint8_t kDeriveHostCryptogram = 0x01U;
inline constexpr std::uint8_t kDeriveSenc = 0x04U;
inline constexpr std::uint8_t kDeriveSmac = 0x06U;
inline constexpr std::uint8_t kDeriveSrmac = 0x07U;
inline constexpr std::uint8_t kKdfCounter = 0x01U;
inline constexpr std::uint16_t kLen128Bit = 0x0080U;
inline constexpr std::uint16_t kLen64Bit = 0x0040U;

inline constexpr std::uint8_t kSbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16};

inline constexpr std::uint8_t kInvSbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e,
    0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32,
    0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49,
    0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50,
    0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05,
    0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41,
    0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8,
    0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b,
    0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59,
    0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d,
    0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63,
    0x55, 0x21, 0x0c, 0x7d};

inline constexpr std::uint8_t kRcon[10] = {0x01, 0x02, 0x04, 0x08, 0x10,
                                           0x20, 0x40, 0x80, 0x1b, 0x36};

inline void AddRoundKey(std::uint8_t s[16], const std::uint8_t* rk) {
  for (int i = 0; i < 16; ++i) {
    s[i] = static_cast<std::uint8_t>(s[i] ^ rk[i]);
  }
}

inline void SubBytes(std::uint8_t s[16]) {
  for (int i = 0; i < 16; ++i) {
    s[i] = kSbox[s[i]];
  }
}

inline void InvSubBytes(std::uint8_t s[16]) {
  for (int i = 0; i < 16; ++i) {
    s[i] = kInvSbox[s[i]];
  }
}

inline void ShiftRows(std::uint8_t s[16]) {
  std::uint8_t t = s[1];
  s[1] = s[5];
  s[5] = s[9];
  s[9] = s[13];
  s[13] = t;
  t = s[2];
  s[2] = s[10];
  s[10] = t;
  t = s[6];
  s[6] = s[14];
  s[14] = t;
  t = s[3];
  s[3] = s[15];
  s[15] = s[11];
  s[11] = s[7];
  s[7] = t;
}

inline void InvShiftRows(std::uint8_t s[16]) {
  std::uint8_t t = s[13];
  s[13] = s[9];
  s[9] = s[5];
  s[5] = s[1];
  s[1] = t;
  t = s[2];
  s[2] = s[10];
  s[10] = t;
  t = s[6];
  s[6] = s[14];
  s[14] = t;
  t = s[3];
  s[3] = s[7];
  s[7] = s[11];
  s[11] = s[15];
  s[15] = t;
}

inline std::uint8_t Xtime(std::uint8_t x) {
  return static_cast<std::uint8_t>((x << 1) ^ ((x & 0x80u) ? 0x1bu : 0u));
}

inline std::uint8_t Gmul(std::uint8_t a, std::uint8_t b) {
  std::uint8_t p = 0;
  for (int i = 0; i < 8; ++i) {
    if ((b & 1U) != 0U) {
      p = static_cast<std::uint8_t>(p ^ a);
    }
    const std::uint8_t hi = static_cast<std::uint8_t>(a & 0x80U);
    a = static_cast<std::uint8_t>(a << 1);
    if (hi != 0U) {
      a = static_cast<std::uint8_t>(a ^ 0x1bU);
    }
    b = static_cast<std::uint8_t>(b >> 1);
  }
  return p;
}

inline void MixColumns(std::uint8_t s[16]) {
  for (int c = 0; c < 4; ++c) {
    std::uint8_t* col = s + 4 * c;
    const std::uint8_t a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
    const std::uint8_t t = static_cast<std::uint8_t>(a0 ^ a1 ^ a2 ^ a3);
    col[0] = static_cast<std::uint8_t>(a0 ^ t ^ Xtime(static_cast<std::uint8_t>(a0 ^ a1)));
    col[1] = static_cast<std::uint8_t>(a1 ^ t ^ Xtime(static_cast<std::uint8_t>(a1 ^ a2)));
    col[2] = static_cast<std::uint8_t>(a2 ^ t ^ Xtime(static_cast<std::uint8_t>(a2 ^ a3)));
    col[3] = static_cast<std::uint8_t>(a3 ^ t ^ Xtime(static_cast<std::uint8_t>(a3 ^ a0)));
  }
}

inline void InvMixColumns(std::uint8_t s[16]) {
  for (int c = 0; c < 4; ++c) {
    std::uint8_t* col = s + 4 * c;
    const std::uint8_t a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
    col[0] = static_cast<std::uint8_t>(Gmul(a0, 0x0e) ^ Gmul(a1, 0x0b) ^
                                      Gmul(a2, 0x0d) ^ Gmul(a3, 0x09));
    col[1] = static_cast<std::uint8_t>(Gmul(a0, 0x09) ^ Gmul(a1, 0x0e) ^
                                      Gmul(a2, 0x0b) ^ Gmul(a3, 0x0d));
    col[2] = static_cast<std::uint8_t>(Gmul(a0, 0x0d) ^ Gmul(a1, 0x09) ^
                                      Gmul(a2, 0x0e) ^ Gmul(a3, 0x0b));
    col[3] = static_cast<std::uint8_t>(Gmul(a0, 0x0b) ^ Gmul(a1, 0x0d) ^
                                      Gmul(a2, 0x09) ^ Gmul(a3, 0x0e));
  }
}

inline void ExpandKey(const std::uint8_t key[16], std::uint8_t rk[176]) {
  std::memcpy(rk, key, 16);
  for (int i = 4; i < 44; ++i) {
    std::uint8_t tmp[4] = {rk[4 * (i - 1)], rk[4 * (i - 1) + 1],
                           rk[4 * (i - 1) + 2], rk[4 * (i - 1) + 3]};
    if ((i % 4) == 0) {
      const std::uint8_t t0 = tmp[0];
      tmp[0] = static_cast<std::uint8_t>(kSbox[tmp[1]] ^ kRcon[i / 4 - 1]);
      tmp[1] = kSbox[tmp[2]];
      tmp[2] = kSbox[tmp[3]];
      tmp[3] = kSbox[t0];
    }
    rk[4 * i] = static_cast<std::uint8_t>(rk[4 * (i - 4)] ^ tmp[0]);
    rk[4 * i + 1] = static_cast<std::uint8_t>(rk[4 * (i - 4) + 1] ^ tmp[1]);
    rk[4 * i + 2] = static_cast<std::uint8_t>(rk[4 * (i - 4) + 2] ^ tmp[2]);
    rk[4 * i + 3] = static_cast<std::uint8_t>(rk[4 * (i - 4) + 3] ^ tmp[3]);
  }
}

inline void Aes128EncryptBlock(const std::uint8_t key[kAes128KeyLen],
                               const std::uint8_t in[16],
                               std::uint8_t out[16]) {
  std::uint8_t rk[176];
  ExpandKey(key, rk);
  std::uint8_t s[16];
  std::memcpy(s, in, 16);
  AddRoundKey(s, rk);
  for (int round = 1; round < 10; ++round) {
    SubBytes(s);
    ShiftRows(s);
    MixColumns(s);
    AddRoundKey(s, rk + 16 * round);
  }
  SubBytes(s);
  ShiftRows(s);
  AddRoundKey(s, rk + 160);
  std::memcpy(out, s, 16);
}

inline void Aes128DecryptBlock(const std::uint8_t key[kAes128KeyLen],
                               const std::uint8_t in[16],
                               std::uint8_t out[16]) {
  std::uint8_t rk[176];
  ExpandKey(key, rk);
  std::uint8_t s[16];
  std::memcpy(s, in, 16);
  AddRoundKey(s, rk + 160);
  for (int round = 9; round >= 1; --round) {
    InvShiftRows(s);
    InvSubBytes(s);
    AddRoundKey(s, rk + 16 * round);
    InvMixColumns(s);
  }
  InvShiftRows(s);
  InvSubBytes(s);
  AddRoundKey(s, rk);
  std::memcpy(out, s, 16);
}

inline void XorBlock(std::uint8_t* a, const std::uint8_t* b) {
  for (int i = 0; i < 16; ++i) {
    a[i] = static_cast<std::uint8_t>(a[i] ^ b[i]);
  }
}

inline void LeftShift1(std::uint8_t in[16]) {
  std::uint8_t overflow = 0;
  for (int i = 15; i >= 0; --i) {
    const std::uint8_t next = static_cast<std::uint8_t>(in[i] >> 7);
    in[i] = static_cast<std::uint8_t>((in[i] << 1) | overflow);
    overflow = next;
  }
}

inline void GenerateSubkeys(const std::uint8_t key[16], std::uint8_t k1[16],
                            std::uint8_t k2[16]) {
  std::uint8_t L[16]{};
  std::uint8_t z[16]{};
  Aes128EncryptBlock(key, z, L);
  const std::uint8_t msb = static_cast<std::uint8_t>(L[0] >> 7);
  std::memcpy(k1, L, 16);
  LeftShift1(k1);
  if (msb) {
    k1[15] = static_cast<std::uint8_t>(k1[15] ^ 0x87u);
  }
  const std::uint8_t msb1 = static_cast<std::uint8_t>(k1[0] >> 7);
  std::memcpy(k2, k1, 16);
  LeftShift1(k2);
  if (msb1) {
    k2[15] = static_cast<std::uint8_t>(k2[15] ^ 0x87u);
  }
}

inline void Aes128Cmac(const std::uint8_t key[kAes128KeyLen],
                       const std::uint8_t* msg, std::size_t msg_len,
                       std::uint8_t out[kCmacLen]) {
  std::uint8_t k1[16], k2[16];
  GenerateSubkeys(key, k1, k2);
  const std::size_t n = (msg_len == 0) ? 1 : ((msg_len + 15) / 16);
  const bool complete = (msg_len != 0) && ((msg_len % 16) == 0);
  std::uint8_t x[16]{};
  std::uint8_t block[16]{};
  for (std::size_t i = 1; i < n; ++i) {
    std::memcpy(block, msg + 16 * (i - 1), 16);
    XorBlock(block, x);
    Aes128EncryptBlock(key, block, x);
  }
  std::memset(block, 0, 16);
  const std::size_t last_off = (n - 1) * 16;
  const std::size_t last_len = (msg_len == 0) ? 0 : (msg_len - last_off);
  if (complete) {
    std::memcpy(block, msg + last_off, 16);
    XorBlock(block, k1);
  } else {
    if (msg != nullptr && last_len != 0) {
      std::memcpy(block, msg + last_off, last_len);
    }
    block[last_len] = 0x80;
    XorBlock(block, k2);
  }
  XorBlock(block, x);
  Aes128EncryptBlock(key, block, out);
}

/** @brief GP Amendment D derivation input (label || 00 || L || i || context). */
inline bool FillDerivationData(std::uint8_t constant, std::uint16_t bit_len,
                               std::uint8_t counter, const std::uint8_t* context,
                               std::uint16_t context_len, std::uint8_t* out,
                               std::size_t out_cap, std::size_t* out_len) {
  if (out == nullptr || out_len == nullptr) {
    return false;
  }
  const std::size_t need = kLabelLen + 4U + context_len;
  if (need > out_cap) {
    return false;
  }
  std::memset(out, 0, kLabelLen - 1U);
  out[kLabelLen - 1U] = constant;
  out[kLabelLen] = 0x00U;
  out[kLabelLen + 1U] = static_cast<std::uint8_t>((bit_len >> 8) & 0xFFU);
  out[kLabelLen + 2U] = static_cast<std::uint8_t>(bit_len & 0xFFU);
  out[kLabelLen + 3U] = counter;
  if (context_len != 0U && context != nullptr) {
    std::memcpy(out + kLabelLen + 4U, context, context_len);
  }
  *out_len = need;
  return true;
}

inline bool DeriveSessionKey(const std::uint8_t static_key[kAes128KeyLen],
                             std::uint8_t constant,
                             const std::uint8_t host_challenge[kChallengeLen],
                             const std::uint8_t card_challenge[kChallengeLen],
                             std::uint8_t out_key[kAes128KeyLen]) {
  if (static_key == nullptr || host_challenge == nullptr ||
      card_challenge == nullptr || out_key == nullptr) {
    return false;
  }
  std::uint8_t context[16];
  std::memcpy(context, host_challenge, kChallengeLen);
  std::memcpy(context + kChallengeLen, card_challenge, kChallengeLen);
  std::uint8_t dd[32];
  std::size_t dd_len = 0;
  if (!FillDerivationData(constant, kLen128Bit, kKdfCounter, context,
                          sizeof(context), dd, sizeof(dd), &dd_len)) {
    return false;
  }
  Aes128Cmac(static_key, dd, dd_len, out_key);
  return true;
}

inline bool ComputeCryptogram(const std::uint8_t session_mac_key[kAes128KeyLen],
                              std::uint8_t constant,
                              const std::uint8_t host_challenge[kChallengeLen],
                              const std::uint8_t card_challenge[kChallengeLen],
                              std::uint8_t out8[kCryptogramLen]) {
  if (session_mac_key == nullptr || host_challenge == nullptr ||
      card_challenge == nullptr || out8 == nullptr) {
    return false;
  }
  std::uint8_t context[16];
  std::memcpy(context, host_challenge, kChallengeLen);
  std::memcpy(context + kChallengeLen, card_challenge, kChallengeLen);
  std::uint8_t dd[32];
  std::size_t dd_len = 0;
  if (!FillDerivationData(constant, kLen64Bit, kKdfCounter, context,
                          sizeof(context), dd, sizeof(dd), &dd_len)) {
    return false;
  }
  std::uint8_t full[kCmacLen];
  Aes128Cmac(session_mac_key, dd, dd_len, full);
  std::memcpy(out8, full, kCryptogramLen);
  return true;
}

inline bool Aes128CbcEncrypt(const std::uint8_t key[kAes128KeyLen],
                             const std::uint8_t iv[16], const std::uint8_t* src,
                             std::uint8_t* dst, std::size_t len) {
  if (key == nullptr || iv == nullptr || src == nullptr || dst == nullptr ||
      (len % 16U) != 0U) {
    return false;
  }
  std::uint8_t chain[16];
  std::memcpy(chain, iv, 16);
  for (std::size_t off = 0; off < len; off += 16U) {
    std::uint8_t block[16];
    std::memcpy(block, src + off, 16);
    XorBlock(block, chain);
    Aes128EncryptBlock(key, block, dst + off);
    std::memcpy(chain, dst + off, 16);
  }
  return true;
}

inline bool Aes128CbcDecrypt(const std::uint8_t key[kAes128KeyLen],
                             const std::uint8_t iv[16], const std::uint8_t* src,
                             std::uint8_t* dst, std::size_t len) {
  if (key == nullptr || iv == nullptr || src == nullptr || dst == nullptr ||
      (len % 16U) != 0U) {
    return false;
  }
  std::uint8_t chain[16];
  std::memcpy(chain, iv, 16);
  for (std::size_t off = 0; off < len; off += 16U) {
    std::uint8_t cipher[16];
    std::memcpy(cipher, src + off, 16);
    std::uint8_t plain[16];
    Aes128DecryptBlock(key, cipher, plain);
    XorBlock(plain, chain);
    std::memcpy(dst + off, plain, 16);
    std::memcpy(chain, cipher, 16);
  }
  return true;
}

inline bool IsoPad80(std::uint8_t* buf, std::size_t* len, std::size_t cap) {
  if (buf == nullptr || len == nullptr) {
    return false;
  }
  if (*len >= cap) {
    return false;
  }
  buf[(*len)++] = 0x80U;
  while ((*len % 16U) != 0U) {
    if (*len >= cap) {
      return false;
    }
    buf[(*len)++] = 0x00U;
  }
  return true;
}

inline bool StaticKeysUsable(const std::uint8_t* enc, std::size_t enc_len,
                             const std::uint8_t* mac, std::size_t mac_len) {
  return enc != nullptr && mac != nullptr && enc_len == kAes128KeyLen &&
         mac_len == kAes128KeyLen;
}

/** @brief Streaming AES-128-CMAC (RFC 4493) — no concatenated MAC buffer. */
struct Cmac {
  std::uint8_t key[kAes128KeyLen]{};
  std::uint8_t x[16]{};
  std::uint8_t buf[16]{};
  std::size_t buf_len{0};
  std::size_t total{0};
};

inline void CmacStart(Cmac& c, const std::uint8_t key[kAes128KeyLen]) {
  std::memcpy(c.key, key, kAes128KeyLen);
  std::memset(c.x, 0, 16);
  std::memset(c.buf, 0, 16);
  c.buf_len = 0;
  c.total = 0;
}

inline void CmacUpdate(Cmac& c, const std::uint8_t* data, std::size_t len) {
  if (data == nullptr && len != 0U) {
    return;
  }
  while (len > 0U) {
    if (c.buf_len < 16U) {
      const std::size_t take = (16U - c.buf_len) < len ? (16U - c.buf_len) : len;
      std::memcpy(c.buf + c.buf_len, data, take);
      c.buf_len += take;
      c.total += take;
      data += take;
      len -= take;
    }
    if (c.buf_len == 16U && len > 0U) {
      XorBlock(c.buf, c.x);
      Aes128EncryptBlock(c.key, c.buf, c.x);
      c.buf_len = 0;
    }
  }
}

inline void CmacFinish(Cmac& c, std::uint8_t out[kCmacLen]) {
  std::uint8_t k1[16], k2[16];
  GenerateSubkeys(c.key, k1, k2);
  std::uint8_t block[16]{};
  if (c.total == 0U) {
    block[0] = 0x80U;
    XorBlock(block, k2);
  } else if (c.buf_len == 16U) {
    std::memcpy(block, c.buf, 16);
    XorBlock(block, k1);
  } else {
    std::memcpy(block, c.buf, c.buf_len);
    block[c.buf_len] = 0x80U;
    XorBlock(block, k2);
  }
  XorBlock(block, c.x);
  Aes128EncryptBlock(c.key, block, out);
}

/** @brief Command ICV = AES-ECB(SENC, counter). CBC with IV=0 of one block. */
inline void CommandIcv(const std::uint8_t senc[kAes128KeyLen],
                       const std::uint8_t counter[16], std::uint8_t icv[16]) {
  Aes128EncryptBlock(senc, counter, icv);
}

/** @brief Response ICV: counter with MSB 0x80, then AES-ECB(SENC, ·). */
inline void ResponseIcv(const std::uint8_t senc[kAes128KeyLen],
                        const std::uint8_t counter[16], std::uint8_t icv[16]) {
  std::uint8_t padded[16];
  std::memcpy(padded, counter, 16);
  padded[0] = 0x80U;
  Aes128EncryptBlock(senc, padded, icv);
}

inline void IncCommandCounter(std::uint8_t counter[16]) {
  for (int i = 15; i > 0; --i) {
    if (counter[i] < 0xFFU) {
      ++counter[i];
      return;
    }
    counter[i] = 0;
  }
}

inline bool IsoUnpad80(const std::uint8_t* padded, std::size_t padded_len,
                       std::size_t* plain_len) {
  if (padded == nullptr || plain_len == nullptr || padded_len < 16U ||
      (padded_len % 16U) != 0U) {
    return false;
  }
  std::size_t i = padded_len;
  while (i > (padded_len - 16U) && i > 0U) {
    if (padded[i - 1U] == 0x00U) {
      --i;
      continue;
    }
    if (padded[i - 1U] == 0x80U) {
      *plain_len = i - 1U;
      return true;
    }
    return false;
  }
  return false;
}

}  // namespace se050::scp03::crypto
