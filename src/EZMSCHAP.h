/*
 * libEZRadius
 *
 * Copyright (c) 2023-2026 Mojtaba Kahvand.
 * All rights reserved.
 *
 * Licensed under the GNU Lesser General Public License v2.1.
 * See LICENSE for details.
 */

#ifndef EZMSCHAP_H
#define EZMSCHAP_H
// Microsoft CHAP support: MS-CHAPv1 (RFC 2433), MS-CHAPv2 (RFC 2759), RADIUS attributes (RFC 2548),
// MPPE keys (RFC 3079). Needs BoringSSL (EZRADIUS_HAS_CRYPTO).
#ifdef EZRADIUS_HAS_CRYPTO

#include "RadiusPacket.h"
#include <cstdint>
#include <string>

// Microsoft vendor attributes (vendor id 311)
enum : uint32_t { D_VENDOR_MICROSOFT = 311 };
enum MSVendorAttribute : unsigned char {
    MS_CHAP_RESPONSE = 1,
    MS_CHAP_ERROR = 2,
    MS_CHAP_DOMAIN = 10,
    MS_CHAP_CHALLENGE = 11,
    MS_MPPE_ENCRYPTION_POLICY = 7,
    MS_MPPE_ENCRYPTION_TYPES = 8,
    MS_MPPE_SEND_KEY = 16,
    MS_MPPE_RECV_KEY = 17,
    MS_CHAP2_RESPONSE = 25,
    MS_CHAP2_SUCCESS = 26
};

// Result of a successful server side MS-CHAPv2 verification
struct EZMSCHAPv2Result
{
    uint8_t ident = 0;
    std::string authenticatorResponse;      // "S=<40 hex>" (put it in MS-CHAP2-Success)
    uint8_t mppeSendKey[16] = {0};          // value for MS-MPPE-Send-Key (NAS -> peer)
    uint8_t mppeRecvKey[16] = {0};          // value for MS-MPPE-Recv-Key (peer -> NAS)
};

class EZMSCHAP
{
public:
    // ---- primitives (RFC 2759 / RFC 2433 / RFC 3079) ----
    // password: UTF-8 text
    static void NtPasswordHash(const std::string &passwordUtf8, uint8_t out[16]);
    static void HashNtPasswordHash(const uint8_t hash[16], uint8_t out[16]);
    // user name without the "DOMAIN\" prefix (as needed by ChallengeHash)
    static std::string StripDomain(const std::string &userName);
    static void ChallengeHash(const uint8_t peerChallenge[16], const uint8_t authChallenge[16],
                              const std::string &userName, uint8_t out[8]);
    // 8 byte challenge + NT hash -> 24 byte response (3 DES encryptions)
    static void ChallengeResponse(const uint8_t challenge[8], const uint8_t ntHash[16], uint8_t out[24]);
    static void GenerateNTResponseV2(const uint8_t authChallenge[16], const uint8_t peerChallenge[16],
                                     const std::string &userName, const uint8_t ntHash[16], uint8_t out[24]);
    // "S=<40 hex uppercase>"
    static std::string AuthenticatorResponseV2(const uint8_t ntHash[16], const uint8_t ntResponse[24],
                                               const uint8_t peerChallenge[16], const uint8_t authChallenge[16],
                                               const std::string &userName);
    static void MppeMasterKey(const uint8_t hashHash[16], const uint8_t ntResponse[24], uint8_t out[16]);
    // server side keys: sendKey = MS-MPPE-Send-Key value, recvKey = MS-MPPE-Recv-Key value
    static void MppeSessionKeys(const uint8_t masterKey[16], uint8_t sendKey[16], uint8_t recvKey[16]);

    // RFC 2548 section 2.4.2 encryption of a key attribute value (Salt + encrypted key, 34 bytes)
    // Any key length 1..238 (EAP uses 32 byte keys). Returns an empty string for an invalid length.
    static std::string EncodeMppeKey(const uint8_t *key, size_t keyLen, const void *secret, size_t secretLen, const uint8_t requestAuthenticator[16]);
    static bool DecodeMppeKey(const std::string &value, const void *secret, size_t secretLen, const uint8_t requestAuthenticator[16], std::string &key);
    static std::string EncodeMppeKey(const uint8_t key[16], const void *secret, size_t secretLen, const uint8_t requestAuthenticator[16]);
    static bool DecodeMppeKey(const std::string &value, const void *secret, size_t secretLen, const uint8_t requestAuthenticator[16], uint8_t key[16]);

    // ---- server side: verify the MS-CHAP attributes of an Access-Request ----
    // password: plain text. false: no MS-CHAPv2 attributes / malformed / wrong password
    static bool VerifyV2(RadiusPacket &request, const std::string &passwordUtf8, EZMSCHAPv2Result &result);
    // same with a stored NT hash (MD4 of the UTF-16LE password)
    static bool VerifyV2WithNtHash(RadiusPacket &request, const uint8_t ntHash[16], EZMSCHAPv2Result &result);
    // MS-CHAPv1 (NT response only; LM responses are not supported)
    static bool VerifyV1(RadiusPacket &request, const std::string &passwordUtf8);
    static bool VerifyV1WithNtHash(RadiusPacket &request, const uint8_t ntHash[16]);

    // which MS-CHAP flavour does the request use
    enum Kind { NONE, V1, V2 };
    static Kind Detect(RadiusPacket &request);

    // value of MS-CHAP-Error: "E=691 R=<retry> C=<32 hex challenge> V=3 M=<message>" with the ident first
    static std::string MakeErrorValue(uint8_t ident, int errorCode, bool retryAllowed, const char *message);
};

#endif // EZRADIUS_HAS_CRYPTO
#endif // EZMSCHAP_H
