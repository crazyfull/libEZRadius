#ifndef EZCRYPTO_H
#define EZCRYPTO_H
// Cryptographic primitives used by the optional protocol extensions (MS-CHAP, later EAP / EAP-TLS).
// Implemented with BoringSSL (build option EZRADIUS_ENABLE_CRYPTO, define EZRADIUS_HAS_CRYPTO).
// The core RADIUS protocol (PAP, CHAP, authenticators, Message-Authenticator) does not need it.
#ifdef EZRADIUS_HAS_CRYPTO

#include <cstddef>
#include <cstdint>
#include <string>

class EZCrypto
{
public:
    static const size_t MD4_SIZE = 16;
    static const size_t MD5_SIZE = 16;
    static const size_t SHA1_SIZE = 20;
    static const size_t SHA256_SIZE = 32;

    static void MD4(const void *data, size_t len, uint8_t out[16]);
    static void MD5(const void *data, size_t len, uint8_t out[16]);
    static void SHA1(const void *data, size_t len, uint8_t out[20]);
    static void SHA256(const void *data, size_t len, uint8_t out[32]);

    // SHA-1 over several buffers (parts[i], lens[i], count)
    static void SHA1Multi(const void *const *parts, const size_t *lens, size_t count, uint8_t out[20]);

    static void HMAC_MD5(const void *key, size_t keyLen, const void *data, size_t len, uint8_t out[16]);
    static void HMAC_SHA256(const void *key, size_t keyLen, const void *data, size_t len, uint8_t out[32]);

    // single DES block (ECB) with a 7 byte key (parity bits are generated), as used by MS-CHAP
    static void DESEncryptBlock7(const uint8_t key7[7], const uint8_t in[8], uint8_t out[8]);

    // cryptographically secure random bytes
    static bool Random(void *buf, size_t len);

    // constant time comparison
    static bool Equal(const void *a, const void *b, size_t len);

    // wipe memory (not optimized away)
    static void Wipe(void *buf, size_t len);

    static std::string ToHex(const void *data, size_t len, bool upper = false);
};

#endif // EZRADIUS_HAS_CRYPTO
#endif // EZCRYPTO_H
