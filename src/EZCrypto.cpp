#include "EZCrypto.h"
#ifdef EZRADIUS_HAS_CRYPTO

#include <openssl/des.h>
#include <openssl/hmac.h>
#include <openssl/md4.h>
#include <openssl/md5.h>
#include <openssl/mem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <cstring>

void EZCrypto::MD4(const void *data, size_t len, uint8_t out[16])
{
    ::MD4((const uint8_t*)data, len, out);
}

void EZCrypto::MD5(const void *data, size_t len, uint8_t out[16])
{
    ::MD5((const uint8_t*)data, len, out);
}

void EZCrypto::SHA1(const void *data, size_t len, uint8_t out[20])
{
    ::SHA1((const uint8_t*)data, len, out);
}

void EZCrypto::SHA256(const void *data, size_t len, uint8_t out[32])
{
    ::SHA256((const uint8_t*)data, len, out);
}

void EZCrypto::SHA1Multi(const void *const *parts, const size_t *lens, size_t count, uint8_t out[20])
{
    SHA_CTX ctx;
    SHA1_Init(&ctx);
    for(size_t i = 0; i < count; i++)
        SHA1_Update(&ctx, parts[i], lens[i]);
    SHA1_Final(out, &ctx);
}

void EZCrypto::HMAC_MD5(const void *key, size_t keyLen, const void *data, size_t len, uint8_t out[16])
{
    unsigned int outLen = 16;
    ::HMAC(EVP_md5(), key, keyLen, (const uint8_t*)data, len, out, &outLen);
}

void EZCrypto::HMAC_SHA256(const void *key, size_t keyLen, const void *data, size_t len, uint8_t out[32])
{
    unsigned int outLen = 32;
    ::HMAC(EVP_sha256(), key, keyLen, (const uint8_t*)data, len, out, &outLen);
}

void EZCrypto::DESEncryptBlock7(const uint8_t k[7], const uint8_t in[8], uint8_t out[8])
{
    // 56 bit key -> 64 bit DES key (7 bits per byte, the low bit is the parity bit)
    DES_cblock key;
    key.bytes[0] = k[0];
    key.bytes[1] = (uint8_t)(((k[0] << 7) & 0xff) | (k[1] >> 1));
    key.bytes[2] = (uint8_t)(((k[1] << 6) & 0xff) | (k[2] >> 2));
    key.bytes[3] = (uint8_t)(((k[2] << 5) & 0xff) | (k[3] >> 3));
    key.bytes[4] = (uint8_t)(((k[3] << 4) & 0xff) | (k[4] >> 4));
    key.bytes[5] = (uint8_t)(((k[4] << 3) & 0xff) | (k[5] >> 5));
    key.bytes[6] = (uint8_t)(((k[5] << 2) & 0xff) | (k[6] >> 6));
    key.bytes[7] = (uint8_t)((k[6] << 1) & 0xff);
    DES_set_odd_parity(&key);

    DES_key_schedule ks;
    DES_set_key_unchecked(&key, &ks);

    DES_cblock src, dst;
    memcpy(src.bytes, in, 8);
    DES_ecb_encrypt(&src, &dst, &ks, DES_ENCRYPT);
    memcpy(out, dst.bytes, 8);

    OPENSSL_cleanse(&key, sizeof(key));
    OPENSSL_cleanse(&ks, sizeof(ks));
}

bool EZCrypto::Random(void *buf, size_t len)
{
    return RAND_bytes((uint8_t*)buf, len) == 1;
}

bool EZCrypto::Equal(const void *a, const void *b, size_t len)
{
    return CRYPTO_memcmp(a, b, len) == 0;
}

void EZCrypto::Wipe(void *buf, size_t len)
{
    OPENSSL_cleanse(buf, len);
}

std::string EZCrypto::ToHex(const void *data, size_t len, bool upper)
{
    static const char lo[] = "0123456789abcdef";
    static const char up[] = "0123456789ABCDEF";
    const char *t = upper ? up : lo;
    std::string s;
    s.reserve(len * 2);
    for(size_t i = 0; i < len; i++){
        s.push_back(t[((const uint8_t*)data)[i] >> 4]);
        s.push_back(t[((const uint8_t*)data)[i] & 15]);
    }
    return s;
}

#endif
