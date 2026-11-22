// MD5 / HMAC-MD5 through BoringSSL (assembly implementations): faster than the portable code in md5.cpp.
// Kept in its own file because <openssl/md5.h> and md5.h both define MD5_CTX.
#ifdef EZRADIUS_HAS_CRYPTO
#include <openssl/digest.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>
#include <openssl/md5.h>
#include <string.h>
#include <stdint.h>

int EZ_MD5_Fast(unsigned char output[16], const unsigned char *input, uint32_t len)
{
    static const unsigned char empty = 0;
    MD5(input ? input : &empty, len, output);
    return 1;
}

// The first two MD5 blocks of an HMAC only depend on the key: a small per-thread cache keeps the prepared
// state of the most recently used secrets (one RADIUS server usually has few secrets), so every HMAC saves
// two of its compressions. Entries are overwritten, never freed: a secret stays in thread memory for the
// lifetime of the thread, like it does in RadiusSecret.
namespace {
struct HmacEntry
{
    bool used = false;
    uint32_t keyLen = 0;
    unsigned char key[256];
    HMAC_CTX ctx;
};
enum { CACHE_ENTRIES = 8 };
thread_local HmacEntry g_cache[CACHE_ENTRIES];
thread_local unsigned g_victim = 0;
}

int EZ_HMAC_MD5_Fast(unsigned char output[16], const unsigned char *key, uint32_t keyLen, const unsigned char *data, uint32_t dataLen)
{
    static const unsigned char empty = 0;
    if(!key)
        key = &empty;
    if(!data)
        data = &empty;
    unsigned int outLen = 16;
    if(keyLen == 0 || keyLen > sizeof(g_cache[0].key))
        return HMAC(EVP_md5(), key, keyLen, data, dataLen, output, &outLen) != nullptr;

    HmacEntry *e = nullptr;
    for(HmacEntry &c : g_cache){
        if(c.used && c.keyLen == keyLen && CRYPTO_memcmp(c.key, key, keyLen) == 0){
            e = &c;
            break;
        }
    }
    if(!e){
        e = &g_cache[g_victim++ % CACHE_ENTRIES];
        if(e->used)
            HMAC_CTX_cleanup(&e->ctx);
        HMAC_CTX_init(&e->ctx);
        if(!HMAC_Init_ex(&e->ctx, key, keyLen, EVP_md5(), nullptr)){
            e->used = false;
            return 0;
        }
        memcpy(e->key, key, keyLen);
        e->keyLen = keyLen;
        e->used = true;
    }
    HMAC_CTX work;
    HMAC_CTX_init(&work);
    int ok = HMAC_CTX_copy_ex(&work, &e->ctx) && HMAC_Update(&work, data, dataLen) && HMAC_Final(&work, output, &outLen);
    HMAC_CTX_cleanup(&work);
    return ok;
}
#endif
