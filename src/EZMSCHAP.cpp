#include "EZMSCHAP.h"
#ifdef EZRADIUS_HAS_CRYPTO

#include "EZCrypto.h"
#include "EZVendor.h"
#include <cstring>

// ---------------------------------------------------------------------------------------------
// UTF-8 -> UTF-16LE (invalid sequences are replaced with U+FFFD)
static std::string utf8ToUtf16le(const std::string &in)
{
    std::string out;
    out.reserve(in.size() * 2);
    auto put = [&out](uint32_t cp){
        if(cp >= 0x10000){
            cp -= 0x10000;
            uint16_t hi = (uint16_t)(0xD800 + (cp >> 10)), lo = (uint16_t)(0xDC00 + (cp & 0x3ff));
            out.push_back((char)(hi & 0xff)); out.push_back((char)(hi >> 8));
            out.push_back((char)(lo & 0xff)); out.push_back((char)(lo >> 8));
        }else{
            out.push_back((char)(cp & 0xff)); out.push_back((char)(cp >> 8));
        }
    };

    size_t i = 0;
    while(i < in.size()){
        const unsigned char c = (unsigned char)in[i];
        uint32_t cp = 0xFFFD;
        size_t n = 1;
        if(c < 0x80){ cp = c; }
        else if((c & 0xE0) == 0xC0 && i + 1 < in.size() && ((unsigned char)in[i+1] & 0xC0) == 0x80){
            cp = ((c & 0x1F) << 6) | ((unsigned char)in[i+1] & 0x3F); n = 2;
            if(cp < 0x80) cp = 0xFFFD;
        }else if((c & 0xF0) == 0xE0 && i + 2 < in.size() && ((unsigned char)in[i+1] & 0xC0) == 0x80 && ((unsigned char)in[i+2] & 0xC0) == 0x80){
            cp = ((c & 0x0F) << 12) | (((unsigned char)in[i+1] & 0x3F) << 6) | ((unsigned char)in[i+2] & 0x3F); n = 3;
            if(cp < 0x800 || (cp >= 0xD800 && cp <= 0xDFFF)) cp = 0xFFFD;
        }else if((c & 0xF8) == 0xF0 && i + 3 < in.size() && ((unsigned char)in[i+1] & 0xC0) == 0x80 && ((unsigned char)in[i+2] & 0xC0) == 0x80 && ((unsigned char)in[i+3] & 0xC0) == 0x80){
            cp = ((c & 0x07) << 18) | (((unsigned char)in[i+1] & 0x3F) << 12) | (((unsigned char)in[i+2] & 0x3F) << 6) | ((unsigned char)in[i+3] & 0x3F); n = 4;
            if(cp < 0x10000 || cp > 0x10FFFF) cp = 0xFFFD;
        }
        put(cp);
        i += n;
    }
    return out;
}

void EZMSCHAP::NtPasswordHash(const std::string &passwordUtf8, uint8_t out[16])
{
    std::string u = utf8ToUtf16le(passwordUtf8);
    EZCrypto::MD4(u.data(), u.size(), out);
    EZCrypto::Wipe(&u[0], u.size());
}

void EZMSCHAP::HashNtPasswordHash(const uint8_t hash[16], uint8_t out[16])
{
    EZCrypto::MD4(hash, 16, out);
}

std::string EZMSCHAP::StripDomain(const std::string &userName)
{
    size_t p = userName.find_last_of('\\');
    return p == std::string::npos ? userName : userName.substr(p + 1);
}

void EZMSCHAP::ChallengeHash(const uint8_t peer[16], const uint8_t auth[16], const std::string &userName, uint8_t out[8])
{
    const std::string name = StripDomain(userName);
    const void *parts[3] = { peer, auth, name.data() };
    const size_t lens[3] = { 16, 16, name.size() };
    uint8_t digest[20];
    EZCrypto::SHA1Multi(parts, lens, 3, digest);
    memcpy(out, digest, 8);
}

void EZMSCHAP::ChallengeResponse(const uint8_t challenge[8], const uint8_t ntHash[16], uint8_t out[24])
{
    uint8_t z[21];
    memset(z, 0, sizeof(z));
    memcpy(z, ntHash, 16);
    for(int i = 0; i < 3; i++)
        EZCrypto::DESEncryptBlock7(z + i * 7, challenge, out + i * 8);
    EZCrypto::Wipe(z, sizeof(z));
}

void EZMSCHAP::GenerateNTResponseV2(const uint8_t auth[16], const uint8_t peer[16], const std::string &userName,
                                    const uint8_t ntHash[16], uint8_t out[24])
{
    uint8_t ch[8];
    ChallengeHash(peer, auth, userName, ch);
    ChallengeResponse(ch, ntHash, out);
}

std::string EZMSCHAP::AuthenticatorResponseV2(const uint8_t ntHash[16], const uint8_t ntResponse[24],
                                              const uint8_t peer[16], const uint8_t auth[16], const std::string &userName)
{
    static const char magic1[] = "Magic server to client signing constant";               // 39 bytes
    static const char magic2[] = "Pad to make it do more than one iteration";             // 41 bytes

    uint8_t hashHash[16];
    HashNtPasswordHash(ntHash, hashHash);

    uint8_t digest[20];
    {
        const void *parts[3] = { hashHash, ntResponse, magic1 };
        const size_t lens[3] = { 16, 24, sizeof(magic1) - 1 };
        EZCrypto::SHA1Multi(parts, lens, 3, digest);
    }
    uint8_t ch[8];
    ChallengeHash(peer, auth, userName, ch);
    uint8_t digest2[20];
    {
        const void *parts[3] = { digest, ch, magic2 };
        const size_t lens[3] = { 20, 8, sizeof(magic2) - 1 };
        EZCrypto::SHA1Multi(parts, lens, 3, digest2);
    }
    EZCrypto::Wipe(hashHash, sizeof(hashHash));
    return "S=" + EZCrypto::ToHex(digest2, 20, true);
}

void EZMSCHAP::MppeMasterKey(const uint8_t hashHash[16], const uint8_t ntResponse[24], uint8_t out[16])
{
    static const char magic1[] = "This is the MPPE Master Key";                           // 27 bytes
    const void *parts[3] = { hashHash, ntResponse, magic1 };
    const size_t lens[3] = { 16, 24, sizeof(magic1) - 1 };
    uint8_t digest[20];
    EZCrypto::SHA1Multi(parts, lens, 3, digest);
    memcpy(out, digest, 16);
}

void EZMSCHAP::MppeSessionKeys(const uint8_t master[16], uint8_t sendKey[16], uint8_t recvKey[16])
{
    static const char magic2[] = "On the client side, this is the send key; on the server side, it is the receive key.";
    static const char magic3[] = "On the client side, this is the receive key; on the server side, it is the send key.";
    uint8_t pad1[40], pad2[40];
    memset(pad1, 0x00, sizeof(pad1));
    memset(pad2, 0xF2, sizeof(pad2));

    auto derive = [&](const char *magic, size_t magicLen, uint8_t out[16]){
        const void *parts[4] = { master, pad1, magic, pad2 };
        const size_t lens[4] = { 16, 40, magicLen, 40 };
        uint8_t digest[20];
        EZCrypto::SHA1Multi(parts, lens, 4, digest);
        memcpy(out, digest, 16);
    };
    // the NAS (server) sends with the key the client receives with
    derive(magic3, sizeof(magic3) - 1, sendKey);
    derive(magic2, sizeof(magic2) - 1, recvKey);
}

std::string EZMSCHAP::EncodeMppeKey(const uint8_t *key, size_t keyLen, const void *secret, size_t secretLen, const uint8_t ra[16])
{
    if(keyLen == 0 || keyLen > 238)        // the plain text (length byte + key + padding) must fit in 239 bytes
        return std::string();

    // Salt: random, most significant bit set
    uint8_t salt[2];
    EZCrypto::Random(salt, 2);
    salt[0] |= 0x80;

    const size_t blocks = (1 + keyLen + 15) / 16;
    std::string plain(blocks * 16, '\0');
    plain[0] = (char)keyLen;
    memcpy(&plain[1], key, keyLen);

    std::string out((const char*)salt, 2);
    uint8_t prev[16];
    for(size_t block = 0; block < blocks; block++){
        std::string in((const char*)secret, secretLen);
        if(block == 0){
            in.append((const char*)ra, 16);
            in.append((const char*)salt, 2);
        }else{
            in.append((const char*)prev, 16);
        }
        uint8_t b[16];
        EZCrypto::MD5(in.data(), in.size(), b);
        for(int i = 0; i < 16; i++)
            prev[i] = (uint8_t)plain[block * 16 + i] ^ b[i];
        out.append((const char*)prev, 16);
    }
    EZCrypto::Wipe(&plain[0], plain.size());
    return out;
}

std::string EZMSCHAP::EncodeMppeKey(const uint8_t key[16], const void *secret, size_t secretLen, const uint8_t ra[16])
{
    return EncodeMppeKey(key, 16, secret, secretLen, ra);
}

bool EZMSCHAP::DecodeMppeKey(const std::string &value, const void *secret, size_t secretLen, const uint8_t ra[16], std::string &key)
{
    key.clear();
    // Salt (2) + at least one 16 byte block, whole blocks only
    if(value.size() < 18 || (value.size() - 2) % 16 != 0)
        return false;

    const size_t blocks = (value.size() - 2) / 16;
    std::string plain(blocks * 16, '\0');
    const uint8_t *cipher = (const uint8_t*)value.data() + 2;
    uint8_t prevCipher[16];
    for(size_t block = 0; block < blocks; block++){
        std::string in((const char*)secret, secretLen);
        if(block == 0){
            in.append((const char*)ra, 16);
            in.append(value.data(), 2);
        }else{
            in.append((const char*)prevCipher, 16);
        }
        uint8_t b[16];
        EZCrypto::MD5(in.data(), in.size(), b);
        for(int i = 0; i < 16; i++)
            plain[block * 16 + i] = (char)(cipher[block * 16 + i] ^ b[i]);
        memcpy(prevCipher, cipher + block * 16, 16);
    }
    const size_t len = (uint8_t)plain[0];
    const bool ok = len >= 1 && len <= plain.size() - 1;
    if(ok)
        key.assign(plain, 1, len);
    EZCrypto::Wipe(&plain[0], plain.size());
    return ok;
}

bool EZMSCHAP::DecodeMppeKey(const std::string &value, const void *secret, size_t secretLen, const uint8_t ra[16], uint8_t key[16])
{
    std::string k;
    if(!DecodeMppeKey(value, secret, secretLen, ra, k) || k.size() != 16)
        return false;
    memcpy(key, k.data(), 16);
    EZCrypto::Wipe(&k[0], k.size());
    return true;
}

// ---------------------------------------------------------------------------------------------
EZMSCHAP::Kind EZMSCHAP::Detect(RadiusPacket &request)
{
    std::string v;
    if(ezvendor::find(request, D_VENDOR_MICROSOFT, MS_CHAP2_RESPONSE, v))
        return V2;
    if(ezvendor::find(request, D_VENDOR_MICROSOFT, MS_CHAP_RESPONSE, v))
        return V1;
    return NONE;
}

// MS-CHAP-Challenge, or the Request Authenticator when the attribute is absent (RFC 2548 section 2.1.1)
static bool getChallenge(RadiusPacket &request, size_t wanted, uint8_t *out)
{
    std::string c;
    if(ezvendor::find(request, D_VENDOR_MICROSOFT, MS_CHAP_CHALLENGE, c)){
        if(c.size() != wanted)
            return false;
        memcpy(out, c.data(), wanted);
        return true;
    }
    if(wanted > D_AUTHENTICATOR_LENGTH)
        return false;
    memcpy(out, request.getAuthenticator(), wanted);
    return true;
}

bool EZMSCHAP::VerifyV2(RadiusPacket &request, const std::string &passwordUtf8, EZMSCHAPv2Result &result)
{
    uint8_t h[16];
    NtPasswordHash(passwordUtf8, h);
    bool ok = VerifyV2WithNtHash(request, h, result);
    EZCrypto::Wipe(h, sizeof(h));
    return ok;
}

bool EZMSCHAP::VerifyV2WithNtHash(RadiusPacket &request, const uint8_t ntHash[16], EZMSCHAPv2Result &result)
{
    std::string resp;
    if(!ezvendor::find(request, D_VENDOR_MICROSOFT, MS_CHAP2_RESPONSE, resp) || resp.size() != 50)
        return false;

    uint8_t authChallenge[16];
    if(!getChallenge(request, 16, authChallenge))
        return false;

    const uint8_t *r = (const uint8_t*)resp.data();
    const uint8_t ident = r[0];
    const uint8_t *peer = r + 2;            // [1] = flags, [2..17] = peer challenge, [18..25] = reserved
    const uint8_t *ntResp = r + 26;

    const std::string user = request.getAttribute(USER_NAME).strValue;

    uint8_t expected[24];
    GenerateNTResponseV2(authChallenge, peer, user, ntHash, expected);
    if(!EZCrypto::Equal(expected, ntResp, 24))
        return false;

    result.ident = ident;
    result.authenticatorResponse = AuthenticatorResponseV2(ntHash, expected, peer, authChallenge, user);

    uint8_t hashHash[16], master[16];
    HashNtPasswordHash(ntHash, hashHash);
    MppeMasterKey(hashHash, expected, master);
    MppeSessionKeys(master, result.mppeSendKey, result.mppeRecvKey);
    EZCrypto::Wipe(hashHash, sizeof(hashHash));
    EZCrypto::Wipe(master, sizeof(master));
    return true;
}

bool EZMSCHAP::VerifyV1(RadiusPacket &request, const std::string &passwordUtf8)
{
    uint8_t h[16];
    NtPasswordHash(passwordUtf8, h);
    bool ok = VerifyV1WithNtHash(request, h);
    EZCrypto::Wipe(h, sizeof(h));
    return ok;
}

bool EZMSCHAP::VerifyV1WithNtHash(RadiusPacket &request, const uint8_t ntHash[16])
{
    std::string resp;
    if(!ezvendor::find(request, D_VENDOR_MICROSOFT, MS_CHAP_RESPONSE, resp) || resp.size() != 50)
        return false;

    uint8_t challenge[8];
    if(!getChallenge(request, 8, challenge))
        return false;

    const uint8_t *r = (const uint8_t*)resp.data();
    if(!(r[1] & 1))                         // flags: 1 = use the NT response (the LM response is not supported)
        return false;

    uint8_t expected[24];
    ChallengeResponse(challenge, ntHash, expected);
    return EZCrypto::Equal(expected, r + 26, 24);
}

std::string EZMSCHAP::MakeErrorValue(uint8_t ident, int errorCode, bool retryAllowed, const char *message)
{
    uint8_t c[16];
    EZCrypto::Random(c, sizeof(c));
    std::string s(1, (char)ident);
    s += "E=" + std::to_string(errorCode) + " R=" + (retryAllowed ? "1" : "0") + " C=" + EZCrypto::ToHex(c, 16, true) + " V=3";
    if(message && *message)
        s += std::string(" M=") + message;
    return s;
}

#endif
