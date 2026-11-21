#include "EZRadius11.h"
#ifdef EZRADIUS_HAS_TLS

#include "EZCrypto.h"
#include "EZMSCHAP.h"
#include <cstring>

namespace ezradius11 {
namespace {

enum : uint8_t { ATTR_USER_PASSWORD = 2, ATTR_VENDOR_SPECIFIC = 26, ATTR_MESSAGE_AUTHENTICATOR = 80,
                 MS_MPPE_SEND_KEY = 16, MS_MPPE_RECV_KEY = 17 };
const uint32_t VENDOR_MICROSOFT = 311;

// PAP password obfuscation (RFC 2865 section 5.2)
std::string passwordXor(const std::string &in, const std::string &secret, const uint8_t ra[16], bool encrypt)
{
    std::string out(in.size(), '\0');
    uint8_t prev[16];
    memcpy(prev, ra, 16);
    for(size_t pos = 0; pos < in.size(); pos += 16){
        std::string h = secret;
        h.append((const char*)prev, 16);
        uint8_t b[16];
        EZCrypto::MD5(h.data(), h.size(), b);
        for(int i = 0; i < 16; i++)
            out[pos + i] = (char)((uint8_t)in[pos + i] ^ b[i]);
        memcpy(prev, encrypt ? (const uint8_t*)out.data() + pos : (const uint8_t*)in.data() + pos, 16);
    }
    return out;
}

void putAttr(std::string &out, uint8_t type, const std::string &value)
{
    out.push_back((char)type);
    out.push_back((char)(2 + value.size()));
    out.append(value);
}

enum Direction { REQUEST_TO_WIRE, WIRE_TO_REQUEST, RESPONSE_TO_WIRE, WIRE_TO_RESPONSE };

// transform the attribute list of a packet
bool convertAttributes(const uint8_t *attrs, size_t len, Direction dir, const std::string &secret, const uint8_t ra[16], std::string &out)
{
    size_t pos = 0;
    while(pos < len){
        if(len - pos < 2)
            return false;
        const uint8_t type = attrs[pos];
        const size_t alen = attrs[pos + 1];
        if(alen < 2 || pos + alen > len)
            return false;
        const std::string value((const char*)attrs + pos + 2, alen - 2);
        pos += alen;

        // never sent in RADIUS/1.1 (RFC 9765 section 5.2): dropped
        if(type == ATTR_MESSAGE_AUTHENTICATOR)
            continue;

        if(type == ATTR_USER_PASSWORD && (dir == REQUEST_TO_WIRE || dir == WIRE_TO_REQUEST)){
            if(dir == REQUEST_TO_WIRE){
                if(value.empty() || value.size() % 16 != 0 || value.size() > 128)
                    return false;
                std::string plain = passwordXor(value, secret, ra, false);
                while(!plain.empty() && plain.back() == '\0')
                    plain.pop_back();
                if(plain.empty())
                    plain.assign(1, '\0');              // an empty password still needs 1 octet
                putAttr(out, type, plain);
            }else{
                if(value.empty() || value.size() > 128)
                    return false;
                std::string padded = value;
                padded.resize((value.size() + 15) / 16 * 16, '\0');
                putAttr(out, type, passwordXor(padded, secret, ra, true));
            }
            continue;
        }

        if(type == ATTR_VENDOR_SPECIFIC && (dir == RESPONSE_TO_WIRE || dir == WIRE_TO_RESPONSE) && value.size() >= 4
           && (((uint32_t)(uint8_t)value[0] << 24) | ((uint32_t)(uint8_t)value[1] << 16) | ((uint32_t)(uint8_t)value[2] << 8) | (uint8_t)value[3]) == VENDOR_MICROSOFT){
            // Microsoft sub-attributes (type, length, data): the MPPE keys change their encoding
            std::string vsa = value.substr(0, 4);
            size_t p = 4;
            while(p < value.size()){
                if(value.size() - p < 2)
                    return false;
                const uint8_t st = (uint8_t)value[p];
                const size_t sl = (uint8_t)value[p + 1];
                if(sl < 2 || p + sl > value.size())
                    return false;
                std::string sv = value.substr(p + 2, sl - 2);
                p += sl;
                if(st == MS_MPPE_SEND_KEY || st == MS_MPPE_RECV_KEY){
                    if(dir == RESPONSE_TO_WIRE){
                        std::string key;
                        if(!EZMSCHAP::DecodeMppeKey(sv, secret.data(), secret.size(), ra, key))
                            return false;
                        sv = key;
                    }else{
                        if(sv.empty() || sv.size() > 238)
                            return false;
                        sv = EZMSCHAP::EncodeMppeKey((const uint8_t*)sv.data(), sv.size(), secret.data(), secret.size(), ra);
                        if(sv.empty())
                            return false;
                    }
                }
                if(2 + sv.size() > 255)
                    return false;
                vsa.push_back((char)st);
                vsa.push_back((char)(2 + sv.size()));
                vsa.append(sv);
            }
            if(vsa.size() > 253)
                return false;
            putAttr(out, type, vsa);
            continue;
        }

        putAttr(out, type, value);
    }
    return true;
}

void putHeader(std::string &p, uint8_t code, uint8_t id, size_t len)
{
    p.push_back((char)code);
    p.push_back((char)id);
    p.push_back((char)(len >> 8));
    p.push_back((char)len);
}

} // namespace

bool classicRequestToWire(const uint8_t *pkt, size_t len, const std::string &secret, std::string &wire)
{
    if(len < 20 || len > 4096 || (((size_t)pkt[2] << 8) | pkt[3]) != len)
        return false;
    std::string attrs;
    if(!convertAttributes(pkt + 20, len - 20, REQUEST_TO_WIRE, secret, pkt + 4, attrs))
        return false;
    wire.clear();
    putHeader(wire, pkt[0], 0, 20 + attrs.size());
    wire.append((const char*)pkt + 4, 4);                 // Token = first 4 bytes of the Request Authenticator
    wire.append(12, '\0');
    wire.append(attrs);
    return wire.size() <= 4096;
}

bool wireRequestToClassic(const uint8_t *w, size_t len, const std::string &secret, std::string &classic)
{
    if(len < 20 || len > 4096 || (((size_t)w[2] << 8) | w[3]) != len)
        return false;
    uint8_t ra[16];
    memcpy(ra, w + 4, 4);
    memset(ra + 4, 0, 12);
    std::string attrs;
    if(!convertAttributes(w + 20, len - 20, WIRE_TO_REQUEST, secret, ra, attrs))
        return false;
    classic.clear();
    putHeader(classic, w[0], w[7], 20 + attrs.size());     // ID = last Token byte
    classic.append((const char*)ra, 16);
    classic.append(attrs);
    return classic.size() <= 4096;
}

bool classicResponseToWire(const uint8_t *pkt, size_t len, const uint8_t requestAuth[16], const std::string &secret, std::string &wire)
{
    if(len < 20 || len > 4096 || (((size_t)pkt[2] << 8) | pkt[3]) != len)
        return false;
    std::string attrs;
    if(!convertAttributes(pkt + 20, len - 20, RESPONSE_TO_WIRE, secret, requestAuth, attrs))
        return false;
    wire.clear();
    putHeader(wire, pkt[0], 0, 20 + attrs.size());
    wire.append((const char*)requestAuth, 4);
    wire.append(12, '\0');
    wire.append(attrs);
    return wire.size() <= 4096;
}

bool wireResponseToClassic(const uint8_t *w, size_t len, uint8_t requestId, const uint8_t requestAuth[16], const std::string &secret, std::string &classic)
{
    if(len < 20 || len > 4096 || (((size_t)w[2] << 8) | w[3]) != len)
        return false;
    if(memcmp(w + 4, requestAuth, 4) != 0)                // Token of another request
        return false;
    std::string attrs;
    if(!convertAttributes(w + 20, len - 20, WIRE_TO_RESPONSE, secret, requestAuth, attrs))
        return false;
    classic.clear();
    putHeader(classic, w[0], requestId, 20 + attrs.size());
    // Response Authenticator = MD5(Code + ID + Length + Request Authenticator + Attributes + Secret)
    std::string h = classic;
    h.append((const char*)requestAuth, 16);
    h.append(attrs);
    h.append(secret);
    uint8_t ra[16];
    EZCrypto::MD5(h.data(), h.size(), ra);
    classic.append((const char*)ra, 16);
    classic.append(attrs);
    return classic.size() <= 4096;
}

} // namespace ezradius11

#endif // EZRADIUS_HAS_TLS
