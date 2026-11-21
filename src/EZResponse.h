#ifndef EZRESPONSE_H
#define EZRESPONSE_H
#include "RadiusAttribute.h"
#include "RadiusPacket.h"
#include "EZMSCHAP.h"
#include <string>

class EZRadiusClientIdentify;

// Response to a request received by EZRadiusServer. Build it with AddAttribute(), then Send().
// Send() is non blocking (one sendto on the reactor socket the request arrived on).
class EZResponse
{
    RadiusPacket m_Pck;
    bool m_forceMA = false;
#ifdef EZRADIUS_HAS_CRYPTO
    bool m_hasMppe = false;
    std::string m_mppeSend;
    std::string m_mppeRecv;
    uint32_t m_mppePolicy = 0;
    uint32_t m_mppeTypes = 0;
#endif

public:
    EZResponse() = default;

    // all AddAttribute / AddVendorAttribute return false (and add nothing) when the value is invalid:
    // too long (>253), not an IPv4 address for IP typed attributes, packet full.
    // (User-Password / CHAP-Password are not valid in a response and are rejected.)
    bool AddAttribute(RADIUSAttribute AttType, const char* value);
    bool AddAttribute(RADIUSAttribute AttType, uint32_t value);
    // Vendor-Specific attribute, e.g. MikroTik (14988) Rate-Limit (type 8): AddVendorAttribute(14988, 8, "10M/10M", 7)
    bool AddVendorAttribute(uint32_t vendorId, unsigned char vendorType, const void *data, uint16_t length);
    bool AddVendorAttribute(uint32_t vendorId, unsigned char vendorType, const char *text);
    // Vendor attribute by dictionary name (EZVendorDict.h): the value is converted according to the attribute
    // type (text, number, IP address, "0x.." octets, symbolic names).
    //   AddVendorAttribute("Mikrotik-Rate-Limit", "10M/10M");   AddVendorAttribute("Mikrotik-Total-Limit", 1000000u);
    bool AddVendorAttribute(const char *name, const char *text);
    bool AddVendorAttribute(const char *name, uint32_t number);
    // binary safe attribute of any type (0..253 bytes), e.g. State
    bool AddRawAttribute(RADIUSAttribute AttType, const void *data, size_t length);

#ifdef EZRADIUS_HAS_CRYPTO
    // EAP packet as EAP-Message attributes (fragmented into 253 byte attributes, see EZEAP.h)
    bool AddEAPMessage(const std::string &eapPacket);
    // ---- MS-CHAP (RFC 2548, needs EZRADIUS_HAS_CRYPTO) ----
    // MS-CHAP2-Success: ident + "S=<40 hex>" (EZMSCHAPv2Result::authenticatorResponse)
    bool AddMSCHAP2Success(uint8_t ident, const std::string &authenticatorResponse);
    // MS-CHAP-Error for a rejected MS-CHAP / MS-CHAPv2 request (691 = authentication failure)
    bool AddMSCHAPError(uint8_t ident, int errorCode = 691, bool retryAllowed = false, const char *message = "Authentication failed");
    // MS-MPPE-Send-Key / MS-MPPE-Recv-Key: encrypted with the shared secret and the Request Authenticator
    // when the response is sent. policy / types (MS-MPPE-Encryption-Policy / -Types) are added when not 0.
    bool AddMPPEKeys(const uint8_t sendKey[16], const uint8_t recvKey[16], uint32_t policy = 0, uint32_t types = 0);
    // same with keys of any length (EAP: two 32 byte halves of the MSK)
    bool AddMPPEKeys(const std::string &sendKey, const std::string &recvKey, uint32_t policy = 0, uint32_t types = 0);
    // MS-CHAP2-Success + MPPE keys of a successful EZMSCHAP::VerifyV2()
    bool AddMSCHAPv2Result(const EZMSCHAPv2Result &result, uint32_t mppePolicy = 0, uint32_t mppeTypes = 0);
#endif

    // Always add a Message-Authenticator to an Access-* response (mandatory when it carries EAP-Message, RFC 3579)
    void ForceMessageAuthenticator(bool force = true) { m_forceMA = force; }

    // Send the response. Access-Accept / Reject / Challenge get a Message-Authenticator when the
    // request had one. Returns false if it could not be sent.
    bool Send(RADIUSPacketTypeCodes code, EZRadiusClientIdentify *ClientIdentify);
};

#endif // EZRESPONSE_H
