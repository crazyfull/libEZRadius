#ifndef EZRESPONSE_H
#define EZRESPONSE_H
#include "RadiusAttribute.h"
#include "RadiusPacket.h"

class EZRadiusClientIdentify;

// Response to a request received by EZRadiusServer. Build it with AddAttribute(), then Send().
// Send() is non blocking (one sendto on the reactor socket the request arrived on).
class EZResponse
{
    RadiusPacket m_Pck;

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

    // Send the response. Access-Accept / Reject / Challenge get a Message-Authenticator when the
    // request had one. Returns false if it could not be sent.
    bool Send(RADIUSPacketTypeCodes code, EZRadiusClientIdentify *ClientIdentify);
};

#endif // EZRESPONSE_H
