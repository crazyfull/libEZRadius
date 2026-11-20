#ifndef EZATTRUTIL_H
#define EZATTRUTIL_H
// Internal helpers shared by EZRadiusClient and EZResponse (not part of the public API)
#include "RadiusPacket.h"
#include <arpa/inet.h>
#include <cstring>

namespace ezutil {

// string attribute. IP typed attributes are parsed with inet_pton (inet_addr() can not report errors).
// false: value too long / not a valid IPv4 address / packet full. Nothing is added on failure.
inline bool addString(RadiusPacket &pck, RADIUSAttribute type, const char *value)
{
    if(!value)
        return false;

    if(RadiusPacket::getAttributeType((uint8_t)type) == ATTR_TYPE_IP_ADDRESS){
        struct in_addr ip;
        if(inet_pton(AF_INET, value, &ip) != 1)
            return false;
        RadiusAttribute attr;
        if(pck.addAttribute((unsigned char)type, attr) != RC_SUCCESS)
            return false;
        return attr.setIPAddress(ip) == RC_SUCCESS;
    }

    size_t len = strnlen(value, D_ATTR_MAX_VALUE_LENGTH + 1);
    if(len > D_ATTR_MAX_VALUE_LENGTH)
        return false;

    RadiusAttribute attr;
    if(pck.addAttribute((unsigned char)type, attr) != RC_SUCCESS)
        return false;
    return attr.setString(value, (uint16_t)len) == RC_SUCCESS;
}

inline bool addNumber(RadiusPacket &pck, RADIUSAttribute type, uint32_t value)
{
    RadiusAttribute attr;
    if(pck.addAttribute((unsigned char)type, attr) != RC_SUCCESS)
        return false;
    return attr.setNumber(value) == RC_SUCCESS;
}

inline bool addVendor(RadiusPacket &pck, uint32_t vendorId, unsigned char vendorType, const void *data, uint16_t len)
{
    RadiusAttribute attr;
    if(pck.addAttribute(D_ATTR_VENDOR_SPECIFIC, attr) != RC_SUCCESS)
        return false;
    return attr.setVendorAttribute(vendorId, vendorType, data, len) == RC_SUCCESS;
}

}

#endif
