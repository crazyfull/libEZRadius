/*
 * libEZRadius
 *
 * Copyright (c) 2023-2026 Mojtaba Kahvand.
 * All rights reserved.
 *
 * Licensed under the GNU Lesser General Public License v2.1.
 * See LICENSE for details.
 */

#ifndef EZATTRUTIL_H
#define EZATTRUTIL_H
// Internal helpers shared by EZRadiusClient and EZResponse (not part of the public API)
#include "RadiusPacket.h"
#include "EZVendorDict.h"
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

    // NAS-IPv6-Address (95): 16 byte address
    if(type == 95){
        struct in6_addr ip6;
        if(inet_pton(AF_INET6, value, &ip6) != 1)
            return false;
        RadiusAttribute attr;
        if(pck.addAttribute((unsigned char)type, attr) != RC_SUCCESS)
            return false;
        return attr.setString((const char*)&ip6, 16) == RC_SUCCESS;
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

// Vendor-Specific attribute; the sub-attribute header follows the vendor's dictionary format (default 1,1)
inline bool addVendor(RadiusPacket &pck, uint32_t vendorId, unsigned char vendorType, const void *data, uint16_t len)
{
    std::string value;
    if(!EZVendorRegistry::instance().buildValue(vendorId, vendorType, data, len, value))
        return false;
    RadiusAttribute attr;
    if(pck.addAttribute(D_ATTR_VENDOR_SPECIFIC, attr) != RC_SUCCESS)
        return false;
    return attr.setString(value.data(), (uint16_t)value.size()) == RC_SUCCESS;
}

// Vendor-Specific attribute by dictionary name (text or number)
inline bool addVendorByName(RadiusPacket &pck, const char *name, const char *text)
{
    std::string value;
    if(!name || !text || !EZVendorRegistry::instance().buildValue(name, std::string(text), value))
        return false;
    RadiusAttribute attr;
    if(pck.addAttribute(D_ATTR_VENDOR_SPECIFIC, attr) != RC_SUCCESS)
        return false;
    return attr.setString(value.data(), (uint16_t)value.size()) == RC_SUCCESS;
}

inline bool addVendorByName(RadiusPacket &pck, const char *name, uint32_t number)
{
    std::string value;
    if(!name || !EZVendorRegistry::instance().buildValue(name, number, value))
        return false;
    RadiusAttribute attr;
    if(pck.addAttribute(D_ATTR_VENDOR_SPECIFIC, attr) != RC_SUCCESS)
        return false;
    return attr.setString(value.data(), (uint16_t)value.size()) == RC_SUCCESS;
}

// binary safe attribute (any type, 0..253 bytes), e.g. EAP-Message, State
inline bool addOctets(RadiusPacket &pck, unsigned char type, const void *data, size_t len)
{
    if(len > D_ATTR_MAX_VALUE_LENGTH || (!data && len))
        return false;
    RadiusAttribute attr;
    if(pck.addAttribute(type, attr) != RC_SUCCESS)
        return false;
    return len == 0 || attr.setString((const char*)data, (uint16_t)len) == RC_SUCCESS;
}

}

#endif
