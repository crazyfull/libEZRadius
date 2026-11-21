#ifndef EZVENDOR_H
#define EZVENDOR_H
// Internal: Vendor-Specific attribute (RFC 2865 section 5.26) helpers.
// Recommended format: Vendor-Id(4) then one or more sub-attributes { type(1) length(1) data(length-2) }.
#include "RadiusPacket.h"
#include "EZVendorDict.h"
#include <string>
#include <vector>

namespace ezvendor {

// first sub-attribute of the vendor with the given type (the vendor's dictionary header format is honored).
// false: not found
inline bool find(RadiusPacket &pck, uint32_t vendorId, unsigned char vendorType, std::string &out)
{
    return EZVendorRegistry::instance().findRaw(pck, vendorId, vendorType, out);
}

}

#endif
