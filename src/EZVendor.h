#ifndef EZVENDOR_H
#define EZVENDOR_H
// Internal: Vendor-Specific attribute (RFC 2865 section 5.26) helpers.
// Recommended format: Vendor-Id(4) then one or more sub-attributes { type(1) length(1) data(length-2) }.
#include "RadiusPacket.h"
#include <string>
#include <vector>

namespace ezvendor {

// first sub-attribute of the vendor with the given type. false: not found
inline bool find(RadiusPacket &pck, uint32_t vendorId, unsigned char vendorType, std::string &out)
{
    for(const AttrValue &v : pck.getAttributes(VENDOR_SPECIFIC)){
        if(!v.valid || v.intValue != vendorId)
            continue;
        const std::string &s = v.strValue;
        size_t pos = 0;
        while(pos + 2 <= s.size()){
            const unsigned char t = (unsigned char)s[pos];
            const size_t l = (unsigned char)s[pos + 1];
            if(l < 2 || pos + l > s.size())
                break;
            if(t == vendorType){
                out.assign(s, pos + 2, l - 2);
                return true;
            }
            pos += l;
        }
    }
    return false;
}

}

#endif
