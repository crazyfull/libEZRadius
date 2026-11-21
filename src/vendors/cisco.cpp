// Cisco (Vendor-Id 9)
#include "../EZVendorDict.h"

const char *EZVendorDictionaryCisco()
{
    return R"DICT(
VENDOR Cisco 9
BEGIN-VENDOR Cisco
ATTRIBUTE Cisco-AVPair        1   string
ATTRIBUTE Cisco-NAS-Port      2   string
ATTRIBUTE Cisco-Account-Info  250 string
ATTRIBUTE Cisco-Service-Info  251 string
END-VENDOR Cisco
)DICT";
}
