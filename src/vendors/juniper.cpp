// Juniper Networks (Vendor-Id 2636)
#include "../EZVendorDict.h"

const char *EZVendorDictionaryJuniper()
{
    return R"DICT(
VENDOR Juniper 2636
BEGIN-VENDOR Juniper
ATTRIBUTE Juniper-Local-User-Name      1  string
ATTRIBUTE Juniper-Allow-Commands       2  string
ATTRIBUTE Juniper-Deny-Commands        3  string
ATTRIBUTE Juniper-Allow-Configuration  4  string
ATTRIBUTE Juniper-Deny-Configuration   5  string
ATTRIBUTE Juniper-Interactive-Command  8  string
ATTRIBUTE Juniper-Configuration-Change 9  string
ATTRIBUTE Juniper-User-Permissions     10 string
END-VENDOR Juniper
)DICT";
}
