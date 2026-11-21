// Microsoft (Vendor-Id 311), RFC 2548
#include "../EZVendorDict.h"

const char *EZVendorDictionaryMicrosoft()
{
    return R"DICT(
VENDOR Microsoft 311
BEGIN-VENDOR Microsoft
ATTRIBUTE MS-CHAP-Response            1  octets
ATTRIBUTE MS-CHAP-Error               2  string
ATTRIBUTE MS-MPPE-Encryption-Policy   7  integer
ATTRIBUTE MS-MPPE-Encryption-Types    8  integer
ATTRIBUTE MS-RAS-Vendor               9  integer
ATTRIBUTE MS-CHAP-Domain              10 string
ATTRIBUTE MS-CHAP-Challenge           11 octets
ATTRIBUTE MS-MPPE-Send-Key            16 octets
ATTRIBUTE MS-MPPE-Recv-Key            17 octets
ATTRIBUTE MS-RAS-Version              18 string
ATTRIBUTE MS-Acct-Auth-Type           23 integer
ATTRIBUTE MS-Acct-EAP-Type            24 integer
ATTRIBUTE MS-CHAP2-Response           25 octets
ATTRIBUTE MS-CHAP2-Success            26 string
ATTRIBUTE MS-Primary-DNS-Server       28 ipaddr
ATTRIBUTE MS-Secondary-DNS-Server     29 ipaddr
ATTRIBUTE MS-Primary-NBNS-Server      30 ipaddr
ATTRIBUTE MS-Secondary-NBNS-Server    31 ipaddr
VALUE MS-MPPE-Encryption-Policy Encryption-Allowed   1
VALUE MS-MPPE-Encryption-Policy Encryption-Required  2
VALUE MS-MPPE-Encryption-Types  RC4-40bit-Allowed    1
VALUE MS-MPPE-Encryption-Types  RC4-128bit-Allowed   2
VALUE MS-MPPE-Encryption-Types  RC4-40or128-bit-Allowed 6
END-VENDOR Microsoft
)DICT";
}
