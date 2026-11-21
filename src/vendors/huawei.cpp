// Huawei (Vendor-Id 2011)
#include "../EZVendorDict.h"

const char *EZVendorDictionaryHuawei()
{
    return R"DICT(
VENDOR Huawei 2011
BEGIN-VENDOR Huawei
ATTRIBUTE Huawei-Input-Committed-Burst-Size         1   integer
ATTRIBUTE Huawei-Input-Committed-Information-Rate   2   integer
ATTRIBUTE Huawei-Input-Peak-Information-Rate        3   integer
ATTRIBUTE Huawei-Output-Committed-Burst-Size        4   integer
ATTRIBUTE Huawei-Output-Committed-Information-Rate  5   integer
ATTRIBUTE Huawei-Output-Peak-Information-Rate       6   integer
ATTRIBUTE Huawei-Exec-Privilege                     29  integer
ATTRIBUTE Huawei-Domain-Name                        138 string
END-VENDOR Huawei
)DICT";
}
