// libFuzzer target for the packet parser. Build with clang:
//   cmake -S . -B build -DCMAKE_CXX_COMPILER=clang++ -DEZRADIUS_BUILD_FUZZER=ON && cmake --build build
//   ./build/fuzz/ezradius_libfuzzer corpus/
#include "RadiusPacket.h"
#include "RadiusSecret.h"
#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static RadiusSecret secret("fuzz-secret");

    RadiusPacket p;
    p.setSecret(&secret);
    if(!p.setRawData((const char*)data, (int)size))
        return 0;

    for(int t = 0; t < 256; t++){
        p.getAttribute((RADIUSAttribute)t);
        p.getAttributes((RADIUSAttribute)t);
    }
    p.hasMessageAuthenticator();
    p.verifyMessageAuthenticator();
    p.verifyRequestAuthenticator();

    RadiusAttribute attr;
    for(int r = p.getFirstAttribute(attr); r == RC_SUCCESS; r = p.getNextAttribute(attr)) {}
    return 0;
}
