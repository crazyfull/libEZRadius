#include <arpa/inet.h>
// Mutation fuzz smoke test for the packet parser (run under ASan/UBSan). Usage: fuzz_packet [iterations]
#include "RadiusPacket.h"
#include "RadiusSecret.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>

int main(int argc, char **argv)
{
    long iters = argc > 1 ? atol(argv[1]) : 20000;
    std::mt19937 rng(12345);
    RadiusSecret s("fuzz");

    // seed packet with various attributes
    RadiusPacket seed(1); seed.setSecret(&s);
    RadiusAttribute a;
    seed.addAttribute(D_ATTR_USER_NAME, a); a.setString("alice");
    seed.addAttribute(D_ATTR_USER_PASSWORD, a); a.setUserPassword("secret-password");
    seed.addAttribute(D_ATTR_NAS_IP_ADDRESS, a); struct in_addr ip; ip.s_addr = 0x0100007f; a.setIPAddress(ip);
    seed.addAttribute(D_ATTR_VENDOR_SPECIFIC, a); a.setVendorAttribute(14988, 8, "1M/1M", 5);
    seed.addMessageAuthenticator(); seed.signMessageAuthenticator();
    const int seedLen = seed.getLength();

    unsigned char buf[D_RADIUS_PACKET_MAX_LENGTH + 64];
    long valid = 0;
    for(long i = 0; i < iters; i++){
        int len = seedLen;
        memcpy(buf, seed.getRawData(), seedLen);
        int muts = 1 + rng() % 8;
        for(int m = 0; m < muts; m++){
            switch(rng() % 4){
            case 0: buf[rng() % len] = (unsigned char)rng(); break;
            case 1: buf[rng() % len] ^= (unsigned char)(1u << (rng() % 8)); break;
            case 2: len = 1 + rng() % (sizeof buf); for(int k = seedLen; k < len; k++) buf[k] = (unsigned char)rng(); break;
            case 3: buf[2] = rng(); buf[3] = rng(); break;
            }
        }
        RadiusPacket p; p.setSecret(&s);
        if(!p.setRawData((const char*)buf, len))
            continue;
        valid++;
        for(int t = 0; t < 256; t++){
            p.getAttribute((RADIUSAttribute)t);
            p.getAttributes((RADIUSAttribute)t);
        }
        p.hasMessageAuthenticator();
        p.verifyMessageAuthenticator();
        p.verifyRequestAuthenticator();
        RadiusAttribute attr;
        for(int r = p.getFirstAttribute(attr); r == RC_SUCCESS; r = p.getNextAttribute(attr)) {}
    }
    printf("fuzz done: %ld iterations, %ld parsed\n", iters, valid);
    return 0;
}
