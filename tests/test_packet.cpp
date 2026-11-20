#include "RadiusPacket.h"
#include "RadiusSecret.h"
#include "md5.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

static int g_fail = 0;
#define CHECK(c) do { if(!(c)){ printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); g_fail++; } } while(0)

static std::string hex(const unsigned char *d, size_t n){ std::string s; char b[3]; for(size_t i=0;i<n;i++){ snprintf(b,3,"%02x",d[i]); s+=b; } return s; }

static void test_md5_hmac()
{
    unsigned char out[16];
    MD5Calc(out, (const unsigned char*)"abc", 3);
    CHECK(hex(out,16) == "900150983cd24fb0d6963f7d28e17f72");
    // RFC 2202 test case 2
    HMAC_MD5(out, (const unsigned char*)"Jefe", 4, (const unsigned char*)"what do ya want for nothing?", 28);
    CHECK(hex(out,16) == "750c783e6ab0b503eaa86e310a5db738");
    CHECK(ConstTimeEqual((const unsigned char*)"abcd",(const unsigned char*)"abcd",4));
    CHECK(!ConstTimeEqual((const unsigned char*)"abcd",(const unsigned char*)"abce",4));
}

static void test_secret()
{
    RadiusSecret s;
    CHECK(s.isEmpty());
    CHECK(s.setSecret(NULL, 5) != RC_SUCCESS);
    CHECK(s.setSecret("x", 0) != RC_SUCCESS);
    std::string big(257, 'k');
    CHECK(s.setSecret(big.c_str(), 257) != RC_SUCCESS);
    CHECK(s.setSecret("secret", 6) == RC_SUCCESS);
    CHECK(s.setSecret(big.c_str(), 257) != RC_SUCCESS);   // old secret kept
    CHECK(s.length() == 6);
    std::string k(256, 'k');
    CHECK(s.setSecret(k.c_str(), 256) == RC_SUCCESS);
}

static void test_pap_roundtrip()
{
    RadiusSecret s("testing123");
    RadiusPacket p(1); p.setSecret(&s);
    RadiusAttribute a;
    p.addAttribute(D_ATTR_USER_PASSWORD, a);
    CHECK(a.setUserPassword("hello-pass") == RC_SUCCESS);
    RadiusPacket q; q.setSecret(&s);
    CHECK(q.setRawData((const char*)p.getRawData(), p.getLength()));
    CHECK(q.getAttribute(USER_PASSWORD).strValue == "hello-pass");

    // 128 chars ok, 129 rejected
    RadiusPacket p2(1); p2.setSecret(&s);
    p2.addAttribute(D_ATTR_USER_PASSWORD, a);
    CHECK(a.setUserPassword(std::string(128,'p').c_str()) == RC_SUCCESS);
    RadiusPacket p3(1); p3.setSecret(&s);
    p3.addAttribute(D_ATTR_USER_PASSWORD, a);
    CHECK(a.setUserPassword(std::string(129,'p').c_str()) != RC_SUCCESS);
}

// RFC 2865 section 7.1 (Access-Request example): secret "xyzzy5461", user "nemo", password "arctangent"
static void test_rfc2865_pap_vector()
{
    static const unsigned char reqAuth[16] = {0x0f,0x40,0x3f,0x94,0x73,0x97,0x80,0x57,0xbd,0x83,0xd5,0xcb,0x98,0xf4,0x22,0x7a};
    static const unsigned char expected[16] = {0x0d,0xbe,0x70,0x8d,0x93,0xd4,0x13,0xce,0x31,0x96,0xe4,0x3f,0x78,0x2a,0x0a,0xee};
    RadiusSecret s("xyzzy5461");
    RadiusPacket p(1); p.setSecret(&s);
    p.setID(0);
    p.setAuthenticator(reqAuth);
    RadiusAttribute a;
    p.addAttribute(D_ATTR_USER_NAME, a); a.setString("nemo");
    p.addAttribute(D_ATTR_USER_PASSWORD, a); CHECK(a.setUserPassword("arctangent") == RC_SUCCESS);
    const unsigned char *raw = p.getRawData();
    // User-Name (2+4) then User-Password (2+16): the encrypted block starts at 20+6+2
    CHECK(p.getLength() == 20 + 6 + 18);
    CHECK(memcmp(raw + 28, expected, 16) == 0);
}

static void test_malformed()
{
    RadiusSecret s("x");
    unsigned char buf[300];

    // oversized PAP attribute
    memset(buf, 0, sizeof buf); buf[0]=1; buf[1]=7; int len=20+2+251; buf[2]=len>>8; buf[3]=len&0xff;
    buf[20]=2; buf[21]=253; memset(buf+22,0x41,251);
    RadiusPacket q; q.setSecret(&s);
    CHECK(q.setRawData((const char*)buf, len));
    CHECK(q.getAttribute(USER_PASSWORD).strValue.size() <= 128);

    // attribute length 1 / past the end / header length > data
    memset(buf,0,sizeof buf); buf[0]=1; buf[3]=22; buf[20]=1; buf[21]=1;
    RadiusPacket a1; CHECK(!a1.setRawData((const char*)buf, 22));
    buf[21]=10;
    RadiusPacket a2; CHECK(!a2.setRawData((const char*)buf, 22));
    buf[21]=2; buf[3]=0xff;
    RadiusPacket a3; CHECK(!a3.setRawData((const char*)buf, 22));
    RadiusPacket a4; CHECK(!a4.setRawData((const char*)buf, 19));      // shorter than the header
    // exactly 20 bytes (no attributes) is valid
    memset(buf,0,sizeof buf); buf[0]=1; buf[3]=20;
    RadiusPacket a5; CHECK(a5.setRawData((const char*)buf, 20));
    // empty attribute (Length == 2)
    buf[3]=22; buf[20]=1; buf[21]=2;
    RadiusPacket a6; CHECK(a6.setRawData((const char*)buf, 22));
    CHECK(a6.getAttribute(USER_NAME).strValue.empty());
}

static void test_limits()
{
    RadiusSecret s("x"); RadiusPacket p(4); p.setSecret(&s);
    RadiusAttribute a; p.addAttribute(D_ATTR_USER_NAME, a);
    CHECK(a.setString(std::string(254,'A').c_str()) != RC_SUCCESS);
    CHECK(p.getLength() <= D_RADIUS_PACKET_MAX_LENGTH);
}

static void test_response_auth()
{
    RadiusSecret s("sharedsecret");
    RadiusPacket req(1); req.setSecret(&s);
    RadiusAttribute a; req.addAttribute(D_ATTR_USER_NAME, a); a.setString("bob");
    CHECK(req.addMessageAuthenticator());
    CHECK(req.signMessageAuthenticator());
    CHECK(req.verifyMessageAuthenticator());

    RadiusPacket rx; CHECK(rx.setRawData((const char*)req.getRawData(), req.getLength())); rx.setSecret(&s);
    CHECK(rx.hasMessageAuthenticator());
    CHECK(rx.verifyMessageAuthenticator());

    // response
    RadiusPacket resp(2); resp.setSecret(&s); resp.setID(req.getID());
    resp.setAuthenticator(req.getAuthenticator());
    CHECK(resp.addMessageAuthenticator());
    CHECK(resp.signMessageAuthenticator());
    CHECK(resp.responseAuthenticator());
    RadiusPacket rr; CHECK(rr.setRawData((const char*)resp.getRawData(), resp.getLength())); rr.setSecret(&s);
    CHECK(req.verifyResponse(rr));
    CHECK(rr.verifyMessageAuthenticator(req.getAuthenticator(), &s));

    // tampered
    unsigned char *raw = resp.getRawData(); raw[resp.getLength()-1] ^= 1;
    RadiusPacket bad; CHECK(bad.setRawData((const char*)raw, resp.getLength())); bad.setSecret(&s);
    CHECK(!req.verifyResponse(bad));

    // wrong secret
    RadiusSecret other("other");
    CHECK(!rr.verifyMessageAuthenticator(req.getAuthenticator(), &other));
}

static void test_accounting_auth()
{
    RadiusSecret s("acct-secret");
    RadiusPacket req(4); req.setSecret(&s);
    RadiusAttribute a; req.addAttribute(D_ATTR_ACCT_STATUS_TYPE, a); a.setNumber(1);
    CHECK(req.accountingRequestAuthenticator());
    RadiusPacket rx; CHECK(rx.setRawData((const char*)req.getRawData(), req.getLength())); rx.setSecret(&s);
    CHECK(rx.verifyRequestAuthenticator());
    RadiusSecret other("nope"); rx.setSecret(&other);
    CHECK(!rx.verifyRequestAuthenticator());
}

static void test_vsa()
{
    RadiusSecret s("x"); RadiusPacket p(2); p.setSecret(&s);
    RadiusAttribute a; p.addAttribute(D_ATTR_VENDOR_SPECIFIC, a);
    CHECK(a.setVendorAttribute(14988, 8, "10M/10M", 7) == RC_SUCCESS);
    RadiusPacket q; CHECK(q.setRawData((const char*)p.getRawData(), p.getLength()));
    AttrValue v = q.getAttribute(VENDOR_SPECIFIC);
    CHECK(v.valid && v.intValue == 14988);
}

int main()
{
    test_md5_hmac(); test_rfc2865_pap_vector(); test_secret(); test_pap_roundtrip(); test_malformed();
    test_limits(); test_response_auth(); test_accounting_auth(); test_vsa();
    printf(g_fail ? "FAILED (%d)\n" : "all packet tests passed\n", g_fail);
    return g_fail ? 1 : 0;
}
