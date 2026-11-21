// Vendor-Specific attribute dictionary: built-in vendors, run-time dictionaries, wire format, end to end.
#include "EZVendorDict.h"
#include "EZRadiusSyncClient.h"
#include "EZRadiusServer.h"
#include "EZRadiusClientIdentify.h"
#include "EZResponse.h"
#include "clsEpollReactor.h"
#include <atomic>
#include <cstdio>
#include <cstring>
#include <thread>

static int g_fail = 0;
#define CHECK(c) do { if(!(c)){ printf("FAIL line %d: %s\n", __LINE__, #c); g_fail++; } } while(0)

static std::string hex(const std::string &s)
{
    static const char h[] = "0123456789abcdef";
    std::string o;
    for(unsigned char c : s){ o.push_back(h[c >> 4]); o.push_back(h[c & 15]); }
    return o;
}

// put a Vendor-Specific value into a packet, serialize, parse again
static RadiusPacket roundTrip(const std::vector<std::string> &values)
{
    static RadiusSecret secret("s");
    RadiusPacket p(2);
    p.setSecret(&secret);
    for(const std::string &v : values){
        RadiusAttribute a;
        p.addAttribute(D_ATTR_VENDOR_SPECIFIC, a);
        CHECK(a.setString(v.data(), (uint16_t)v.size()) == RC_SUCCESS);
    }
    RadiusPacket q;
    CHECK(q.setRawData((const char*)p.getRawData(), p.getLength()));
    return q;
}

static void test_builtin()
{
    EZVendorRegistry &r = EZVendorRegistry::instance();
    CHECK(r.findVendor(14988) && r.findVendor("mikrotik") && r.findVendor("Cisco") && r.findVendor("Juniper")
          && r.findVendor("HUAWEI") && r.findVendor(311));
    CHECK(r.findAttribute("mikrotik-rate-limit") && r.findAttribute("Mikrotik-Rate-Limit")->type == 8);
    CHECK(r.findAttribute("Cisco-AVPair") && r.findAttribute("Juniper-Local-User-Name") && r.findAttribute("Huawei-Domain-Name"));

    // wire format of the standard (1,1) header: Vendor-Id 14988 = 0x00003A8C, type 8, length 9
    std::string v;
    CHECK(r.buildValue("Mikrotik-Rate-Limit", "10M/10M", v));
    CHECK(hex(v) == "00003a8c0809" + hex("10M/10M"));

    // typed values
    CHECK(r.buildValue("Mikrotik-Total-Limit", 1000000u, v));
    CHECK(hex(v) == "00003a8c1106000f4240");
    CHECK(r.buildValue("Mikrotik-Host-IP", "10.1.2.3", v));
    CHECK(hex(v) == "00003a8c0a060a010203");
    CHECK(!r.buildValue("Mikrotik-Host-IP", "not-an-ip", v));
    CHECK(!r.buildValue("Mikrotik-Total-Limit", "abc", v));
    CHECK(!r.buildValue("No-Such-Attribute", "x", v));
    CHECK(!r.buildValue("Mikrotik-Rate-Limit", std::string(300, 'x'), v));      // too long

    // symbolic value
    CHECK(r.buildValue("MS-MPPE-Encryption-Policy", "Encryption-Required", v));
    CHECK(hex(v) == "0000013707060000" "0002");

    // decode by name
    RadiusPacket q = roundTrip({[&]{ std::string s; r.buildValue("Mikrotik-Group", "gold", s); return s; }(),
                                [&]{ std::string s; r.buildValue("Mikrotik-Host-IP", "192.168.0.9", s); return s; }(),
                                [&]{ std::string s; r.buildValue("Mikrotik-Total-Limit", 77u, s); return s; }()});
    EZVSAValue val;
    CHECK(r.find(q, "Mikrotik-Group", val) && val.text == "gold" && val.vendorName == "Mikrotik");
    CHECK(r.find(q, "Mikrotik-Host-IP", val) && val.text == "192.168.0.9");
    CHECK(r.find(q, "mikrotik-total-limit", val) && val.number == 77 && val.text == "77");
    CHECK(!r.find(q, "Mikrotik-Realm", val));
    CHECK(r.decode(q).size() == 3);

    // unknown vendor is decoded raw
    RadiusPacket u = roundTrip({std::string("\x00\x01\x86\xa0" "\x05\x05" "abc", 9)});
    auto d = r.decode(u);
    CHECK(d.size() == 1 && d[0].vendorId == 100000 && d[0].type == 5 && d[0].raw == "abc" && d[0].name.empty());
}

static void test_custom_dictionary()
{
    EZVendorRegistry r = EZVendorRegistry::empty();
    std::string err;
    size_t n = r.loadDictionary(R"(
# a vendor with 2 byte type and 2 byte length
VENDOR Acme 99999 format=2,2
BEGIN-VENDOR Acme
ATTRIBUTE Acme-Level  300 byte
ATTRIBUTE Acme-Mode   301 integer
ATTRIBUTE Acme-Addr6  302 ipv6addr
ATTRIBUTE Acme-Blob   303 octets
ATTRIBUTE Acme-Name   304 string   # trailing comment
VALUE Acme-Mode Fast 7
VALUE Acme-Mode Slow 1
END-VENDOR Acme
# vendor without a length field
VENDOR Plain 4242 format=4,0
BEGIN-VENDOR Plain
ATTRIBUTE Plain-Tag 1 integer
END-VENDOR Plain
)", &err);
    CHECK(n == 6);
    CHECK(err.empty());
    CHECK(r.vendorCount() == 2 && r.attributeCount() == 6);

    std::string v;
    CHECK(r.buildValue("Acme-Mode", "Fast", v));
    // vendor 99999 = 0x0001869F, type 301 = 0x012D, length 2+2+4 = 8
    CHECK(hex(v) == "0001869f012d000800000007");
    CHECK(r.buildValue("Acme-Level", "200", v));
    CHECK(!r.buildValue("Acme-Level", "300", v));                          // does not fit a byte
    CHECK(r.buildValue("Acme-Addr6", "2001:db8::1", v) && v.size() == 4 + 4 + 16);
    CHECK(r.buildValue("Acme-Blob", "0xdeadbeef", v) && hex(v).substr(hex(v).size() - 8) == "deadbeef");
    CHECK(!r.buildValue("Acme-Blob", "0xdeadbee", v));
    CHECK(r.buildValue("Plain-Tag", 5u, v) && hex(v) == "000010920000" "0001" "00000005" + std::string());

    // round trip with the 2,2 header (two sub-attributes inside one VSA)
    std::string a, b;
    CHECK(r.buildValue("Acme-Name", "node-1", a) && r.buildValue("Acme-Mode", "Slow", b));
    std::string both = a + b.substr(4);                 // second sub-attribute appended without a second Vendor-Id
    RadiusPacket q = roundTrip({both});
    EZVSAValue val;
    CHECK(r.find(q, "Acme-Name", val) && val.text == "node-1");
    CHECK(r.find(q, "Acme-Mode", val) && val.text == "Slow" && val.number == 1);
    CHECK(r.decode(q).size() == 2);

    // errors
    std::string e2;
    CHECK(r.loadDictionary("ATTRIBUTE X 1 string\n", &e2) == 0 && !e2.empty());          // outside BEGIN-VENDOR
    e2.clear();
    CHECK(r.loadDictionary("VENDOR Bad 5 format=3,1\n", &e2) == 0 && !e2.empty());      // type size 3 is invalid
    CHECK(!r.registerVendor(EZVendorDef{0, "zero", 1, 1}));
}

// ---- end to end: server answers with vendor attributes by name, the client reads them by name -----
static void onRequest(RADIUSPacketTypeCodes type, RadiusPacket &, EZRadiusClientIdentify &from, EZRadiusServer *, void *)
{
    if(type != ACCESS_REQUEST)
        return;
    EZResponse resp;
    CHECK(resp.AddVendorAttribute("Mikrotik-Rate-Limit", "5M/20M"));
    CHECK(resp.AddVendorAttribute("Mikrotik-Address-List", "paid-users"));
    CHECK(resp.AddVendorAttribute("Mikrotik-Total-Limit", 123456u));
    CHECK(resp.AddVendorAttribute("Cisco-AVPair", "shell:priv-lvl=15"));
    CHECK(resp.AddVendorAttribute("Huawei-Domain-Name", "isp.example"));
    CHECK(!resp.AddVendorAttribute("Mikrotik-Host-IP", "garbage"));
    CHECK(!resp.AddVendorAttribute("Unknown-Thing", "x"));
    resp.Send(ACCESS_ACCEPT, &from);
}

static void test_end_to_end()
{
    std::atomic<bool> stop{false};
    std::atomic<int> started{0};
    std::thread server([&]{
        netrector::EpollReactor reactor(0, 16);
        EZRadiusServer srv(&reactor);
        srv.setAuthenticationPort(18320);
        srv.setAccountingPort(18330);
        srv.SeRequestCallback(onRequest, nullptr);
        srv.RASList()->AddRAS("vsa-secret", "127.0.0.1");
        started = srv.Start() ? 1 : -1;
        reactor.run(stop);
    });
    while(started == 0) std::this_thread::sleep_for(std::chrono::milliseconds(5));
    CHECK(started == 1);

    EZClientSettings s;
    s.Host = "127.0.0.1"; s.Secret = "vsa-secret"; s.AuthenticationPort = 18320; s.TimeOut = 400; s.RetryCount = 2;
    EZRadiusSyncClient c(s);
    CHECK(c.AddAttribute(USER_NAME, "u"));
    CHECK(c.AddVendorAttribute("Mikrotik-Group", "req-group"));
    CHECK(c.Send(C_ACCESS_REQUEST) == EZResult::OK);
    CHECK(c.GetResponseType() == ACCESS_ACCEPT);

    // read the vendor attributes of the response by name through the low level packet API
    RadiusPacket dummy;
    (void)dummy;
    std::vector<AttrValue> vsas = c.GetAttributes(VENDOR_SPECIFIC);
    CHECK(vsas.size() == 5);
    EZVendorRegistry &r = EZVendorRegistry::instance();
    int seen = 0;
    for(const AttrValue &av : vsas){
        std::string raw(4, '\0');
        raw[0] = (char)(av.intValue >> 24); raw[1] = (char)(av.intValue >> 16); raw[2] = (char)(av.intValue >> 8); raw[3] = (char)av.intValue;
        RadiusSecret sec("x");
        RadiusPacket p(2); p.setSecret(&sec);
        RadiusAttribute a; p.addAttribute(D_ATTR_VENDOR_SPECIFIC, a);
        std::string full = raw + av.strValue;
        a.setString(full.data(), (uint16_t)full.size());
        RadiusPacket q; q.setRawData((const char*)p.getRawData(), p.getLength());
        for(const EZVSAValue &v : r.decode(q)){
            if(v.name == "Mikrotik-Rate-Limit" && v.text == "5M/20M") seen++;
            if(v.name == "Mikrotik-Address-List" && v.text == "paid-users") seen++;
            if(v.name == "Mikrotik-Total-Limit" && v.number == 123456) seen++;
            if(v.name == "Cisco-AVPair" && v.text == "shell:priv-lvl=15") seen++;
            if(v.name == "Huawei-Domain-Name" && v.text == "isp.example") seen++;
        }
    }
    CHECK(seen == 5);
    stop = true;
    server.join();
}

int main()
{
    test_builtin();
    test_custom_dictionary();
    test_end_to_end();
    printf(g_fail ? "FAILED (%d)\n" : "all vendor tests passed\n", g_fail);
    return g_fail ? 1 : 0;
}
