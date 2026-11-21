// RADIUS/1.1 (RFC 9765): wire conversion, ALPN negotiation, end to end over TLS 1.3.
#include "EZRadius11.h"
#include "EZRadiusSyncClient.h"
#include "EZRadiusServer.h"
#include "EZRadiusClientIdentify.h"
#include "EZResponse.h"
#include "EZEAP.h"
#include "EZMSCHAP.h"
#include "EZCrypto.h"
#include "EZTLS.h"
#include "EZTransport.h"
#include "clsEpollReactor.h"
#include "test_certs.h"
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

static std::string classicRequest(const std::string &password, const std::string &secret, const uint8_t ra[16])
{
    // Access-Request, id 9: User-Name "bob", User-Password (obfuscated), Message-Authenticator (zeros)
    std::string attrs;
    attrs += std::string("\x01\x05" "bob", 5);
    std::string padded = password;
    padded.resize((password.size() + 15) / 16 * 16, '\0');
    std::string enc;
    uint8_t prev[16]; memcpy(prev, ra, 16);
    for(size_t p = 0; p < padded.size(); p += 16){
        std::string h = secret; h.append((const char*)prev, 16);
        uint8_t b[16]; EZCrypto::MD5(h.data(), h.size(), b);
        for(int i = 0; i < 16; i++) enc.push_back((char)(padded[p + i] ^ b[i]));
        memcpy(prev, enc.data() + p, 16);
    }
    attrs.push_back(2); attrs.push_back((char)(2 + enc.size())); attrs += enc;
    attrs.push_back(80); attrs.push_back(18); attrs.append(16, '\0');
    std::string pk;
    size_t len = 20 + attrs.size();
    pk.push_back(1); pk.push_back(9); pk.push_back((char)(len >> 8)); pk.push_back((char)len);
    pk.append((const char*)ra, 16);
    pk += attrs;
    return pk;
}

static void test_codec()
{
    uint8_t ra[16];
    for(int i = 0; i < 16; i++) ra[i] = (uint8_t)(0x10 + i);
    const std::string req = classicRequest("hunter2", "radsec", ra);

    std::string wire;
    CHECK(ezradius11::classicRequestToWire((const uint8_t*)req.data(), req.size(), "radsec", wire));
    // Code 1, Reserved 0, Length, Token = first 4 bytes of the authenticator, 12 zero bytes
    CHECK(hex(wire.substr(0, 20)) == "0100" + hex(std::string(1, (char)(wire.size() >> 8)) + std::string(1, (char)wire.size())) + "10111213" + std::string(24, '0'));
    // User-Name kept, password in clear text, no Message-Authenticator
    CHECK(wire.find("\x01\x05" "bob") != std::string::npos);
    CHECK(wire.find("\x02\x09" "hunter2") != std::string::npos);
    CHECK(wire.find(std::string("\x50\x12", 2)) == std::string::npos);
    CHECK(wire.size() == 20 + 5 + 9);

    // the server side turns it into a classic packet again: password re-encrypted, ID = last token byte
    std::string back;
    CHECK(ezradius11::wireRequestToClassic((const uint8_t*)wire.data(), wire.size(), "radsec", back));
    CHECK((uint8_t)back[1] == 0x13);
    CHECK(back.substr(4, 4) == req.substr(4, 4) && back.substr(8, 12) == std::string(12, '\0'));
    uint8_t ra2[16]; memcpy(ra2, back.data() + 4, 16);
    const std::string expect = classicRequest("hunter2", "radsec", ra2);
    CHECK(back.find(expect.substr(expect.find(std::string("\x02\x12", 2)), 18)) != std::string::npos);

    // wrong length / truncated attribute
    std::string bad = wire; bad[3] = (char)(bad.size() + 1);
    CHECK(!ezradius11::wireRequestToClassic((const uint8_t*)bad.data(), bad.size(), "radsec", back));
    std::string bad2 = wire; bad2[20 + 1] = (char)99;                      // attribute length beyond the packet
    CHECK(!ezradius11::wireRequestToClassic((const uint8_t*)bad2.data(), bad2.size(), "radsec", back));

    // response: MPPE keys travel as plain strings, the client rebuilds a valid classic response
    uint8_t key[32];
    for(int i = 0; i < 32; i++) key[i] = (uint8_t)(0x40 + i);
    std::string mppe = EZMSCHAP::EncodeMppeKey(key, 32, "radsec", 6, ra);
    std::string vsa("\x00\x00\x01\x37", 4);
    vsa.push_back(16); vsa.push_back((char)(2 + mppe.size())); vsa += mppe;
    std::string attrs;
    attrs.push_back(26); attrs.push_back((char)(2 + vsa.size())); attrs += vsa;
    attrs.push_back(80); attrs.push_back(18); attrs.append(16, '\0');
    std::string resp;
    size_t len = 20 + attrs.size();
    resp.push_back(2); resp.push_back(9); resp.push_back((char)(len >> 8)); resp.push_back((char)len);
    resp.append(16, '\0'); resp += attrs;
    CHECK(ezradius11::classicResponseToWire((const uint8_t*)resp.data(), resp.size(), ra, "radsec", wire));
    CHECK(wire.find(std::string((const char*)key, 32)) != std::string::npos);             // plain key in the TLS tunnel
    CHECK(wire.find(std::string("\x50\x12", 2)) == std::string::npos);
    std::string classic;
    CHECK(ezradius11::wireResponseToClassic((const uint8_t*)wire.data(), wire.size(), 9, ra, "radsec", classic));
    CHECK((uint8_t)classic[1] == 9 && classic.size() == resp.size() - 18);        // the Message-Authenticator is gone
    // valid Response Authenticator
    std::string h = classic.substr(0, 4); h.append((const char*)ra, 16); h += classic.substr(20); h += "radsec";
    uint8_t ex[16]; EZCrypto::MD5(h.data(), h.size(), ex);
    CHECK(memcmp(classic.data() + 4, ex, 16) == 0);
    // the key decrypts with the client's Request Authenticator
    const size_t vp = classic.find(std::string("\x00\x00\x01\x37\x10", 5));
    CHECK(vp != std::string::npos);
    const size_t mlen = (uint8_t)classic[vp + 5] - 2;
    std::string dec;
    CHECK(EZMSCHAP::DecodeMppeKey(classic.substr(vp + 6, mlen), "radsec", 6, ra, dec) && dec == std::string((const char*)key, 32));
    // a response with another Token is refused
    uint8_t other[16]; memcpy(other, ra, 16); other[0] ^= 1;
    CHECK(!ezradius11::wireResponseToClassic((const uint8_t*)wire.data(), wire.size(), 9, other, "radsec", classic));
}

static EZEAPServer *g_eap = nullptr;
// random / mutated input must never crash or hang (runs under ASan / UBSan in CI)
static void test_robustness()
{
    uint32_t x = 12345;
    auto rnd = [&]{ x = x * 1664525u + 1013904223u; return x >> 8; };
    uint8_t ra[16] = {1, 2, 3, 4};
    const std::string base = classicRequest("password", "radsec", ra);
    std::string wire;
    ezradius11::classicRequestToWire((const uint8_t*)base.data(), base.size(), "radsec", wire);
    for(int i = 0; i < 30000; i++){
        std::string m = (i & 1) ? wire : base;
        const int edits = 1 + (int)(rnd() % 4);
        for(int e = 0; e < edits; e++)
            m[rnd() % m.size()] = (char)rnd();
        if(rnd() % 4 == 0)
            m.resize(rnd() % (m.size() + 1));
        std::string out;
        ezradius11::wireRequestToClassic((const uint8_t*)m.data(), m.size(), "radsec", out);
        ezradius11::classicRequestToWire((const uint8_t*)m.data(), m.size(), "radsec", out);
        ezradius11::classicResponseToWire((const uint8_t*)m.data(), m.size(), ra, "radsec", out);
        ezradius11::wireResponseToClassic((const uint8_t*)m.data(), m.size(), 1, ra, "radsec", out);
        EZStreamFramer f;
        f.append((const uint8_t*)m.data(), m.size());
        std::string p;
        while(f.next(p) == EZStreamFramer::PACKET) {}
    }
}

static std::atomic<int> g_radius11{-1};
static std::atomic<bool> g_passwordOk{false};

static void onRequest(RADIUSPacketTypeCodes type, RadiusPacket &req, EZRadiusClientIdentify &from, EZRadiusServer *, void *)
{
    if(type != ACCESS_REQUEST)
        return;
    g_radius11 = from.isRadius11() ? 1 : 0;
    if(g_eap && g_eap->Process(req, from) != EZEAPResult::NOT_EAP)
        return;
    AttrValue u = req.getAttribute(USER_NAME);
    AttrValue pw = req.getAttribute(USER_PASSWORD);
    g_passwordOk = (u.strValue == "alice" && pw.strValue == "secret");
    EZResponse resp;
    if(g_passwordOk){
        resp.AddVendorAttribute("Mikrotik-Rate-Limit", "9M/9M");
        uint8_t send[16], recv[16];
        for(int i = 0; i < 16; i++){ send[i] = (uint8_t)i; recv[i] = (uint8_t)(0xF0 + i); }
        resp.AddMPPEKeys(send, recv);
    }
    resp.Send(g_passwordOk ? ACCESS_ACCEPT : ACCESS_REJECT, &from);
}

int main()
{
    test_codec();
    test_robustness();

    TestCert ca = makeTestCert("Test CA", nullptr);
    TestCert srvc = makeTestCert("radius.test", &ca, "DNS:radius.test,IP:127.0.0.1");
    TestCert clic = makeTestCert("nas1", &ca, "DNS:nas1.test");

    auto serverCfg = [&](const char *versions){
        EZTLSConfig c;
        c.certChainPem = srvc.certPem; c.privateKeyPem = srvc.keyPem; c.caPem = ca.certPem;
        c.radiusVersions = versions;
        return c;
    };
    auto clientSettings = [&](uint16_t port, const char *versions){
        EZClientSettings s;
        s.Host = "127.0.0.1"; s.RadSecPort = port; s.TimeOut = 1500; s.RetryCount = 1;
        s.Transport = EZTransport::TLS;
        s.TLS.certChainPem = clic.certPem; s.TLS.privateKeyPem = clic.keyPem; s.TLS.caPem = ca.certPem;
        s.TLS.serverName = "radius.test";
        s.TLS.radiusVersions = versions;
        return s;
    };

    // four servers in one reactor, one per server-side setting
    EZEAPServer eap;
    g_eap = &eap;
    eap.enableMD5([](const std::string &id, std::string &pw) { if(id == "eve"){ pw = "pw"; return true; } return false; });
    std::atomic<bool> stop{false};
    std::atomic<int> started{0};
    std::thread server([&]{
        netrector::EpollReactor reactor(0, 16);
        const char *versions[4] = {"1.0,1.1", "1.0", "1.1", ""};
        EZRadiusServer *srv[4];
        for(int i = 0; i < 4; i++){
            srv[i] = new EZRadiusServer(&reactor);
            std::string err;
            if(!srv[i]->EnableTLS(serverCfg(versions[i]), (uint16_t)(18630 + i), &err)){ printf("EnableTLS: %s\n", err.c_str()); started = -1; return; }
            srv[i]->setRadSecIPFilter(false);
            srv[i]->SeRequestCallback(onRequest, nullptr);
            if(!srv[i]->Start()){ started = -1; return; }
        }
        started = 1;
        reactor.run(stop);
        for(int i = 0; i < 4; i++){ srv[i]->Stop(); delete srv[i]; }
    });
    while(started == 0) std::this_thread::sleep_for(std::chrono::milliseconds(5));
    CHECK(started == 1);

    struct Case { const char *client; int serverIndex; bool ok; int version; };
    const Case cases[] = {
        {"1.0,1.1", 0, true, 11},       // both support 1.1: TLS 1.3 + radius/1.1
        {"1.0",     0, true, 10},
        {"",        0, true, 10},       // no ALPN offered: historic RADIUS/TLS
        {"1.0,1.1", 1, true, 10},       // server only does 1.0
        {"1.1",     0, true, 11},
        {"1.1",     2, true, 11},
        {"1.0",     2, false, 0},       // no common protocol: no_application_protocol
        {"1.1",     1, false, 0},
        {"1.1",     3, false, 0},       // the server does not do ALPN: a 1.1-only client gives up
        {"1.0,1.1", 3, true, 10},
        {"",        3, true, 10},
    };
    for(const Case &c : cases){
        g_radius11 = -1;
        g_passwordOk = false;
        EZRadiusSyncClient cl(clientSettings((uint16_t)(18630 + c.serverIndex), c.client));
        cl.AddAttribute(USER_NAME, "alice");
        cl.AddAttribute(USER_PASSWORD, "secret");
        EZResult r = cl.Send(C_ACCESS_REQUEST);
        if((r == EZResult::OK) != c.ok)
            printf("case client=\"%s\" server=%d: result %d\n", c.client, c.serverIndex, (int)r);
        CHECK((r == EZResult::OK) == c.ok);
        if(!c.ok)
            continue;
        CHECK(cl.GetResponseType() == ACCESS_ACCEPT);
        CHECK(g_passwordOk);                                    // the password survived the conversion
        CHECK(g_radius11 == (c.version == 11 ? 1 : 0));        // the server saw the negotiated version
        CHECK(cl.UsedRadius11() == (c.version == 11));
        bool rate = false;
        for(const AttrValue &v : cl.GetAttributes(VENDOR_SPECIFIC))
            if(v.strValue.find("9M/9M") != std::string::npos)
                rate = true;
        CHECK(rate);
        // MPPE keys: sent plain inside the 1.1 tunnel, readable by the client in both versions
        uint8_t s[16], rv[16];
        CHECK(cl.GetMPPEKeys(s, rv) && s[0] == 0 && s[15] == 15 && rv[0] == 0xF0 && rv[15] == 0xFF);
    }

    // EAP over RADIUS/1.1: no Message-Authenticator exists on the connection, the EAP server must accept that
    for(const char *versions : {"1.0,1.1", "1.0"}){
        EZEAPPeer peer("eve");
        peer.setPassword("pw");
        EZClientSettings st = clientSettings(18630, versions);
        EZRadiusSyncClient cl(st);
        ezeap::Packet first;
        first.code = ezeap::CODE_RESPONSE; first.id = 1; first.type = ezeap::TYPE_IDENTITY; first.data = "eve";
        std::string eapOut = first.serialize(), state;
        RADIUSPacketTypeCodes last = UNKNOWN;
        bool used11 = false;
        for(int round = 0; round < 10; round++){
            cl.Reset();
            cl.AddAttribute(USER_NAME, "eve");
            if(!state.empty())
                cl.AddRawAttribute((RADIUSAttribute)ezeap::ATTR_STATE, state.data(), state.size());
            if(!cl.AddEAPMessage(eapOut) || cl.Send(C_ACCESS_REQUEST) != EZResult::OK)
                break;
            used11 = cl.UsedRadius11();
            last = cl.GetResponseType();
            if(last != ACCESS_CHALLENGE){
                peer.handle(cl.GetEAPMessage());
                break;
            }
            state = cl.GetState();
            eapOut = peer.handle(cl.GetEAPMessage());
        }
        CHECK(last == ACCESS_ACCEPT);
        CHECK(peer.state() == EZEAPPeer::SUCCESS);
        CHECK(used11 == (std::string(versions) == "1.0,1.1"));
    }

    stop = true;
    server.join();
    printf(g_fail ? "FAILED (%d)\n" : "all RADIUS/1.1 tests passed\n", g_fail);
    return g_fail ? 1 : 0;
}
