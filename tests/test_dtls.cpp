// RADIUS over DTLS (RFC 7360): handshake with mutual authentication, requests, large packets, refused peers.
#include "EZRadiusSyncClient.h"
#include "EZRadiusServer.h"
#include "EZRadiusClientIdentify.h"
#include "EZResponse.h"
#include "EZTLS.h"
#include "clsEpollReactor.h"
#include "test_certs.h"
#include <atomic>
#include <cstdio>
#include <thread>

static int g_fail = 0;
#define CHECK(c) do { if(!(c)){ printf("FAIL line %d: %s\n", __LINE__, #c); g_fail++; } } while(0)

static std::atomic<size_t> g_lastSize{0};

static void onRequest(RADIUSPacketTypeCodes type, RadiusPacket &req, EZRadiusClientIdentify &from, EZRadiusServer *, void *)
{
    EZResponse resp;
    if(type == ACCESS_REQUEST){
        AttrValue u = req.getAttribute(USER_NAME);
        AttrValue pw = req.getAttribute(USER_PASSWORD);
        g_lastSize = req.getLength();
        const bool ok = (u.strValue == "alice" && pw.strValue == "secret");
        if(ok)
            resp.AddVendorAttribute("Mikrotik-Rate-Limit", "7M/7M");
        resp.Send(ok ? ACCESS_ACCEPT : ACCESS_REJECT, &from);
    }
}

static EZClientSettings settings(uint16_t port, const EZTLSConfig &tls)
{
    EZClientSettings s;
    s.Host = "127.0.0.1"; s.RadSecPort = port; s.TimeOut = 1500; s.RetryCount = 2;
    s.Transport = EZTransport::DTLS;
    s.TLS = tls;
    return s;
}

static EZResult login(const EZClientSettings &s, int padAttributes = 0, RADIUSPacketTypeCodes *type = nullptr)
{
    EZRadiusSyncClient c(s);
    c.AddAttribute(USER_NAME, "alice");
    c.AddAttribute(USER_PASSWORD, "secret");
    const std::string pad(250, 'p');
    for(int i = 0; i < padAttributes; i++)
        if(!c.AddRawAttribute((RADIUSAttribute)18, pad.data(), pad.size()))          // Reply-Message
            return EZResult::SEND_FAILED;
    EZResult r = c.Send(C_ACCESS_REQUEST);
    if(type) *type = c.GetResponseType();
    return r;
}

int main()
{
    TestCert ca = makeTestCert("Test CA", nullptr);
    TestCert srv = makeTestCert("radius.test", &ca, "DNS:radius.test,IP:127.0.0.1");
    TestCert cli = makeTestCert("nas1", &ca, "DNS:nas1.test");
    TestCert rogueCa = makeTestCert("Rogue CA", nullptr);
    TestCert rogue = makeTestCert("mallory", &rogueCa, "DNS:mallory.test");

    EZTLSConfig sc;
    sc.certChainPem = srv.certPem; sc.privateKeyPem = srv.keyPem; sc.caPem = ca.certPem;

    EZTLSConfig cc;
    cc.certChainPem = cli.certPem; cc.privateKeyPem = cli.keyPem; cc.caPem = ca.certPem; cc.serverName = "radius.test";

    {   // RADIUS/1.1 can not run on DTLS 1.2
        std::string err;
        EZTLSConfig bad = sc; bad.radiusVersions = "1.1";
        CHECK(!EZTLSContext::create(bad, true, true, &err));
    }

    std::atomic<bool> stop{false};
    std::atomic<int> started{0};
    std::thread server([&]{
        netrector::EpollReactor reactor(0, 16);
        EZRadiusServer srv2(&reactor);
        std::string err;
        if(!srv2.EnableDTLS(sc, 18720, &err)){ printf("EnableDTLS: %s\n", err.c_str()); started = -1; return; }
        srv2.SeRequestCallback(onRequest, nullptr);
        srv2.RASList()->AddRAS("unused", "127.0.0.1");
        started = srv2.Start() ? 1 : -1;
        reactor.run(stop);
        srv2.Stop();
    });
    while(started == 0) std::this_thread::sleep_for(std::chrono::milliseconds(5));
    CHECK(started == 1);

    {   // handshake + request
        RADIUSPacketTypeCodes t = UNKNOWN;
        CHECK(login(settings(18720, cc), 0, &t) == EZResult::OK);
        CHECK(t == ACCESS_ACCEPT);
    }
    {   // a 3.3 kB packet: larger than the handshake MTU, one DTLS record
        RADIUSPacketTypeCodes t = UNKNOWN;
        CHECK(login(settings(18720, cc), 13, &t) == EZResult::OK);
        CHECK(t == ACCESS_ACCEPT);
        CHECK(g_lastSize > 3200);
    }
    {   // status server over DTLS
        EZRadiusSyncClient c(settings(18720, cc));
        CHECK(c.Send(C_STATUS_SERVER) == EZResult::OK);
        CHECK(c.GetResponseType() == ACCESS_ACCEPT);
    }
    {   // client certificate of an unknown CA
        EZTLSConfig c = cc;
        c.certChainPem = rogue.certPem; c.privateKeyPem = rogue.keyPem;
        EZClientSettings s = settings(18720, c);
        s.TimeOut = 500;
        CHECK(login(s) != EZResult::OK);
    }
    {   // no client certificate
        EZTLSConfig c;
        c.caPem = ca.certPem; c.serverName = "radius.test";
        EZClientSettings s = settings(18720, c);
        s.TimeOut = 500;
        CHECK(login(s) != EZResult::OK);
    }
    {   // wrong server name
        EZTLSConfig c = cc;
        c.serverName = "evil.test";
        EZClientSettings s = settings(18720, c);
        s.TimeOut = 500;
        CHECK(login(s) != EZResult::OK);
    }
    {   // pinned server certificate
        EZTLSConfig c;
        c.certChainPem = cli.certPem; c.privateKeyPem = cli.keyPem;
        c.verifyPeer = false; c.pinnedSHA256 = {srv.fingerprint};
        CHECK(login(settings(18720, c)) == EZResult::OK);
    }
    {   // nobody listens: the handshake times out
        EZClientSettings s = settings(18799, cc);
        s.TimeOut = 300;
        CHECK(login(s) != EZResult::OK);
    }

    stop = true;
    server.join();
    printf(g_fail ? "FAILED (%d)\n" : "all DTLS tests passed\n", g_fail);
    return g_fail ? 1 : 0;
}
