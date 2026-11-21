// RadSec (RFC 6614): mutual TLS, certificate checks, pinning, ALPN / RADIUS versions.
#include "EZRadiusSyncClient.h"
#include "EZRadiusClient.h"
#include "EZRadiusServer.h"
#include "EZRadiusClientIdentify.h"
#include "EZResponse.h"
#include "EZTLS.h"
#include "clsEpollReactor.h"
#include "test_certs.h"
#include <atomic>
#include <cstdio>
#include <functional>
#include <future>
#include <thread>

static int g_fail = 0;
#define CHECK(c) do { if(!(c)){ printf("FAIL line %d: %s\n", __LINE__, #c); g_fail++; } } while(0)

static void onRequest(RADIUSPacketTypeCodes type, RadiusPacket &req, EZRadiusClientIdentify &from, EZRadiusServer *, void *)
{
    EZResponse resp;
    if(type == ACCESS_REQUEST){
        AttrValue u = req.getAttribute(USER_NAME);
        AttrValue pw = req.getAttribute(USER_PASSWORD);
        const bool ok = (u.strValue == "alice" && pw.strValue == "secret");
        if(ok)
            resp.AddVendorAttribute("Mikrotik-Rate-Limit", "5M/5M");
        resp.Send(ok ? ACCESS_ACCEPT : ACCESS_REJECT, &from);
    }else if(type == ACCOUNTING_REQUEST){
        resp.Send(ACCOUNTING_RESPONSE, &from);
    }
}

template <class F> static auto onReactor(netrector::EpollReactor &r, F f) -> decltype(f())
{
    std::promise<decltype(f())> pr;
    auto fut = pr.get_future();
    r.post([&]{ pr.set_value(f()); });
    return fut.get();
}

struct Env
{
    TestCert ca, server, client, rogueCa, rogue, selfSigned;
    Env()
        : ca(makeTestCert("Test CA", nullptr)),
          server(makeTestCert("radius.test", &ca, "DNS:radius.test,IP:127.0.0.1")),
          client(makeTestCert("nas1", &ca, "DNS:nas1.test")),
          rogueCa(makeTestCert("Rogue CA", nullptr)),
          rogue(makeTestCert("mallory", &rogueCa, "DNS:mallory.test")),
          selfSigned(makeTestCert("self", nullptr, "DNS:self.test")) {}
};

static EZTLSConfig clientCfg(const Env &e)
{
    EZTLSConfig c;
    c.certChainPem = e.client.certPem; c.privateKeyPem = e.client.keyPem; c.caPem = e.ca.certPem;
    c.serverName = "radius.test";
    return c;
}

static EZClientSettings settings(uint16_t port, const EZTLSConfig &tls)
{
    EZClientSettings s;
    s.Host = "127.0.0.1"; s.RadSecPort = port; s.TimeOut = 1500; s.RetryCount = 1;
    s.Transport = EZTransport::TLS;
    s.TLS = tls;
    return s;
}

// one Access-Request with the blocking client: EZResult::OK + Accept for alice/secret
static EZResult login(const EZClientSettings &s, RADIUSPacketTypeCodes *type = nullptr, std::string *rate = nullptr)
{
    EZRadiusSyncClient c(s);
    c.AddAttribute(USER_NAME, "alice");
    c.AddAttribute(USER_PASSWORD, "secret");
    EZResult r = c.Send(C_ACCESS_REQUEST);
    if(type) *type = c.GetResponseType();
    if(rate){
        for(const AttrValue &v : c.GetAttributes(VENDOR_SPECIFIC))
            if(v.strValue.find("5M/5M") != std::string::npos)
                *rate = "5M/5M";
    }
    return r;
}

int main()
{
    Env env;

    EZTLSConfig sc;
    sc.certChainPem = env.server.certPem; sc.privateKeyPem = env.server.keyPem; sc.caPem = env.ca.certPem;

    std::atomic<bool> stop{false};
    std::atomic<int> started{0};
    netrector::EpollReactor *reactorPtr = nullptr;
    EZRadiusServer *srvPtr = nullptr;
    std::thread server([&]{
        netrector::EpollReactor reactor(0, 16);
        EZRadiusServer srv(&reactor);
        std::string err;
        if(!srv.EnableTLS(sc, 18620, &err)){ printf("EnableTLS: %s\n", err.c_str()); started = -1; return; }
        srv.SeRequestCallback(onRequest, nullptr);
        srv.RASList()->AddRAS("unused-for-tls", "127.0.0.1");
        reactorPtr = &reactor; srvPtr = &srv;
        started = srv.Start() ? 1 : -1;
        reactor.run(stop);
        srv.Stop();
    });
    while(started == 0) std::this_thread::sleep_for(std::chrono::milliseconds(5));
    CHECK(started == 1);

    // configuration errors are reported
    {
        std::string err;
        EZTLSConfig bad;
        CHECK(!EZTLSContext::create(bad, true, false, &err) && !err.empty());              // nothing to authenticate with
        EZTLSConfig noCa = sc; noCa.caPem.clear();
        CHECK(!EZTLSContext::create(noCa, true, false, &err));                              // verifyPeer without CA
        EZTLSConfig badVer = sc; badVer.radiusVersions = "2.0";
        CHECK(!EZTLSContext::create(badVer, true, false, &err));
        EZTLSConfig mismatch = sc; mismatch.privateKeyPem = env.client.keyPem;
        CHECK(!EZTLSContext::create(mismatch, true, false, &err));
    }

    // 1. mutual TLS, PAP over the tunnel
    {
        RADIUSPacketTypeCodes t = UNKNOWN; std::string rate;
        CHECK(login(settings(18620, clientCfg(env)), &t, &rate) == EZResult::OK);
        CHECK(t == ACCESS_ACCEPT);
        CHECK(rate == "5M/5M");
    }

    // 2. several requests on one connection (async client, one reactor run)
    {
        netrector::EpollReactor cr(0, 16);
        std::atomic<bool> done{false};
        EZRadiusClient c(&cr, settings(18620, clientCfg(env)));
        int n = 0;
        std::function<void()> next = [&]{
            c.Reset();
            c.AddAttribute(USER_NAME, "alice");
            c.AddAttribute(USER_PASSWORD, n == 1 ? "wrong" : "secret");
            CHECK(c.Send(C_ACCESS_REQUEST, [&](EZRadiusClient &r, EZResult e){
                CHECK(e == EZResult::OK);
                CHECK(r.GetResponseType() == (n == 1 ? ACCESS_REJECT : ACCESS_ACCEPT));
                CHECK(onReactor(*reactorPtr, [&]{ return srvPtr->connectionCount(); }) == 1);       // still the same connection
                if(++n < 3) next(); else done = true;
            }));
        };
        cr.post(next);
        cr.run(done);
    }

    // 3. a client certificate from an unknown CA is refused
    {
        EZTLSConfig c = clientCfg(env);
        c.certChainPem = env.rogue.certPem; c.privateKeyPem = env.rogue.keyPem;
        CHECK(login(settings(18620, c)) != EZResult::OK);
    }
    // 4. no client certificate at all
    {
        EZTLSConfig c;
        c.caPem = env.ca.certPem; c.serverName = "radius.test";
        CHECK(login(settings(18620, c)) != EZResult::OK);
    }
    // 5. the server name must match the subjectAltName
    {
        EZTLSConfig c = clientCfg(env);
        c.serverName = "other.test";
        CHECK(login(settings(18620, c)) != EZResult::OK);
        c.serverName = "127.0.0.1";                  // IP address SAN
        CHECK(login(settings(18620, c)) == EZResult::OK);
    }
    // 6. the client does not trust the server CA
    {
        EZTLSConfig c = clientCfg(env);
        c.caPem = env.rogueCa.certPem;
        CHECK(login(settings(18620, c)) != EZResult::OK);
    }
    // 7. pinning the server certificate fingerprint instead of a CA
    {
        EZTLSConfig c;
        c.certChainPem = env.client.certPem; c.privateKeyPem = env.client.keyPem;
        c.verifyPeer = false;
        c.pinnedSHA256 = {env.server.fingerprint};
        CHECK(login(settings(18620, c)) == EZResult::OK);
        c.pinnedSHA256 = {std::string(64, 'a')};
        CHECK(login(settings(18620, c)) != EZResult::OK);
    }
    // 8. an address that is not in the RASList is refused (and allowed again without the IP filter)
    onReactor(*reactorPtr, [&]{ srvPtr->RASList()->removeRASByIP("127.0.0.1"); return 0; });
    CHECK(login(settings(18620, clientCfg(env))) != EZResult::OK);
    onReactor(*reactorPtr, [&]{ srvPtr->setRadSecIPFilter(false); return 0; });
    CHECK(login(settings(18620, clientCfg(env))) == EZResult::OK);

    stop = true;
    server.join();

    // 9. a server that pins client certificates (self-signed clients are fine)
    {
        EZTLSConfig p;
        p.certChainPem = env.server.certPem; p.privateKeyPem = env.server.keyPem;
        p.verifyPeer = false;
        p.pinnedSHA256 = {env.selfSigned.fingerprint};
        std::atomic<bool> stop2{false};
        std::atomic<int> st2{0};
        std::thread s2([&]{
            netrector::EpollReactor reactor(0, 16);
            EZRadiusServer srv(&reactor);
            srv.EnableTLS(p, 18621);
            srv.SeRequestCallback(onRequest, nullptr);
            srv.setRadSecIPFilter(false);
            st2 = srv.Start() ? 1 : -1;
            reactor.run(stop2);
            srv.Stop();
        });
        while(st2 == 0) std::this_thread::sleep_for(std::chrono::milliseconds(5));
        EZTLSConfig c;
        c.certChainPem = env.selfSigned.certPem; c.privateKeyPem = env.selfSigned.keyPem;
        c.caPem = env.ca.certPem; c.serverName = "radius.test";
        CHECK(login(settings(18621, c)) == EZResult::OK);
        EZTLSConfig other = clientCfg(env);                // valid certificate, but not the pinned one
        CHECK(login(settings(18621, other)) != EZResult::OK);
        stop2 = true;
        s2.join();
    }

    printf(g_fail ? "FAILED (%d)\n" : "all RadSec tests passed\n", g_fail);
    return g_fail ? 1 : 0;
}
