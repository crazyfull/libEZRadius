// End to end test on one reactor (one thread, no blocking): server + async clients + CoA over loopback.
#include <atomic>
#include <cstdio>
#include <cstring>
#include <functional>
#include <memory>
#include <arpa/inet.h>
#include "clsEpollReactor.h"
#include "clsUDPSocket.h"
#include "EZRadiusServer.h"
#include "EZRadiusClient.h"
#include "EZRadiusClientIdentify.h"
#include "EZResponse.h"
#include "EZCoA.h"

static int g_fail = 0;
#define CHECK(c) do { if(!(c)){ printf("FAIL line %d: %s\n", __LINE__, #c); g_fail++; } } while(0)

static std::atomic<bool> g_stop{false};
static netrector::EpollReactor *g_reactor;
static const char *SECRET = "loop-secret";
static const int AUTH_PORT = 18120, ACCT_PORT = 18130, COA_PORT = 18799;

static int g_accessSeen = 0, g_acctSeen = 0;

static void onRequest(RADIUSPacketTypeCodes type, RadiusPacket &req, EZRadiusClientIdentify &from, EZRadiusServer *, void *)
{
    EZResponse resp;
    if(type == ACCESS_REQUEST){
        g_accessSeen++;
        std::string user = req.getAttribute(USER_NAME).strValue;
        std::string pass = req.getAttribute(USER_PASSWORD).strValue;
        AttrValue chap = req.getAttribute(CHAP_PASSWORD);
        bool ok = (user == "alice" && (pass == "wonderland" || chap.valid));
        CHECK(from.RequestHadMessageAuthenticator());
        if(ok){
            resp.AddAttribute(REPLY_MESSAGE, "welcome");
            resp.AddVendorAttribute(14988, 8, "10M/10M");
            resp.Send(ACCESS_ACCEPT, &from);
        }else{
            resp.AddAttribute(REPLY_MESSAGE, "denied");
            resp.Send(ACCESS_REJECT, &from);
        }
    }else if(type == ACCOUNTING_REQUEST){
        g_acctSeen++;
        resp.Send(ACCOUNTING_RESPONSE, &from);
    }
}

static EZClientSettings baseSettings()
{
    EZClientSettings s;
    s.Host = "127.0.0.1";
    s.Secret = SECRET;
    s.AuthenticationPort = AUTH_PORT;
    s.AccountingPort = ACCT_PORT;
    s.TimeOut = 300;
    s.RetryCount = 2;
    return s;
}

// ---- tiny step runner ------------------------------------------------------
static std::vector<std::function<void(std::function<void()>)>> g_steps;
static size_t g_next = 0;
static std::vector<std::unique_ptr<EZRadiusClient>> g_clients;    // kept alive until the end

static void runNext()
{
    if(g_next >= g_steps.size()){
        g_stop = true;
        return;
    }
    auto step = g_steps[g_next++];
    step([]{ g_reactor->post([]{ runNext(); }); });
}

static EZRadiusClient *newClient(const EZClientSettings &s)
{
    g_clients.emplace_back(new EZRadiusClient(g_reactor, s));
    return g_clients.back().get();
}

// ---- CoA raw sender ---------------------------------------------------------
class CoAPeer : public netrector::UDPSocket
{
public:
    std::function<void(const uint8_t*, size_t)> handler;
    void onDatagram(const uint8_t *d, size_t n, const sockaddr *, socklen_t) override { if(handler) handler(d, n); }
};

int main()
{
    netrector::EpollReactor reactor(0, 256);
    g_reactor = &reactor;

    EZRadiusServer server(&reactor);
    server.setAuthenticationPort(AUTH_PORT);
    server.setAccountingPort(ACCT_PORT);
    server.SeRequestCallback(onRequest, nullptr);
    CHECK(server.RASList()->AddRAS(SECRET, "127.0.0.1"));
    CHECK(server.Start());

    EZCoA coa(&reactor, [] { EZClientSettings s; s.Host = "127.0.0.1"; s.Secret = SECRET; s.CoAPort = COA_PORT; return s; }());
    int coaSeen = 0;
    coa.SetGetRequests([&](RADIUSPacketTypeCodes t, RadiusPacket &r, EZResponse &resp, void *) {
        coaSeen++;
        resp.AddAttribute(USER_NAME, r.getAttribute(USER_NAME).strValue.c_str());
        return t == DISCONNECT_REQUEST ? DISCONNECT_ACK : COA_NAK;
    }, nullptr);
    CHECK(coa.Start());

    // 1. PAP accept (+ Message-Authenticator + VSA)
    g_steps.push_back([](std::function<void()> next){
        EZRadiusClient *c = newClient(baseSettings());
        CHECK(c->AddAttribute(USER_NAME, "alice"));
        CHECK(c->AddAttribute(USER_PASSWORD, "wonderland"));
        CHECK(c->AddAttribute(NAS_IP_ADDRESS, "10.0.0.1"));
        CHECK(!c->AddAttribute(NAS_IP_ADDRESS, "not-an-ip"));
        CHECK(!c->AddAttribute(USER_NAME, std::string(300,'a').c_str()));
        CHECK(c->Send(C_ACCESS_REQUEST, [next](EZRadiusClient &c, EZResult r){
            CHECK(r == EZResult::OK);
            CHECK(c.GetResponseType() == ACCESS_ACCEPT);
            CHECK(c.GetAttribute(REPLY_MESSAGE).strValue == "welcome");
            AttrValue v = c.GetAttribute(VENDOR_SPECIFIC);
            CHECK(v.valid && v.intValue == 14988);
            next();
        }));
    });
    // 2. wrong password -> reject
    g_steps.push_back([](std::function<void()> next){
        EZRadiusClient *c = newClient(baseSettings());
        c->AddAttribute(USER_NAME, "alice"); c->AddAttribute(USER_PASSWORD, "wrong");
        c->Send(C_ACCESS_REQUEST, [next](EZRadiusClient &c, EZResult r){
            CHECK(r == EZResult::OK); CHECK(c.GetResponseType() == ACCESS_REJECT); next(); });
    });
    // 3. CHAP
    g_steps.push_back([](std::function<void()> next){
        EZRadiusClient *c = newClient(baseSettings());
        c->AddAttribute(USER_NAME, "alice"); CHECK(c->AddAttribute(CHAP_PASSWORD, "wonderland"));
        c->Send(C_ACCESS_REQUEST, [next](EZRadiusClient &c, EZResult r){
            CHECK(r == EZResult::OK); CHECK(c.GetResponseType() == ACCESS_ACCEPT); next(); });
    });
    // 4. accounting
    g_steps.push_back([](std::function<void()> next){
        EZRadiusClient *c = newClient(baseSettings());
        c->AddAttribute(ACCT_STATUS_TYPE, (int)RADIUSAcctStatusType::START);
        c->AddAttribute(USER_NAME, "alice"); c->AddAttribute(ACCT_SESSION_ID, "s1");
        c->Send(C_ACCOUNTING_REQUEST, [next](EZRadiusClient &c, EZResult r){
            CHECK(r == EZResult::OK); CHECK(c.GetResponseType() == ACCOUNTING_RESPONSE); next(); });
    });
    // 5. wrong secret on the client: server drops (bad Message-Authenticator) -> timeout after 2 attempts
    g_steps.push_back([](std::function<void()> next){
        EZClientSettings s = baseSettings(); s.Secret = "wrong-secret";
        int before = g_accessSeen;
        EZRadiusClient *c = newClient(s);
        c->AddAttribute(USER_NAME, "alice"); c->AddAttribute(USER_PASSWORD, "wonderland");
        c->Send(C_ACCESS_REQUEST, [next, before](EZRadiusClient &c, EZResult r){
            CHECK(r == EZResult::TIMEOUT); CHECK(c.GetResponseType() == UNKNOWN);
            CHECK(g_accessSeen == before);      // never reached the callback
            next(); });
    });
    // 6. no server on that port: timeout, no blocking
    g_steps.push_back([](std::function<void()> next){
        EZClientSettings s = baseSettings(); s.AuthenticationPort = 18999; s.TimeOut = 100; s.RetryCount = 3;
        EZRadiusClient *c = newClient(s);
        c->AddAttribute(USER_NAME, "x");
        auto t0 = std::chrono::steady_clock::now();
        c->Send(C_ACCESS_REQUEST, [next, t0](EZRadiusClient &, EZResult r){
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
            CHECK(r == EZResult::TIMEOUT); CHECK(ms >= 280 && ms < 900);
            next(); });
    });
    // 7. two requests in flight at once on one reactor
    g_steps.push_back([](std::function<void()> next){
        auto left = std::make_shared<int>(2);
        for(int i = 0; i < 2; i++){
            EZRadiusClient *c = newClient(baseSettings());
            c->AddAttribute(USER_NAME, "alice"); c->AddAttribute(USER_PASSWORD, "wonderland");
            c->Send(C_ACCESS_REQUEST, [next, left](EZRadiusClient &c, EZResult r){
                CHECK(r == EZResult::OK && c.GetResponseType() == ACCESS_ACCEPT);
                if(--*left == 0) next(); });
        }
    });
    // 8. cancel
    g_steps.push_back([](std::function<void()> next){
        EZClientSettings s = baseSettings(); s.AuthenticationPort = 18999; s.TimeOut = 5000;
        EZRadiusClient *c = newClient(s);
        c->AddAttribute(USER_NAME, "x");
        c->Send(C_ACCESS_REQUEST, [next](EZRadiusClient &, EZResult r){ CHECK(r == EZResult::CANCELED); next(); });
        c->Cancel();
    });
    // 9. client destroyed while a request is in flight (no callback, no crash)
    g_steps.push_back([](std::function<void()> next){
        EZClientSettings s = baseSettings(); s.AuthenticationPort = 18999; s.TimeOut = 50;
        {
            EZRadiusClient tmp(g_reactor, s);
            tmp.AddAttribute(USER_NAME, "x");
            tmp.Send(C_ACCESS_REQUEST, [](EZRadiusClient &, EZResult){ CHECK(false); });
        }
        g_reactor->addTimer(200, next, true);
    });
    // 10. unknown RAS address is ignored: bind client to a different source is not possible on
    //     loopback, so use an address removed from the list instead
    g_steps.push_back([](std::function<void()> next){
        EZRadiusClient *c = newClient(baseSettings());
        c->AddAttribute(USER_NAME, "alice"); c->AddAttribute(USER_PASSWORD, "wonderland");
        // (server is stopped for the RAS 127.0.0.1 only through the list)
        c->Send(C_ACCESS_REQUEST, [next](EZRadiusClient &, EZResult r){ CHECK(r == EZResult::TIMEOUT); next(); });
    });
    // 11. CoA Disconnect + CoA NAK + bad authenticator
    g_steps.push_back([&coaSeen](std::function<void()> next){
        auto *peer = new CoAPeer;
        peer->setReactor(g_reactor);
        peer->open(AF_INET);
        peer->connect("127.0.0.1", COA_PORT);
        auto replies = std::make_shared<int>(0);
        peer->handler = [peer, replies, next](const uint8_t *d, size_t n){
            RadiusSecret sec(SECRET);
            RadiusPacket r; r.setSecret(&sec);
            CHECK(r.setRawData((const char*)d, (int)n));
            (*replies)++;
            if(*replies == 1){
                CHECK(r.getCode() == DISCONNECT_ACK);
                CHECK(r.getAttribute(USER_NAME).strValue == "alice");
            }else{
                CHECK(r.getCode() == COA_NAK);
                peer->close();
                next();
            }
        };
        RadiusSecret sec(SECRET);
        auto sendReq = [&](unsigned char code, const char *secretToUse){
            RadiusSecret use(secretToUse);
            RadiusPacket p(code); p.setSecret(&use);
            RadiusAttribute a; p.addAttribute(D_ATTR_USER_NAME, a); a.setString("alice");
            p.accountingRequestAuthenticator();
            peer->send(p.getRawData(), p.getLength());
        };
        sendReq(DISCONNECT_REQUEST, "bad-secret");      // dropped: bad Request Authenticator
        sendReq(DISCONNECT_REQUEST, SECRET);            // ack
        sendReq(COA_REQUEST, SECRET);                   // nak
        (void)coaSeen;
    });

    // run: first remove nothing; step 10 needs the RAS removed first
    g_steps.insert(g_steps.begin() + 9, [&server](std::function<void()> next){ server.RASList()->removeRASByIP("127.0.0.1"); next(); });
    g_steps.insert(g_steps.begin() + 11, [&server](std::function<void()> next){ server.RASList()->AddRAS(SECRET, "127.0.0.1"); next(); });

    // watchdog
    reactor.addTimer(20000, []{ printf("FAIL: test timed out\n"); g_fail++; g_stop = true; }, true);
    reactor.post([]{ runNext(); });
    reactor.run(g_stop);

    CHECK(coaSeen == 2);
    CHECK(g_acctSeen == 1);
    g_clients.clear();
    printf(g_fail ? "FAILED (%d)\n" : "all loopback tests passed\n", g_fail);
    return g_fail ? 1 : 0;
}
