// EZRadiusPool: shared sockets / connections for the asynchronous client.
#include "EZRadiusClient.h"
#include "EZRadiusPool.h"
#include "EZRadiusServer.h"
#include "EZRadiusSyncClient.h"
#include "EZRadiusClientIdentify.h"
#include "EZResponse.h"
#include "clsEpollReactor.h"
#ifdef EZRADIUS_HAS_TLS
#include "EZTLS.h"
#include "test_certs.h"
#endif
#include <arpa/inet.h>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <functional>
#include <future>
#include <netinet/in.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

static int g_fail = 0;
#define CHECK(c) do { if(!(c)){ printf("FAIL line %d: %s\n", __LINE__, #c); g_fail++; } } while(0)

static std::atomic<int> g_requests{0};
static void onRequest(RADIUSPacketTypeCodes type, RadiusPacket &req, EZRadiusClientIdentify &from, EZRadiusServer *, void *)
{
    g_requests++;
    EZResponse resp;
    if(type == ACCESS_REQUEST){
        AttrValue pw = req.getAttribute(USER_PASSWORD);
        resp.Send(pw.strValue == "secret" ? ACCESS_ACCEPT : ACCESS_REJECT, &from);
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

// The client side runs on its own reactor thread (a connection only lives while its reactor runs); the test
// thread drives it with run().
struct Loop
{
    netrector::EpollReactor r{0, 64};
    std::atomic<bool> stop{false};
    std::thread t;
    Loop() { t = std::thread([this]{ r.run(stop); }); }
    ~Loop() { stop = true; r.post([]{}); t.join(); }
    template <class F> auto run(F f) -> decltype(f()) { return onReactor(r, f); }
};

struct Burst
{
    int ok = 0, accepted = 0, failed = 0, notStarted = 0, used11 = 0;
};

// Runs `count` requests at once (one client object each) and waits for all of them.
static Burst burst(Loop &L, const EZClientSettings &s, int count, RADIUSClientRequestType type = C_ACCESS_REQUEST, const char *password = "secret")
{
    struct State { Burst b; int pending = 0; bool signaled = false; std::vector<std::unique_ptr<EZRadiusClient>> clients; std::promise<Burst> pr; };
    auto st = std::make_shared<State>();
    auto fut = st->pr.get_future();
    L.r.post([&L, s, count, type, password, st]{
        for(int i = 0; i < count; i++){
            st->clients.emplace_back(new EZRadiusClient(&L.r, s));
            EZRadiusClient *c = st->clients.back().get();
            c->AddAttribute(USER_NAME, "alice");
            if(type == C_ACCESS_REQUEST){
                c->AddAttribute(USER_PASSWORD, password);
            }else{
                c->AddAttribute(ACCT_STATUS_TYPE, 1);
                c->AddAttribute(ACCT_SESSION_ID, "sess-1");
            }
            const bool started = c->Send(type, [st](EZRadiusClient &r, EZResult e){
                if(e == EZResult::OK){
                    st->b.ok++;
                    const RADIUSPacketTypeCodes t = r.GetResponseType();
                    if(t == ACCESS_ACCEPT || t == ACCOUNTING_RESPONSE)
                        st->b.accepted++;
                    if(r.UsedRadius11())
                        st->b.used11++;
                }else{
                    st->b.failed++;
                }
                if(--st->pending == 0 && !st->signaled){
                    st->signaled = true;
                    st->pr.set_value(st->b);
                }
            });
            if(started)
                st->pending++;
            else
                st->b.notStarted++;
        }
        if(st->pending == 0 && !st->signaled){
            st->signaled = true;
            st->pr.set_value(st->b);
        }
    });
    Burst b;
    if(fut.wait_for(std::chrono::seconds(20)) == std::future_status::ready)
        b = fut.get();
    else
        b.failed = -1;
    L.run([&]{ st->clients.clear(); return 0; });
    return b;
}

static const int AUTH_PORT = 18700, ACCT_PORT = 18701, SEC_PORT = 18702;

int main()
{
#ifdef EZRADIUS_HAS_TLS
    TestCert ca = makeTestCert("Test CA", nullptr);
    TestCert srvCert = makeTestCert("server", &ca, "DNS:radius.test,IP:127.0.0.1");
    TestCert cliCert = makeTestCert("client", &ca);
    EZTLSConfig serverTls, clientTls;
    serverTls.certChainPem = srvCert.certPem; serverTls.privateKeyPem = srvCert.keyPem; serverTls.caPem = ca.certPem;
    clientTls.certChainPem = cliCert.certPem; clientTls.privateKeyPem = cliCert.keyPem; clientTls.caPem = ca.certPem;
    clientTls.serverName = "radius.test";
#endif

    std::atomic<bool> stopServer{false};
    std::atomic<int> started{0};
    netrector::EpollReactor *reactorPtr = nullptr;
    EZRadiusServer *srvPtr = nullptr;
    std::thread server([&]{
        netrector::EpollReactor reactor(0, 64);
        EZRadiusServer srv(&reactor);
        srv.setAuthenticationPort(AUTH_PORT);
        srv.setAccountingPort(ACCT_PORT);
        srv.setDuplicateWindow(0);
        srv.EnableTCP();
        srv.SeRequestCallback(onRequest, nullptr);
        srv.RASList()->AddRAS("pool-secret", "127.0.0.1");
#ifdef EZRADIUS_HAS_TLS
        std::string err;
        if(!srv.EnableTLS(serverTls, SEC_PORT, &err) || !srv.EnableDTLS(serverTls, SEC_PORT, &err)){ printf("tls: %s\n", err.c_str()); started = -1; return; }
#endif
        reactorPtr = &reactor; srvPtr = &srv;
        started = srv.Start() ? 1 : -1;
        if(started == 1)
            reactor.run(stopServer);
        srv.Stop();
    });
    while(started == 0) std::this_thread::sleep_for(std::chrono::milliseconds(5));
    CHECK(started == 1);
    if(started != 1){ stopServer = true; server.join(); return 1; }

    EZClientSettings base;
    base.Host = "127.0.0.1"; base.Secret = "pool-secret"; base.AuthenticationPort = AUTH_PORT; base.AccountingPort = ACCT_PORT;
    base.RadSecPort = SEC_PORT; base.TimeOut = 1500; base.RetryCount = 2;

    // helpers: all pool calls happen on the client reactor thread
    auto mkPool = [](Loop &L, EZClientSettings &s) { auto p = L.run([&]{ return EZRadiusPool::create(&L.r, s); }); s.Pool = p; return p; };
    auto drop = [](Loop &L, EZClientSettings &s, std::shared_ptr<EZRadiusPool> &p) { L.run([&]{ s.Pool.reset(); p.reset(); return 0; }); };
    auto connected = [](Loop &L, std::shared_ptr<EZRadiusPool> &p) { return L.run([&]{ return p->connectedCount(); }); };
    auto reconnects = [](Loop &L, std::shared_ptr<EZRadiusPool> &p) { return L.run([&]{ return p->reconnects(); }); };
    auto inFlight = [](Loop &L, std::shared_ptr<EZRadiusPool> &p) { return L.run([&]{ return p->inFlight(); }); };
    auto serverConns = [&]{ return onReactor(*reactorPtr, [&]{ return srvPtr->connectionCount(); }); };

    {   // ---- UDP: one socket carries 200 requests at once (the Identifier tells them apart) ----
        Loop L;
        EZClientSettings s = base;
        auto pool = mkPool(L, s);
        CHECK(pool != nullptr);
        Burst b = burst(L, s, 200);
        CHECK(b.ok == 200 && b.accepted == 200 && b.failed == 0);
        CHECK(inFlight(L, pool) == 0);
        Burst r = burst(L, s, 5, C_ACCESS_REQUEST, "bad");      // Access-Reject is a valid answer, not an accept
        CHECK(r.ok == 5 && r.accepted == 0);
        Burst a = burst(L, s, 20, C_ACCOUNTING_REQUEST);        // Request Authenticator computed after the Identifier is known
        CHECK(a.ok == 20 && a.accepted == 20);
        Burst many = burst(L, s, 300);                          // more than 256 on one socket: the surplus is refused
        CHECK(many.notStarted == 300 - 256 && many.ok == 256);
        drop(L, s, pool);
    }
    {   // two connections carry 300 requests
        Loop L;
        EZClientSettings s = base;
        auto pool = mkPool(L, s);
        L.run([&]{ pool->setConnections(2); return 0; });
        Burst b = burst(L, s, 300);
        CHECK(b.ok == 300 && b.notStarted == 0);
        drop(L, s, pool);
    }
    {   // ---- TCP: the connection outlives the clients ----
        Loop L;
        EZClientSettings s = base;
        s.Transport = EZTransport::TCP;
        auto pool = mkPool(L, s);
        Burst b = burst(L, s, 150);
        CHECK(b.ok == 150 && b.accepted == 150);
        CHECK(connected(L, pool) == 1);
        CHECK(serverConns() == 1);
        Burst b2 = burst(L, s, 150);                            // new client objects, same connection
        CHECK(b2.ok == 150);
        CHECK(serverConns() == 1);
        Burst a = burst(L, s, 10, C_ACCOUNTING_REQUEST);        // the accounting port is a second connection
        CHECK(a.ok == 10);
        CHECK(connected(L, pool) == 2);
        CHECK(reconnects(L, pool) == 0);
        drop(L, s, pool);
    }
    {   // ---- clients destroyed while their requests are in flight ----
        Loop L;
        EZClientSettings s = base;
        s.Transport = EZTransport::TCP;
        auto pool = mkPool(L, s);
        L.run([&]{
            std::vector<std::unique_ptr<EZRadiusClient>> clients;
            for(int i = 0; i < 50; i++){
                clients.emplace_back(new EZRadiusClient(&L.r, s));
                clients.back()->AddAttribute(USER_NAME, "alice");
                clients.back()->AddAttribute(USER_PASSWORD, "secret");
                CHECK(clients.back()->Send(C_ACCESS_REQUEST, [](EZRadiusClient &, EZResult){ CHECK(false); }));
            }
            CHECK(pool->inFlight() == 50);
            clients.clear();                                    // no callback, nothing left in the pool
            CHECK(pool->inFlight() == 0);
            return 0;
        });
        Burst b = burst(L, s, 20);                              // late answers of the old requests are ignored
        CHECK(b.ok == 20);
        // pool->close(): requests are canceled, a closed pool reconnects on demand
        EZResult got = EZResult::NONE;
        L.run([&]{
            EZRadiusClient c(&L.r, s);
            c.AddAttribute(USER_NAME, "alice"); c.AddAttribute(USER_PASSWORD, "secret");
            CHECK(c.Send(C_ACCESS_REQUEST, [&](EZRadiusClient &, EZResult e){ got = e; }));
            pool->close();
            CHECK(got == EZResult::CANCELED && pool->connectedCount() == 0);
            return 0;
        });
        CHECK(burst(L, s, 5).ok == 5);
        drop(L, s, pool);
    }
    {   // ---- reconnect: the server goes away and comes back ----
        Loop L;
        EZClientSettings s = base;
        s.Transport = EZTransport::TCP;
        s.TimeOut = 3000;
        auto pool = mkPool(L, s);
        L.run([&]{ pool->setReconnectDelay(200, 400); return 0; });
        CHECK(burst(L, s, 5).ok == 5);
        CHECK(onReactor(*reactorPtr, [&]{ srvPtr->Stop(); return true; }));
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        CHECK(connected(L, pool) == 0);
        CHECK(reconnects(L, pool) >= 1);
        // a request made while the server is down waits and is answered after the restart
        std::thread restart([&]{
            std::this_thread::sleep_for(std::chrono::milliseconds(600));
            onReactor(*reactorPtr, [&]{ return srvPtr->Start(); });
        });
        Burst b = burst(L, s, 10);
        restart.join();
        CHECK(b.ok == 10);
        CHECK(connected(L, pool) == 1);
        drop(L, s, pool);
    }

    // ---- watchdog: a peer that accepts and never answers is detected (raw TCP black hole) ----
    {
        int ls = socket(AF_INET, SOCK_STREAM, 0);
        int one = 1; setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        struct sockaddr_in a; memset(&a, 0, sizeof(a));
        a.sin_family = AF_INET; a.sin_port = htons(18710); a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        CHECK(bind(ls, (struct sockaddr*)&a, sizeof(a)) == 0 && listen(ls, 8) == 0);
        std::atomic<int> accepts{0};
        std::atomic<bool> done{false};
        std::thread hole([&]{
            std::vector<int> conns;
            while(!done){
                struct timeval tv = {0, 100000};
                fd_set fs; FD_ZERO(&fs); FD_SET(ls, &fs);
                int mx = ls;
                for(int c : conns){ FD_SET(c, &fs); if(c > mx) mx = c; }
                if(select(mx + 1, &fs, nullptr, nullptr, &tv) <= 0) continue;
                if(FD_ISSET(ls, &fs)){ int c = accept(ls, nullptr, nullptr); if(c >= 0){ conns.push_back(c); accepts++; } }
                for(size_t i = 0; i < conns.size();){
                    char buf[512];
                    if(FD_ISSET(conns[i], &fs) && recv(conns[i], buf, sizeof(buf), 0) <= 0){ close(conns[i]); conns.erase(conns.begin() + i); }
                    else i++;
                }
            }
            for(int c : conns) close(c);
        });
        Loop L;
        EZClientSettings s = base;
        s.Transport = EZTransport::TCP; s.AuthenticationPort = 18710; s.TimeOut = 300; s.RetryCount = 1;
        auto pool = mkPool(L, s);
        L.run([&]{ pool->setKeepAlive(200); pool->setReconnectDelay(100, 200); pool->connect(); return 0; });
        std::this_thread::sleep_for(std::chrono::milliseconds(2500));
        CHECK(accepts >= 2);                                    // probe unanswered -> closed -> reconnected
        CHECK(reconnects(L, pool) >= 1);
        Burst b = burst(L, s, 3);                               // a request to a peer that never answers times out
        CHECK(b.ok == 0 && b.failed == 3);
        drop(L, s, pool);
        done = true;
        hole.join();
        close(ls);
    }

    {   // a pool given to the blocking client is ignored (it has its own reactor)
        Loop L;
        EZClientSettings s = base;
        auto pool = mkPool(L, s);
        EZRadiusSyncClient sc(s);
        sc.AddAttribute(USER_NAME, "alice"); sc.AddAttribute(USER_PASSWORD, "secret");
        CHECK(sc.Send(C_ACCESS_REQUEST) == EZResult::OK && sc.GetResponseType() == ACCESS_ACCEPT);
        drop(L, s, pool);
    }

#ifdef EZRADIUS_HAS_TLS
    {   // ---- RadSec through the pool: one TLS session, RADIUS/1.1 negotiated ----
        Loop L;
        EZClientSettings s = base;
        s.Transport = EZTransport::TLS; s.TLS = clientTls;
        auto pool = mkPool(L, s);
        CHECK(pool != nullptr);
        Burst b = burst(L, s, 120);
        CHECK(b.ok == 120 && b.accepted == 120 && b.used11 == 120);
        CHECK(connected(L, pool) == 1);
        CHECK(serverConns() == 1);
        Burst a = burst(L, s, 10, C_ACCOUNTING_REQUEST);        // same connection (one RadSec port)
        CHECK(a.ok == 10 && connected(L, pool) == 1);
        CHECK(burst(L, s, 5, C_ACCESS_REQUEST, "bad").accepted == 0);
        drop(L, s, pool);
    }
    {   // RADIUS/1.0 only
        Loop L;
        EZClientSettings s = base;
        s.Transport = EZTransport::TLS; s.TLS = clientTls; s.TLS.radiusVersions = "1.0";
        auto pool = mkPool(L, s);
        Burst b = burst(L, s, 60);
        CHECK(b.ok == 60 && b.used11 == 0);
        drop(L, s, pool);
    }
    {   // bad configuration is refused at creation
        Loop L;
        EZClientSettings s = base;
        s.Transport = EZTransport::TLS;                         // no certificates
        CHECK(mkPool(L, s) == nullptr);
    }
    {   // ---- DTLS through the pool: one session for many requests ----
        Loop L;
        EZClientSettings s = base;
        s.Transport = EZTransport::DTLS; s.TLS = clientTls;
        auto pool = mkPool(L, s);
        CHECK(pool != nullptr);
        Burst b = burst(L, s, 100);
        CHECK(b.ok == 100 && b.accepted == 100);
        CHECK(connected(L, pool) == 1);
        Burst b2 = burst(L, s, 100);
        CHECK(b2.ok == 100 && reconnects(L, pool) == 0);
        drop(L, s, pool);
    }
    {   // one-shot DTLS clients close their session: more than the server's session limit (1024) in a row still works
        Loop L;
        EZClientSettings s = base;
        s.Transport = EZTransport::DTLS; s.TLS = clientTls; s.TimeOut = 3000;
        int ok = 0;
        for(int i = 0; i < 22; i++)
            ok += burst(L, s, 50).ok;
        CHECK(ok == 1100);
    }
#endif

    stopServer = true;
    server.join();
    if(g_fail){
        printf("%d check(s) failed\n", g_fail);
        return 1;
    }
    printf("all pool tests passed\n");
    return 0;
}
