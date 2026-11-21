// RADIUS transports: framing, TCP (RFC 6613) end to end, connection reuse and error handling.
#include "EZRadiusSyncClient.h"
#include "EZRadiusClient.h"
#include <functional>
#include "EZRadiusServer.h"
#include "EZRadiusClientIdentify.h"
#include "EZResponse.h"
#include "EZTransport.h"
#include "clsEpollReactor.h"
#include <arpa/inet.h>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <future>
#include <netinet/in.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

static int g_fail = 0;
#define CHECK(c) do { if(!(c)){ printf("FAIL line %d: %s\n", __LINE__, #c); g_fail++; } } while(0)

static void test_framer()
{
    EZStreamFramer f;
    std::string p;
    uint8_t pkt[24] = {2, 1, 0, 24};                            // Access-Accept, length 24
    CHECK(f.next(p) == EZStreamFramer::NEED_MORE);
    f.append(pkt, 3);
    CHECK(f.next(p) == EZStreamFramer::NEED_MORE);
    f.append(pkt + 3, 10);
    CHECK(f.next(p) == EZStreamFramer::NEED_MORE);              // header known, body incomplete
    f.append(pkt + 13, 11);
    CHECK(f.next(p) == EZStreamFramer::PACKET && p.size() == 24 && f.buffered() == 0);
    // two packets in one read + the start of a third
    std::string two((const char*)pkt, 24);
    two += std::string((const char*)pkt, 24);
    two += std::string((const char*)pkt, 6);
    f.append((const uint8_t*)two.data(), two.size());
    CHECK(f.next(p) == EZStreamFramer::PACKET);
    CHECK(f.next(p) == EZStreamFramer::PACKET);
    CHECK(f.next(p) == EZStreamFramer::NEED_MORE && f.buffered() == 6);
    // bad lengths close the connection
    EZStreamFramer g;
    uint8_t small[4] = {1, 0, 0, 19};
    g.append(small, 4);
    CHECK(g.next(p) == EZStreamFramer::INVALID);
    EZStreamFramer h;
    uint8_t big[4] = {1, 0, 0x10, 0x01};                        // 4097
    h.append(big, 4);
    CHECK(h.next(p) == EZStreamFramer::INVALID);
    EZStreamFramer k;
    uint8_t max[4] = {1, 0, 0x10, 0x00};                        // 4096 is allowed
    k.append(max, 4);
    CHECK(k.next(p) == EZStreamFramer::NEED_MORE);
}

static std::atomic<int> g_requests{0};
static void onRequest(RADIUSPacketTypeCodes type, RadiusPacket &req, EZRadiusClientIdentify &from, EZRadiusServer *, void *)
{
    g_requests++;
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

static EZClientSettings settings(uint16_t authPort, uint16_t acctPort)
{
    EZClientSettings s;
    s.Host = "127.0.0.1"; s.Secret = "tcp-secret"; s.AuthenticationPort = authPort; s.AccountingPort = acctPort;
    s.TimeOut = 800; s.RetryCount = 2;
    s.Transport = EZTransport::TCP;
    return s;
}

int main()
{
    test_framer();

    std::atomic<bool> stop{false};
    std::atomic<int> started{0};
    netrector::EpollReactor *reactorPtr = nullptr;
    EZRadiusServer *srvPtr = nullptr;
    std::thread server([&]{
        netrector::EpollReactor reactor(0, 16);
        EZRadiusServer srv(&reactor);
        srv.setAuthenticationPort(18520);
        srv.setAccountingPort(18521);
        srv.EnableTCP();
        srv.SeRequestCallback(onRequest, nullptr);
        srv.RASList()->AddRAS("tcp-secret", "127.0.0.1");
        reactorPtr = &reactor; srvPtr = &srv;
        started = srv.Start() ? 1 : -1;
        reactor.run(stop);
        srv.Stop();
    });
    while(started == 0) std::this_thread::sleep_for(std::chrono::milliseconds(5));
    CHECK(started == 1);

    {   // asynchronous client: one reactor run, several requests on the same object
        netrector::EpollReactor cr(0, 16);
        std::atomic<bool> done{false};
        EZRadiusClient c(&cr, settings(18520, 18521));
        auto conns = [&]{ return onReactor(*reactorPtr, [&]{ return srvPtr->connectionCount(); }); };
        std::function<void(int)> step;
        step = [&](int i){
            c.Reset();
            switch(i){
            case 0:     // Access-Request / Accept with a PAP password
                CHECK(c.AddAttribute(USER_NAME, "alice") && c.AddAttribute(USER_PASSWORD, "secret"));
                CHECK(c.Send(C_ACCESS_REQUEST, [&](EZRadiusClient &r, EZResult e){
                    CHECK(e == EZResult::OK && r.GetResponseType() == ACCESS_ACCEPT);
                    CHECK(conns() == 1);
                    step(1);
                }));
                break;
            case 1:     // the same connection carries the next request
                CHECK(c.AddAttribute(USER_NAME, "alice") && c.AddAttribute(USER_PASSWORD, "wrong"));
                CHECK(c.Send(C_ACCESS_REQUEST, [&](EZRadiusClient &r, EZResult e){
                    CHECK(e == EZResult::OK && r.GetResponseType() == ACCESS_REJECT);
                    CHECK(conns() == 1);
                    step(2);
                }));
                break;
            case 2:     // Status-Server (RFC 5997) is answered by the library
                CHECK(c.Send(C_STATUS_SERVER, [&](EZRadiusClient &r, EZResult e){
                    CHECK(e == EZResult::OK && r.GetResponseType() == ACCESS_ACCEPT);
                    step(3);
                }));
                break;
            case 3:     // accounting uses the accounting port: a new connection replaces the old one
                CHECK(c.AddAttribute(USER_NAME, "alice"));
                CHECK(c.AddAttribute(ACCT_STATUS_TYPE, (uint32_t)1));
                CHECK(c.AddAttribute(ACCT_SESSION_ID, "s1"));
                CHECK(c.Send(C_ACCOUNTING_REQUEST, [&](EZRadiusClient &r, EZResult e){
                    CHECK(e == EZResult::OK && r.GetResponseType() == ACCOUNTING_RESPONSE);
                    CHECK(conns() >= 1);          // one connection per client object: the old one is replaced
                    step(4);
                }));
                break;
            default:    // back to authentication
                CHECK(c.AddAttribute(USER_NAME, "alice") && c.AddAttribute(USER_PASSWORD, "secret"));
                CHECK(c.Send(C_ACCESS_REQUEST, [&](EZRadiusClient &r, EZResult e){
                    CHECK(e == EZResult::OK && r.GetResponseType() == ACCESS_ACCEPT);
                    done = true;
                }));
                break;
            }
        };
        cr.post([&]{ step(0); });
        cr.run(done);
    }
    // the client is gone: its connections are closed
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    { size_t n = onReactor(*reactorPtr, [&]{ return srvPtr->connectionCount(); }); if(n != 0) printf("conn count %zu\n", n); CHECK(n == 0); }

    {   // the blocking client works over TCP too (one connection per Send(): the private reactor closes it)
        EZRadiusSyncClient c(settings(18520, 18521));
        CHECK(c.AddAttribute(USER_NAME, "alice") && c.AddAttribute(USER_PASSWORD, "secret"));
        CHECK(c.Send(C_ACCESS_REQUEST) == EZResult::OK);
        CHECK(c.GetResponseType() == ACCESS_ACCEPT);
        c.Reset();
        CHECK(c.AddAttribute(USER_NAME, "alice") && c.AddAttribute(USER_PASSWORD, "wrong"));
        CHECK(c.Send(C_ACCESS_REQUEST) == EZResult::OK);
        CHECK(c.GetResponseType() == ACCESS_REJECT);
    }

    {   // wrong secret: the server drops the packet (bad Request Authenticator / Message-Authenticator) and closes
        EZClientSettings s = settings(18520, 18521);
        s.Secret = "other";
        s.TimeOut = 300; s.RetryCount = 1;
        EZRadiusSyncClient c(s);
        CHECK(c.AddAttribute(USER_NAME, "alice") && c.AddAttribute(USER_PASSWORD, "secret"));
        EZResult r = c.Send(C_ACCESS_REQUEST);
        CHECK(r != EZResult::OK);
    }

    {   // a raw peer sending a packet with an impossible length is disconnected
        int fd = ::socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in a{};
        a.sin_family = AF_INET; a.sin_port = htons(18520); inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
        CHECK(::connect(fd, (sockaddr*)&a, sizeof(a)) == 0);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        { size_t n_ = onReactor(*reactorPtr, [&]{ return srvPtr->connectionCount(); }); if(n_ != 1) printf("conn count %zu expected 1 (line %d)\n", n_, __LINE__); CHECK(n_ == 1); }
        const uint8_t bad[8] = {1, 1, 0, 3, 0, 0, 0, 0};
        CHECK(::write(fd, bad, sizeof(bad)) == (ssize_t)sizeof(bad));
        char buf[8];
        CHECK(::read(fd, buf, sizeof(buf)) == 0);                 // the server closed the connection
        ::close(fd);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        { size_t n_ = onReactor(*reactorPtr, [&]{ return srvPtr->connectionCount(); }); if(n_ != 0) printf("conn count %zu expected 0 (line %d)\n", n_, __LINE__); CHECK(n_ == 0); }
    }

    CHECK(g_requests >= 5);
    stop = true;
    server.join();
    printf(g_fail ? "FAILED (%d)\n" : "all transport tests passed\n", g_fail);
    return g_fail ? 1 : 0;
}
