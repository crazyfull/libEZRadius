// Throughput benchmark (not a unit test): bench_transport <udp|tcp|tls> [workers] [seconds]
// A server runs on its own reactor thread, the client workers (each one request in flight) on the main thread.
#include "EZRadiusClient.h"
#include "EZRadiusPool.h"
#include "EZRadiusServer.h"
#include "EZRadiusClientIdentify.h"
#include "EZResponse.h"
#include "EZTransport.h"
#include "clsEpollReactor.h"
#ifdef EZRADIUS_HAS_TLS
#include "EZTLS.h"
#include "test_certs.h"
#endif
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <memory>
#include <string>
#include <thread>

static void onRequest(RADIUSPacketTypeCodes type, RadiusPacket &req, EZRadiusClientIdentify &from, EZRadiusServer *, void *)
{
    EZResponse resp;
    if(type == ACCESS_REQUEST){
        AttrValue pw = req.getAttribute(USER_PASSWORD);
        resp.Send(pw.strValue == "secret" ? ACCESS_ACCEPT : ACCESS_REJECT, &from);
    }
}

int main(int argc, char **argv)
{
    const std::string mode = argc > 1 ? argv[1] : "udp";
    const int workers = argc > 2 ? atoi(argv[2]) : 32;
    const int seconds = argc > 3 ? atoi(argv[3]) : 3;
    const bool pool = mode.find("-pool") != std::string::npos;
    const std::string base = mode.substr(0, mode.find("-pool"));

    EZTransport transport = EZTransport::UDP;
    if(base == "tcp") transport = EZTransport::TCP;
    else if(base == "tls") transport = EZTransport::TLS;
    else if(base == "dtls") transport = EZTransport::DTLS;

#ifdef EZRADIUS_HAS_TLS
    TestCert ca = makeTestCert("Bench CA", nullptr);
    TestCert srvCert = makeTestCert("server", &ca, "DNS:radius.test,IP:127.0.0.1");
    TestCert cliCert = makeTestCert("client", &ca);
    EZTLSConfig serverTls, clientTls;
    serverTls.certChainPem = srvCert.certPem; serverTls.privateKeyPem = srvCert.keyPem; serverTls.caPem = ca.certPem;
    clientTls.certChainPem = cliCert.certPem; clientTls.privateKeyPem = cliCert.keyPem; clientTls.caPem = ca.certPem;
    clientTls.serverName = "radius.test";
#endif

    std::atomic<bool> stopServer{false};
    std::atomic<int> started{0};
    std::thread server([&]{
        netrector::EpollReactor reactor(0, 4096);
        EZRadiusServer srv(&reactor);
        srv.setAuthenticationPort(18620);
        srv.setAccountingPort(18621);
        srv.setDuplicateWindow(0);
        srv.EnableTCP();
        srv.SeRequestCallback(onRequest, nullptr);
        srv.RASList()->AddRAS("bench-secret", "127.0.0.1");
#ifdef EZRADIUS_HAS_TLS
        std::string err;
        if(!srv.EnableTLS(serverTls, 2083 + 100, &err) || !srv.EnableDTLS(serverTls, 2083 + 100, &err)){ printf("tls: %s\n", err.c_str()); started = -1; return; }
        srv.setRadSecIPFilter(true);
#endif
        started = srv.Start() ? 1 : -1;
        if(started == 1)
            reactor.run(stopServer);
        srv.Stop();
    });
    while(started == 0) std::this_thread::sleep_for(std::chrono::milliseconds(5));
    if(started != 1){ stopServer = true; server.join(); return 2; }

    long done = 0, failed = 0;
    {
        netrector::EpollReactor cr(0, 4096);
        std::atomic<bool> stop{false};
        EZClientSettings s;
        s.Host = "127.0.0.1"; s.Secret = "bench-secret"; s.AuthenticationPort = 18620; s.AccountingPort = 18621;
        s.RadSecPort = 2083 + 100;
        s.TimeOut = 2000; s.RetryCount = 2;
        s.Transport = transport;
#ifdef EZRADIUS_HAS_TLS
        s.TLS = clientTls;
#endif
        extern void benchApplyPool(EZClientSettings &, netrector::EpollReactor *, bool);
        benchApplyPool(s, &cr, pool);

        std::vector<std::unique_ptr<EZRadiusClient>> clients;
        std::vector<std::function<void()>> loops(workers);
        bool running = true;
        for(int i = 0; i < workers; i++){
            clients.emplace_back(new EZRadiusClient(&cr, s));
            EZRadiusClient *c = clients.back().get();
            loops[i] = [&, c, i]{
                if(!running)
                    return;
                c->Reset();
                c->AddAttribute(USER_NAME, "alice");
                c->AddAttribute(USER_PASSWORD, "secret");
                c->AddAttribute(NAS_IP_ADDRESS, "10.0.0.1");
                c->AddAttribute(NAS_PORT, 7);
                if(!c->Send(C_ACCESS_REQUEST, [&, i](EZRadiusClient &r, EZResult e){
                    if(e == EZResult::OK && r.GetResponseType() == ACCESS_ACCEPT) done++; else failed++;
                    loops[i]();
                })){
                    failed++;
                }
            };
        }
        auto t0 = std::chrono::steady_clock::now();
        cr.post([&]{ for(int i = 0; i < workers; i++) loops[i](); });
        cr.addTimer(seconds * 1000, [&]{ running = false; stop = true; }, true);
        cr.run(stop);
        double el = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
        clients.clear();
        printf("%-10s workers=%-4d ok=%ld failed=%ld  %.0f req/s\n", mode.c_str(), workers, done, failed, done / el);
    }
    stopServer = true;
    server.join();
    return 0;
}

void benchApplyPool(EZClientSettings &s, netrector::EpollReactor *r, bool pool)
{
    if(!pool)
        return;
    std::shared_ptr<EZRadiusPool> p = EZRadiusPool::create(r, s);
    if(!p){ printf("pool: invalid settings\n"); exit(2); }
    s.Pool = p;
}
