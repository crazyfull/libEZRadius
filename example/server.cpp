// Minimal RADIUS server: answers every Access-Request with Access-Accept and every
// Accounting-Request with Accounting-Response. Single thread, fully asynchronous.
//   ./ezradius_server [secret] [nas-ip]
#include <atomic>
#include <csignal>
#include <cstdio>
#include "clsEpollReactor.h"
#include "EZRadiusServer.h"
#include "EZRadiusClientIdentify.h"
#include "EZResponse.h"

static std::atomic<bool> g_stop{false};

static void onReceiveRequest(RADIUSPacketTypeCodes type, RadiusPacket &request, EZRadiusClientIdentify &from, EZRadiusServer *, void *)
{
    // never log passwords
    printf("%s from %s user=[%s] nas-port=%u\n", request.getCodeDescription((unsigned char)type), from.IPAddressDescription().c_str(),
           request.getAttribute(USER_NAME).strValue.c_str(), request.getAttribute(NAS_PORT).intValue);

    EZResponse response;
    if(type == ACCESS_REQUEST){
        response.AddAttribute(SERVICE_TYPE, 2);                 // Framed
        response.AddAttribute(FRAMED_PROTOCOL, (uint32_t)1);    // PPP
        response.AddAttribute(ACCT_INTERIM_INTERVAL, 60);
        response.AddVendorAttribute(14988, 8, "10M/10M");        // MikroTik Rate-Limit
        response.Send(ACCESS_ACCEPT, &from);
    }else if(type == ACCOUNTING_REQUEST){
        response.Send(ACCOUNTING_RESPONSE, &from);
    }
}

int main(int argc, char **argv)
{
    const char *secret = argc > 1 ? argv[1] : "change-me";
    const char *nas = argc > 2 ? argv[2] : "127.0.0.1";

    signal(SIGINT, [](int){ g_stop = true; });
    signal(SIGTERM, [](int){ g_stop = true; });

    netrector::EpollReactor reactor(0, 1024);

    EZRadiusServer server(&reactor);
    server.setAuthenticationPort(1812);
    server.setAccountingPort(1813);
    server.SeRequestCallback(onReceiveRequest, nullptr);
    server.RASList()->AddRAS(secret, nas);     // only these addresses are served

    if(!server.Start()){
        fprintf(stderr, "can not bind the RADIUS ports\n");
        return 1;
    }

    printf("RADIUS server running (auth %u, acct %u)\n", server.AuthenticatorPort(), server.AccountingPort());
    reactor.run(g_stop);
    return 0;
}
