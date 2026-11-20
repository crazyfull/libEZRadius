// CoA / Disconnect listener (RFC 5176). Host / RAS_IP = addresses allowed to send requests.
//   ./ezradius_coa <server-host-or-ip> <secret>
#include <atomic>
#include <csignal>
#include <cstdio>
#include "clsEpollReactor.h"
#include "EZCoA.h"

static std::atomic<bool> g_stop{false};

static RADIUSPacketTypeCodes onCoA(RADIUSPacketTypeCodes type, RadiusPacket &request, EZResponse &response, void *)
{
    printf("%s user=[%s] session=[%s]\n", request.getCodeDescription((unsigned char)type),
           request.getAttribute(USER_NAME).strValue.c_str(), request.getAttribute(ACCT_SESSION_ID).strValue.c_str());

    // identify the session in the answer
    response.AddAttribute(USER_NAME, request.getAttribute(USER_NAME).strValue.c_str());
    response.AddAttribute(ACCT_SESSION_ID, request.getAttribute(ACCT_SESSION_ID).strValue.c_str());

    return type == DISCONNECT_REQUEST ? DISCONNECT_ACK : COA_ACK;
}

int main(int argc, char **argv)
{
    EZClientSettings settings;
    settings.Host = argc > 1 ? argv[1] : "127.0.0.1";
    settings.Secret = argc > 2 ? argv[2] : "change-me";
    settings.CoAPort = 3799;

    signal(SIGINT, [](int){ g_stop = true; });
    netrector::EpollReactor reactor(0, 64);

    EZCoA coa(&reactor, settings);
    coa.SetGetRequests(onCoA, nullptr);
    if(!coa.Start()){
        fprintf(stderr, "can not bind the CoA port\n");
        return 1;
    }
    reactor.run(g_stop);
    return 0;
}
