// Asynchronous client: Accounting-Start, then an Access-Request (PAP) when the accounting finished.
//   ./ezradius_client <host> <secret> <user> <password>
#include <atomic>
#include <csignal>
#include <cstdio>
#include "clsEpollReactor.h"
#include "EZRadiusClient.h"

static std::atomic<bool> g_stop{false};

static const char *resultText(EZResult r)
{
    switch(r){
    case EZResult::OK: return "ok";
    case EZResult::TIMEOUT: return "timeout";
    case EZResult::DNS_FAILED: return "dns failed";
    case EZResult::SEND_FAILED: return "send failed";
    case EZResult::CANCELED: return "canceled";
    default: return "?";
    }
}

int main(int argc, char **argv)
{
    EZClientSettings settings;
    settings.Host = argc > 1 ? argv[1] : "127.0.0.1";     // IPv4 or host name (resolved asynchronously)
    settings.Secret = argc > 2 ? argv[2] : "change-me";
    const char *user = argc > 3 ? argv[3] : "user";
    const char *pass = argc > 4 ? argv[4] : "pass";
    settings.TimeOut = 1500;        // ms per attempt
    settings.RetryCount = 3;        // attempts

    signal(SIGINT, [](int){ g_stop = true; });

    netrector::EpollReactor reactor(0, 64);

    EZRadiusClient accounting(&reactor, settings);
    EZRadiusClient auth(&reactor, settings);

    accounting.AddAttribute(ACCT_STATUS_TYPE, (int)RADIUSAcctStatusType::START);
    accounting.AddAttribute(USER_NAME, user);
    accounting.AddAttribute(NAS_IP_ADDRESS, "192.168.1.1");
    accounting.AddAttribute(CALLING_STATION_ID, "192.168.1.10");
    accounting.AddAttribute(ACCT_SESSION_ID, "my-session-1");

    auth.AddAttribute(USER_NAME, user);
    auth.AddAttribute(USER_PASSWORD, pass);          // PAP (CHAP_PASSWORD for CHAP)
    auth.AddAttribute(NAS_IP_ADDRESS, "192.168.1.1");

    // nothing blocks: both requests are started at once and finish from the reactor
    accounting.Send(C_ACCOUNTING_REQUEST, [](EZRadiusClient &c, EZResult r){
        printf("accounting: %s %s\n", resultText(r), c.GetResponseTypeDescription());
    });
    auth.Send(C_ACCESS_REQUEST, [](EZRadiusClient &c, EZResult r){
        printf("access: %s %s\n", resultText(r), c.GetResponseTypeDescription());
        if(r == EZResult::OK && c.GetResponseType() != ACCESS_ACCEPT)
            printf("reply-message: %s\n", c.GetAttribute(REPLY_MESSAGE).strValue.c_str());
        g_stop = true;
    });

    reactor.run(g_stop);
    return 0;
}
