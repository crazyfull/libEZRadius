#ifndef EZCLIENTSETTINGS_H
#define EZCLIENTSETTINGS_H
#include <string>

class EZClientSettings
{
public:
    // time to wait for a response (milliseconds), per attempt
    int TimeOut = 2200;

    // total number of attempts (the request is retransmitted when no valid response arrived in TimeOut)
    int RetryCount = 1;

    int AuthenticationPort = 1812;
    int AccountingPort = 1813;
    int CoAPort = 3799;
    int AcctInterimIntravel = 0;

    // RADIUS server (IPv4 address or host name; names are resolved asynchronously)
    std::string Host;
    std::string Secret;
    std::string NAS_IP;

    // CoA / Disconnect listener: second address that is allowed to send requests (RAS = NAS address)
    std::string RAS_IP;

    // Client: add (and sign) a Message-Authenticator attribute (RFC 3579) to every Access-Request.
    // This protects the request from the BlastRADIUS attack (CVE-2024-3596).
    bool UseMessageAuthenticator = true;

    // Client: drop Access-Accept / Reject / Challenge responses that have no valid Message-Authenticator.
    // Enable it when the server is known to send it (recommended for servers patched against BlastRADIUS).
    bool RequireMessageAuthenticator = false;

    EZClientSettings() = default;
};

#endif // EZCLIENTSETTINGS_H
