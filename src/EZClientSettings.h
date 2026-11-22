/*
 * libEZRadius
 *
 * Copyright (c) 2023-2026 Mojtaba Kahvand.
 * All rights reserved.
 *
 * Licensed under the GNU Lesser General Public License v2.1.
 * See LICENSE for details.
 */

#ifndef EZCLIENTSETTINGS_H
#define EZCLIENTSETTINGS_H
#include <memory>
#include <string>
#include "EZTransport.h"
#include "EZTLS.h"

class EZRadiusPool;

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

    // Transport: UDP (default), TCP (RFC 6613), TLS (RadSec, RFC 6614) or DTLS (RFC 7360).
    // TCP uses the Authentication / Accounting / CoA ports above (TCP, same numbers); TLS and DTLS use RadSecPort.
    // Over TLS the shared secret is the fixed string "radsec", over DTLS "radius/dtls" (Secret is ignored).
    EZTransport Transport = EZTransport::UDP;
    int RadSecPort = 2083;
    // TCP / TLS / DTLS: keep the connection open after a request and use it for the next request of the same
    // client object (a new connection is made when it was closed). RADIUS over TCP does not retransmit on a
    // connection: RetryCount > 1 means "reconnect and send again".
    bool ReuseConnection = true;

#ifdef EZRADIUS_HAS_TLS
    // TLS / DTLS settings (certificates, trust, server name, RADIUS/1.1 negotiation): see EZTLS.h
    EZTLSConfig TLS;
#endif

    // Optional connection pool (see EZRadiusPool.h): the client then sends its requests through the pool's
    // shared sockets / connections. Host, Secret, Transport and TLS of the pool are used instead of the ones here.
    std::shared_ptr<EZRadiusPool> Pool;

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
