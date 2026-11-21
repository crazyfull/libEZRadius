/*
 * libEZRadius
 *
 * Copyright (c) 2023-2026 Mojtaba Kahvand.
 * All rights reserved.
 *
 * Licensed under the GNU Lesser General Public License v2.1.
 * See LICENSE for details.
 */

#ifndef EZCOA_H
#define EZCOA_H
#include "EZClientSettings.h"
#include "EZRadiusServer.h"
#include "RadiusPacket.h"
#include "EZResponse.h"
#include <functional>
#include <memory>

// Called for every valid Disconnect-Request / CoA-Request. Return DISCONNECT_ACK / DISCONNECT_NAK for a
// Disconnect-Request and COA_ACK / COA_NAK for a CoA-Request. UNKNOWN (or a code of the wrong kind): no answer.
typedef std::function< RADIUSPacketTypeCodes (RADIUSPacketTypeCodes type, RadiusPacket& request, EZResponse &response, void *p)> CoACallback;

// RFC 5176 Dynamic Authorization listener (non blocking, on a netRector reactor).
// Settings used: Host and RAS_IP (the addresses allowed to send requests; host names are resolved
// asynchronously), Secret, CoAPort.
class EZCoA
{
    EZClientSettings m_settings;
    CoACallback m_callback;
    std::unique_ptr<EZRadiusServer> m_pServer;
    void *m_pPointerCallback = nullptr;
    bool m_alive = true;

    static void onGetRadiusRequest(RADIUSPacketTypeCodes PacketType, RadiusPacket &request, EZRadiusClientIdentify &ClientIdentify, EZRadiusServer *pRadiusServer, void *p);
    static void onResolved(const char *hostname, char **ips, size_t count, int qtype, void *user_data);
    void addAllowed(const std::string &hostOrIp);

public:
    EZCoA(netrector::EpollReactor *reactor, const EZClientSettings &Settings);
    ~EZCoA();
    EZCoA(const EZCoA&) = delete;
    EZCoA &operator=(const EZCoA&) = delete;

    void SetGetRequests(const CoACallback &callback, void *p);
    // bind the CoA port. false: bind failed
    bool Start();
    void Stop();
    EZRadiusServer *server() { return m_pServer.get(); }
};

#endif // EZCOA_H
