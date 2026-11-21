/*
 * libEZRadius
 *
 * Copyright (c) 2023-2026 Mojtaba Kahvand.
 * All rights reserved.
 *
 * Licensed under the GNU Lesser General Public License v2.1.
 * See LICENSE for details.
 */

#ifndef EZRADIUSSERVER_H
#define EZRADIUSSERVER_H
#include "RadiusPacket.h"
#include "EZRASList.h"
#include "EZTransport.h"
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace netrector { class EpollReactor; class UDPSocket; class Listener; }

class EZRadiusServer;
class EZDedupCache;
class EZRadiusClientIdentify;
class EZStreamServerConn;
class EZReplyChannel;
class EZTLSContext;
struct EZTLSConfig;
typedef std::function<void(RADIUSPacketTypeCodes, RadiusPacket &, EZRadiusClientIdentify &ClientIdentify, EZRadiusServer *pRadiusServer, void *p)> RADIUSCallback;

// Asynchronous RADIUS server on a netRector reactor (no threads, no blocking calls).
//
// All methods must be called from the reactor thread (use reactor->post() from other threads).
// Every received packet is checked before the callback runs:
//   - the sender must be in RASList() (otherwise it is dropped silently)
//   - the packet must be a well formed RADIUS packet
//   - Accounting / Disconnect / CoA requests: Request Authenticator verified
//   - retransmissions are detected (setDuplicateWindow)
//   - Status-Server is answered automatically
//   - IPv4 and IPv6: bind "::" (dual stack) with setBindAddress("::"); RAS addresses can be IPv6
//   - Message-Authenticator verified when present (required for Access-Request if
//     setRequireMessageAuthenticator(true))
//
// Transports: UDP is always on. EnableTCP() adds RADIUS over TCP (RFC 6613) on the same port numbers;
// EnableTLS() / EnableDTLS() add RadSec (RFC 6614) and RADIUS/DTLS (RFC 7360) on port 2083 (see EZTLS.h).
// Over TCP the shared secret of the client's EZRASList entry is used, over TLS the fixed secret "radsec",
// over DTLS "radius/dtls"; the RASList decides which client addresses may connect.
class EZRadiusServer
{
    netrector::EpollReactor *m_pReactor;
    EZRASList m_RASList;
    std::shared_ptr<EZDedupCache> m_Dedup;
    bool m_AutoStatusServer = true;
    std::vector<netrector::UDPSocket*> m_sockets;

    struct ListenerSpec { EZTransport transport; uint16_t port; bool accounting; };
    std::vector<ListenerSpec> m_specs;                  // stream / datagram listeners added with Enable*
    std::vector<netrector::Listener*> m_listeners;
    std::vector<EZStreamServerConn*> m_conns;
    std::vector<std::shared_ptr<void>> m_acceptContexts;      // factory arguments of the listeners
    std::shared_ptr<EZTLSContext> m_tlsCtx;             // RadSec (TLS) server context
    std::shared_ptr<EZTLSContext> m_dtlsCtx;            // RADIUS/DTLS server context
    bool m_radsecIPFilter = true;
    int m_IdleTimeoutSec = 600;
    size_t m_MaxConnections = 1024;
    friend class EZStreamServerConn;
    friend class EZDtlsServerSocket;
    struct DtlsSession;                                 // defined with EZRADIUS_HAS_TLS
    std::vector<DtlsSession*> m_dtlsSessions;
    int m_dtlsTimer = -1;
    void dtlsDatagram(netrector::UDPSocket *socket, const uint8_t *data, size_t len, const struct sockaddr *from, socklen_t fromLen);
    void dtlsTick();
    void dtlsRemove(DtlsSession *s);
    void dtlsStop();
    friend class EZStreamAcceptContext;
    void connClosed(EZStreamServerConn *c);
    void stopStreams();
    // shared by every transport: validate one classic RADIUS packet and call the application.
    // false: the packet was invalid and a stream connection must be closed (RFC 6613 section 2.6.4 / bis 3.12)
    bool processPacket(const uint8_t *data, size_t len, const struct sockaddr *from, socklen_t fromLen,
                       const std::shared_ptr<RASItem> &ras, netrector::UDPSocket *udp,
                       const std::shared_ptr<EZReplyChannel> &channel, bool radius11);

    uint16_t m_AuthPort;
    uint16_t m_AccPort;
    std::string m_BindAddress;
    bool m_RequireMA = false;

    RADIUSCallback m_callback;
    void *m_pPointerCallback = nullptr;

    netrector::UDPSocket *openSocket(uint16_t port, bool dtls = false);
    friend class EZServerSocket;
    void socketClosed(netrector::UDPSocket *s);
    void handleDatagram(netrector::UDPSocket *socket, const uint8_t *data, size_t len, const struct sockaddr *from, socklen_t fromLen);

public:
    explicit EZRadiusServer(netrector::EpollReactor *reactor);
    virtual ~EZRadiusServer();
    EZRadiusServer(const EZRadiusServer&) = delete;
    EZRadiusServer &operator=(const EZRadiusServer&) = delete;

    void setAuthenticationPort(uint16_t newAuthenticationPort);
    void setAccountingPort(uint16_t newAccountingPort);
    // local address to bind to (default "0.0.0.0")
    void setBindAddress(const char *ip);
    void setRequireMessageAuthenticator(bool required) { m_RequireMA = required; }
    // Retransmission detection window in ms (default 30000, 0 = off). A retransmitted request is not given
    // to the callback again: the stored answer is sent again, or the duplicate is dropped while the first
    // one is still being processed.
    void setDuplicateWindow(int ms);
    // answer Status-Server requests (RFC 5997) automatically (default true)
    void setAutoStatusServer(bool on) { m_AutoStatusServer = on; }

    // RADIUS over TCP (RFC 6613): listen on the Authentication and Accounting ports with TCP too.
    // No encryption: for trusted networks only (or inside a tunnel). Call before Start().
    void EnableTCP();
#ifdef EZRADIUS_HAS_TLS
    // RadSec, RADIUS over TLS (RFC 6614): listen on TCP `port` (default 2083, no UDP/TCP ports are shared).
    // Both sides authenticate with certificates (see EZTLSConfig), the shared secret is the fixed string "radsec".
    // Call before Start(). false: invalid configuration (reason in *error).
    bool EnableTLS(const EZTLSConfig &config, uint16_t port = D_RADSEC_PORT, std::string *error = nullptr);
    // RADIUS over DTLS (RFC 7360): UDP `port` (default 2083), shared secret "radius/dtls"
    bool EnableDTLS(const EZTLSConfig &config, uint16_t port = D_RADSEC_PORT, std::string *error = nullptr);
#endif
    // RadSec / DTLS: only accept connections from addresses that are in RASList() (default true, bis section 3.4).
    // With false the certificate alone decides who may connect (the RAS entry is not needed).
    void setRadSecIPFilter(bool on) { m_radsecIPFilter = on; }
    // close a connection that sent nothing for this many seconds (default 600, 0 = never)
    void setConnectionIdleTimeout(int seconds) { m_IdleTimeoutSec = seconds; }
    // at the limit a new connection is refused (default 1024)
    void setMaxConnections(size_t n) { m_MaxConnections = n; }
    size_t connectionCount() const { return m_conns.size(); }

    // bind the sockets. false: already started or bind failed (nothing stays open on failure)
    bool Start();
    void Stop();
    bool isStarted() const { return !m_sockets.empty() || !m_listeners.empty(); }

    uint16_t AuthenticatorPort() const;
    uint16_t AccountingPort() const;
    EZRASList *RASList();
    netrector::EpollReactor *reactor() const { return m_pReactor; }

    // default handler (used when no callback is set): does nothing
    virtual void onReceiveRequest(RADIUSPacketTypeCodes PacketType, RadiusPacket &pRequest, EZRadiusClientIdentify &ClientIdentify, EZRadiusServer *pRadiusServer);
    void SeRequestCallback(const RADIUSCallback &callback, void *p = nullptr);
};

#endif // EZRADIUSSERVER_H
