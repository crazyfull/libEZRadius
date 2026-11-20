#ifndef EZRADIUSSERVER_H
#define EZRADIUSSERVER_H
#include "RadiusPacket.h"
#include "EZRASList.h"
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace netrector { class EpollReactor; class UDPSocket; }

class EZRadiusServer;
class EZDedupCache;
class EZRadiusClientIdentify;
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
class EZRadiusServer
{
    netrector::EpollReactor *m_pReactor;
    EZRASList m_RASList;
    std::shared_ptr<EZDedupCache> m_Dedup;
    bool m_AutoStatusServer = true;
    std::vector<netrector::UDPSocket*> m_sockets;

    uint16_t m_AuthPort;
    uint16_t m_AccPort;
    std::string m_BindAddress;
    bool m_RequireMA = false;

    RADIUSCallback m_callback;
    void *m_pPointerCallback = nullptr;

    netrector::UDPSocket *openSocket(uint16_t port);
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

    // bind the sockets. false: already started or bind failed (nothing stays open on failure)
    bool Start();
    void Stop();
    bool isStarted() const { return !m_sockets.empty(); }

    uint16_t AuthenticatorPort() const;
    uint16_t AccountingPort() const;
    EZRASList *RASList();
    netrector::EpollReactor *reactor() const { return m_pReactor; }

    // default handler (used when no callback is set): does nothing
    virtual void onReceiveRequest(RADIUSPacketTypeCodes PacketType, RadiusPacket &pRequest, EZRadiusClientIdentify &ClientIdentify, EZRadiusServer *pRadiusServer);
    void SeRequestCallback(const RADIUSCallback &callback, void *p = nullptr);
};

#endif // EZRADIUSSERVER_H
