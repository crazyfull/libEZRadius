#ifndef EZRADIUSPOOL_H
#define EZRADIUSPOOL_H
// Connection pool for the asynchronous client (EZRadiusClient): requests of many client objects share a few
// long-lived sockets / connections instead of opening one per request.
//
//   auto pool = EZRadiusPool::create(&reactor, settings);      // Host, Secret, ports, Transport, TLS ...
//   settings.Pool = pool;
//   EZRadiusClient c(&reactor, settings);                      // any number of clients, any lifetime
//   c.Send(...);
//
// What the pool does for you:
//   - UDP: one socket per pool connection, requests are told apart by the RADIUS Identifier (256 in flight per
//     connection), retransmission with the same Identifier. No socket is opened per request.
//   - TCP / TLS (RadSec) / DTLS: the connection (and TLS / DTLS session) is opened on the first request and kept.
//     A lost connection is re-established in the background (0.5 s, doubling up to 30 s); requests that were
//     in flight are sent again (up to RetryCount sends in total) once it is back. Destroying a client object does
//     not close the connection.
//   - Status-Server watchdog on idle TCP / TLS / DTLS connections: no answer closes the connection and reconnects.
//   - Several connections per pool (setConnections) share the load (each carries up to 256 requests).
// Everything runs on the reactor thread, like the client. The pool must be destroyed (or close()d) before the
// reactor; clients keep it alive through EZClientSettings::Pool.
#include "EZClientSettings.h"
#include "EZResult.h"
#include "RadiusSecret.h"
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <vector>

namespace netrector { class EpollReactor; }
class EZPoolLink;
class EZRadiusPool;
class EZTLSContext;

// A request that travels through a pool (implemented by EZRadiusClient).
class EZConnectionRequest
{
public:
    virtual ~EZConnectionRequest() = default;
    // the pool picked the Identifier: set it and finish the packet (signatures that depend on it)
    virtual bool connPrepare(uint8_t id) = 0;
    // the classic (RADIUS/1.0) request packet
    virtual const uint8_t *connPacket(size_t &len) = 0;
    // a response with the right Identifier arrived (classic form): validate and store it. false: not valid, keep waiting
    virtual bool connAccept(const uint8_t *packet, size_t len, bool radius11) = 0;
    // the request is over (OK, TIMEOUT, SEND_FAILED, CANCELED). The pool no longer knows the request.
    virtual void connFinished(EZResult result) = 0;

private:
    friend class EZPoolLink;
    friend class EZRadiusPool;
    EZPoolLink *m_link = nullptr;
    int m_slot = -1;
};

class EZRadiusPool
{
public:
    // Host, Secret (fixed for TLS / DTLS), ports, TimeOut, Transport and TLS come from `settings`.
    static std::shared_ptr<EZRadiusPool> create(netrector::EpollReactor *reactor, const EZClientSettings &settings);
    ~EZRadiusPool();
    EZRadiusPool(const EZRadiusPool&) = delete;
    EZRadiusPool &operator=(const EZRadiusPool&) = delete;

    // connections per port (default 1, 1..64); call before the first request
    void setConnections(int count);
    // idle TCP / TLS / DTLS connections are probed with Status-Server after this many ms (default 30000, 0 = off)
    void setKeepAlive(int ms) { m_keepAliveMs = ms < 0 ? 0 : ms; }
    // reconnect delay: first retry after minMs, doubling up to maxMs (defaults 500 / 30000)
    void setReconnectDelay(int minMs, int maxMs);

    // open the connection(s) now instead of with the first request (TCP / TLS / DTLS). No effect for UDP.
    void connect(int port = 0);
    // cancel all requests (they finish with EZResult::CANCELED) and close every connection. New requests reopen them.
    void close();

    // used by EZRadiusClient
    bool submit(EZConnectionRequest *request, int port, int attempts);
    void cancel(EZConnectionRequest *request);

    EZTransport transport() const { return m_settings.Transport; }
    const std::string &secret() const { return m_settings.Secret; }
    // statistics
    size_t inFlight() const;
    size_t connectedCount() const;
    uint64_t reconnects() const { return m_reconnects; }
    uint64_t requestsSent() const { return m_sent; }

private:
    EZRadiusPool(netrector::EpollReactor *reactor, const EZClientSettings &settings);
    friend class EZPoolLink;
    netrector::EpollReactor *m_pReactor;
    EZClientSettings m_settings;
    RadiusSecret m_secret;
    std::shared_ptr<EZTLSContext> m_tlsCtx;
    int m_connections = 1;
    int m_keepAliveMs = 30000;
    int m_reconnectMin = 500, m_reconnectMax = 30000;
    uint64_t m_reconnects = 0, m_sent = 0;
    std::map<int, std::vector<std::unique_ptr<EZPoolLink>>> m_links;
    std::vector<std::unique_ptr<EZPoolLink>> &linksFor(int port);
};

#endif // EZRADIUSPOOL_H
