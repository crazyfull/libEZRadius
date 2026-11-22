#include "EZRadiusServer.h"
#include "EZRadiusClientIdentify.h"
#include "EZResponse.h"
#include "EZAddr.h"
#include "EZDedup.h"
#include "clsUDPSocket.h"
#include "clsTCPSocket.h"
#include "clsListener.h"
#include "EZTLS.h"
#include "EZRadius11.h"
#include "clsEpollReactor.h"
#include "clsLog.h"
#include <arpa/inet.h>
#include <chrono>
#include <cstring>

struct EZStreamAcceptContext { EZRadiusServer *server; EZTransport transport; bool accounting; };
static netrector::TCPSocket *acceptStream(void *ctx);

// UDP socket that knows its server (so a request can be answered on the socket it arrived on)
class EZServerSocket : public netrector::UDPSocket
{
public:
    EZRadiusServer *owner = nullptr;
    void onDatagram(const uint8_t *data, size_t len, const struct sockaddr *from, socklen_t fromLen) override
    {
        if(owner)
            owner->handleDatagram(this, data, len, from, fromLen);
    }
    // the reactor closes every socket when run() ends: the server must forget it
    void onClose() override
    {
        if(owner)
            owner->socketClosed(this);
    }
};

// UDP socket of the RADIUS/DTLS listener: datagrams belong to DTLS sessions
class EZDtlsServerSocket : public EZServerSocket
{
public:
    void onDatagram(const uint8_t *data, size_t len, const struct sockaddr *from, socklen_t fromLen) override
    {
        if(owner)
            owner->dtlsDatagram(this, data, len, from, fromLen);
    }
};

EZRadiusServer::EZRadiusServer(netrector::EpollReactor *reactor)
    
    : m_pReactor(reactor), m_Dedup(std::make_shared<EZDedupCache>()), m_AuthPort(D_RADIUS_AUTHENTICATION_PORT), m_AccPort(D_RADIUS_ACCOUNTING_PORT), m_BindAddress("0.0.0.0")
{
}

EZRadiusServer::~EZRadiusServer()
{
    Stop();
}

uint16_t EZRadiusServer::AuthenticatorPort() const { return m_AuthPort; }
uint16_t EZRadiusServer::AccountingPort() const { return m_AccPort; }
EZRASList *EZRadiusServer::RASList() { return &m_RASList; }

void EZRadiusServer::onReceiveRequest(RADIUSPacketTypeCodes, RadiusPacket &, EZRadiusClientIdentify &, EZRadiusServer *)
{
    // default: nothing (set a callback with SeRequestCallback or override this method)
}

void EZRadiusServer::setAuthenticationPort(uint16_t p) { m_AuthPort = p; }
void EZRadiusServer::setAccountingPort(uint16_t p) { m_AccPort = p; }
void EZRadiusServer::setDuplicateWindow(int ms) { m_Dedup->setWindow(ms); }

void EZRadiusServer::setBindAddress(const char *ip) { m_BindAddress = (ip && *ip) ? ip : "0.0.0.0"; }

void EZRadiusServer::SeRequestCallback(const RADIUSCallback &callback, void *p)
{
    m_pPointerCallback = p;
    m_callback = callback;
}

netrector::UDPSocket *EZRadiusServer::openSocket(uint16_t port, bool dtls)
{
    EZServerSocket *sock = dtls ? new EZDtlsServerSocket : new EZServerSocket;
    sock->owner = this;
    sock->setReactor(m_pReactor);
    sock->setMaxDatagramSize(D_RADIUS_PACKET_MAX_LENGTH);
    if(!sock->bind(m_BindAddress.c_str(), port)){
        NR_LOG(netrector::LOG_ERROR, "EZRadiusServer: bind %s:%u failed", m_BindAddress.c_str(), (unsigned)port);
        sock->owner = nullptr;
        sock->close();      // autoDelete: the reactor deletes it
        return nullptr;
    }
    return sock;
}

bool EZRadiusServer::Start()
{
    if(!m_pReactor || !m_sockets.empty())
        return false;

    netrector::UDPSocket *a = openSocket(m_AuthPort);
    if(!a)
        return false;
    m_sockets.push_back(a);

    if(m_AccPort != m_AuthPort){
        netrector::UDPSocket *b = openSocket(m_AccPort);
        if(!b){
            Stop();
            return false;
        }
        m_sockets.push_back(b);
    }

    // TCP listeners
    for(const ListenerSpec &spec : m_specs){
        if(spec.transport == EZTransport::DTLS){
            netrector::UDPSocket *d = openSocket(spec.port, true);
            if(!d){
                Stop();
                return false;
            }
            m_sockets.push_back(d);
            if(m_dtlsTimer < 0)
                m_dtlsTimer = m_pReactor->addTimer(50, [this]{ dtlsTick(); });
            continue;
        }
        std::vector<std::pair<uint16_t, bool>> ports;
        if(spec.transport == EZTransport::TCP){
            ports.push_back({m_AuthPort, false});
            if(m_AccPort != m_AuthPort)
                ports.push_back({m_AccPort, true});
        }else{
            ports.push_back({spec.port, spec.accounting});
        }
        for(const auto &pa : ports){
            auto *lst = new netrector::Listener(m_pReactor);
            auto ctx = std::make_shared<EZStreamAcceptContext>(EZStreamAcceptContext{this, spec.transport, pa.second});
            if(!lst->start(pa.first, m_BindAddress.c_str(), acceptStream, ctx.get())){
                NR_LOG(netrector::LOG_ERROR, "EZRadiusServer: TCP listen %s:%u failed", m_BindAddress.c_str(), (unsigned)pa.first);
                delete lst;
                Stop();
                return false;
            }
            m_listeners.push_back(lst);
            m_acceptContexts.push_back(ctx);
        }
    }
    return true;
}

void EZRadiusServer::socketClosed(netrector::UDPSocket *s)
{
    for(size_t i = 0; i < m_sockets.size(); i++){
        if(m_sockets[i] == s){
            m_sockets.erase(m_sockets.begin() + i);
            return;
        }
    }
}

void EZRadiusServer::Stop()
{
    dtlsStop();
    stopStreams();
    for(netrector::UDPSocket *s : m_sockets){
        static_cast<EZServerSocket*>(s)->owner = nullptr;   // the object lives until the reactor deletes it
        s->close();
    }
    m_sockets.clear();
}

void EZRadiusServer::handleDatagram(netrector::UDPSocket *socket, const uint8_t *data, size_t len, const struct sockaddr *from, socklen_t fromLen)
{
    if(!from || fromLen < sizeof(struct sockaddr_in) || (from->sa_family != AF_INET && from->sa_family != AF_INET6))
        return;

    std::shared_ptr<RASItem> ras = m_RASList.GetRAS(from);

    // unknown RAS: drop silently (no answer, so the server can not be used to probe)
    if(!ras){
        NR_LOG(netrector::LOG_DEBUG, "EZRadiusServer: RAS not found, packet dropped");
        return;
    }
    processPacket(data, len, from, fromLen, ras, socket, nullptr, false);
}

bool EZRadiusServer::processPacket(const uint8_t *data, size_t len, const struct sockaddr *from, socklen_t fromLen,
                                   const std::shared_ptr<RASItem> &ras, netrector::UDPSocket *socket,
                                   const std::shared_ptr<EZReplyChannel> &channel, bool radius11)
{
    RadiusPacket request;
    if(!request.setRawData((const char*)data, (int)len)){
        NR_LOG(netrector::LOG_DEBUG, "EZRadiusServer: malformed packet dropped");
        return false;
    }
    request.setSecret(&ras->Secret);

    const unsigned char code = request.getCode();
    const bool hasMA = request.hasMessageAuthenticator();

    // Request Authenticator: accounting / CoA / disconnect requests are authenticated by it
    // (RADIUS/1.1 has no authenticators: the transport protects the packet)
    if(!radius11 && (code == ACCOUNTING_REQUEST || code == DISCONNECT_REQUEST || code == COA_REQUEST)){
        if(!request.verifyRequestAuthenticator()){
            NR_LOG(netrector::LOG_WARN, "EZRadiusServer: bad Request Authenticator, packet dropped");
            return false;
        }
    }

    // Message-Authenticator (RFC 3579, BlastRADIUS); mandatory in Status-Server (RFC 5997) except in RADIUS/1.1
    if(hasMA){
        if(!request.verifyMessageAuthenticator()){
            NR_LOG(netrector::LOG_WARN, "EZRadiusServer: bad Message-Authenticator, packet dropped");
            return false;
        }
    }else if(!radius11 && ((m_RequireMA && code == ACCESS_REQUEST) || code == STATUS_SERVER)){
        NR_LOG(netrector::LOG_WARN, "EZRadiusServer: request without Message-Authenticator dropped");
        return false;
    }

    // retransmission: same source (address + port), ID and Request Authenticator
    std::string dedupKey = ezaddr::keyOf(from);
    const uint16_t peerPort = ezaddr::portOf(from);
    dedupKey.append((const char*)&peerPort, sizeof(peerPort));
    dedupKey.push_back((char)request.getID());
    dedupKey.append((const char*)request.getAuthenticator(), D_AUTHENTICATOR_LENGTH);

    RADIUSPacketTypeCodes type = (code > D_PACKET_MAX_KNOWN_CODE) ? UNKNOWN : (RADIUSPacketTypeCodes)code;

    EZRadiusClientIdentify identify(request.getID(), from, fromLen, socket, request.getAuthenticator(), ras, hasMA);
    identify.setChannel(channel);
    identify.setRadius11(radius11);

    const std::string *cached = nullptr;
    switch(m_Dedup->check(dedupKey, &cached)){
    case EZDedupCache::REPLAY:
        if(channel)
            channel->send((const uint8_t*)cached->data(), cached->size(), identify);
        else
            socket->sendTo((const uint8_t*)cached->data(), cached->size(), from, fromLen);
        return true;
    case EZDedupCache::IN_PROGRESS:
        return true;
    default:
        break;
    }

    identify.setDedup(m_Dedup, dedupKey);
    for(const AttrValue &ps : request.getAttributes(PROXY_STATE))
        identify.addProxyState(ps.strValue);

    // Status-Server (RFC 5997): answered here, the application is not bothered
    if(type == STATUS_SERVER && m_AutoStatusServer){
        const bool acctPort = channel ? channel->isAccountingPort()
                                      : (m_AccPort != m_AuthPort && socket->getLocalPort() == m_AccPort);
        EZResponse response;
        response.Send(acctPort ? ACCOUNTING_RESPONSE : ACCESS_ACCEPT, &identify);
        return true;
    }

    if(m_callback)
        m_callback(type, request, identify, this, m_pPointerCallback);
    else
        onReceiveRequest(type, request, identify, this);
    return true;
}

// =============================================================================================
// stream transports (TCP; TLS is added by EZTLS)
class EZStreamServerConn;
struct EZStreamLink { EZStreamServerConn *conn = nullptr; };

class EZStreamChannel : public EZReplyChannel
{
    std::shared_ptr<EZStreamLink> m_link;
    bool m_acct;
public:
    EZStreamChannel(std::shared_ptr<EZStreamLink> link, bool acct) : m_link(std::move(link)), m_acct(acct) {}
    bool send(const uint8_t *packet, size_t len, const EZRadiusClientIdentify &request) override;
    bool isAccountingPort() const override { return m_acct; }
};

class EZStreamServerConn : public netrector::TCPSocket
{
public:
    EZRadiusServer *owner = nullptr;
    EZTransport transport = EZTransport::TCP;
    bool accounting = false;
    EZStreamFramer framer;
    std::shared_ptr<RASItem> ras;
    struct sockaddr_storage peer;
    socklen_t peerLen = 0;
    std::shared_ptr<EZStreamLink> link = std::make_shared<EZStreamLink>();
    std::shared_ptr<EZReplyChannel> channel;
    bool radius11 = false;
#ifdef EZRADIUS_HAS_TLS
    std::unique_ptr<EZTLSEngine> tls;
    bool tlsDone = false;
#endif

    EZStreamServerConn() { memset(&peer, 0, sizeof(peer)); link->conn = this; }

    // Write batching: responses produced while one read is processed leave with a single write.
    std::string wbuf;
    int batch = 0;
    bool out(const void *data, size_t len)
    {
        if(batch > 0){
            wbuf.append((const char*)data, len);
            return true;
        }
        return send(data, len);
    }
    struct Batch {
        EZStreamServerConn *c;
        explicit Batch(EZStreamServerConn *conn) : c(conn) { c->batch++; }
        ~Batch()
        {
            if(--c->batch == 0 && !c->wbuf.empty()){
                c->send(c->wbuf.data(), c->wbuf.size());
                c->wbuf.clear();
            }
        }
    };

    bool sendApp(const uint8_t *packet, size_t len, const EZRadiusClientIdentify *request)
    {
#ifdef EZRADIUS_HAS_TLS
        if(tls){
            if(!tlsDone)
                return false;
            if(radius11){
                // RADIUS/1.1: the response goes out in the Token format (RFC 9765)
                std::string wire;
                if(!request || !ezradius11::classicResponseToWire(packet, len, request->Authenticator(), "radsec", wire))
                    return false;
                if(!tls->write((const uint8_t*)wire.data(), wire.size()))
                    return false;
            }else if(!tls->write(packet, len)){
                return false;
            }
            return flushTls();
        }
#endif
        (void)request;
        return out(packet, len);
    }

#ifdef EZRADIUS_HAS_TLS
    // TLS bytes produced by the engine go to the socket
    bool flushTls()
    {
        for(const std::string &chunk : tls->takeOutput())
            if(!out(chunk.data(), chunk.size()))
                return false;
        return true;
    }
#endif

    void onAccepted() override
    {
        std::string ip;
        uint16_t port = 0;
        if(!owner || !getPeerAddress(ip, port) || !ezaddr::parse(ip.c_str(), port, peer, peerLen)){
            close(true);
            return;
        }
        if(owner->m_conns.size() >= owner->m_MaxConnections){
            NR_LOG(netrector::LOG_WARN, "EZRadiusServer: connection limit reached, %s refused", ip.c_str());
            close(true);
            return;
        }
        ras = owner->m_RASList.GetRAS((const struct sockaddr*)&peer);
        if(transport == EZTransport::TLS){
#ifdef EZRADIUS_HAS_TLS
            // RFC 6614: the shared secret is the fixed string "radsec"; the RASList only restricts the addresses
            if(!ras && owner->m_radsecIPFilter){
                NR_LOG(netrector::LOG_DEBUG, "EZRadiusServer: RAS %s not found, connection closed", ip.c_str());
                close(true);
                return;
            }
            ras = std::make_shared<RASItem>("radsec", ip);
            std::string err;
            tls = EZTLSEngine::create(owner->m_tlsCtx, &err);
            if(!tls){
                NR_LOG(netrector::LOG_ERROR, "EZRadiusServer: TLS: %s", err.c_str());
                close(true);
                return;
            }
#else
            close(true);
            return;
#endif
        }else if(!ras){
            NR_LOG(netrector::LOG_DEBUG, "EZRadiusServer: RAS %s not found, connection closed", ip.c_str());
            close(true);
            return;
        }
        owner->m_conns.push_back(this);
        channel = std::make_shared<EZStreamChannel>(link, accounting);
        // the handshake has to finish quickly; the idle timeout applies afterwards
        if(tls)
            setIdleTimeout(15);
        else if(owner->m_IdleTimeoutSec > 0)
            setIdleTimeout((uint32_t)owner->m_IdleTimeoutSec);
    }

    void onReceiveData(const uint8_t *data, size_t len) override
    {
        if(!owner || !ras)
            return;
        Batch batchGuard(this);
#ifdef EZRADIUS_HAS_TLS
        if(tls){
            const bool ok = tls->feed(data, len);
            flushTls();                                     // a fatal alert goes out before the close
            if(!ok){
                NR_LOG(netrector::LOG_WARN, "EZRadiusServer: TLS from %s: %s", ezaddr::toString((const struct sockaddr*)&peer).c_str(), tls->errorText().c_str());
                close(false);
                return;
            }
            if(!tlsDone && tls->established()){
                tlsDone = true;
                radius11 = (tls->radiusVersion() == 11);
                setIdleTimeout(owner->m_IdleTimeoutSec > 0 ? (uint32_t)owner->m_IdleTimeoutSec : 0);
            }
            const std::string plain = tls->takePlain();
            if(!plain.empty())
                handleBytes((const uint8_t*)plain.data(), plain.size());
            if(tls && tls->peerClosed())
                close(false);
            return;
        }
#endif
        handleBytes(data, len);
    }

    void handleBytes(const uint8_t *data, size_t len)
    {
        if(!owner || !ras)
            return;
        framer.append(data, len);
        std::string pkt;
        for(;;){
            const EZStreamFramer::Result r = framer.next(pkt);
            if(r == EZStreamFramer::NEED_MORE)
                return;
            if(r == EZStreamFramer::INVALID){
                NR_LOG(netrector::LOG_WARN, "EZRadiusServer: bad packet length from %s, connection closed", ezaddr::toString((const struct sockaddr*)&peer).c_str());
                close(true);
                return;
            }
            if(radius11){
#ifdef EZRADIUS_HAS_TLS
                std::string classic;
                if(!ezradius11::wireRequestToClassic((const uint8_t*)pkt.data(), pkt.size(), "radsec", classic)){
                    close(true);
                    return;
                }
                pkt.swap(classic);
#endif
            }
            if(!owner->processPacket((const uint8_t*)pkt.data(), pkt.size(), (const struct sockaddr*)&peer, peerLen, ras, nullptr, channel, radius11)){
                // RFC 6613: an invalid packet closes the connection
                close(true);
                return;
            }
            if(!owner)      // the application stopped the server from inside the callback
                return;
        }
    }

    void onClose() override
    {
        link->conn = nullptr;
        if(owner)
            owner->connClosed(this);
    }
};

bool EZStreamChannel::send(const uint8_t *packet, size_t len, const EZRadiusClientIdentify &request)
{
    return m_link->conn && m_link->conn->sendApp(packet, len, &request);
}

// factory called by netRector for every accepted TCP connection

static netrector::TCPSocket *acceptStream(void *ctx)
{
    EZStreamAcceptContext *c = static_cast<EZStreamAcceptContext*>(ctx);
    auto *conn = new EZStreamServerConn;
    conn->owner = c->server;
    conn->transport = c->transport;
    conn->accounting = c->accounting;
    return conn;
}

void EZRadiusServer::connClosed(EZStreamServerConn *c)
{
    for(size_t i = 0; i < m_conns.size(); i++){
        if(m_conns[i] == c){
            m_conns.erase(m_conns.begin() + i);
            return;
        }
    }
}

#ifdef EZRADIUS_HAS_TLS
bool EZRadiusServer::EnableTLS(const EZTLSConfig &config, uint16_t port, std::string *error)
{
    m_tlsCtx = EZTLSContext::create(config, true, false, error);
    if(!m_tlsCtx)
        return false;
    m_specs.push_back({EZTransport::TLS, port, false});
    return true;
}
#endif

void EZRadiusServer::EnableTCP()
{
    m_specs.push_back({EZTransport::TCP, 0, false});
}

void EZRadiusServer::stopStreams()
{
    for(netrector::Listener *l : m_listeners){
        l->stop();
        delete l;
    }
    m_listeners.clear();
    m_acceptContexts.clear();
    std::vector<EZStreamServerConn*> conns;
    conns.swap(m_conns);
    for(EZStreamServerConn *c : conns){
        c->owner = nullptr;
        c->close(true);
    }
}

// =============================================================================================
// RADIUS over DTLS (RFC 7360): one DTLS session per peer address and port, one RADIUS packet per record
struct EZDtlsLink { std::function<bool(const uint8_t*, size_t)> sender; };

class EZDtlsChannel : public EZReplyChannel
{
    std::shared_ptr<EZDtlsLink> m_link;
public:
    explicit EZDtlsChannel(std::shared_ptr<EZDtlsLink> link) : m_link(std::move(link)) {}
    bool send(const uint8_t *packet, size_t len, const EZRadiusClientIdentify &) override
    {
        return m_link->sender && m_link->sender(packet, len);
    }
};

#ifdef EZRADIUS_HAS_TLS
struct EZRadiusServer::DtlsSession
{
    std::unique_ptr<EZTLSEngine> engine;
    std::string key;
    struct sockaddr_storage peer;
    socklen_t peerLen = 0;
    netrector::UDPSocket *socket = nullptr;
    std::shared_ptr<RASItem> ras;
    std::shared_ptr<EZDtlsLink> link = std::make_shared<EZDtlsLink>();
    std::shared_ptr<EZReplyChannel> channel;
    bool established = false;
    std::chrono::steady_clock::time_point created, lastActive;

    // datagrams produced by the engine go back to the peer
    void flush()
    {
        for(const std::string &d : engine->takeOutput())
            socket->sendTo(d.data(), d.size(), (const struct sockaddr*)&peer, peerLen);
    }
};

bool EZRadiusServer::EnableDTLS(const EZTLSConfig &config, uint16_t port, std::string *error)
{
    m_dtlsCtx = EZTLSContext::create(config, true, true, error);
    if(!m_dtlsCtx)
        return false;
    m_specs.push_back({EZTransport::DTLS, port, false});
    return true;
}

void EZRadiusServer::dtlsRemove(DtlsSession *s)
{
    for(size_t i = 0; i < m_dtlsSessions.size(); i++){
        if(m_dtlsSessions[i] == s){
            m_dtlsSessions.erase(m_dtlsSessions.begin() + i);
            break;
        }
    }
    s->link->sender = nullptr;
    delete s;
}

void EZRadiusServer::dtlsDatagram(netrector::UDPSocket *socket, const uint8_t *data, size_t len, const struct sockaddr *from, socklen_t fromLen)
{
    if(!from || fromLen < sizeof(struct sockaddr_in) || (from->sa_family != AF_INET && from->sa_family != AF_INET6) || !m_dtlsCtx)
        return;

    std::string key = ezaddr::keyOf(from);
    const uint16_t port = ezaddr::portOf(from);
    key.append((const char*)&port, sizeof(port));

    DtlsSession *s = nullptr;
    for(DtlsSession *x : m_dtlsSessions)
        if(x->key == key){ s = x; break; }

    if(!s){
        // a new peer: cheap checks first, so a flood of ClientHellos does not allocate anything
        // (bis section 6.5.1.1: partial sessions are limited)
        std::shared_ptr<RASItem> known = m_RASList.GetRAS(from);
        if(!known && m_radsecIPFilter)
            return;
        size_t partial = 0;
        for(DtlsSession *x : m_dtlsSessions)
            if(!x->established)
                partial++;
        if(m_dtlsSessions.size() >= m_MaxConnections || partial >= 256)
            return;
        std::string err;
        std::unique_ptr<EZTLSEngine> e = EZTLSEngine::create(m_dtlsCtx, &err);
        if(!e)
            return;
        s = new DtlsSession;
        s->engine = std::move(e);
        s->key = key;
        memset(&s->peer, 0, sizeof(s->peer));
        memcpy(&s->peer, from, fromLen);
        s->peerLen = fromLen;
        s->socket = socket;
        s->ras = std::make_shared<RASItem>("radius/dtls", ezaddr::toString(from));
        s->created = std::chrono::steady_clock::now();
        DtlsSession *raw = s;
        s->link->sender = [raw](const uint8_t *pkt, size_t n) {
            if(!raw->established || !raw->engine->write(pkt, n))
                return false;
            raw->flush();
            return true;
        };
        s->channel = std::make_shared<EZDtlsChannel>(s->link);
        m_dtlsSessions.push_back(s);
    }
    s->lastActive = std::chrono::steady_clock::now();

    const bool ok = s->engine->feed(data, len);
    s->flush();                             // handshake flights / alerts
    if(!ok){
        NR_LOG(netrector::LOG_WARN, "EZRadiusServer: DTLS from %s: %s", ezaddr::toString(from).c_str(), s->engine->errorText().c_str());
        dtlsRemove(s);
        return;
    }
    if(!s->established && s->engine->established())
        s->established = true;

    std::shared_ptr<EZDtlsLink> alive = s->link;
    const std::vector<std::string> records = s->engine->takeRecords();
    for(const std::string &rec : records){
        // one RADIUS packet per record; an invalid packet is dropped, the session stays
        processPacket((const uint8_t*)rec.data(), rec.size(), (const struct sockaddr*)&s->peer, s->peerLen, s->ras, nullptr, s->channel, false);
        if(!alive->sender)                   // the application stopped the server
            return;
    }
    if(s->engine->peerClosed())
        dtlsRemove(s);
}

void EZRadiusServer::dtlsTick()
{
    const auto now = std::chrono::steady_clock::now();
    std::vector<DtlsSession*> copy = m_dtlsSessions;
    for(DtlsSession *s : copy){
        const int ms = s->engine->msUntilTimeout();
        if(ms == 0){
            if(!s->engine->handleTimeout()){
                dtlsRemove(s);
                continue;
            }
            s->flush();
        }
        const auto idle = std::chrono::duration_cast<std::chrono::seconds>(now - s->lastActive).count();
        const long limit = s->established ? (long)m_IdleTimeoutSec : 20;       // handshake: 20 s
        if(limit > 0 && idle > limit)
            dtlsRemove(s);
    }
}

void EZRadiusServer::dtlsStop()
{
    if(m_dtlsTimer >= 0){
        m_pReactor->removeTimer(m_dtlsTimer);
        m_dtlsTimer = -1;
    }
    std::vector<DtlsSession*> copy;
    copy.swap(m_dtlsSessions);
    for(DtlsSession *s : copy){
        s->link->sender = nullptr;
        delete s;
    }
}
#else
void EZRadiusServer::dtlsDatagram(netrector::UDPSocket *, const uint8_t *, size_t, const struct sockaddr *, socklen_t) {}
void EZRadiusServer::dtlsTick() {}
void EZRadiusServer::dtlsRemove(DtlsSession *) {}
void EZRadiusServer::dtlsStop() {}
#endif
