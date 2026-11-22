// Connection pool: see EZRadiusPool.h
#include "EZRadiusPool.h"
#include "EZAddr.h"
#include "EZTLS.h"
#include "EZRadius11.h"
#include "EZTransport.h"
#include "RadiusPacket.h"
#include "clsTCPSocket.h"
#include "clsUDPSocket.h"
#include "clsEpollReactor.h"
#include "clsLog.h"
#include <chrono>
#include <deque>
#include <unordered_map>

static inline uint64_t nowMs()
{
    return (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
}

namespace {

enum : int { TICK_MS = 50, SLOTS = 256 };

struct Slot
{
    EZConnectionRequest *req = nullptr;
    uint32_t gen = 0;
    int attempt = 0;                // sends so far
    int maxAttempts = 1;
    bool sent = false;
    bool probe = false;
    uint64_t deadline = 0;
    uint8_t auth[16] = {0};         // Request Authenticator (RADIUS/1.1: Token = first 4 bytes)
    uint32_t token = 0;
};

struct Deadline { uint64_t when; uint8_t id; uint32_t gen; };

} // namespace

class PoolTcp;
class PoolUdp;

// Status-Server probe of the watchdog (it travels like a normal request)
class ProbeRequest : public EZConnectionRequest
{
public:
    EZPoolLink *link = nullptr;
    RadiusSecret *secret = nullptr;
    RadiusPacket pck;
    bool connPrepare(uint8_t id) override
    {
        pck = RadiusPacket();
        pck.setSecret(secret);
        pck.setCode((unsigned char)C_STATUS_SERVER);
        pck.setID(id);
        return pck.addMessageAuthenticator() && pck.signMessageAuthenticator();
    }
    const uint8_t *connPacket(size_t &len) override { len = pck.getLength(); return pck.getRawData(); }
    bool connAccept(const uint8_t *packet, size_t len, bool radius11) override
    {
        RadiusPacket resp;
        if(!resp.setRawData((const char*)packet, (int)len))
            return false;
        if(resp.getCode() != ACCESS_ACCEPT && resp.getCode() != ACCOUNTING_RESPONSE)
            return false;
        if(!pck.verifyResponse(resp))
            return false;
        resp.setSecret(secret);
        if(resp.hasMessageAuthenticator() && !resp.verifyMessageAuthenticator(pck.getAuthenticator(), secret))
            return false;
        (void)radius11;
        return true;
    }
    void connFinished(EZResult result) override;
};

// One socket / connection of the pool with its table of requests in flight.
class EZPoolLink
{
public:
    EZPoolLink(EZRadiusPool *pool, int port) : m_pool(pool), m_port(port)
    {
        memset(&m_server, 0, sizeof(m_server));
        m_probe.link = this;
        m_probe.secret = &pool->m_secret;
    }
    ~EZPoolLink() { shutdown(false); }

    bool submit(EZConnectionRequest *req, int attempts);
    void cancel(EZConnectionRequest *req);
    void connect() { if(m_state == State::Down) startConnect(); ensureTimer(); }
    void shutdown(bool notify);
    size_t active() const { return m_active; }
    bool up() const { return m_state == State::Up; }
    void probeDone(EZResult r);

    // socket callbacks
    void tcpConnected();
    void tcpData(const uint8_t *data, size_t len);
    void sockClosed(bool tcp);
    void udpData(const uint8_t *data, size_t len, const struct sockaddr *from);

private:
    enum class State { Down, Resolving, Connecting, Handshaking, Up, Backoff };

    EZRadiusPool *m_pool;
    int m_port;
    State m_state = State::Down;
    Slot m_slots[SLOTS];
    unsigned m_next = 0;
    size_t m_active = 0;
    std::deque<Deadline> m_dl;
    std::unordered_map<uint32_t, uint8_t> m_tokens;     // RADIUS/1.1: Token -> slot

    PoolTcp *m_tcp = nullptr;
    PoolUdp *m_udp = nullptr;
    std::unique_ptr<EZTLSEngine> m_tls;
    EZStreamFramer m_framer;
    bool m_r11 = false;
    struct sockaddr_storage m_server;
    socklen_t m_serverLen = 0;
    bool m_triedAAAA = false, m_dnsPending = false;

    int m_timer = -1;
    uint64_t m_retryAt = 0, m_hsDeadline = 0, m_lastRx = 0, m_lastProbe = 0;
    int m_backoff = 0;
    bool m_suspect = false, m_needLost = false, m_probing = false;
    ProbeRequest m_probe;

    // write batching: requests sent while one read is processed leave with a single write (TCP / TLS)
    std::string m_wbuf;
    int m_batch = 0;
    struct Batch {
        EZPoolLink *l;
        explicit Batch(EZPoolLink *link) : l(link) { l->m_batch++; }
        ~Batch();
    };

    bool stream() const { return m_pool->m_settings.Transport == EZTransport::TCP || m_pool->m_settings.Transport == EZTransport::TLS; }
    bool datagram() const { return !stream(); }
    bool secure() const { return m_pool->m_settings.Transport == EZTransport::TLS || m_pool->m_settings.Transport == EZTransport::DTLS; }
    int timeoutMs() const { return m_pool->m_settings.TimeOut < 1 ? 1 : m_pool->m_settings.TimeOut; }

    void ensureTimer();
    void tick();
    void startConnect();
    void resolved(const char *ip);
    static void onResolved(const char *, char **ips, size_t count, int qtype, void *user_data);
    void addressReady();
    void becomeUp();
    void lost(const char *why);
    void closeIo();
    bool sendSlot(int id);
    bool writeRaw(const uint8_t *data, size_t len);
    bool flushTls();
    void complete(int id, EZResult r);
    void arm(int id);
    void response(const uint8_t *pkt, size_t len);
    void wireResponse(const std::string &wire);
    void handlePackets();
    void expire(uint64_t now);
    void watchdog(uint64_t now);
    int allocId();
    friend class ProbeRequest;
};

// ---- sockets ----
class PoolTcp : public netrector::TCPSocket
{
public:
    EZPoolLink *owner = nullptr;
    void onConnected() override { if(owner) owner->tcpConnected(); }
    void onReceiveData(const uint8_t *data, size_t len) override { if(owner) owner->tcpData(data, len); }
    void onClose() override
    {
        if(owner){
            EZPoolLink *l = owner;
            owner = nullptr;
            l->sockClosed(true);
        }
    }
};

class PoolUdp : public netrector::UDPSocket
{
public:
    EZPoolLink *owner = nullptr;
    void onDatagram(const uint8_t *data, size_t len, const struct sockaddr *from, socklen_t) override { if(owner) owner->udpData(data, len, from); }
    void onClose() override
    {
        if(owner){
            EZPoolLink *l = owner;
            owner = nullptr;
            l->sockClosed(false);
        }
    }
};

EZPoolLink::Batch::~Batch()
{
    if(--l->m_batch == 0 && !l->m_wbuf.empty()){
        if(!l->m_tcp || !l->m_tcp->send(l->m_wbuf.data(), l->m_wbuf.size()))
            l->m_needLost = l->m_tcp != nullptr;
        l->m_wbuf.clear();
    }
}

void ProbeRequest::connFinished(EZResult result) { if(link) link->probeDone(result); }

// ---- link ----
int EZPoolLink::allocId()
{
    for(int i = 0; i < SLOTS; i++){
        const unsigned id = (m_next + i) & (SLOTS - 1);
        if(!m_slots[id].req){
            m_next = id + 1;
            return (int)id;
        }
    }
    return -1;
}

bool EZPoolLink::submit(EZConnectionRequest *req, int attempts)
{
    const int id = allocId();
    if(id < 0 || !req->connPrepare((uint8_t)id))
        return false;
    size_t len = 0;
    const uint8_t *pkt = req->connPacket(len);
    if(!pkt || len < 20)
        return false;

    Slot &s = m_slots[id];
    s.req = req;
    s.attempt = 0;
    s.maxAttempts = attempts < 1 ? 1 : attempts;
    s.sent = false;
    s.probe = (req == &m_probe);
    memcpy(s.auth, pkt + 4, 16);
    s.token = ((uint32_t)pkt[4] << 24) | ((uint32_t)pkt[5] << 16) | ((uint32_t)pkt[6] << 8) | pkt[7];
    req->m_link = this;
    req->m_slot = id;
    m_active++;
    arm(id);
    ensureTimer();

    if(m_state == State::Down)
        startConnect();
    else if(m_state == State::Up && !sendSlot(id))
        m_needLost = true;              // the tick closes the connection (never complete a request inside submit)
    return true;
}

void EZPoolLink::arm(int id)
{
    Slot &s = m_slots[id];
    s.deadline = nowMs() + (uint64_t)timeoutMs();
    m_dl.push_back({s.deadline, (uint8_t)id, s.gen});
}

void EZPoolLink::cancel(EZConnectionRequest *req)
{
    if(req->m_link != this || req->m_slot < 0)
        return;
    Slot &s = m_slots[req->m_slot];
    if(s.req != req)
        return;
    if(m_r11)
        m_tokens.erase(s.token);
    s.req = nullptr;
    s.gen++;
    m_active--;
    req->m_link = nullptr;
    req->m_slot = -1;
}

void EZPoolLink::complete(int id, EZResult r)
{
    Slot &s = m_slots[id];
    EZConnectionRequest *req = s.req;
    if(!req)
        return;
    if(m_r11)
        m_tokens.erase(s.token);
    s.req = nullptr;
    s.gen++;
    m_active--;
    req->m_link = nullptr;
    req->m_slot = -1;
    req->connFinished(r);               // may submit new requests: the link is consistent here
}

void EZPoolLink::ensureTimer()
{
    if(m_timer >= 0)
        return;
    m_timer = m_pool->m_pReactor->addTimer(TICK_MS, [this]{ tick(); });
}

bool EZPoolLink::writeRaw(const uint8_t *data, size_t len)
{
    if(stream()){
        if(!m_tcp)
            return false;
        if(m_batch > 0){
            m_wbuf.append((const char*)data, len);
            return true;
        }
        return m_tcp->send(data, len);
    }
    return m_udp && m_udp->sendTo(data, len, (const struct sockaddr*)&m_server, m_serverLen);
}

bool EZPoolLink::flushTls()
{
    if(!m_tls)
        return false;
    for(const std::string &chunk : m_tls->takeOutput())
        if(!writeRaw((const uint8_t*)chunk.data(), chunk.size()))
            return false;
    return true;
}

bool EZPoolLink::sendSlot(int id)
{
    Slot &s = m_slots[id];
    size_t len = 0;
    const uint8_t *pkt = s.req->connPacket(len);
    s.attempt++;
    s.sent = true;
    m_pool->m_sent++;
    bool ok;
    std::string wire;
    if(m_tls){
        if(m_r11){
            if(!ezradius11::classicRequestToWire(pkt, len, m_pool->m_settings.Secret, wire))
                return false;
            m_tokens[s.token] = (uint8_t)id;
            ok = m_tls->write((const uint8_t*)wire.data(), wire.size());
        }else{
            ok = m_tls->write(pkt, len);
        }
        return ok && flushTls();
    }
    return writeRaw(pkt, len);
}

void EZPoolLink::closeIo()
{
#ifdef EZRADIUS_HAS_TLS
    // orderly close: the peer frees the TLS / DTLS session at once
    if(m_tls && m_state == State::Up && m_batch == 0 && (m_udp || m_tcp)){
        m_tls->close();
        flushTls();
    }
#endif
    if(m_tcp){
        m_tcp->owner = nullptr;
        m_tcp->close(true);             // autoDelete: the reactor deletes it
        m_tcp = nullptr;
    }
    if(m_udp){
        m_udp->owner = nullptr;
        m_udp->close();
        m_udp = nullptr;
    }
    m_tls.reset();
    m_framer.clear();
    m_wbuf.clear();
    m_tokens.clear();
    m_r11 = false;
    if(m_dnsPending){
        m_pool->m_pReactor->cancelDNS(this);
        m_dnsPending = false;
    }
}

void EZPoolLink::startConnect()
{
    closeIo();
    m_state = State::Resolving;
    m_triedAAAA = false;
    const uint64_t now = nowMs();
    const int hs = m_pool->m_settings.TimeOut * 3 < 5000 ? 5000 : m_pool->m_settings.TimeOut * 3;
    m_hsDeadline = now + (uint64_t)hs;

    if(ezaddr::parse(m_pool->m_settings.Host.c_str(), (uint16_t)m_port, m_server, m_serverLen)){
        addressReady();
        return;
    }
    m_dnsPending = true;
    const bool ok = m_pool->m_pReactor->getIPbyName(m_pool->m_settings.Host.c_str(),
        (netrector::DNSLookup::callback_t)[](const char *h, char **ips, size_t c, netrector::DNSLookup::QUERY_TYPE q, void *u){ onResolved(h, ips, c, (int)q, u); },
        this, netrector::DNSLookup::A);
    if(!ok){
        m_dnsPending = false;
        lost("dns");
    }
}

void EZPoolLink::onResolved(const char *, char **ips, size_t count, int qtype, void *user_data)
{
    EZPoolLink *l = static_cast<EZPoolLink*>(user_data);
    l->m_dnsPending = false;
    if(l->m_state != State::Resolving)
        return;
    if(count == 0 || !ips || !ips[0] || !ezaddr::parse(ips[0], (uint16_t)l->m_port, l->m_server, l->m_serverLen)){
        if(qtype == netrector::DNSLookup::A && !l->m_triedAAAA){
            l->m_triedAAAA = true;
            l->m_dnsPending = true;
            if(l->m_pool->m_pReactor->getIPbyName(l->m_pool->m_settings.Host.c_str(),
                (netrector::DNSLookup::callback_t)[](const char *h, char **i, size_t c, netrector::DNSLookup::QUERY_TYPE q, void *u){ onResolved(h, i, c, (int)q, u); },
                l, netrector::DNSLookup::AAAA))
                return;
            l->m_dnsPending = false;
        }
        l->lost("dns");
        return;
    }
    l->addressReady();
}

void EZPoolLink::addressReady()
{
    netrector::EpollReactor *r = m_pool->m_pReactor;
    const EZTransport t = m_pool->m_settings.Transport;
    if(datagram()){
        auto *sock = new PoolUdp;
        sock->owner = this;
        sock->setReactor(r);
        sock->setMaxDatagramSize(D_RADIUS_PACKET_MAX_LENGTH);
        if(!sock->open(((const struct sockaddr*)&m_server)->sa_family)){
            sock->owner = nullptr;
            sock->close();
            lost("socket");
            return;
        }
        m_udp = sock;
        if(t == EZTransport::DTLS){
#ifdef EZRADIUS_HAS_TLS
            std::string err;
            m_tls = EZTLSEngine::create(m_pool->m_tlsCtx, &err);
            if(!m_tls || !m_tls->start()){
                NR_LOG(netrector::LOG_ERROR, "EZRadiusPool: DTLS: %s", m_tls ? m_tls->errorText().c_str() : err.c_str());
                lost("dtls");
                return;
            }
            m_state = State::Handshaking;
            flushTls();
#else
            lost("no tls");
#endif
            return;
        }
        becomeUp();
        return;
    }
    auto *conn = new PoolTcp;
    conn->owner = this;
    conn->setReactor(r);
    m_tcp = conn;
    m_state = State::Connecting;
    const std::string ip = ezaddr::toString((const struct sockaddr*)&m_server);
    if(!conn->connectTo(ip.c_str(), (uint16_t)m_port)){
        m_tcp = nullptr;
        conn->owner = nullptr;
        delete conn;
        lost("connect");
    }
}

void EZPoolLink::tcpConnected()
{
    if(m_state != State::Connecting)
        return;
    m_framer.clear();
    if(m_pool->m_settings.Transport == EZTransport::TLS){
#ifdef EZRADIUS_HAS_TLS
        std::string err;
        m_tls = EZTLSEngine::create(m_pool->m_tlsCtx, &err);
        if(!m_tls || !m_tls->start()){
            NR_LOG(netrector::LOG_ERROR, "EZRadiusPool: TLS: %s", m_tls ? m_tls->errorText().c_str() : err.c_str());
            lost("tls");
            return;
        }
        m_state = State::Handshaking;
        if(!flushTls())
            lost("send");
        return;
#else
        lost("no tls");
        return;
#endif
    }
    becomeUp();
}

void EZPoolLink::becomeUp()
{
    Batch batchGuard(this);
    m_state = State::Up;
    m_backoff = 0;
    m_lastRx = nowMs();
    m_suspect = false;
    // send everything that waited for the connection
    for(int id = 0; id < SLOTS; id++){
        Slot &s = m_slots[id];
        if(s.req && !s.sent){
            arm(id);
            if(!sendSlot(id)){
                m_needLost = true;
                break;
            }
        }
    }
}

void EZPoolLink::tcpData(const uint8_t *data, size_t len)
{
    Batch batchGuard(this);
    m_lastRx = nowMs();
    if(m_tls){
#ifdef EZRADIUS_HAS_TLS
        const bool ok = m_tls->feed(data, len);
        flushTls();
        if(!ok){
            NR_LOG(netrector::LOG_WARN, "EZRadiusPool: TLS: %s", m_tls->errorText().c_str());
            lost("tls error");
            return;
        }
        if(m_state == State::Handshaking && m_tls->established()){
            const bool prev11 = m_r11;
            m_r11 = (m_tls->radiusVersion() == 11);
            (void)prev11;
            becomeUp();
            if(m_state != State::Up)
                return;
        }
        if(m_state == State::Up){
            const std::string plain = m_tls->takePlain();
            m_framer.append((const uint8_t*)plain.data(), plain.size());
        }
#endif
    }else{
        m_framer.append(data, len);
    }
    if(m_state == State::Up)
        handlePackets();
}

void EZPoolLink::handlePackets()
{
    std::string pkt;
    for(;;){
        const EZStreamFramer::Result r = m_framer.next(pkt);
        if(r == EZStreamFramer::NEED_MORE)
            return;
        if(r == EZStreamFramer::INVALID){
            lost("bad length");
            return;
        }
        if(m_r11)
            wireResponse(pkt);
        else
            response((const uint8_t*)pkt.data(), pkt.size());
        if(m_state != State::Up)
            return;
    }
}

void EZPoolLink::wireResponse(const std::string &wire)
{
#ifdef EZRADIUS_HAS_TLS
    if(wire.size() < 20)
        return;
    const uint8_t *w = (const uint8_t*)wire.data();
    const uint32_t token = ((uint32_t)w[4] << 24) | ((uint32_t)w[5] << 16) | ((uint32_t)w[6] << 8) | w[7];
    auto it = m_tokens.find(token);
    if(it == m_tokens.end())
        return;
    const int id = it->second;
    Slot &s = m_slots[id];
    if(!s.req)
        return;
    std::string classic;
    if(!ezradius11::wireResponseToClassic(w, wire.size(), (uint8_t)id, s.auth, m_pool->m_settings.Secret, classic))
        return;
    if(s.req->connAccept((const uint8_t*)classic.data(), classic.size(), true))
        complete(id, EZResult::OK);
#else
    (void)wire;
#endif
}

void EZPoolLink::response(const uint8_t *pkt, size_t len)
{
    if(len < 20)
        return;
    const int id = pkt[1];
    Slot &s = m_slots[id];
    if(!s.req || !s.sent)
        return;
    if(s.req->connAccept(pkt, len, false))
        complete(id, EZResult::OK);
}

void EZPoolLink::udpData(const uint8_t *data, size_t len, const struct sockaddr *from)
{
    if(!from)
        return;
    unsigned char a[16], b[16];
    if(!ezaddr::toKey(from, a) || !ezaddr::toKey((const struct sockaddr*)&m_server, b)
       || memcmp(a, b, 16) != 0 || ezaddr::portOf(from) != (uint16_t)m_port)
        return;
    m_lastRx = nowMs();
    if(!m_tls){
        if(m_state == State::Up)
            response(data, len);
        return;
    }
#ifdef EZRADIUS_HAS_TLS
    const bool ok = m_tls->feed(data, len);
    flushTls();
    if(!ok){
        NR_LOG(netrector::LOG_WARN, "EZRadiusPool: DTLS: %s", m_tls->errorText().c_str());
        lost("dtls error");
        return;
    }
    if(m_state == State::Handshaking && m_tls->established()){
        m_r11 = false;
        becomeUp();
        if(m_state != State::Up)
            return;
    }
    if(m_state == State::Up){
        for(const std::string &rec : m_tls->takeRecords()){
            response((const uint8_t*)rec.data(), rec.size());
            if(m_state != State::Up)
                return;
        }
    }
#endif
}

void EZPoolLink::sockClosed(bool)
{
    // the owner was cleared by the socket: the pointer is gone
    m_tcp = nullptr;
    m_udp = nullptr;
    if(m_state != State::Down && m_state != State::Backoff)
        lost("closed");
}

// The connection is gone (or never came up): requests that were sent are sent again later (while attempts
// are left), the others keep waiting; the link reconnects after a delay.
void EZPoolLink::lost(const char *why)
{
    (void)why;
    closeIo();
    m_needLost = false;
    m_probing = false;
    const uint64_t now = nowMs();
    m_state = State::Backoff;
    m_backoff = m_backoff == 0 ? m_pool->m_reconnectMin : (m_backoff * 2 > m_pool->m_reconnectMax ? m_pool->m_reconnectMax : m_backoff * 2);
    m_retryAt = now + (uint64_t)m_backoff;
    m_pool->m_reconnects++;

    std::vector<int> failed;
    for(int id = 0; id < SLOTS; id++){
        Slot &s = m_slots[id];
        if(!s.req || !s.sent)
            continue;
        if(s.probe || s.attempt >= s.maxAttempts){
            failed.push_back(id);
        }else{
            s.sent = false;
            arm(id);
        }
    }
    for(int id : failed)
        complete(id, EZResult::TIMEOUT);
}

void EZPoolLink::probeDone(EZResult r)
{
    m_probing = false;
    if(r == EZResult::OK){
        m_suspect = false;
        m_lastRx = nowMs();
    }else if(r != EZResult::CANCELED && m_state == State::Up){
        m_needLost = true;                  // no answer to the probe: the connection is dead
    }
}

void EZPoolLink::watchdog(uint64_t now)
{
    const int ka = m_pool->m_keepAliveMs;
    if(m_state != State::Up || m_probing || (!secure() && datagram()))
        return;
    if(!m_suspect && (ka <= 0 || now - m_lastRx < (uint64_t)ka || now - m_lastProbe < (uint64_t)ka))
        return;
    m_lastProbe = now;
    m_probing = true;
    if(!submit(&m_probe, 1))
        m_probing = false;
}

void EZPoolLink::expire(uint64_t now)
{
    while(!m_dl.empty() && m_dl.front().when <= now){
        const Deadline e = m_dl.front();
        m_dl.pop_front();
        Slot &s = m_slots[e.id];
        if(!s.req || s.gen != e.gen || s.deadline != e.when)
            continue;                       // finished, or a newer deadline exists
        if(datagram() && m_state == State::Up && s.sent && s.attempt < s.maxAttempts){
            if(!sendSlot(e.id))
                m_needLost = true;
            arm(e.id);                      // retransmission: same Identifier, same authenticator
            continue;
        }
        if(stream() && s.sent)
            m_suspect = true;               // no answer on a live connection: probe it
        complete(e.id, s.sent ? EZResult::TIMEOUT : (m_state == State::Backoff || m_state == State::Down ? EZResult::SEND_FAILED : EZResult::TIMEOUT));
    }
}

void EZPoolLink::tick()
{
    const uint64_t now = nowMs();
#ifdef EZRADIUS_HAS_TLS
    if(m_tls && m_udp && m_tls->msUntilTimeout() == 0){
        if(!m_tls->handleTimeout())
            m_needLost = true;
        else
            flushTls();
    }
#endif
    if(m_needLost && m_state != State::Backoff && m_state != State::Down)
        lost("send failed");
    if((m_state == State::Handshaking || m_state == State::Connecting || m_state == State::Resolving) && now >= m_hsDeadline)
        lost("handshake timeout");
    if(m_state == State::Backoff && now >= m_retryAt)
        startConnect();                     // persistent: the connection is kept ready even without requests
    if(m_state == State::Down && m_active > 0)
        startConnect();
    expire(now);
    if(m_state == State::Up && m_needLost)
        lost("send failed");
    watchdog(now);
}

void EZPoolLink::shutdown(bool notify)
{
    if(m_timer >= 0){
        m_pool->m_pReactor->removeTimer(m_timer);
        m_timer = -1;
    }
    closeIo();
    m_state = State::Down;
    m_dl.clear();
    std::vector<int> ids;
    for(int id = 0; id < SLOTS; id++)
        if(m_slots[id].req)
            ids.push_back(id);
    for(int id : ids){
        if(notify)
            complete(id, EZResult::CANCELED);
        else{
            Slot &s = m_slots[id];
            s.req->m_link = nullptr;
            s.req->m_slot = -1;
            s.req = nullptr;
        }
    }
    m_active = 0;
    m_backoff = 0;
}

// ---- pool ----
EZRadiusPool::EZRadiusPool(netrector::EpollReactor *reactor, const EZClientSettings &settings)
    : m_pReactor(reactor), m_settings(settings)
{
    m_settings.Pool.reset();
    if(m_settings.Transport == EZTransport::TLS)
        m_settings.Secret = "radsec";
    else if(m_settings.Transport == EZTransport::DTLS)
        m_settings.Secret = "radius/dtls";
    m_secret.setSecret(m_settings.Secret.c_str(), (uint16_t)strnlen(m_settings.Secret.c_str(), D_SECRET_MAX_LENGTH + 1));
}

std::shared_ptr<EZRadiusPool> EZRadiusPool::create(netrector::EpollReactor *reactor, const EZClientSettings &settings)
{
    if(!reactor || settings.Host.empty() || (settings.Transport != EZTransport::TLS && settings.Transport != EZTransport::DTLS && settings.Secret.empty()))
        return nullptr;
    std::shared_ptr<EZRadiusPool> p(new EZRadiusPool(reactor, settings));
    if(p->m_settings.Transport == EZTransport::TLS || p->m_settings.Transport == EZTransport::DTLS){
#ifdef EZRADIUS_HAS_TLS
        std::string err;
        p->m_tlsCtx = EZTLSContext::create(p->m_settings.TLS, false, p->m_settings.Transport == EZTransport::DTLS, &err);
        if(!p->m_tlsCtx){
            NR_LOG(netrector::LOG_ERROR, "EZRadiusPool: TLS configuration: %s", err.c_str());
            return nullptr;
        }
#else
        return nullptr;
#endif
    }
    return p;
}

EZRadiusPool::~EZRadiusPool()
{
    m_links.clear();                        // links close their sockets; requests are detached without callbacks
}

void EZRadiusPool::setConnections(int count)
{
    m_connections = count < 1 ? 1 : (count > 64 ? 64 : count);
}

void EZRadiusPool::setReconnectDelay(int minMs, int maxMs)
{
    m_reconnectMin = minMs < 1 ? 1 : minMs;
    m_reconnectMax = maxMs < m_reconnectMin ? m_reconnectMin : maxMs;
}

std::vector<std::unique_ptr<EZPoolLink>> &EZRadiusPool::linksFor(int port)
{
    std::vector<std::unique_ptr<EZPoolLink>> &v = m_links[port];
    while((int)v.size() < m_connections)
        v.emplace_back(new EZPoolLink(this, port));
    return v;
}

void EZRadiusPool::connect(int port)
{
    const bool secure = m_settings.Transport == EZTransport::TLS || m_settings.Transport == EZTransport::DTLS;
    if(port == 0)
        port = secure ? m_settings.RadSecPort : m_settings.AuthenticationPort;
    for(auto &l : linksFor(port))
        l->connect();
}

bool EZRadiusPool::submit(EZConnectionRequest *request, int port, int attempts)
{
    if(!request || port <= 0 || port > 65535 || request->m_link)
        return false;
    std::vector<std::unique_ptr<EZPoolLink>> &v = linksFor(port);
    // least loaded connection (a connected one wins a tie)
    EZPoolLink *best = nullptr;
    for(auto &l : v){
        if(!best || l->active() < best->active() || (l->active() == best->active() && l->up() && !best->up()))
            best = l.get();
    }
    return best && best->submit(request, attempts);
}

void EZRadiusPool::cancel(EZConnectionRequest *request)
{
    if(request && request->m_link)
        request->m_link->cancel(request);
}

void EZRadiusPool::close()
{
    for(auto &kv : m_links)
        for(auto &l : kv.second)
            l->shutdown(true);
}

size_t EZRadiusPool::inFlight() const
{
    size_t n = 0;
    for(const auto &kv : m_links)
        for(const auto &l : kv.second)
            n += l->active();
    return n;
}

size_t EZRadiusPool::connectedCount() const
{
    size_t n = 0;
    for(const auto &kv : m_links)
        for(const auto &l : kv.second)
            n += l->up() ? 1 : 0;
    return n;
}
