// EZRadiusClient over TCP (RFC 6613). TLS / DTLS plug into the same hooks (see EZTLS.h).
#include "EZRadiusClient.h"
#include "EZAddr.h"
#include "EZTLS.h"
#include "EZRadius11.h"
#include "clsTCPSocket.h"
#include "clsUDPSocket.h"
#include "clsEpollReactor.h"
#include "clsLog.h"

class EZClientStreamConn : public netrector::TCPSocket
{
public:
    EZRadiusClient *owner = nullptr;
    bool connected = false;

    void onConnected() override
    {
        connected = true;
        if(owner)
            owner->streamConnected();
    }
    void onReceiveData(const uint8_t *data, size_t len) override
    {
        if(owner)
            owner->streamData(data, len);
    }
    void onClose() override
    {
        if(owner){
            EZRadiusClient *c = owner;
            owner = nullptr;
            c->m_conn = nullptr;
            c->m_haveServer = false;
            c->streamClosed();
        }
    }
};

bool EZRadiusClient::flushTls()
{
#ifdef EZRADIUS_HAS_TLS
    if(!m_tls)
        return false;
    if(!m_conn){
        // DTLS: one UDP datagram per entry
        if(!m_pSocket)
            return false;
        for(const std::string &d : m_tls->takeOutput())
            m_pSocket->sendTo(d.data(), d.size(), (const struct sockaddr*)&m_server, m_serverLen);
        return true;
    }
    for(const std::string &chunk : m_tls->takeOutput())
        if(!m_conn->send(chunk.data(), chunk.size()))
            return false;
    return true;
#else
    return false;
#endif
}

// the request goes out as it is (RADIUS/1.0) through the TLS engine when there is one
bool EZRadiusClient::sendRequest()
{
    if(!m_conn && !m_pSocket)
        return false;
#ifdef EZRADIUS_HAS_TLS
    if(m_tls){
        if(m_radius11){
            std::string wire;
            if(!ezradius11::classicRequestToWire(m_RequestPck.getRawData(), m_RequestPck.getLength(), m_settings.Secret, wire))
                return false;
            if(!m_tls->write((const uint8_t*)wire.data(), wire.size()))
                return false;
        }else if(!m_tls->write(m_RequestPck.getRawData(), m_RequestPck.getLength())){
            return false;
        }
        return flushTls();
    }
#endif
    return m_conn->send(m_RequestPck.getRawData(), m_RequestPck.getLength());
}

void EZRadiusClient::closeStream()
{
#ifdef EZRADIUS_HAS_TLS
    delete m_tls;
#endif
    m_tls = nullptr;
    m_radius11 = false;
    if(m_conn){
        m_conn->owner = nullptr;
        m_conn->close(true);        // autoDelete: the reactor deletes it
        m_conn = nullptr;
    }
    m_haveServer = false;
    m_framer.clear();
}

void EZRadiusClient::startStream()
{
    closeStream();
    auto *conn = new EZClientStreamConn;
    conn->owner = this;
    conn->setReactor(m_pReactor);
    m_conn = conn;
    m_connPort = m_serverPort;

    const std::string ip = ezaddr::toString((const struct sockaddr*)&m_server);
    if(!conn->connectTo(ip.c_str(), m_serverPort)){
        m_conn = nullptr;
        conn->owner = nullptr;
        delete conn;                // no callback will come: the object is still ours
        finish(EZResult::SEND_FAILED);
        return;
    }
    // one timer for the whole attempt: connect (+ handshake) + response
    m_attempt++;
    m_timerId = m_pReactor->addTimer(m_settings.TimeOut < 1 ? 1 : m_settings.TimeOut, [this]{ m_timerId = -1; streamTimeout(); }, true);
    if(m_timerId < 0)
        finish(EZResult::SEND_FAILED);
}

void EZRadiusClient::streamConnected()
{
    if(m_state != State::Running)
        return;
    m_framer.clear();
#ifdef EZRADIUS_HAS_TLS
    if(m_settings.Transport == EZTransport::TLS){
        // the handshake starts at once (no STARTTLS, bis section 3.2); the request follows when it is done
        std::string err;
        std::unique_ptr<EZTLSEngine> e = EZTLSEngine::create(m_tlsCtx, &err);
        if(!e || !e->start()){
            NR_LOG(netrector::LOG_ERROR, "EZRadiusClient: TLS: %s", e ? e->errorText().c_str() : err.c_str());
            closeStream();
            finish(EZResult::SEND_FAILED);
            return;
        }
        m_tls = e.release();
        if(!flushTls()){
            closeStream();
            finish(EZResult::SEND_FAILED);
        }
        return;
    }
#endif
    m_haveServer = true;
    if(!sendRequest()){
        closeStream();
        finish(EZResult::SEND_FAILED);
    }
}

// the connection is open: send the request again (a following request of the same object)
void EZRadiusClient::transmitStream()
{
    m_attempt++;
    if(!sendRequest()){
        // the connection died without us noticing: reconnect
        m_attempt--;
        startStream();
        return;
    }
    m_timerId = m_pReactor->addTimer(m_settings.TimeOut < 1 ? 1 : m_settings.TimeOut, [this]{ m_timerId = -1; streamTimeout(); }, true);
    if(m_timerId < 0)
        finish(EZResult::SEND_FAILED);
}

void EZRadiusClient::streamData(const uint8_t *data, size_t len)
{
    if(m_state != State::Running){
        m_framer.clear();           // unsolicited data on an idle connection
        return;
    }
#ifdef EZRADIUS_HAS_TLS
    if(m_tls){
        const bool ok = m_tls->feed(data, len);
        flushTls();
        if(!ok){
            NR_LOG(netrector::LOG_WARN, "EZRadiusClient: TLS: %s", m_tls->errorText().c_str());
            closeStream();
            streamClosed();
            return;
        }
        if(!m_haveServer && m_tls->established()){
            m_haveServer = true;
            m_radius11 = (m_tls->radiusVersion() == 11);
            m_negotiated11 = m_radius11;
            if(!sendRequest()){
                closeStream();
                finish(EZResult::SEND_FAILED);
                return;
            }
        }
        const std::string plain = m_tls->takePlain();
        m_framer.append((const uint8_t*)plain.data(), plain.size());
    }else
#endif
    m_framer.append(data, len);
    std::string pkt;
    for(;;){
        const EZStreamFramer::Result r = m_framer.next(pkt);
        if(r == EZStreamFramer::NEED_MORE)
            return;
        if(r == EZStreamFramer::INVALID){
            closeStream();
            streamClosed();
            return;
        }
#ifdef EZRADIUS_HAS_TLS
        if(m_radius11){
            std::string classic;
            if(!ezradius11::wireResponseToClassic((const uint8_t*)pkt.data(), pkt.size(), m_RequestPck.getID(), m_RequestPck.getAuthenticator(), m_settings.Secret, classic))
                continue;                       // another Token or malformed: ignored
            pkt.swap(classic);
        }
#endif
        handleResponse((const uint8_t*)pkt.data(), pkt.size());
        if(m_state != State::Running)
            return;
    }
}

// no valid response in time: RFC 6613 does not retransmit on a connection, so the next attempt is a new connection
void EZRadiusClient::streamTimeout()
{
    if(m_state != State::Running)
        return;
    closeStream();
    if(m_attempt >= m_maxAttempts){
        finish(EZResult::TIMEOUT);
        return;
    }
    startStream();
}

void EZRadiusClient::streamClosed()
{
    if(m_state != State::Running)
        return;
    if(m_timerId >= 0){
        m_pReactor->removeTimer(m_timerId);
        m_timerId = -1;
    }
    if(m_attempt >= m_maxAttempts){
        finish(m_haveServer ? EZResult::TIMEOUT : EZResult::SEND_FAILED);
        return;
    }
    // do not reconnect at once (draft-ietf-radext-radiusdtls-bis section 3.9.1: at least 0.5 s)
    const int wait = m_settings.TimeOut < 500 ? m_settings.TimeOut : 500;
    m_timerId = m_pReactor->addTimer(wait < 1 ? 1 : wait, [this]{ m_timerId = -1; if(m_state == State::Running) startStream(); }, true);
    if(m_timerId < 0)
        finish(EZResult::SEND_FAILED);
}

// ---- RADIUS over DTLS (RFC 7360): the UDP socket carries a DTLS session; one request = one session ----
void EZRadiusClient::startDtls()
{
#ifdef EZRADIUS_HAS_TLS
    std::string err;
    std::unique_ptr<EZTLSEngine> e = EZTLSEngine::create(m_tlsCtx, &err);
    if(!e || !e->start()){
        NR_LOG(netrector::LOG_ERROR, "EZRadiusClient: DTLS: %s", e ? e->errorText().c_str() : err.c_str());
        finish(EZResult::SEND_FAILED);
        return;
    }
    m_tls = e.release();
    m_haveServer = false;
    flushTls();
    m_dtlsTimer = m_pReactor->addTimer(50, [this]{ dtlsTick(); });
    // handshake deadline (several flights with retransmissions)
    const int limit = m_settings.TimeOut * 3 < 5000 ? 5000 : m_settings.TimeOut * 3;
    m_timerId = m_pReactor->addTimer(limit, [this]{ m_timerId = -1; onTimeout(); }, true);
    if(m_dtlsTimer < 0 || m_timerId < 0)
        finish(EZResult::SEND_FAILED);
#else
    finish(EZResult::SEND_FAILED);
#endif
}

void EZRadiusClient::dtlsTick()
{
#ifdef EZRADIUS_HAS_TLS
    if(m_state != State::Running || !m_tls)
        return;
    if(m_tls->msUntilTimeout() == 0){
        if(!m_tls->handleTimeout()){
            finish(EZResult::SEND_FAILED);
            return;
        }
        flushTls();
    }
#endif
}

void EZRadiusClient::dtlsDatagram(const uint8_t *data, size_t len)
{
#ifdef EZRADIUS_HAS_TLS
    if(m_state != State::Running || !m_tls)
        return;
    const bool ok = m_tls->feed(data, len);
    flushTls();
    if(!ok){
        NR_LOG(netrector::LOG_WARN, "EZRadiusClient: DTLS: %s", m_tls->errorText().c_str());
        finish(EZResult::SEND_FAILED);
        return;
    }
    if(!m_haveServer && m_tls->established()){
        m_haveServer = true;
        if(m_timerId >= 0){
            m_pReactor->removeTimer(m_timerId);
            m_timerId = -1;
        }
        transmit();                         // starts the normal retry timer
        if(m_state != State::Running)
            return;
    }
    for(const std::string &rec : m_tls->takeRecords()){
        handleResponse((const uint8_t*)rec.data(), rec.size());
        if(m_state != State::Running)
            return;
    }
#else
    (void)data; (void)len;
#endif
}
