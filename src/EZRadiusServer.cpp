#include "EZRadiusServer.h"
#include "EZRadiusClientIdentify.h"
#include "clsUDPSocket.h"
#include "clsEpollReactor.h"
#include "clsLog.h"
#include <arpa/inet.h>

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

EZRadiusServer::EZRadiusServer(netrector::EpollReactor *reactor)
    : m_pReactor(reactor), m_AuthPort(D_RADIUS_AUTHENTICATION_PORT), m_AccPort(D_RADIUS_ACCOUNTING_PORT), m_BindAddress("0.0.0.0")
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
void EZRadiusServer::setBindAddress(const char *ip) { m_BindAddress = (ip && *ip) ? ip : "0.0.0.0"; }

void EZRadiusServer::SeRequestCallback(const RADIUSCallback &callback, void *p)
{
    m_pPointerCallback = p;
    m_callback = callback;
}

netrector::UDPSocket *EZRadiusServer::openSocket(uint16_t port)
{
    auto *sock = new EZServerSocket;
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
    for(netrector::UDPSocket *s : m_sockets){
        static_cast<EZServerSocket*>(s)->owner = nullptr;   // the object lives until the reactor deletes it
        s->close();
    }
    m_sockets.clear();
}

void EZRadiusServer::handleDatagram(netrector::UDPSocket *socket, const uint8_t *data, size_t len, const struct sockaddr *from, socklen_t fromLen)
{
    if(!from || from->sa_family != AF_INET || fromLen < sizeof(struct sockaddr_in))
        return;

    const in_addr_t peerIP = ((const struct sockaddr_in*)from)->sin_addr.s_addr;
    std::shared_ptr<RASItem> ras = m_RASList.GetRASByIP(peerIP);

    // unknown RAS: drop silently (no answer, so the server can not be used to probe)
    if(!ras){
        NR_LOG(netrector::LOG_DEBUG, "EZRadiusServer: RAS not found, packet dropped");
        return;
    }

    RadiusPacket request;
    if(!request.setRawData((const char*)data, (int)len)){
        NR_LOG(netrector::LOG_DEBUG, "EZRadiusServer: malformed packet dropped");
        return;
    }
    request.setSecret(&ras->Secret);

    const unsigned char code = request.getCode();
    const bool hasMA = request.hasMessageAuthenticator();

    // Request Authenticator: accounting / CoA / disconnect requests are authenticated by it
    if(code == ACCOUNTING_REQUEST || code == DISCONNECT_REQUEST || code == COA_REQUEST){
        if(!request.verifyRequestAuthenticator()){
            NR_LOG(netrector::LOG_WARN, "EZRadiusServer: bad Request Authenticator, packet dropped");
            return;
        }
    }

    // Message-Authenticator (RFC 3579, BlastRADIUS)
    if(hasMA){
        if(!request.verifyMessageAuthenticator()){
            NR_LOG(netrector::LOG_WARN, "EZRadiusServer: bad Message-Authenticator, packet dropped");
            return;
        }
    }else if(m_RequireMA && code == ACCESS_REQUEST){
        NR_LOG(netrector::LOG_WARN, "EZRadiusServer: Access-Request without Message-Authenticator dropped");
        return;
    }

    RADIUSPacketTypeCodes type = (code > D_PACKET_MAX_KNOWN_CODE) ? UNKNOWN : (RADIUSPacketTypeCodes)code;

    EZRadiusClientIdentify identify(request.getID(), from, fromLen, socket, request.getAuthenticator(), ras, hasMA);

    if(m_callback)
        m_callback(type, request, identify, this, m_pPointerCallback);
    else
        onReceiveRequest(type, request, identify, this);
}
