#include "EZRadiusClient.h"
#include "EZAttrUtil.h"
#include "md5.h"
#include "clsUDPSocket.h"
#include "clsEpollReactor.h"
#include "clsLog.h"
#include <arpa/inet.h>
#include <cstring>

// UDP socket that forwards datagrams to its client (virtual dispatch: no static callback needed)
class EZClientSocket : public netrector::UDPSocket
{
public:
    EZRadiusClient *owner = nullptr;
    void onDatagram(const uint8_t *data, size_t len, const struct sockaddr *from, socklen_t) override
    {
        if(owner)
            owner->onDatagram(data, len, from);
    }
    // closed by the reactor (shutdown): the request can not continue
    void onClose() override
    {
        if(owner){
            EZRadiusClient *c = owner;
            owner = nullptr;
            c->m_pSocket = nullptr;
            c->Cancel();
        }
    }
};

EZRadiusClient::EZRadiusClient(netrector::EpollReactor *reactor, const EZClientSettings &Settings)
    : m_pReactor(reactor), m_settings(Settings)
{
    m_Secret.setSecret(m_settings.Secret.c_str(), (uint16_t)strnlen(m_settings.Secret.c_str(), D_SECRET_MAX_LENGTH + 1));
    m_RequestPck.setSecret(&m_Secret);
    m_RequestPck.randomID();
}

EZRadiusClient::~EZRadiusClient()
{
    m_callback = nullptr;
    releaseResources();
}

void EZRadiusClient::releaseResources()
{
    if(m_timerId >= 0){
        if(m_pReactor)
            m_pReactor->removeTimer(m_timerId);
        m_timerId = -1;
    }
    if(m_dnsPending){
        if(m_pReactor)
            m_pReactor->cancelDNS(this);
        m_dnsPending = false;
    }
    if(m_pSocket){
        static_cast<EZClientSocket*>(m_pSocket)->owner = nullptr;
        m_pSocket->close();         // autoDelete: deleted later by the reactor
        m_pSocket = nullptr;
    }
}

void EZRadiusClient::Reset()
{
    releaseResources();
    m_callback = nullptr;
    m_RequestPck = RadiusPacket();
    m_RequestPck.setSecret(&m_Secret);
    m_RequestPck.randomID();
    m_Response = RadiusPacket();
    m_state = State::Idle;
    m_result = EZResult::NONE;
}

bool EZRadiusClient::AddAttribute(RADIUSAttribute AttType, const char *value)
{
    if(m_state != State::Idle || !value)
        return false;

    switch (AttType) {
    case D_ATTR_USER_PASSWORD:
        // PAP: encrypted with the Request Authenticator (random, set when the packet was created)
        {
            size_t len = strnlen(value, D_MAX_PASSWORD_LENGTH + 1);
            if(len > D_MAX_PASSWORD_LENGTH)
                return false;
            RadiusAttribute attr;
            if(m_RequestPck.addAttribute(AttType, attr) != RC_SUCCESS)
                return false;
            return attr.setUserPassword(value, (uint16_t)len) == RC_SUCCESS;
        }
    case D_ATTR_CHAP_PASSWORD:
        {
            // CHAP: MD5(id + password + challenge), the Request Authenticator is used as the challenge
            size_t len = strnlen(value, D_MAX_PASSWORD_LENGTH + 1);
            if(len > D_MAX_PASSWORD_LENGTH)
                return false;
            unsigned char buf[1 + D_MAX_PASSWORD_LENGTH + D_AUTHENTICATOR_LENGTH];
            unsigned char resp[16];
            const unsigned char id = m_RequestPck.getID();
            buf[0] = id;
            memcpy(buf + 1, value, len);
            memcpy(buf + 1 + len, m_RequestPck.getAuthenticator(), D_AUTHENTICATOR_LENGTH);
            MD5Calc(resp, buf, (unsigned)(len + 1 + D_AUTHENTICATOR_LENGTH));
            memset(buf, 0, sizeof(buf));

            RadiusAttribute attr;
            if(m_RequestPck.addAttribute(AttType, attr) != RC_SUCCESS)
                return false;
            return attr.setChapIdentifier(id) == RC_SUCCESS && attr.setChapString((const char*)resp, 16) == RC_SUCCESS;
        }
    case D_ATTR_MESSAGE_AUTHENTICATOR:
        return false;       // added and signed by the library
    default:
        return ezutil::addString(m_RequestPck, AttType, value);
    }
}

bool EZRadiusClient::AddAttribute(RADIUSAttribute AttType, int value)
{
    return AddAttribute(AttType, (uint32_t)value);
}

bool EZRadiusClient::AddAttribute(RADIUSAttribute AttType, uint32_t value)
{
    if(m_state != State::Idle)
        return false;
    return ezutil::addNumber(m_RequestPck, AttType, value);
}

bool EZRadiusClient::AddVendorAttribute(uint32_t vendorId, unsigned char vendorType, const void *data, uint16_t length)
{
    if(m_state != State::Idle)
        return false;
    return ezutil::addVendor(m_RequestPck, vendorId, vendorType, data, length);
}

bool EZRadiusClient::AddVendorAttribute(uint32_t vendorId, unsigned char vendorType, const char *text)
{
    if(!text)
        return false;
    size_t len = strnlen(text, 256);
    return len <= 255 && AddVendorAttribute(vendorId, vendorType, text, (uint16_t)len);
}

bool EZRadiusClient::Send(RADIUSClientRequestType RequestType, const Callback &callback)
{
    if(m_state != State::Idle || !m_pReactor || m_Secret.isEmpty())
        return false;
    if(RequestType != C_ACCESS_REQUEST && RequestType != C_ACCOUNTING_REQUEST)
        return false;

    m_type = RequestType;
    m_serverPort = (uint16_t)(RequestType == C_ACCESS_REQUEST ? m_settings.AuthenticationPort : m_settings.AccountingPort);
    m_maxAttempts = m_settings.RetryCount < 1 ? 1 : m_settings.RetryCount;
    if(m_serverPort == 0)
        return false;

    m_RequestPck.setCode((unsigned char)RequestType);
    if(RequestType == C_ACCOUNTING_REQUEST){
        // Request Authenticator of an accounting request depends on the final packet content
        if(!m_RequestPck.accountingRequestAuthenticator())
            return false;
    }else if(m_settings.UseMessageAuthenticator){
        if(!m_RequestPck.addMessageAuthenticator() || !m_RequestPck.signMessageAuthenticator())
            return false;
    }

    m_callback = callback;
    m_state = State::Running;
    m_result = EZResult::NONE;
    m_attempt = 0;

    struct in_addr ip;
    if(inet_pton(AF_INET, m_settings.Host.c_str(), &ip) == 1){
        startWithAddress(ip.s_addr);
        return true;
    }

    // host name: asynchronous DNS (the callback can be called before getIPbyName returns: DNS cache)
    m_dnsPending = true;
    bool ok = m_pReactor->getIPbyName(m_settings.Host.c_str(),
        (netrector::DNSLookup::callback_t)[](const char *h, char **ips, size_t c, netrector::DNSLookup::QUERY_TYPE q, void *u){ onResolved(h, ips, c, (int)q, u); },
        this, netrector::DNSLookup::A);
    if(!ok){
        m_dnsPending = false;
        m_state = State::Idle;
        m_callback = nullptr;
        return false;
    }
    return true;
}

void EZRadiusClient::onResolved(const char *, char **ips, size_t count, int, void *user_data)
{
    EZRadiusClient *pThis = static_cast<EZRadiusClient*>(user_data);
    pThis->m_dnsPending = false;
    if(pThis->m_state != State::Running)
        return;

    struct in_addr ip;
    if(count == 0 || !ips || !ips[0] || inet_pton(AF_INET, ips[0], &ip) != 1){
        pThis->finish(EZResult::DNS_FAILED);
        return;
    }
    pThis->startWithAddress(ip.s_addr);
}

void EZRadiusClient::startWithAddress(uint32_t ip)
{
    m_serverIP = ip;

    auto *sock = new EZClientSocket;
    sock->owner = this;
    sock->setReactor(m_pReactor);
    sock->setMaxDatagramSize(D_RADIUS_PACKET_MAX_LENGTH);
    if(!sock->open(AF_INET)){
        sock->owner = nullptr;
        sock->close();
        finish(EZResult::SEND_FAILED);
        return;
    }
    m_pSocket = sock;
    transmit();
}

void EZRadiusClient::transmit()
{
    struct sockaddr_in to;
    memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET;
    to.sin_port = htons(m_serverPort);
    to.sin_addr.s_addr = m_serverIP;

    m_attempt++;
    // a failed sendto (full kernel buffer) is handled like a lost packet: the timer retries
    m_pSocket->sendTo(m_RequestPck.getRawData(), m_RequestPck.getLength(), (const struct sockaddr*)&to, sizeof(to));

    m_timerId = m_pReactor->addTimer(m_settings.TimeOut < 1 ? 1 : m_settings.TimeOut, [this]{ m_timerId = -1; onTimeout(); }, true);
    if(m_timerId < 0)
        finish(EZResult::SEND_FAILED);
}

void EZRadiusClient::onTimeout()
{
    if(m_state != State::Running)
        return;
    if(m_attempt >= m_maxAttempts){
        finish(EZResult::TIMEOUT);
        return;
    }
    transmit();     // same ID and authenticator: it is a retransmission
}

void EZRadiusClient::onDatagram(const uint8_t *data, size_t len, const struct sockaddr *from)
{
    if(m_state != State::Running || !from || from->sa_family != AF_INET)
        return;

    const struct sockaddr_in *in = (const struct sockaddr_in*)from;
    if(in->sin_addr.s_addr != m_serverIP || ntohs(in->sin_port) != m_serverPort)
        return;

    RadiusPacket resp;
    if(!resp.setRawData((const char*)data, (int)len))
        return;

    // right kind of response for this request
    const unsigned char code = resp.getCode();
    const bool accessResp = (code == ACCESS_ACCEPT || code == ACCESS_REJECT || code == ACCESS_CHALLENGE);
    if(m_type == C_ACCESS_REQUEST ? !accessResp : code != ACCOUNTING_RESPONSE)
        return;

    // ID + Response Authenticator (needs the Request Authenticator, so the request must be unchanged)
    if(!m_RequestPck.verifyResponse(resp))
        return;

    resp.setSecret(&m_Secret);
    if(resp.hasMessageAuthenticator()){
        if(!resp.verifyMessageAuthenticator(m_RequestPck.getAuthenticator(), &m_Secret))
            return;
    }else if(accessResp && m_settings.RequireMessageAuthenticator){
        return;
    }

    m_Response = resp;
    m_Response.setSecret(&m_Secret);
    finish(EZResult::OK);
}

void EZRadiusClient::Cancel()
{
    if(m_state == State::Running)
        finish(EZResult::CANCELED);
}

void EZRadiusClient::finish(EZResult result)
{
    releaseResources();
    m_state = State::Done;
    m_result = result;

    // the callback is the last thing: it may call Reset() or start a new request
    Callback cb = std::move(m_callback);
    m_callback = nullptr;
    if(cb)
        cb(*this, result);
}

RADIUSPacketTypeCodes EZRadiusClient::GetResponseType()
{
    return m_result == EZResult::OK ? (RADIUSPacketTypeCodes)m_Response.getCode() : UNKNOWN;
}

const char *EZRadiusClient::GetResponseTypeDescription()
{
    return m_result == EZResult::OK ? m_Response.getCodeDescription() : "No response";
}

AttrValue EZRadiusClient::GetAttribute(RADIUSAttribute AttrType)
{
    return m_result == EZResult::OK ? m_Response.getAttribute(AttrType) : AttrValue();
}

std::vector<AttrValue> EZRadiusClient::GetAttributes(RADIUSAttribute AttrType)
{
    return m_result == EZResult::OK ? m_Response.getAttributes(AttrType) : std::vector<AttrValue>();
}

void EZRadiusClient::DumpResponse()
{
    if(m_result == EZResult::OK)
        m_Response.dump();
}
