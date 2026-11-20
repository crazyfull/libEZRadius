#include "EZRadiusClient.h"
#include "EZAttrUtil.h"
#include "EZAddr.h"
#include "md5.h"
#include "EZCrypto.h"
#include "EZVendor.h"
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
    memset(&m_server, 0, sizeof(m_server));
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
#ifdef EZRADIUS_HAS_CRYPTO
    EZCrypto::Wipe(m_msNtHash, sizeof(m_msNtHash));
    m_msKind = 0;
    m_msUser.clear();
#endif
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

bool EZRadiusClient::resolve(int qtype)
{
    m_dnsPending = true;
    bool ok = m_pReactor->getIPbyName(m_settings.Host.c_str(),
        (netrector::DNSLookup::callback_t)[](const char *h, char **ips, size_t c, netrector::DNSLookup::QUERY_TYPE q, void *u){ onResolved(h, ips, c, (int)q, u); },
        this, (netrector::DNSLookup::QUERY_TYPE)qtype);
    if(!ok)
        m_dnsPending = false;
    return ok;
}

#ifdef EZRADIUS_HAS_CRYPTO
bool EZRadiusClient::AddMSCHAPv2(const char *userName, const char *password)
{
    if(m_state != State::Idle || !userName || !password || m_msKind != 0)
        return false;
    if(strnlen(userName, 254) > 253 || strnlen(password, 1025) > 1024)
        return false;

    m_msUser = userName;
    EZCrypto::Random(m_msAuthChallenge, 16);
    EZCrypto::Random(m_msPeerChallenge, 16);
    EZCrypto::Random(&m_msIdent, 1);
    EZMSCHAP::NtPasswordHash(password, m_msNtHash);
    EZMSCHAP::GenerateNTResponseV2(m_msAuthChallenge, m_msPeerChallenge, m_msUser, m_msNtHash, m_msNtResponse);

    // MS-CHAP2-Response: ident, flags, peer challenge(16), reserved(8), NT response(24)
    unsigned char resp[50];
    memset(resp, 0, sizeof(resp));
    resp[0] = m_msIdent;
    memcpy(resp + 2, m_msPeerChallenge, 16);
    memcpy(resp + 26, m_msNtResponse, 24);

    if(!ezutil::addString(m_RequestPck, USER_NAME, userName)
       || !ezutil::addVendor(m_RequestPck, D_VENDOR_MICROSOFT, MS_CHAP_CHALLENGE, m_msAuthChallenge, 16)
       || !ezutil::addVendor(m_RequestPck, D_VENDOR_MICROSOFT, MS_CHAP2_RESPONSE, resp, 50))
        return false;
    m_msKind = 2;
    return true;
}

bool EZRadiusClient::AddMSCHAPv1(const char *userName, const char *password)
{
    if(m_state != State::Idle || !userName || !password || m_msKind != 0)
        return false;
    if(strnlen(userName, 254) > 253 || strnlen(password, 1025) > 1024)
        return false;

    m_msUser = userName;
    uint8_t challenge[8];
    EZCrypto::Random(challenge, 8);
    EZCrypto::Random(&m_msIdent, 1);
    EZMSCHAP::NtPasswordHash(password, m_msNtHash);

    // MS-CHAP-Response: ident, flags (1 = NT response), LM response(24, unused), NT response(24)
    unsigned char resp[50];
    memset(resp, 0, sizeof(resp));
    resp[0] = m_msIdent;
    resp[1] = 1;
    EZMSCHAP::ChallengeResponse(challenge, m_msNtHash, resp + 26);

    if(!ezutil::addString(m_RequestPck, USER_NAME, userName)
       || !ezutil::addVendor(m_RequestPck, D_VENDOR_MICROSOFT, MS_CHAP_CHALLENGE, challenge, 8)
       || !ezutil::addVendor(m_RequestPck, D_VENDOR_MICROSOFT, MS_CHAP_RESPONSE, resp, 50))
        return false;
    m_msKind = 1;
    return true;
}

bool EZRadiusClient::MSCHAPv2ServerVerified()
{
    if(m_result != EZResult::OK || m_msKind != 2 || m_Response.getCode() != ACCESS_ACCEPT)
        return false;

    std::string v;
    if(!ezvendor::find(m_Response, D_VENDOR_MICROSOFT, MS_CHAP2_SUCCESS, v) || v.size() != 43 || (uint8_t)v[0] != m_msIdent)
        return false;

    const std::string expected = EZMSCHAP::AuthenticatorResponseV2(m_msNtHash, m_msNtResponse, m_msPeerChallenge, m_msAuthChallenge, m_msUser);
    return expected.size() == 42 && EZCrypto::Equal(expected.data(), v.data() + 1, 42);
}

bool EZRadiusClient::GetMPPEKeys(uint8_t sendKey[16], uint8_t recvKey[16])
{
    if(m_result != EZResult::OK)
        return false;
    const unsigned char *secret = nullptr;
    uint16_t secretLen = 0;
    if(m_Secret.getSecret(secret, secretLen) != RC_SUCCESS)
        return false;

    std::string s, r;
    if(!ezvendor::find(m_Response, D_VENDOR_MICROSOFT, MS_MPPE_SEND_KEY, s) || !ezvendor::find(m_Response, D_VENDOR_MICROSOFT, MS_MPPE_RECV_KEY, r))
        return false;
    return EZMSCHAP::DecodeMppeKey(s, secret, secretLen, m_RequestPck.getAuthenticator(), sendKey)
        && EZMSCHAP::DecodeMppeKey(r, secret, secretLen, m_RequestPck.getAuthenticator(), recvKey);
}
#endif

bool EZRadiusClient::Send(RADIUSClientRequestType RequestType, const Callback &callback)
{
    if(m_state != State::Idle || !m_pReactor || m_Secret.isEmpty())
        return false;

    int port = 0;
    switch(RequestType){
    case C_ACCESS_REQUEST:
    case C_STATUS_SERVER:
        port = m_settings.AuthenticationPort; break;
    case C_ACCOUNTING_REQUEST:
        port = m_settings.AccountingPort; break;
    case C_DISCONNECT_REQUEST:
    case C_COA_REQUEST:
        port = m_settings.CoAPort; break;
    default:
        return false;
    }
    if(port <= 0 || port > 65535)
        return false;

    m_type = RequestType;
    m_serverPort = (uint16_t)port;
    m_maxAttempts = m_settings.RetryCount < 1 ? 1 : m_settings.RetryCount;

    m_RequestPck.setCode((unsigned char)RequestType);
    switch(RequestType){
    case C_ACCOUNTING_REQUEST:
    case C_DISCONNECT_REQUEST:
    case C_COA_REQUEST:
        // Request Authenticator = MD5(packet with zero authenticator + secret): depends on the final packet content
        if(!m_RequestPck.accountingRequestAuthenticator())
            return false;
        break;
    case C_STATUS_SERVER:
        // Message-Authenticator is mandatory (RFC 5997); the Request Authenticator is random
        if(!m_RequestPck.addMessageAuthenticator() || !m_RequestPck.signMessageAuthenticator())
            return false;
        break;
    default:
        if(m_settings.UseMessageAuthenticator){
            if(!m_RequestPck.addMessageAuthenticator() || !m_RequestPck.signMessageAuthenticator())
                return false;
        }
        break;
    }

    m_callback = callback;
    m_state = State::Running;
    m_result = EZResult::NONE;
    m_attempt = 0;
    m_triedAAAA = false;

    struct sockaddr_storage ss;
    socklen_t len = 0;
    if(ezaddr::parse(m_settings.Host.c_str(), m_serverPort, ss, len)){
        startWithAddress((const struct sockaddr*)&ss, len);
        return true;
    }

    // host name: asynchronous DNS (the callback can be called before getIPbyName returns: DNS cache)
    if(!resolve(netrector::DNSLookup::A)){
        m_state = State::Idle;
        m_callback = nullptr;
        return false;
    }
    return true;
}

void EZRadiusClient::onResolved(const char *, char **ips, size_t count, int qtype, void *user_data)
{
    EZRadiusClient *pThis = static_cast<EZRadiusClient*>(user_data);
    pThis->m_dnsPending = false;
    if(pThis->m_state != State::Running)
        return;

    struct sockaddr_storage ss;
    socklen_t len = 0;
    if(count == 0 || !ips || !ips[0] || !ezaddr::parse(ips[0], pThis->m_serverPort, ss, len)){
        // no IPv4 address: try IPv6
        if(qtype == netrector::DNSLookup::A && !pThis->m_triedAAAA){
            pThis->m_triedAAAA = true;
            if(pThis->resolve(netrector::DNSLookup::AAAA))
                return;
        }
        pThis->finish(EZResult::DNS_FAILED);
        return;
    }
    pThis->startWithAddress((const struct sockaddr*)&ss, len);
}

void EZRadiusClient::startWithAddress(const struct sockaddr *address, socklen_t len)
{
    memcpy(&m_server, address, len);
    m_serverLen = len;

    auto *sock = new EZClientSocket;
    sock->owner = this;
    sock->setReactor(m_pReactor);
    sock->setMaxDatagramSize(D_RADIUS_PACKET_MAX_LENGTH);
    if(!sock->open(address->sa_family)){
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
    m_attempt++;
    // a failed sendto (full kernel buffer) is handled like a lost packet: the timer retries
    m_pSocket->sendTo(m_RequestPck.getRawData(), m_RequestPck.getLength(), (const struct sockaddr*)&m_server, m_serverLen);

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
    if(m_state != State::Running || !from)
        return;

    // only the server we asked may answer (IPv4-mapped IPv6 addresses compare equal to IPv4)
    unsigned char a[16], b[16];
    if(!ezaddr::toKey(from, a) || !ezaddr::toKey((const struct sockaddr*)&m_server, b)
       || memcmp(a, b, 16) != 0 || ezaddr::portOf(from) != m_serverPort)
        return;

    RadiusPacket resp;
    if(!resp.setRawData((const char*)data, (int)len))
        return;

    // right kind of response for this request
    const unsigned char code = resp.getCode();
    const bool accessResp = (code == ACCESS_ACCEPT || code == ACCESS_REJECT || code == ACCESS_CHALLENGE);
    bool expected = false;
    switch(m_type){
    case C_ACCESS_REQUEST:      expected = accessResp; break;
    case C_ACCOUNTING_REQUEST:  expected = (code == ACCOUNTING_RESPONSE); break;
    case C_STATUS_SERVER:       expected = (code == ACCESS_ACCEPT || code == ACCOUNTING_RESPONSE); break;
    case C_DISCONNECT_REQUEST:  expected = (code == DISCONNECT_ACK || code == DISCONNECT_NAK); break;
    case C_COA_REQUEST:         expected = (code == COA_ACK || code == COA_NAK); break;
    }
    if(!expected)
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
