#include "EZCoA.h"
#include "EZRadiusClientIdentify.h"
#include "clsEpollReactor.h"
#include "clsLog.h"
#include <arpa/inet.h>

EZCoA::EZCoA(netrector::EpollReactor *reactor, const EZClientSettings &Settings)
    : m_settings(Settings), m_pServer(new EZRadiusServer(reactor))
{
}

EZCoA::~EZCoA()
{
    Stop();
    if(m_pServer->reactor())
        m_pServer->reactor()->cancelDNS(this);
}

void EZCoA::SetGetRequests(const CoACallback &callback, void *p)
{
    m_pPointerCallback = p;
    m_callback = callback;
}

void EZCoA::onResolved(const char *hostname, char **ips, size_t count, int, void *user_data)
{
    EZCoA *pThis = static_cast<EZCoA*>(user_data);
    if(count == 0 || !ips || !ips[0]){
        NR_LOG(netrector::LOG_WARN, "EZCoA: can not resolve %s", hostname ? hostname : "?");
        return;
    }
    if(!pThis->m_pServer->RASList()->SetRAS(pThis->m_settings.Secret.c_str(), ips[0]))
        NR_LOG(netrector::LOG_WARN, "EZCoA: can not add %s", ips[0]);
}

void EZCoA::addAllowed(const std::string &hostOrIp)
{
    if(hostOrIp.empty())
        return;

    // IPv4 literal: added at once. Otherwise: asynchronous DNS lookup, added when it completes.
    if(m_pServer->RASList()->SetRAS(m_settings.Secret.c_str(), hostOrIp.c_str()))
        return;

    struct in_addr tmp;
    if(inet_pton(AF_INET, hostOrIp.c_str(), &tmp) == 1)
        return;     // valid IP but the secret was rejected (empty / too long)

    m_pServer->reactor()->getIPbyName(hostOrIp.c_str(),
        (netrector::DNSLookup::callback_t)[](const char *h, char **ips, size_t c, netrector::DNSLookup::QUERY_TYPE q, void *u){ onResolved(h, ips, c, (int)q, u); },
        this, netrector::DNSLookup::A);
}

bool EZCoA::Start()
{
    m_pServer->setAuthenticationPort((uint16_t)m_settings.CoAPort);
    m_pServer->setAccountingPort((uint16_t)m_settings.CoAPort);
    m_pServer->SeRequestCallback(onGetRadiusRequest, this);

    if(!m_pServer->Start())
        return false;

    addAllowed(m_settings.Host);
    addAllowed(m_settings.RAS_IP);
    return true;
}

void EZCoA::Stop()
{
    m_pServer->Stop();
}

void EZCoA::onGetRadiusRequest(RADIUSPacketTypeCodes PacketType, RadiusPacket &request, EZRadiusClientIdentify &ClientIdentify, EZRadiusServer *, void *p)
{
    EZCoA *pThis = static_cast<EZCoA*>(p);
    if(!pThis || !pThis->m_callback)
        return;

    // only requests are handled (ACK / NAK packets sent to us are ignored)
    if(PacketType != DISCONNECT_REQUEST && PacketType != COA_REQUEST)
        return;

    EZResponse response;
    RADIUSPacketTypeCodes ret = pThis->m_callback(PacketType, request, response, pThis->m_pPointerCallback);

    const bool ok = (PacketType == DISCONNECT_REQUEST) ? (ret == DISCONNECT_ACK || ret == DISCONNECT_NAK)
                                                       : (ret == COA_ACK || ret == COA_NAK);
    if(ok)
        response.Send(ret, &ClientIdentify);
}
