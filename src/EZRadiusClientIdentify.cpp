#include "EZRadiusClientIdentify.h"
#include "EZAddr.h"
#include <arpa/inet.h>
#include <cstring>

EZRadiusClientIdentify::EZRadiusClientIdentify(uint8_t ID, const struct sockaddr *peer, socklen_t peerLen,
                                               netrector::UDPSocket *socket, const unsigned char *pAuthenticator,
                                               std::shared_ptr<RASItem> ras, bool requestHadMessageAuthenticator)
    : m_pSocket(socket), m_RAS(std::move(ras)), m_ID(ID), m_RequestHadMA(requestHadMessageAuthenticator)
{
    memset(&m_Peer, 0, sizeof(m_Peer));
    memset(m_Authenticator, 0, sizeof(m_Authenticator));

    if(peer && peerLen > 0 && peerLen <= sizeof(m_Peer)){
        memcpy(&m_Peer, peer, peerLen);
        m_PeerLen = peerLen;
    }
    if(pAuthenticator)
        memcpy(m_Authenticator, pAuthenticator, D_AUTHENTICATOR_LENGTH);
}

uint32_t EZRadiusClientIdentify::IPAddress() const
{
    if(m_Peer.ss_family == AF_INET)
        return ((const struct sockaddr_in*)&m_Peer)->sin_addr.s_addr;
    if(m_Peer.ss_family == AF_INET6){
        const unsigned char *a = ((const struct sockaddr_in6*)&m_Peer)->sin6_addr.s6_addr;
        static const unsigned char mapped[12] = {0,0,0,0,0,0,0,0,0,0,0xff,0xff};
        if(memcmp(a, mapped, 12) == 0){
            uint32_t ip;
            memcpy(&ip, a + 12, 4);
            return ip;
        }
    }
    return 0;
}

std::string EZRadiusClientIdentify::IPAddressDescription() const
{
    return ezaddr::toString((const struct sockaddr*)&m_Peer);
}
