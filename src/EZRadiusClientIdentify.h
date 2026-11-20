#ifndef EZRADIUSCLIENTIDENTIFY_H
#define EZRADIUSCLIENTIDENTIFY_H

#include "RadiusPacket.h"
#include "EZRASList.h"
#include <memory>
#include <string>
#include <sys/socket.h>
#include <netinet/in.h>

namespace netrector { class UDPSocket; }

// Who sent a request and everything that is needed to answer it:
// peer address, the server socket the request arrived on, request ID / authenticator and the RAS.
// Plain value object (copyable). The socket pointer stays valid while the EZRadiusServer is running.
class EZRadiusClientIdentify
{
    unsigned char m_Authenticator[D_AUTHENTICATOR_LENGTH];
    struct sockaddr_storage m_Peer;
    socklen_t m_PeerLen = 0;
    netrector::UDPSocket *m_pSocket = nullptr;
    std::shared_ptr<RASItem> m_RAS;
    uint8_t m_ID = 0;
    bool m_RequestHadMA = false;

public:
    EZRadiusClientIdentify(uint8_t ID, const struct sockaddr *peer, socklen_t peerLen,
                           netrector::UDPSocket *socket, const unsigned char *pAuthenticator,
                           std::shared_ptr<RASItem> ras, bool requestHadMessageAuthenticator);

    uint8_t ID() const { return m_ID; }
    const unsigned char *Authenticator() const { return m_Authenticator; }
    netrector::UDPSocket *Socket() const { return m_pSocket; }
    const struct sockaddr *Peer() const { return (const struct sockaddr*)&m_Peer; }
    socklen_t PeerLen() const { return m_PeerLen; }
    std::shared_ptr<RASItem> RAS() const { return m_RAS; }

    // IPv4 address of the peer (network byte order), 0 when the peer is not IPv4
    uint32_t IPAddress() const;
    std::string IPAddressDescription() const;

    // true when the request carried a (valid) Message-Authenticator: the response will carry one too
    bool RequestHadMessageAuthenticator() const { return m_RequestHadMA; }
};

#endif // EZRADIUSCLIENTIDENTIFY_H
