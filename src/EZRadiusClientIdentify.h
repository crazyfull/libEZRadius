#ifndef EZRADIUSCLIENTIDENTIFY_H
#define EZRADIUSCLIENTIDENTIFY_H

#include "RadiusPacket.h"
#include "EZRASList.h"
#include "EZTransport.h"
#include <memory>
#include <vector>
#include <string>
#include <sys/socket.h>
#include <netinet/in.h>

namespace netrector { class UDPSocket; }
class EZDedupCache;

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
    std::shared_ptr<EZDedupCache> m_Dedup;
    std::string m_DedupKey;
    std::vector<std::string> m_ProxyStates;
    std::shared_ptr<EZReplyChannel> m_Channel;
    bool m_Radius11 = false;

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

    // Proxy-State attributes of the request: copied into the response (RFC 2865 section 5.33)
    const std::vector<std::string> &ProxyStates() const { return m_ProxyStates; }
    void addProxyState(const std::string &value) { m_ProxyStates.push_back(value); }

    // retransmission cache (used by EZResponse::Send to remember the answer)
    void setDedup(std::shared_ptr<EZDedupCache> cache, const std::string &key) { m_Dedup = std::move(cache); m_DedupKey = key; }
    const std::shared_ptr<EZDedupCache> &dedup() const { return m_Dedup; }
    const std::string &dedupKey() const { return m_DedupKey; }

    // TCP / TLS / DTLS: the channel the response is sent on (Socket() is null then)
    const std::shared_ptr<EZReplyChannel> &channel() const { return m_Channel; }
    void setChannel(std::shared_ptr<EZReplyChannel> channel) { m_Channel = std::move(channel); }
    // the request came in RADIUS/1.1 format (RFC 9765): no Message-Authenticator exists on this connection
    bool isRadius11() const { return m_Radius11; }
    void setRadius11(bool on) { m_Radius11 = on; }

    // IPv4 address of the peer (network byte order), 0 when the peer is not IPv4
    // (an IPv4-mapped IPv6 peer counts as IPv4)
    uint32_t IPAddress() const;
    std::string IPAddressDescription() const;

    // true when the request carried a (valid) Message-Authenticator: the response will carry one too
    bool RequestHadMessageAuthenticator() const { return m_RequestHadMA; }
};

#endif // EZRADIUSCLIENTIDENTIFY_H
