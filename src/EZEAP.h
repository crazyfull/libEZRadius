#ifndef EZEAP_H
#define EZEAP_H
// EAP over RADIUS (RFC 3579) with pluggable methods.
//
//   EZEAPServer   server side state machine: turns Access-Requests carrying EAP-Message into
//                 Access-Challenge / Access-Accept / Access-Reject (State sessions, fragmentation,
//                 Message-Authenticator, MPPE keys from the MSK).
//   EZEAPMethod   interface of an authentication method; built in: EAP-MD5 (RFC 3748) and
//                 EAP-TLS (RFC 5216, TLS 1.2). Other methods can be added with EZEAPServer::registerMethod().
//   EZEAPPeer     minimal supplicant (MD5 + TLS): lets tools / tests run a full EAP conversation through
//                 EZRadiusClient / EZRadiusSyncClient without an 802.1X supplicant.
//
// Needs BoringSSL (EZRADIUS_HAS_CRYPTO); EAP-TLS also needs libssl (EZRADIUS_HAS_TLS).
#ifdef EZRADIUS_HAS_CRYPTO

#include "RadiusPacket.h"
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

class EZResponse;
class EZRadiusClientIdentify;

namespace ezeap {

enum Code : uint8_t { CODE_REQUEST = 1, CODE_RESPONSE = 2, CODE_SUCCESS = 3, CODE_FAILURE = 4 };
enum Type : uint8_t { TYPE_IDENTITY = 1, TYPE_NOTIFICATION = 2, TYPE_NAK = 3, TYPE_MD5 = 4, TYPE_TLS = 13 };

enum : uint8_t { ATTR_STATE = 24, ATTR_EAP_MESSAGE = 79 };

// one EAP packet (RFC 3748 section 4): Code, Identifier, Length, [Type, Type-Data]
struct Packet
{
    uint8_t code = 0;
    uint8_t id = 0;
    uint8_t type = 0;           // only Request / Response
    std::string data;           // Type-Data

    bool hasType() const { return code == CODE_REQUEST || code == CODE_RESPONSE; }
    std::string serialize() const;
    static bool parse(const std::string &bytes, Packet &out);       // false: malformed
};

// concatenated value of all EAP-Message attributes of a packet (empty when there is none)
std::string extractMessage(RadiusPacket &pck);
// adds the EAP packet as EAP-Message attributes of at most 253 bytes each
bool addMessage(RadiusPacket &pck, const std::string &eapPacket);

} // namespace ezeap

// ---------------------------------------------------------------------------------------------
// authentication method (server side)
struct EZEAPStep
{
    enum Status { CONTINUE, SUCCESS, FAILURE };
    Status status = FAILURE;
    std::string data;           // CONTINUE: Type-Data of the next Request
};

class EZEAPMethod
{
public:
    virtual ~EZEAPMethod() = default;
    virtual uint8_t type() const = 0;
    // first Request of the method; requestId = EAP identifier it will be sent with
    virtual EZEAPStep start(uint8_t requestId) = 0;
    // Type-Data of a Response of this method; responseId = its EAP identifier
    virtual EZEAPStep handle(uint8_t responseId, const std::string &typeData) = 0;
    // after SUCCESS: Master Session Key (64 bytes) or empty for methods that do not export keys (EAP-MD5)
    virtual std::string msk() const { return std::string(); }
    // after SUCCESS: name the method authenticated (EAP-TLS: subject CN of the client certificate)
    virtual std::string peerName() const { return std::string(); }
};

// what the application learns about a finished conversation
struct EZEAPSessionInfo
{
    std::string identity;       // EAP-Response/Identity
    uint8_t methodType = 0;
    std::string peerName;       // EAP-TLS: CN of the client certificate
    std::string msk;            // 64 bytes (empty for EAP-MD5)
};

#ifdef EZRADIUS_HAS_TLS
struct EZEAPTLSConfig
{
    std::string certChainPem;           // own certificate (+ intermediate certificates)
    std::string privateKeyPem;          // own private key
    std::string caPem;                  // trusted CA certificates (verify the other side)
    bool verifyPeer = true;             // server: require + verify the client certificate; peer: verify the server certificate
    size_t fragmentSize = 1000;         // maximum TLS bytes per EAP packet (RFC 5216 section 3.1)
    // helper: read a PEM file (empty string when it can not be read)
    static std::string readFile(const std::string &path);
};

struct ezeap_tls_ctx;                   // opaque, wraps SSL_CTX
class EZEAPTLSContext
{
public:
    ~EZEAPTLSContext();
    static std::shared_ptr<EZEAPTLSContext> create(const EZEAPTLSConfig &cfg, bool server, std::string *error = nullptr);
    ezeap_tls_ctx *impl() const { return m_impl; }
    size_t fragmentSize() const { return m_fragmentSize; }
private:
    EZEAPTLSContext() = default;
    ezeap_tls_ctx *m_impl = nullptr;
    size_t m_fragmentSize = 1000;
};
#endif

// ---------------------------------------------------------------------------------------------
enum class EZEAPResult { NOT_EAP, CHALLENGE, ACCEPT, REJECT, ERROR };

class EZEAPServer
{
public:
    // password of an identity for EAP-MD5 (return false when the user is unknown)
    using PasswordLookup = std::function<bool(const std::string &identity, std::string &password)>;
    using MethodFactory = std::function<std::unique_ptr<EZEAPMethod>(const std::string &identity)>;
    // called before an Access-Accept is sent: add Reply attributes (rate limits, VLAN, ...) to the response
    using AcceptHook = std::function<void(EZResponse &response, const EZEAPSessionInfo &info)>;
    // called when a conversation fails (EAP-Failure / Access-Reject)
    using RejectHook = std::function<void(const std::string &identity, uint8_t methodType)>;

    EZEAPServer();
    ~EZEAPServer();

    // enable EAP-MD5 (RFC 3748 section 5.4). Note: MD5-Challenge gives no mutual authentication and no keys;
    // use it only on trusted links. Registered after the methods that are already enabled (lower priority).
    void enableMD5(PasswordLookup lookup);
#ifdef EZRADIUS_HAS_TLS
    // enable EAP-TLS (RFC 5216). Methods registered first are offered first.
    bool enableTLS(const EZEAPTLSConfig &cfg, std::string *error = nullptr);
#endif
    // add an own method; the first registered method is offered first, the others when the peer sends EAP-Nak
    void registerMethod(uint8_t type, MethodFactory factory);

    void setAcceptHook(AcceptHook hook) { m_acceptHook = std::move(hook); }
    void setRejectHook(RejectHook hook) { m_rejectHook = std::move(hook); }
    void setSessionTimeout(int seconds) { m_timeoutSec = seconds; }          // default 30
    void setMaxSessions(size_t n) { m_maxSessions = n; }                     // default 4096

    size_t activeSessions() const { return m_sessions.size(); }

    // Handle an Access-Request (call it from the request callback of EZRadiusServer, reactor thread only).
    // NOT_EAP: the request has no EAP-Message, nothing was sent. Otherwise the response was sent.
    EZEAPResult Process(RadiusPacket &request, EZRadiusClientIdentify &from);

private:
    struct Session
    {
        std::string identity;
        std::string peerKey;                    // source address of the NAS: a State is not valid from another NAS
        std::unique_ptr<EZEAPMethod> method;
        uint8_t lastId = 0;
        std::chrono::steady_clock::time_point deadline;
    };
    struct MethodEntry { uint8_t type; MethodFactory factory; };

    bool send(EZEAPResult result, EZResponse &resp, const std::string &state, const std::string &eap, EZRadiusClientIdentify &from, const EZEAPSessionInfo *info);
    EZEAPResult reject(EZRadiusClientIdentify &from, uint8_t responseId, const Session *s);
    void purge();

    std::vector<MethodEntry> m_methods;
    std::map<std::string, Session> m_sessions;
    AcceptHook m_acceptHook;
    RejectHook m_rejectHook;
    int m_timeoutSec = 30;
    size_t m_maxSessions = 4096;
    std::chrono::steady_clock::time_point m_lastPurge;
};

// ---------------------------------------------------------------------------------------------
// minimal supplicant
class EZEAPPeer
{
public:
    enum State { RUNNING, SUCCESS, FAILURE };

    explicit EZEAPPeer(const std::string &identity);
    ~EZEAPPeer();
    EZEAPPeer(const EZEAPPeer&) = delete;
    EZEAPPeer &operator=(const EZEAPPeer&) = delete;

    void setPassword(const std::string &password);                 // EAP-MD5
#ifdef EZRADIUS_HAS_TLS
    bool setTLS(const EZEAPTLSConfig &cfg, std::string *error = nullptr);   // EAP-TLS
#endif

    // Feed the EAP packet received from the server (EAP-Message of an Access-Challenge / Accept / Reject).
    // Returns the EAP-Response to send in the next Access-Request, or an empty string when there is none
    // (the conversation ended: check state()).
    std::string handle(const std::string &eapPacket);

    State state() const { return m_state; }
    // after SUCCESS with EAP-TLS: the 64 byte MSK (compare with the keys of the Access-Accept)
    const std::string &msk() const { return m_msk; }

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
    std::string m_identity, m_password;
    bool m_hasPassword = false;
    State m_state = RUNNING;
    std::string m_msk;
};

#endif // EZRADIUS_HAS_CRYPTO
#endif // EZEAP_H
