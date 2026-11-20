#ifndef EZRADIUSCLIENT_H
#define EZRADIUSCLIENT_H
#include "RadiusAttribute.h"
#include "RadiusPacket.h"
#include "RadiusSecret.h"
#include "EZClientSettings.h"
#include <functional>
#include <string>

namespace netrector { class EpollReactor; class UDPSocket; }

enum class EZResult {
    NONE = 0,           // nothing sent yet / request in progress
    OK,                 // a valid response was received (see GetResponseType())
    TIMEOUT,            // no valid response after RetryCount attempts
    DNS_FAILED,         // the host name could not be resolved
    SEND_FAILED,        // socket error
    CANCELED            // Cancel() was called
};

// Asynchronous RADIUS client on a netRector reactor: no threads, nothing blocks.
//
//   EZRadiusClient c(&reactor, settings);
//   c.AddAttribute(USER_NAME, "user");
//   c.AddAttribute(USER_PASSWORD, "pass");
//   c.Send(C_ACCESS_REQUEST, [](EZRadiusClient &c, EZResult r){ if(r == EZResult::OK) ... c.GetResponseType() ... });
//
// - one request per object (call Reset() to build another one)
// - must be used from the reactor thread; the object must not be destroyed from inside its own callback
//   until the callback returned (destroying it elsewhere cancels the request, the callback is not called)
// - a fresh UDP socket (random source port) is used for every request
// - the response is accepted only when ID and Response Authenticator are valid (and the
//   Message-Authenticator, when present / required)
class EZRadiusClient
{
public:
    typedef std::function<void(EZRadiusClient &client, EZResult result)> Callback;

    EZRadiusClient(netrector::EpollReactor *reactor, const EZClientSettings &Settings);
    ~EZRadiusClient();
    EZRadiusClient(const EZRadiusClient&) = delete;
    EZRadiusClient &operator=(const EZRadiusClient&) = delete;

    // Return false (and add nothing) when the value is invalid: too long, not an IPv4 address for
    // IP typed attributes, packet full, called after Send(). Call before Send().
    bool AddAttribute(RADIUSAttribute AttType, const char* value);
    bool AddAttribute(RADIUSAttribute AttType, uint32_t value);
    bool AddAttribute(RADIUSAttribute AttType, int value);
    bool AddVendorAttribute(uint32_t vendorId, unsigned char vendorType, const void *data, uint16_t length);
    bool AddVendorAttribute(uint32_t vendorId, unsigned char vendorType, const char *text);

    // Start the request and return at once; callback is called (once) from the reactor when it is finished.
    // false: could not start (already sent, bad settings, no reactor); callback is not called.
    bool Send(RADIUSClientRequestType RequestType, const Callback &callback);

    // abort a running request (callback gets EZResult::CANCELED)
    void Cancel();

    // forget the request and the response: the object can be used for a new request
    void Reset();

    bool isBusy() const { return m_state == State::Running; }
    EZResult Result() const { return m_result; }

    RADIUSPacketTypeCodes GetResponseType();
    const char* GetResponseTypeDescription();
    AttrValue GetAttribute(RADIUSAttribute AttrType);
    std::vector<AttrValue> GetAttributes(RADIUSAttribute AttrType);
    void DumpResponse();

private:
    enum class State { Idle, Running, Done };

    netrector::EpollReactor *m_pReactor;
    EZClientSettings m_settings;
    RadiusSecret m_Secret;
    RadiusPacket m_RequestPck;
    RadiusPacket m_Response;
    Callback m_callback;
    State m_state = State::Idle;
    EZResult m_result = EZResult::NONE;

    netrector::UDPSocket *m_pSocket = nullptr;
    int m_timerId = -1;
    bool m_dnsPending = false;
    int m_attempt = 0;
    int m_maxAttempts = 1;
    uint32_t m_serverIP = 0;        // network byte order
    uint16_t m_serverPort = 0;
    RADIUSClientRequestType m_type = C_ACCESS_REQUEST;

    static void onResolved(const char *hostname, char **ips, size_t count, int qtype, void *user_data);
    void startWithAddress(uint32_t ip);
    void transmit();
    void onTimeout();
    void onDatagram(const uint8_t *data, size_t len, const struct sockaddr *from);
    void releaseResources();
    void finish(EZResult result);

    friend class EZClientSocket;
};

#endif // EZRADIUSCLIENT_H
