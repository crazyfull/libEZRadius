#ifndef EZRADIUSSYNCCLIENT_H
#define EZRADIUSSYNCCLIENT_H
#include "EZRadiusClient.h"
#include <atomic>
#include <memory>

namespace netrector { class EpollReactor; }

// Blocking RADIUS client: Send() returns when the request is finished (response, timeout or error).
//
// For programs that do not run a netRector reactor (scripts, CLI tools, worker threads). The object owns a
// private reactor that is run on the calling thread only while Send() waits, so it is the same
// non-blocking engine as EZRadiusClient (timeouts, retries, async DNS), just driven synchronously.
//
// - one object per thread (different objects can be used from different threads at the same time)
// - do not call it from inside a reactor callback of another EZRadiusClient/Server (it would block that reactor)
// - one request per Send(); call Reset() to build another one with the same object
class EZRadiusSyncClient
{
    std::unique_ptr<netrector::EpollReactor> m_reactor;
    std::unique_ptr<EZRadiusClient> m_client;
    std::atomic<bool> m_stop{false};
    EZClientSettings m_settings;
    EZResult m_result = EZResult::NONE;

public:
    explicit EZRadiusSyncClient(const EZClientSettings &Settings);
    ~EZRadiusSyncClient();
    EZRadiusSyncClient(const EZRadiusSyncClient&) = delete;
    EZRadiusSyncClient &operator=(const EZRadiusSyncClient&) = delete;

    // same rules as EZRadiusClient::AddAttribute...
    bool AddAttribute(RADIUSAttribute AttType, const char* value) { return m_client->AddAttribute(AttType, value); }
    bool AddAttribute(RADIUSAttribute AttType, uint32_t value) { return m_client->AddAttribute(AttType, value); }
    bool AddAttribute(RADIUSAttribute AttType, int value) { return m_client->AddAttribute(AttType, value); }
    bool AddVendorAttribute(uint32_t vendorId, unsigned char vendorType, const void *data, uint16_t length) { return m_client->AddVendorAttribute(vendorId, vendorType, data, length); }
    bool AddVendorAttribute(uint32_t vendorId, unsigned char vendorType, const char *text) { return m_client->AddVendorAttribute(vendorId, vendorType, text); }
    bool AddVendorAttribute(const char *name, const char *text) { return m_client->AddVendorAttribute(name, text); }
    bool AddVendorAttribute(const char *name, uint32_t number) { return m_client->AddVendorAttribute(name, number); }
    bool AddRawAttribute(RADIUSAttribute AttType, const void *data, size_t length) { return m_client->AddRawAttribute(AttType, data, length); }
#ifdef EZRADIUS_HAS_CRYPTO
    bool AddMSCHAPv2(const char *userName, const char *password) { return m_client->AddMSCHAPv2(userName, password); }
    bool AddMSCHAPv1(const char *userName, const char *password) { return m_client->AddMSCHAPv1(userName, password); }
    bool MSCHAPv2ServerVerified() { return m_client->MSCHAPv2ServerVerified(); }
    bool GetMPPEKeys(uint8_t sendKey[16], uint8_t recvKey[16]) { return m_client->GetMPPEKeys(sendKey, recvKey); }
    bool AddEAPMessage(const std::string &eapPacket) { return m_client->AddEAPMessage(eapPacket); }
    std::string GetEAPMessage() { return m_client->GetEAPMessage(); }
    std::string GetState() { return m_client->GetState(); }
    bool GetMPPEKeys(std::string &sendKey, std::string &recvKey) { return m_client->GetMPPEKeys(sendKey, recvKey); }
#endif

    // Send the request and wait for the result (blocks at most about TimeOut * RetryCount milliseconds,
    // plus the DNS lookup). SEND_FAILED is also returned when the request could not be started.
    EZResult Send(RADIUSClientRequestType RequestType);

    void Reset();

    EZResult Result() const { return m_result; }
    bool UsedRadius11() { return m_client->UsedRadius11(); }
    RADIUSPacketTypeCodes GetResponseType() { return m_client->GetResponseType(); }
    const char* GetResponseTypeDescription() { return m_client->GetResponseTypeDescription(); }
    AttrValue GetAttribute(RADIUSAttribute AttrType) { return m_client->GetAttribute(AttrType); }
    std::vector<AttrValue> GetAttributes(RADIUSAttribute AttrType) { return m_client->GetAttributes(AttrType); }
    void DumpResponse() { m_client->DumpResponse(); }
};

#endif // EZRADIUSSYNCCLIENT_H
