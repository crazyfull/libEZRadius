#ifndef EZRADIUSCLIENT_H
#define EZRADIUSCLIENT_H
#include "RadiusAttribute.h"
#include "RadiusPacket.h"
#include "RadiusSecret.h"

struct RadiussClientSettings
{
    int TimeOut;
    int RetryCount;
    int AuthenticationPort;
    int AccountingPort;
    std::string Host;
    std::string Secret;
};

class EZRadiusClient
{
    RadiussClientSettings m_settings;
    //radius packet
    RadiusPacket m_RequestPck;
    RadiusPacket m_Response;
    RadiusSecret m_Secret;

public:
    EZRadiusClient(const RadiussClientSettings &Settings);
    void AddAttribute(RADIUSAttribute AttType, const char* value);
    void AddAttribute(RADIUSAttribute AttType, uint32_t value);
    void SendRequest(RADIUSPacketTypeCodes RequestType);
    RADIUSPacketTypeCodes GetResponseType();
    const char* GetResponseTypeDescription();
    AttrValue GetAttribute(RADIUSAttribute AttrType);
    void DumpResponse();
};

#endif // EZRADIUSCLIENT_H
