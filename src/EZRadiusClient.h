#ifndef EZRADIUSCLIENT_H
#define EZRADIUSCLIENT_H
#include "RadiusAttribute.h"
#include "RadiusPacket.h"
#include "RadiusSecret.h"

struct EZClientSettings
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
    EZClientSettings m_settings;
    //radius packet
    RadiusPacket m_RequestPck;
    RadiusPacket m_Response;
    RadiusSecret m_Secret;

public:
    EZRadiusClient(const EZClientSettings &Settings);
    void AddAttribute(RADIUSAttribute AttType, const char* value);
    void AddAttribute(RADIUSAttribute AttType, uint32_t value);
    void AddAttribute(RADIUSAttribute AttType, int value);
    void SendRequest(RADIUSClientRequestType RequestType);
    RADIUSPacketTypeCodes GetResponseType();
    const char* GetResponseTypeDescription();
    AttrValue GetAttribute(RADIUSAttribute AttrType);
    void DumpResponse();

};

#endif // EZRADIUSCLIENT_H
