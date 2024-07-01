#ifndef EZCOA_H
#define EZCOA_H
#include "EZClientSettings.h"
#include <functional>
#include "RadiusPacket.h"
#include "EZResponse.h"

typedef std::function< RADIUSPacketTypeCodes (RADIUSPacketTypeCodes type, RadiusPacket& request, EZResponse &response, void *p)> CoACallback;

class EZRadiusServer;
class EZCoA
{
    EZClientSettings m_settings;
    CoACallback m_callback;
    EZRadiusServer *m_pServer;
    void *m_pPointerCallback;
    static void onGetRadiusRequest(RADIUSPacketTypeCodes PacketType, RadiusPacket &request, EZRadiusClientIdentify &ClientIdentify, EZRadiusServer *pRadiusServer, void *p);

public:
    EZCoA(const EZClientSettings &Settings);
    //
    void SetGetRequests(const CoACallback &callback, void *p);
    void Start();
};

#endif // EZCOA_H
