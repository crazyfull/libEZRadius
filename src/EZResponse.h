#ifndef EZRESPONSE_H
#define EZRESPONSE_H
#include "RadiusAttribute.h"
#include <Wrench/clsUDPSocket.h>
#include "RadiusPacket.h"

class EZRadiusServer;
class EZRadiusClientIdentify;
class EZResponse
{
    //server pointer
    EZRadiusServer *m_pRadiusServer;

    //radius packet
    RadiusPacket m_Pck;

public:
    EZResponse(EZRadiusServer *pRadiusServer);
    void AddAttribute(RADIUSAttribute AttType, const char* value);
    void AddAttribute(RADIUSAttribute AttType, uint32_t value);
    void Send(RADIUSPacketTypeCodes code, EZRadiusClientIdentify *ClientIdentify);
};

#endif // EZRESPONSE_H
