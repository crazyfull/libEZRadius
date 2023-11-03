#ifndef EZRESPONSE_H
#define EZRESPONSE_H
#include "src/RadiusAttribute.h"
#include <Wrench/clsUDPSocket.h>
#include "RadiusPacket.h"

class EZRadiusServer;
class EZResponse
{
    //server pointer
    EZRadiusServer *m_pRadiusServer;

    //radius packet
    RadiusPacket m_Pck;

public:
    EZResponse(EZRadiusServer *pRadiusServer);
    void AddAttribute(uint8_t AttType, const char* value);
    void AddAttribute(uint8_t AttType, uint32_t value);
    void Send(PacketTypeCodes code, clsUDPSocket& UDPClient, uint8_t ID, const unsigned char *p_auth);
};

#endif // EZRESPONSE_H
