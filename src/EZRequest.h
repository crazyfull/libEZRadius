#ifndef EZREQUEST_H
#define EZREQUEST_H

#include "src/RadiusPacket.h"
#include <Wrench/clsUDPSocket.h>

class EZRequest
{
    unsigned char m_Authenticator[D_AUTHENTICATOR_LENGTH];
    //client identify
    clsUDPSocket m_UDPClient;

    uint8_t ID;
public:
    EZRequest();
};

#endif // EZREQUEST_H
