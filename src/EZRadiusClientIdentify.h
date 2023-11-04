#ifndef EZRADIUSCLIENTIDENTIFY_H
#define EZRADIUSCLIENTIDENTIFY_H

#include "src/RadiusPacket.h"
#include <Wrench/clsUDPSocket.h>

class EZRadiusClientIdentify
{
    unsigned char m_Authenticator[D_AUTHENTICATOR_LENGTH+1];
    //client identify
    clsUDPSocket m_UDPClient;

    uint8_t m_ID;
public:
    EZRadiusClientIdentify(uint8_t ID, clsUDPSocket &UDPClient, const unsigned char *pAuthenticator);
    EZRadiusClientIdentify(EZRadiusClientIdentify &ClientIdentify);
    uint8_t ID() const;
    clsUDPSocket UDPClient() const;
    const unsigned char *Authenticator();
};

#endif // EZRADIUSCLIENTIDENTIFY_H
