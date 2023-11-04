#include "EZRadiusClientIdentify.h"



EZRadiusClientIdentify::EZRadiusClientIdentify(uint8_t ID, clsUDPSocket &UDPClient, const unsigned char *pAuthenticator)
{
    m_ID = ID;
    m_UDPClient = UDPClient;
    if(pAuthenticator){
        memcpy(m_Authenticator, pAuthenticator, D_AUTHENTICATOR_LENGTH);
        m_Authenticator[D_AUTHENTICATOR_LENGTH] = 0;
    }
}

EZRadiusClientIdentify::EZRadiusClientIdentify(EZRadiusClientIdentify &ClientIdentify)
{
    m_ID = ClientIdentify.ID();
    m_UDPClient = ClientIdentify.UDPClient();
    if(ClientIdentify.Authenticator()){
        memcpy(m_Authenticator, ClientIdentify.Authenticator(), D_AUTHENTICATOR_LENGTH);
        m_Authenticator[D_AUTHENTICATOR_LENGTH] = 0;
    }
}

uint8_t EZRadiusClientIdentify::ID() const
{
    return m_ID;
}

clsUDPSocket EZRadiusClientIdentify::UDPClient() const
{
    return m_UDPClient;
}

const unsigned char *EZRadiusClientIdentify::Authenticator()
{
    return m_Authenticator;
}
