#include "EZRadiusServer.h"
#include <cstring>
#include <Wrench/clsUDPServer.h>
#include <Wrench/clsUDPSocket.h>
#include <Wrench/log.h>

EZRadiusServer::EZRadiusServer()
{
    m_pUDPServer = nullptr;

    //set default ports
    setAuthenticationPort(D_RADIUS_AUTHENTICATION_PORT);
    setAccountingPort(D_RADIUS_ACCOUNTING_PORT);
}

EZRadiusServer::~EZRadiusServer()
{
    if(m_pUDPServer){
        //m_pUDPServer.s
        delete m_pUDPServer;
    }
}

uint16_t EZRadiusServer::AuthenticatorPort() const
{
    return m_AuthPort;
}

uint16_t EZRadiusServer::AccountingPort() const
{
    return m_AccPort;
}

void EZRadiusServer::setSecret(const char *secret)
{
    m_secret.setSecret(secret, strlen(secret));


    // set secret key
    m_request.setSecret(&m_secret);
}

void EZRadiusServer::setAuthenticationPort(uint16_t newAuthenticationPort)
{
    m_AuthPort = newAuthenticationPort;
}

void EZRadiusServer::setAccountingPort(uint16_t newAccountingPort)
{
    m_AccPort = newAccountingPort;
}

void EZRadiusServer::Start()
{
    if(!m_pUDPServer){
        m_pUDPServer = new clsUDPServer;

        m_pUDPServer->AddNewListener(m_AccPort, nullptr, this, onReceiveUDPData);
        if(m_AccPort != m_AuthPort)
            m_pUDPServer->AddNewListener(m_AuthPort, nullptr, this, onReceiveUDPData);
    }

    //m_request.getRawData()
}

void EZRadiusServer::onReceiveUDPData(clsUDPListener* pListener, void*p, clsUDPSocket& UDPClient, const char*Data, int DataLength)
{
    EZRadiusServer *pThis = static_cast<EZRadiusServer*>(p);

    RadiusPacket l_request ;


    LOG_COLOR(White, "OnReceiveUDPPackets[%s]\n", Data , UDPClient.getIPAddress());
}
