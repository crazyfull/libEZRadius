#include "EZRadiusServer.h"
#include <cstring>
#include <Wrench/clsUDPServer.h>
#include <Wrench/clsUDPSocket.h>
#include <Wrench/log.h>
#include <string>
using namespace std;

EZRadiusServer::EZRadiusServer()
{
    m_pUDPServer = nullptr;
    _radiusallback = nullptr;

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

RadiusSecret *EZRadiusServer::Secret()
{
    return &m_secret;
}

void EZRadiusServer::onReceiveRequest(PacketTypeCodes PacketType, RadiusPacket &pRequest, clsUDPSocket &UDPClient, EZRadiusServer *pRadiusServer)
{
    //not working
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

        m_pUDPServer->AddNewListener(m_AuthPort, nullptr, this, onReceiveUDPData);
        if(m_AccPort != m_AuthPort)
            m_pUDPServer->AddNewListener(m_AccPort, nullptr, this, onReceiveUDPData);

        m_pUDPServer->Start();
    }

    //m_request.getRawData()
}

void EZRadiusServer::onReceiveUDPData(clsUDPListener* pListener, void*p, clsUDPSocket& UDPClient, const char*Data, int DataLength)
{
    //if Datalength lesser then 20(RADIUS_PACKET_HEADER_LENGTH) DropPacket
    if(D_RADIUS_PACKET_HEADER_LENGTH >= DataLength)
        return;

    EZRadiusServer *pThis = static_cast<EZRadiusServer*>(p);

    RadiusPacket request(Data, DataLength) ;
    request.setSecret(pThis->Secret());


    PacketTypeCodes RType = UNKNOWN;
    if(request.getCode() > 11){
        RType = UNKNOWN;
    }else{
        RType = (PacketTypeCodes)request.getCode();
    }

    //pThis->onReceiveRequest(RType, request, UDPClient);

    if(pThis->_radiusallback){
        pThis->_radiusallback(RType, request, UDPClient, pThis);
    }else{
        pThis->onReceiveRequest(RType, request, UDPClient, pThis);
    }

}

void EZRadiusServer::onReceiveRequest(const RADIUSCallback &callback)
{
    this->_radiusallback = callback;
}


