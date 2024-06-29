#include "EZRadiusServer.h"
#include "EZRadiusClientIdentify.h"
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

EZRASList *EZRadiusServer::RASList()
{
    return &m_RASList;
}

void EZRadiusServer::onReceiveRequest(RADIUSPacketTypeCodes PacketType, RadiusPacket &pRequest, EZRadiusClientIdentify &ClientIdentify, EZRadiusServer *pRadiusServer)
{
    //not working
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
    EZRadiusServer *pThis = static_cast<EZRadiusServer*>(p);
    RASItem *pRAS = pThis->RASList()->GetRASByIP(UDPClient.getIPAddress());

    //if RAS not exit then DropPacket
    if(!pRAS){
        LOG("Drop Packet [%s]", UDPClient.getIPAddressDescription());
        return;
    }

    //if Datalength lesser then 20(RADIUS_PACKET_HEADER_LENGTH) DropPacket
    if(D_RADIUS_PACKET_HEADER_LENGTH >= DataLength)
        return;

    RadiusPacket request(Data, DataLength) ;
    request.setSecret(&pRAS->Secret);


    RADIUSPacketTypeCodes RType = UNKNOWN;
    if(request.getCode() > D_PACKET_MAX_KNOWN_CODE){
        RType = UNKNOWN;
    }else{
        RType = (RADIUSPacketTypeCodes)request.getCode();
    }

    //
    EZRadiusClientIdentify RadiusClientIdentify(request.getID(), UDPClient, request.getAuthenticator());

    //pThis->onReceiveRequest(RType, request, UDPClient);

    if(pThis->_radiusallback){
        pThis->_radiusallback(RType, request, RadiusClientIdentify, pThis);
    }else{
        pThis->onReceiveRequest(RType, request, RadiusClientIdentify, pThis);
    }

}

void EZRadiusServer::onReceiveRequest(const RADIUSCallback &callback)
{
    this->_radiusallback = callback;
}


