#include "EZCoA.h"
#include "EZRadiusClientIdentify.h"
#include "EZRadiusServer.h"
#include <Wrench/clsDNSLookup.h>
#include <Wrench/clsTCPSocket.h>
#include <Wrench/log.h>

//#include "RadiusPacket.h"

EZCoA::EZCoA(const EZClientSettings &Settings) {
    m_callback = nullptr;
    m_pPointerCallback = nullptr;
    m_pServer = new EZRadiusServer;
    m_settings = Settings;
}

void EZCoA::SetGetRequests(const CoACallback &callback, void *p)
{
    m_pPointerCallback = p;
    m_callback = callback;
}


void EZCoA::Start()
{
    clsTCPSocket::GetIPFromHostAddress(m_settings.Host.c_str());

    m_pServer->setAuthenticationPort(m_settings.CoAPort);
    m_pServer->setAccountingPort(m_settings.CoAPort);
    m_pServer->SeRequestCallback(onGetRadiusRequest, this);
    m_pServer->RASList()->AddRAS(m_settings.Secret.c_str(), clsTCPSocket::GetIPFromHostAddress(m_settings.Host.c_str()).s_addr);
    m_pServer->Start();

}


void EZCoA::onGetRadiusRequest(RADIUSPacketTypeCodes PacketType, RadiusPacket &request, EZRadiusClientIdentify &ClientIdentify, EZRadiusServer *pRadiusServer,void *p)
{
    EZCoA *pThis = static_cast<EZCoA*>(p);
    if(!pThis){
        DebugPrint("Error: callback pointer is not set");
        return;
    }

    uint32_t RASIp = ClientIdentify.UDPClient().getIPAddress();
    if(!pRadiusServer->RASList()->isExist(RASIp)){
        DebugPrint("Error: RAS IP is Not Acceptable [%s]", ClientIdentify.UDPClient().getIPAddressDescription());
        return;
    }


    if(PacketType == DISCONNECT_REQUEST || PacketType == DISCONNECT_ACK || PacketType == DISCONNECT_NAK ||PacketType == COA_REQUEST || PacketType == COA_ACK || PacketType == COA_NAK) {

        EZResponse RadiusResponse(pRadiusServer);
        if(pThis->m_callback){
            RADIUSPacketTypeCodes ret = pThis->m_callback(PacketType, request, RadiusResponse, pThis->m_pPointerCallback);
            //RadiusResponse.AddAttribute(USER_NAME, request.getAttribute(USER_NAME).strValue.c_str());
            //RadiusResponse.AddAttribute(NAS_IP_ADDRESS, pRequest.getAttribute(NAS_IP_ADDRESS).strValue.c_str());
            //RadiusResponse.AddAttribute(CALLING_STATION_ID, pRequest.getAttribute(CALLING_STATION_ID).strValue.c_str());
            //RadiusResponse.AddAttribute(ACCT_SESSION_ID, pRequest.getAttribute(ACCT_SESSION_ID).strValue.c_str());
            RadiusResponse.Send(ret, &ClientIdentify);
        }
    }

}

