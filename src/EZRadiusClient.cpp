#include "EZRadiusClient.h"
#include "RadiusSecret.h"
#include <Wrench/clsUDPSocket.h>
#include <Wrench/UDPClient.h>
#include <Wrench/log.h>

EZRadiusClient::EZRadiusClient(const EZClientSettings &Settings) {
    //m_pResponse = NULL;
    m_settings = Settings;

    //set default setting
    if(m_settings.RetryCount <=0){
        m_settings.RetryCount = 1;
    }

    if(m_settings.TimeOut <= 0){
        m_settings.TimeOut = 2200;
    }

    if(m_settings.AccountingPort <= 0){
        m_settings.AccountingPort = 1812;
    }

    if(m_settings.AuthenticationPort <= 0){
        m_settings.AuthenticationPort = 1813;
    }

    //set secret
    m_Secret.setSecret(m_settings.Secret.c_str(), m_settings.Secret.length());
    m_RequestPck.setSecret(&m_Secret);
}

void EZRadiusClient::AddAttribute(RADIUSAttribute AttType, const char *value)
{
    if(!value)
        return;

    //attributes
    RadiusAttribute MyAttr;

    //add string attribute
    m_RequestPck.addAttribute(AttType, MyAttr);
    if(AttType == D_ATTR_USER_PASSWORD){
        //PAP password
        MyAttr.setUserPassword(value);
    }else if(AttType == D_ATTR_NAS_IP_ADDRESS || AttType == D_ATTR_FRAMED_IP_ADDRESS || AttType == D_ATTR_FRAMED_IP_NETMASK || AttType == D_ATTR_LOGIN_IP_HOST || AttType == D_ATTR_FRAMED_IPX_NETWORK){
        //set IP Addresses
        struct in_addr IPaddr;
        IPaddr.s_addr = inet_addr(value);
        MyAttr.setIPAddress(IPaddr);
    }else{
        //plain text
        MyAttr.setString(value);
    }



}

void EZRadiusClient::AddAttribute(RADIUSAttribute AttType, int value){
    AddAttribute(AttType, (uint32_t)value);
}

void EZRadiusClient::AddAttribute(RADIUSAttribute AttType, uint32_t value)
{
    //attributes
    RadiusAttribute MyAttr;

    //add string attribute
    m_RequestPck.addAttribute(AttType, MyAttr);
    MyAttr.setNumber(value);
}

void EZRadiusClient::SendRequest(RADIUSClientRequestType RequestType){

    //set request type
    m_RequestPck.setCode(RequestType);

    //
    m_RequestPck.randomID();   //packet identificator
    //m_Pck.setID();           //custom packet identificator

    if (RequestType == C_ACCOUNTING_REQUEST)
        m_RequestPck.accountingRequestAuthenticator();

    // if packet has User-Password attribute, it should re-encode it
    /*
    if ((RequestType == C_ACCESS_REQUEST) ||  (RequestType == C_ACCOUNTING_REQUEST))
        m_RequestPck.setSecret(&m_Secret);
    */

    //m_RequestPck.dump();

    //AddAttribute(USER_NAME, "ir1test");
    //AddAttribute(USER_PASSWORD, "12345");

    //set udp client
    UDPClient udpClient;
    udpClient.setHost(m_settings.Host.c_str());
    udpClient.setTimeOut(m_settings.TimeOut);
    if(RequestType == C_ACCESS_REQUEST){
        //set authenticator port
        udpClient.setPort(m_settings.AuthenticationPort);
    }else{
        //set accounting port
        udpClient.setPort(m_settings.AccountingPort);
    }

    string recbuff;
    for(int i = 0; i< m_settings.RetryCount;i++){
        recbuff = udpClient.SendReceive((const char*)m_RequestPck.getRawData(), m_RequestPck.getLength());
        if(recbuff.length() > 0){
            break;
        }
    }

    //create
    //if(!m_pResponse)
    //m_pResponse = new RadiusPacket(recbuff.c_str(), recbuff.length());

    //set raw data
    m_Response.setRawData(recbuff.c_str(), recbuff.length());
    m_Response.setSecret(&m_Secret);
}

RADIUSPacketTypeCodes EZRadiusClient::GetResponseType()
{
    return (RADIUSPacketTypeCodes)m_Response.getCode();
}

const char *EZRadiusClient::GetResponseTypeDescription()
{
    return m_Response.getCodeDescription();
}

AttrValue EZRadiusClient::GetAttribute(RADIUSAttribute AttrType)
{
    return m_Response.getAttribute(AttrType);
}

void EZRadiusClient::DumpResponse()
{
    m_Response.dump();
}
