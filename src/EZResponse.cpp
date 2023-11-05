#include "EZResponse.h"
#include "EZRadiusServer.h"
#include "EZRadiusClientIdentify.h"

EZResponse::EZResponse(EZRadiusServer *pRadiusServer)
{
    m_pRadiusServer = pRadiusServer;
}

void EZResponse::AddAttribute(uint8_t AttType, const char *value)
{
    if(!value)
        return;

    //attributes
    RadiusAttribute MyAttr;

    //add string attribute
    m_Pck.addAttribute(AttType, MyAttr);

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

void EZResponse::AddAttribute(uint8_t AttType, uint32_t value)
{
    //https://g.co/bard/share/dc01ca6ca8d4
    //attributes
    RadiusAttribute MyAttr;

    //add string attribute
    m_Pck.addAttribute(AttType, MyAttr);
    MyAttr.setNumber(value);
}

void EZResponse::Send(PacketTypeCodes code, EZRadiusClientIdentify *ClientIdentify)
{
    if(!ClientIdentify)
        return;

    RASItem *pRAS = m_pRadiusServer->RASList()->GetRASByIP(ClientIdentify->UDPClient().getIPAddress());
    //if secret not found
    if(!pRAS){
        return;
    }

    m_Pck.setCode(code);
    m_Pck.setID(ClientIdentify->ID());

    if (code == ACCESS_REQUEST || code == ACCOUNTING_REQUEST){
        //zamani ke ghasde accounting ya acess dashtim bayad setesh konim
        m_Pck.setSecret(&pRAS->Secret);
    }

    //RadiusSecret secret("123456");
    m_Pck.setSecret(&pRAS->Secret);
    m_Pck.setAuthenticator(ClientIdentify->Authenticator());
    m_Pck.responseAuthenticator();

    m_Pck.dump();

    //send
    ClientIdentify->UDPClient().Send((const char*)m_Pck.getRawData(), m_Pck.getLength());

}
