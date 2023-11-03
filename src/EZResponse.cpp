#include "EZResponse.h"
#include "EZRadiusServer.h"

EZResponse::EZResponse(EZRadiusServer *pRadiusServer)
{
    m_pRadiusServer = pRadiusServer;
}

void EZResponse::AddAttribute(uint8_t AttType, const char *value)
{
    //attributes
    RadiusAttribute MyAttr;

    //add string attribute
    m_Pck.addAttribute(AttType, MyAttr);

    if(AttType == D_ATTR_USER_PASSWORD){
        //PAP password
        MyAttr.setUserPassword(value);
    }else{
        //plain text
        MyAttr.setString("moji");
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

void EZResponse::Send(PacketTypeCodes code, clsUDPSocket &UDPClient, uint8_t ID,const unsigned char * p_auth)
{
    m_Pck.setCode(code);
    m_Pck.setID(ID);


    if (code == ACCESS_REQUEST || code == ACCOUNTING_REQUEST){
        //zamani ke ghasde accounting ya acess dashtim bayad setesh konim

    }
    m_Pck.setSecret(m_pRadiusServer->Secret());
    //RadiusSecret secret("123456");
    //m_Pck.setSecret(&secret);
    m_Pck.setAuthenticator(p_auth);
    m_Pck.responseAuthenticator(m_pRadiusServer->Secret());

    m_Pck.dump();
    //send
    UDPClient.Send((const char*)m_Pck.getRawData(), m_Pck.getLength());

}
