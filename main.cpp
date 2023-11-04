#include <Wrench/clsUDPSocket.h>
#include <iostream>
#include <Wrench/log.h>
#include <unordered_set>
#include "src/EZRadiusServer.h"
#include "src/EZResponse.h"
#include <typeinfo>
using namespace std;

EZRadiusServer m_EZRadiusServer;

void GenRadiusPacket(RadiusPacket &pRequest, clsUDPSocket& UDPClient, EZRadiusServer *pRadiusServer){
    //https://g.co/bard/share/dc01ca6ca8d4

    /*
     * Acct-Output-Gigawords 64-bit
     * Acct-Output-Octets
*/
    PacketTypeCodes code = ACCESS_REQUEST;
    RadiusPacket Pck(code);
    RadiusSecret secret("123456");
    if (code == ACCESS_REQUEST || code == ACCOUNTING_REQUEST){
        //zamani ke ghasde accounting ya acess dashtim bayad setesh konim
        Pck.setSecret(&secret);
    }

    Pck.setID(pRequest.getCode());
    Pck.setAuthenticator(pRequest.getAuthenticator());

    //for attributes
    RadiusAttribute MyAttr;

    /*
    //add user
    Pck.addAttribute(D_ATTR_USER_NAME, MyAttr);
    MyAttr.setString("moji");


    //add pass
    Pck.addAttribute(D_ATTR_USER_PASSWORD, MyAttr);
    MyAttr.setUserPassword("goooz");

    //Set NasPort - for IBSng
    Pck.addAttribute(D_ATTR_NAS_PORT, MyAttr);
    MyAttr.setNumber(90000);
*/
    //send
    UDPClient.Send((const char*)Pck.getRawData(), Pck.getLength());

}

void onReceiveRequest(PacketTypeCodes PacketType, RadiusPacket &pRequest, clsUDPSocket &UDPClient, EZRadiusServer *pRadiusServer)
{
    pRequest.dump();


    LOG_COLOR(Green, "onReceiveRequest PacketType[%s] NAS-IP[%s]  NAS-Port[%d]  Username[%s] Psassword[%s] NAS_IP_ADDRESS[%s]\n",
              pRequest.getCodeDescription(PacketType),
              UDPClient.getIPAddress(),
              pRequest.getAttribute(D_ATTR_NAS_PORT).intValue,
              pRequest.getAttribute(D_ATTR_USER_NAME).strValue.c_str() ,
              pRequest.getAttribute(D_ATTR_CHAP_PASSWORD).strValue.c_str(),
              pRequest.getAttribute(D_ATTR_NAS_IP_ADDRESS).strValue.c_str()
              );

    //GenRadiusPacket(pRequest, UDPClient, pRadiusServer);

    //
    EZResponse RadiusResponse(pRadiusServer);

/*
    RadiusResponse.AddAttribute(D_ATTR_USER_NAME, "moji");
    RadiusResponse.AddAttribute(D_ATTR_ACCT_SESSION_ID, "AAAAAAAAAAA");
    RadiusResponse.AddAttribute(D_ATTR_ACCT_AUTHENTIC, 1);
    RadiusResponse.AddAttribute(D_ATTR_ACCT_SESSION_TIME, 999999);
  */

    // add interim intravel attribute
    RadiusResponse.AddAttribute(D_ATTR_ACCT_INTERIM_INTRAVEL, 60);

    // add Service-Type attribute
    RadiusResponse.AddAttribute(D_ATTR_SERVICE_TYPE, 2);

    // add Framed-protocole
    RadiusResponse.AddAttribute(D_ATTR_FRAMED_PROTOCOL, 1);


    RadiusResponse.Send(ACCESS_ACCEPT, UDPClient, pRequest.getID(), pRequest.getAuthenticator() );
}

int main()
{

    std::unordered_set<int> mySet = {1, 22, 3, 4, 6};
    mySet.insert(9);

    if (mySet.count(22) > 0) {
        std::cout << "The item 5 exists in the set." << std::endl;
    } else {
        std::cout << "The item 5 does not exist in the set." << std::endl;
    }

    /*
 * https://idblender.com/tools/test-radius#85a7e4a0-6dce-4f70-a1b0-fcc8a2cdb2be
     * radtest -t pap moji moji '2.176.229.202:1812' 0 123456
*/

    //Need a create a RAS list [IP,Secret]

    m_EZRadiusServer.setAuthenticationPort(1812);
    m_EZRadiusServer.setSecret("123456");
    m_EZRadiusServer.onReceiveRequest(onReceiveRequest);
    m_EZRadiusServer.Start();

    LOG_COLOR(Green, "Hiiii RadiusPacket: %lu", sizeof(RadiusPacket));
    getchar();
    return 0;
}
