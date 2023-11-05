#include <unordered_set>
#include <iostream>
#include <typeinfo>
#include <Wrench/clsUDPSocket.h>
#include <Wrench/log.h>
#include <EZRadius/EZRadiusClientIdentify.h>
#include <EZRadius/EZRadiusServer.h>
#include <EZRadius/EZResponse.h>

using namespace std;

EZRadiusServer m_EZRadiusServer;


void onReceiveRequest(RADIUSPacketTypeCodes PacketType, RadiusPacket &pRequest, EZRadiusClientIdentify &ClientIdentify, EZRadiusServer *pRadiusServer)
{
    pRequest.dump();

    LOG_COLOR(Green, "onReceiveRequest PacketType[%s] NAS-IP[%s]  NAS-Port[%d]  Username[%s] Psassword[%s] NAS_IP_ADDRESS[%s]\n",
              pRequest.getCodeDescription(PacketType),
              ClientIdentify.UDPClient().getIPAddressDescription(),
              pRequest.getAttribute(NAS_PORT).intValue,
              pRequest.getAttribute(USER_NAME).strValue.c_str() ,
              pRequest.getAttribute(USER_PASSWORD).strValue.c_str(),
              pRequest.getAttribute(NAS_IP_ADDRESS).strValue.c_str()
              );

    //GenRadiusPacket(pRequest, UDPClient, pRadiusServer);


    //
    EZResponse RadiusResponse(pRadiusServer);
/**/
    RadiusResponse.AddAttribute(ACCT_AUTHENTIC, 1);
    RadiusResponse.AddAttribute(USER_NAME, "mojtaba");
    RadiusResponse.AddAttribute(NAS_IP_ADDRESS, "127.0.0.1");
    RadiusResponse.AddAttribute(ACCT_SESSION_ID, "AAAAAAAAAAA");
    // add interim intravel attribute
    RadiusResponse.AddAttribute(ACCT_INTERIM_INTRAVEL, 60);
    // add Service-Type attribute
    RadiusResponse.AddAttribute(SERVICE_TYPE, 2);
    // add Framed-protocole
    RadiusResponse.AddAttribute(FRAMED_PROTOCOL, 1);

    RadiusResponse.Send(ACCESS_ACCEPT, &ClientIdentify);
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
    m_EZRadiusServer.setAccountingPort(1813);
    m_EZRadiusServer.onReceiveRequest(onReceiveRequest);
    m_EZRadiusServer.RASList()->AddRAS("123456","127.0.0.1");
    m_EZRadiusServer.Start();

    LOG_COLOR(Green, "Hiiii RadiusPacket: %lu", sizeof(EZRadiusClientIdentify));

    for(;;){
        getchar();
    }
    return 0;
}
