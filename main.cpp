#include <Wrench/clsUDPSocket.h>
#include <iostream>
#include <Wrench/log.h>
#include <unordered_set>
#include "src/EZRadiusServer.h"
#include <typeinfo>
using namespace std;

EZRadiusServer m_EZRadiusServer;

void onReceiveRequest(PacketTypeCodes PacketType, RadiusPacket &pRequest, clsUDPSocket &UDPClient)
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

    //LOG_COLOR(Green, "Hiiii ");
    getchar();
    return 0;
}
