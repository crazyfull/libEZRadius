#include <unordered_set>
#include <iostream>
#include <typeinfo>
#include <Wrench/clsUDPSocket.h>
#include <Wrench/log.h>
#include "EZRadiusClientIdentify.h"
#include "EZRadiusServer.h"
#include "EZResponse.h"

using namespace std;

EZRadiusServer m_EZRadiusServer;


int parseAccessRequest(RadiusPacket &p_request)
{
    RadiusAttribute l_attr;
    const char * l_data;
    uint16_t l_length = 0;
    char l_password[D_USER_PASSWORD_MAX_LENGTH];
    memset(&l_password, 0, sizeof(l_password));


    // verify User-Password attribute
    if (p_request.findAttribute(D_ATTR_USER_PASSWORD, l_attr) != RC_SUCCESS)
    {
        printf("ERROR: Can't find User-Password attribute\n");
        return RC_FAIL;
    }

    if (l_attr.getUserPassword(l_password, l_length) != RC_SUCCESS)
    {
        printf("ERROR: Can't parse User-Password attribute\n");
        return RC_FAIL;
    }


    printf("l_password: [%s]\n", l_password);

    // everything looks OK
    return RC_SUCCESS;
}

void onReceiveRequest(PacketTypeCodes PacketType, RadiusPacket &pRequest, EZRadiusClientIdentify &ClientIdentify, EZRadiusServer *pRadiusServer)
{
    parseAccessRequest(pRequest);
    //pRequest.dump();
/*
    LOG_COLOR(Green, "onReceiveRequest PacketType[%s] NAS-IP[%s]  NAS-Port[%d]  Username[%s] Psassword[%s] NAS_IP_ADDRESS[%s]\n",
              pRequest.getCodeDescription(PacketType),
              ClientIdentify.UDPClient().getIPAddressDescription(),
              pRequest.getAttribute(D_ATTR_NAS_PORT).intValue,
              pRequest.getAttribute(D_ATTR_USER_NAME).strValue.c_str() ,
              pRequest.getAttribute(D_ATTR_USER_PASSWORD).strValue.c_str(),
              pRequest.getAttribute(D_ATTR_NAS_IP_ADDRESS).strValue.c_str()
              );
*/

    LOG_COLOR(Green, "Psassword[%s]\n",pRequest.getAttribute(D_ATTR_USER_PASSWORD).strValue.c_str());


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


    RadiusResponse.Send(ACCESS_ACCEPT, &ClientIdentify);
}

int main()
{
    /*
     * https://idblender.com/tools/test-radius#85a7e4a0-6dce-4f70-a1b0-fcc8a2cdb2be
     * radtest -t pap moji moji '2.176.229.202:1812' 0 123456 -x
    */

    //Need a create a RAS list [IP,Secret]

    m_EZRadiusServer.setAuthenticationPort(1812);
    m_EZRadiusServer.onReceiveRequest(onReceiveRequest);
    m_EZRadiusServer.RASList()->AddRAS("123456", "127.0.0.1");
    m_EZRadiusServer.Start();

/*
    auto RAS = m_EZRadiusServer.RASList()->GetRASByIP(127001);
    if(RAS)
        LOG_COLOR(Green, "RAS secret: %s", RAS->Secret);
*/
    for(;;){
        getchar();
    }
    return 0;
}
