#include <unordered_set>
#include <iostream>
#include <typeinfo>

#include <Wrench/log.h>
#include <EZRadius/EZRadiusClientIdentify.h>
#include <EZRadius/EZRadiusServer.h>
#include <EZRadius/EZResponse.h>


void onReceiveRequest(RADIUSPacketTypeCodes PacketType, RadiusPacket &pRequest, EZRadiusClientIdentify &ClientIdentify, EZRadiusServer *pRadiusServer, void *p)
{
    //print request details
    pRequest.dump();

    LOG_COLOR(Green, "onReceiveRequest "
                     "PacketType[%s] "
                     "NAS-IP[%s]  "
                     "NAS-Port[%d]  "
                     "Username[%s] "
                     "Psassword[%s] "
                     "NAS_IP_ADDRESS[%s]"
                     "CALLED_STATION_ID[%s]"
                     "ACCT_STATUS_TYPE[%u]\n",
              pRequest.getCodeDescription(PacketType),
              ClientIdentify.UDPClient().getIPAddressDescription(),
              pRequest.getAttribute(NAS_PORT).intValue,
              pRequest.getAttribute(USER_NAME).strValue.c_str(),
              pRequest.getAttribute(USER_PASSWORD).strValue.c_str(),
              pRequest.getAttribute(NAS_IP_ADDRESS).strValue.c_str(),
              pRequest.getAttribute(CALLING_STATION_ID).strValue.c_str(),
              pRequest.getAttribute(ACCT_STATUS_TYPE).intValue
              );


    if(PacketType == ACCOUNTING_REQUEST){
        if((RADIUSAcctStatusType)pRequest.getAttribute(ACCT_STATUS_TYPE).intValue == RADIUSAcctStatusType::START){
            LOG("request Accounting start");
            return;
        }
    }


    //example response for ACCESS_ACCEPT
    if(PacketType == ACCESS_REQUEST){
        EZResponse RadiusResponse(pRadiusServer);
        RadiusResponse.AddAttribute(USER_NAME, "crazyfull");
        RadiusResponse.AddAttribute(NAS_IP_ADDRESS, "127.0.0.1");
        RadiusResponse.AddAttribute(ACCT_SESSION_ID, "--client-seassion---");

        // add interim intravel attribute
        RadiusResponse.AddAttribute(ACCT_INTERIM_INTRAVEL, 60);
        RadiusResponse.AddAttribute(ACCT_AUTHENTIC, 1);         //1: RADIUS

        // add Service-Type attribute
        RadiusResponse.AddAttribute(SERVICE_TYPE, 2);            //2: Framed
        // add Framed-protocole
        RadiusResponse.AddAttribute(FRAMED_PROTOCOL, (int)0);    //0: PPP

        //send response to client
        RadiusResponse.Send(ACCESS_ACCEPT, &ClientIdentify);
    }

}

int main3()
{
    /*
     * https://idblender.com/tools/test-radius#85a7e4a0-6dce-4f70-a1b0-fcc8a2cdb2be
     * radtest -t pap moji moji '2.176.229.202:1812' 0 123456
    */

    //Need a create a RAS list [IP,Secret]

    EZRadiusServer m_EZRadiusServer;
    m_EZRadiusServer.setAuthenticationPort(1812);
    m_EZRadiusServer.setAccountingPort(1813);
    m_EZRadiusServer.SeRequestCallback(onReceiveRequest, nullptr);            //set a call back function for get all requests
    m_EZRadiusServer.RASList()->AddRAS("123456", "127.0.0.1");      //access to NAP-IP with the secret
    m_EZRadiusServer.RASList()->AddRAS("123456", "192.168.1.10");
    m_EZRadiusServer.RASList()->AddRAS("123456", "198.244.189.2");

    m_EZRadiusServer.Start();

    for(;;){
        getchar();
    }
    return 0;
}
