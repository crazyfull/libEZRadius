#include <unordered_set>
#include <iostream>
#include <typeinfo>
#include <Wrench/clsUDPSocket.h>
#include <Wrench/log.h>
#include "EZRadiusClientIdentify.h"
#include "EZRadiusServer.h"
#include "EZResponse.h"
#include "EZRadiusClient.h"
#include "EZCoA.h"

using namespace std;

EZRadiusServer m_EZRadiusServer;



void onReceiveRequest(RADIUSPacketTypeCodes PacketType, RadiusPacket &pRequest, EZRadiusClientIdentify &ClientIdentify, EZRadiusServer *pRadiusServer, void *p)
{
    pRequest.dump();

    LOG_COLOR(Green, "onReceiveRequest PacketType[%s] ClientIP[%s:%d]  NAS-Port[%d]  Username[%s] Psassword[%s] NAS_IP_ADDRESS[%s]\n",
              pRequest.getCodeDescription(PacketType),
              ClientIdentify.UDPClient().getIPAddressDescription(),
              ClientIdentify.UDPClient().getPort(),
              pRequest.getAttribute(NAS_PORT).intValue,
              pRequest.getAttribute(USER_NAME).strValue.c_str() ,
              pRequest.getAttribute(USER_PASSWORD).strValue.c_str(),
              pRequest.getAttribute(NAS_IP_ADDRESS).strValue.c_str()
              );

    //response
    /*
    EZResponse RadiusResponse(pRadiusServer);
    RadiusResponse.AddAttribute(ACCT_AUTHENTIC, 1);
    // add interim intravel attribute
    RadiusResponse.AddAttribute(ACCT_INTERIM_INTRAVEL, 60);
    // add Service-Type attribute
    RadiusResponse.AddAttribute(SERVICE_TYPE, 2);
    // add Framed-protocole
    RadiusResponse.AddAttribute(FRAMED_PROTOCOL, 1);

    RadiusResponse.AddAttribute(FRAMED_IP_ADDRESS, "172.6.1.241");
    RadiusResponse.Send(ACCESS_ACCEPT, &ClientIdentify);
*/

    //
    //onReceiveRequest PacketType[Access-Request] NAS-IP[192.168.1.20]  NAS-Port[15728660]  Username[ubuntu] Psassword[moji] NAS_IP_ADDRESS[192.168.1.20
    /* PPTP
Code = Access-Request (1)
 1  ID = 27
 2  Length = 124
16  Request Authenticator = ( 16 b8 7b 20 52 96 d3 37 ab 20 54 55 ba 6f 50 2c )
 6  Service-Type (6) = 2 ( 00 00 00 02 )
 6  Framed-Protocol (7) = 1 ( 00 00 00 01 )
 6  NAS-Port (5) = 15728661 ( 00 f0 00 15 )
 6  NAS-Port-Type (61) = 5 ( 00 00 00 05 )  *
 8  User-Name (1) = "ubuntu" ( 75 62 75 6e 74 75 )
14  Calling-Station-Id (31) = "192.168.1.10" ( 31 39 32 2e 31 36 38 2e 31 2e 31 30 )
14  Called-Station-Id (30) = "192.168.1.20" ( 31 39 32 2e 31 36 38 2e 31 2e 32 30 )
10  Acct-Session-Id (44) = "81200015" ( 38 31 32 30 30 30 31 35 )
18  User-Password (2) = USER_PASSWORD: [moji]( bf 4b 85 d3 8e 5b 41 6a 0d c8 7c 76 0c 6e 7a 3b )
10  NAS-Identifier (32) = "MikroTik" ( 4d 69 6b 72 6f 54 69 6b )
 6  NAS-IP-Address (4) = 192.168.1.20 ( c0 a8 01 14 )

request-type: Access-Request

Service-Type: 2
Framed-Protocol: 1
NAS-Port: 15728661
NAS-Port-Type: 5
User-Name: "moji"
Calling-Station-Id: "192.168.1.10"
Called-Station-Id: "192.168.1.20"
Acct-Session-Id: "81200015"
User-Password: "1122"
NAS-Identifier: "MikroTik"
NAS-IP-Address: 192.168.1.20

*/

    /*
Access-Accept
Service-Type = Framed-Service
Framed-Protocol = PPP
NAS-Port = 15728661
NAS-Port-Type = Ethernet
User-Name = "moji"
Calling-Station-Id = "192.168.1.10"
Called-Station-Id = "192.168.1.20"
Acct-Session-Id = "81200015"
Framed-IP-Address = 192.168.1.101
Framed-IP-Netmask = 255.255.255.0
Framed-MTU = 1500
Session-Timeout = 3600
Idle-Timeout = 1800
Termination-Action = Disconnect
Acct-Interim-Interval = 300
*/
    //RadiusResponse.AddAttribute(USER_NAME, "ubuntu");
    //RadiusResponse.AddAttribute(NAS_PORT, 00);

    if(PacketType == ACCESS_REQUEST){
        EZResponse RadiusResponse(pRadiusServer);
        // add interim intravel attribute
        //RadiusResponse.AddAttribute(ACCT_INTERIM_INTRAVEL, 60);
        // add Service-Type attribute
        RadiusResponse.AddAttribute(SERVICE_TYPE, 2);   //2	Framed
        // add Framed-protocole
        RadiusResponse.AddAttribute(FRAMED_PROTOCOL, 1);    //1 PPP

        //RadiusResponse.AddAttribute(FRAMED_IP_ADDRESS, "255.255.255.254");
        //Acct-Interim-Interval
        RadiusResponse.AddAttribute(ACCT_INTERIM_INTRAVEL, 10);
        RadiusResponse.AddAttribute(NAS_PORT, pRequest.getAttribute(NAS_PORT).intValue);
        RadiusResponse.AddAttribute(NAS_PORT_TYPE, 5);     //15	Ethernet        5	Virtual
        RadiusResponse.AddAttribute(USER_NAME, "moji");
        //RadiusResponse.AddAttribute(CALLING_STATION_ID, "192.168.1.10");
        //RadiusResponse.AddAttribute(CALLED_STATION_ID, "192.168.1.20");
        RadiusResponse.AddAttribute(ACCT_SESSION_ID, pRequest.getAttribute(ACCT_SESSION_ID).intValue);

        RadiusResponse.AddAttribute(FRAMED_IP_ADDRESS, "192.168.1.0/24");
        //RadiusResponse.AddAttribute(FRAMED_IP_NETMASK, "255.255.255.0");
        //RadiusResponse.AddAttribute(FRAMED_MTU, 1500);
        //RadiusResponse.AddAttribute(SESSION_TIMEOUT, 3600); //sec
        //RadiusResponse.AddAttribute(IDLE_TIMEOUT, 10);
        //RadiusResponse.AddAttribute(FRAMED_IP_ADDRESS, "0.0.0.0");
        //RadiusResponse.AddAttribute(TERMINATION_ACTION, 1800);

        //RadiusResponse.AddAttribute(ACCT_AUTHENTIC, 1);//1 RADIUS    2 Local    3 Remote
        RadiusResponse.AddAttribute(ACCT_DELAY_TIME, 1);
        RadiusResponse.Send(ACCESS_ACCEPT, &ClientIdentify);


    }

    /*
    if(PacketType == ACCOUNTING_REQUEST){
        int val = 10;
        EZResponse RadiusResponse(pRadiusServer);
        //RadiusResponse.AddAttribute(SERVICE_TYPE, 2);   //2	Framed
        //RadiusResponse.AddAttribute(FRAMED_PROTOCOL, 1);    //1 PPP
        RadiusResponse.AddAttribute(ACCT_SESSION_ID, pRequest.getAttribute(ACCT_SESSION_ID).intValue);
        //RadiusResponse.AddAttribute(NAS_PORT, pRequest.getAttribute(NAS_PORT).intValue);


        RadiusResponse.AddAttribute(ACCT_STATUS_TYPE, 2);
        RadiusResponse.Send(ACCOUNTING_RESPONSE, &ClientIdentify);
}
*/

    /*
Code = Accounting-Request
Service-Type = 2
Framed-Protocol = 1
NAS-Port = 15728641
NAS-Port-Type = 5
User-Name = "moji"
Calling-Station-Id = "192.168.1.10"
Called-Station-Id = "192.168.1.20"
Acct-Session-Id = "81600001"
Framed-IP-Address = 172.6.1.253
Acct-Status-Type = 2
NAS-Identifier = "MikroTik"
Acct-Delay-Time = 0
NAS-IP-Address = 192.168.1.20
*/

    /*
    if(PacketType == ACCOUNTING_REQUEST){
        int val = 0;
        EZResponse RadiusResponse(pRadiusServer);
        RadiusResponse.AddAttribute(SERVICE_TYPE, 2);   //2	Framed
        RadiusResponse.AddAttribute(FRAMED_PROTOCOL, 1);    //1 PPP
        RadiusResponse.AddAttribute(ACCT_SESSION_ID, pRequest.getAttribute(ACCT_SESSION_ID).intValue);
        RadiusResponse.AddAttribute(NAS_PORT, pRequest.getAttribute(NAS_PORT).intValue);
        RadiusResponse.AddAttribute(NAS_PORT_TYPE, 5);
        RadiusResponse.AddAttribute(USER_NAME, "moji");
        //RadiusResponse.AddAttribute(CALLING_STATION_ID, "192.168.1.10");
        RadiusResponse.AddAttribute(CALLED_STATION_ID, "192.168.1.20");
        RadiusResponse.AddAttribute(ACCT_DELAY_TIME, val);

        //RadiusResponse.AddAttribute(ACCT_INTERIM_INTRAVEL, 1000);
        RadiusResponse.AddAttribute(ACCT_STATUS_TYPE, 2);   //RADIUSAcctStatusType::STOP


        RadiusResponse.Send(ACCESS_REJECT, &ClientIdentify);
    }
*/

    /*
 1  Code = Disconnect-Request (40)
 1  ID = 81
 2  Length = 62
16  Request Authenticator = ( be d1 31 06 2e a8 34 40 bc da 41 bf bd cb 4c 25 )
 9  User-Name (1) = "mojtaba" ( 6d 6f 6a 74 61 62 61 )
 6  NAS-IP-Address (4) = 192.168.1.10 ( c0 a8 01 0a )
15  Calling-Station-Id (31) = "192.168.1.105" ( 31 39 32 2e 31 36 38 2e 31 2e 31 30 35 )
12  Acct-Session-Id (44) = "SSH-213395" ( 53 53 48 2d 32 31 33 33 39 35 )
*/
    if(PacketType == DISCONNECT_REQUEST){
        EZResponse RadiusResponse(pRadiusServer);
        RadiusResponse.AddAttribute(USER_NAME, pRequest.getAttribute(USER_NAME).strValue.c_str());
        //RadiusResponse.AddAttribute(NAS_IP_ADDRESS, pRequest.getAttribute(NAS_IP_ADDRESS).strValue.c_str());
        //RadiusResponse.AddAttribute(CALLING_STATION_ID, pRequest.getAttribute(CALLING_STATION_ID).strValue.c_str());
        //RadiusResponse.AddAttribute(ACCT_SESSION_ID, pRequest.getAttribute(ACCT_SESSION_ID).strValue.c_str());
        RadiusResponse.Send(DISCONNECT_ACK, &ClientIdentify);

/*
        // add interim intravel attribute
        //RadiusResponse.AddAttribute(ACCT_INTERIM_INTRAVEL, 60);
        // add Service-Type attribute
        RadiusResponse.AddAttribute(SERVICE_TYPE, 2);   //2	Framed
        // add Framed-protocole
        RadiusResponse.AddAttribute(FRAMED_PROTOCOL, 1);    //1 PPP

        //RadiusResponse.AddAttribute(FRAMED_IP_ADDRESS, "255.255.255.254");
        //Acct-Interim-Interval
        RadiusResponse.AddAttribute(ACCT_INTERIM_INTRAVEL, 10);
        RadiusResponse.AddAttribute(NAS_PORT, pRequest.getAttribute(NAS_PORT).intValue);
        RadiusResponse.AddAttribute(NAS_PORT_TYPE, 5);     //15	Ethernet        5	Virtual

        //RadiusResponse.AddAttribute(CALLING_STATION_ID, "192.168.1.10");
        //RadiusResponse.AddAttribute(CALLED_STATION_ID, "192.168.1.20");
        RadiusResponse.AddAttribute(ACCT_SESSION_ID, pRequest.getAttribute(ACCT_SESSION_ID).intValue);

        RadiusResponse.AddAttribute(FRAMED_IP_ADDRESS, "192.168.1.0/24");
        //RadiusResponse.AddAttribute(FRAMED_IP_NETMASK, "255.255.255.0");
        //RadiusResponse.AddAttribute(FRAMED_MTU, 1500);
        //RadiusResponse.AddAttribute(SESSION_TIMEOUT, 3600); //sec
        //RadiusResponse.AddAttribute(IDLE_TIMEOUT, 10);
        //RadiusResponse.AddAttribute(FRAMED_IP_ADDRESS, "0.0.0.0");
        //RadiusResponse.AddAttribute(TERMINATION_ACTION, 1800);

        //RadiusResponse.AddAttribute(ACCT_AUTHENTIC, 1);//1 RADIUS    2 Local    3 Remote
        RadiusResponse.AddAttribute(ACCT_DELAY_TIME, 1);

*/

    }
}

int main3()
{
    /*
     * https://idblender.com/tools/test-radius#85a7e4a0-6dce-4f70-a1b0-fcc8a2cdb2be
     * radtest -t pap moji moji '2.176.229.202:1812' 0 123456 -x
    */

    //Need a create a RAS list [IP,Secret]



    m_EZRadiusServer.setAuthenticationPort(3799);
    m_EZRadiusServer.setAccountingPort(3799);
    m_EZRadiusServer.SeRequestCallback(onReceiveRequest);
    m_EZRadiusServer.RASList()->AddRAS("123456", "198.244.189.2");
    m_EZRadiusServer.RASList()->AddRAS("123456", "192.168.1.10");
    m_EZRadiusServer.RASList()->AddRAS("123456", "127.0.0.1");
    m_EZRadiusServer.RASList()->AddRAS("123456", "85.9.96.165");

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

int main2(){
    EZClientSettings radiusSettings;
    radiusSettings.Host = "accounting.mojz.ir";  //198.244.189.2
    radiusSettings.Secret = "123456";
    radiusSettings.AccountingPort = 1813;
    radiusSettings.AuthenticationPort = 1812;
    radiusSettings.TimeOut = 1500;
    radiusSettings.RetryCount = 1;



    //authentication request
    EZRadiusClient AuthRequest(radiusSettings);
    AuthRequest.AddAttribute(USER_NAME, "ir1test");
    //AuthRequest.AddAttribute(USER_PASSWORD, "12345");
    AuthRequest.AddAttribute(CHAP_PASSWORD, "12345");
    AuthRequest.SendRequest(C_ACCESS_REQUEST);

    //
    //AuthRequest.DumpResponse();
    AuthRequest.GetAttribute(MESSAGE_AUTHENTICATOR);
    //AuthRequest.GetAttribute(REPLY_MESSAGE);
    //AuthRequest.GetResponseType();
    LOG("ResponseType [%s]", AuthRequest.GetResponseTypeDescription());
    if(AuthRequest.GetResponseType() != ACCESS_ACCEPT){
        LOG("REPLY_MESSAGE [%s]", AuthRequest.GetAttribute(REPLY_MESSAGE).strValue.c_str());
    }


/*
    //accounting-start
    EZRadiusClient AccountingStart(radiusSettings);
    AccountingStart.AddAttribute(USER_NAME, "ir1test");
    AccountingStart.AddAttribute(ACCT_STATUS_TYPE, (int)RADIUSAcctStatusType::START);      //1 = start
    AccountingStart.AddAttribute(NAS_IP_ADDRESS, "192.168.1.1");
    AccountingStart.AddAttribute(CALLING_STATION_ID, "192.168.1.10");
    AccountingStart.AddAttribute(ACCT_SESSION_ID, "-----------3");
    AccountingStart.SendRequest(RADIUSClientRequestType::C_ACCOUNTING_REQUEST);

    LOG("ResponseType [%d][%s]", AccountingStart.GetResponseType(), AccountingStart.GetResponseTypeDescription());
    LOG("USER_NAME [%s]", AccountingStart.GetAttribute(USER_NAME).strValue.c_str());

    AccountingStart.DumpResponse();
*/
    getchar();
    return 0;
}


RADIUSPacketTypeCodes onCoaCallback(RADIUSPacketTypeCodes type, RadiusPacket& request, EZResponse &response, void *p){

    //
    request.dump();

    if(type == DISCONNECT_REQUEST){
        response.AddAttribute(USER_NAME, request.getAttribute(USER_NAME).strValue.c_str());
        response.AddAttribute(NAS_IP_ADDRESS, request.getAttribute(NAS_IP_ADDRESS).strValue.c_str());
        response.AddAttribute(CALLING_STATION_ID, request.getAttribute(CALLING_STATION_ID).strValue.c_str());
        response.AddAttribute(ACCT_SESSION_ID, request.getAttribute(ACCT_SESSION_ID).strValue.c_str());
    }
    return DISCONNECT_ACK;
}

int main()
{
    EZClientSettings radiusSettings;
    radiusSettings.Host = "accounting.mojz.ir";         //198.244.189.2
    radiusSettings.Secret = "123456";
    radiusSettings.AccountingPort = 1813;
    radiusSettings.AuthenticationPort = 1812;
    radiusSettings.CoAPort = 3799;
    radiusSettings.TimeOut = 1500;
    radiusSettings.RetryCount = 1;

    EZCoA CoA(radiusSettings);
    CoA.SetGetRequests(onCoaCallback, nullptr);
    CoA.Start();


    for(;;){
        getchar();
    }
    return 0;
}
