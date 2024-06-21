#include <Wrench/log.h>
#include <EZRadius/EZRadiusClient.h>

int main(){
    //create radius settings
    EZClientSettings radiusSettings;
    radiusSettings.Host = "accounting.mojz.ir";
    radiusSettings.Secret = "123456";
    radiusSettings.AccountingPort = 1813;
    radiusSettings.AuthenticationPort = 1812;
    radiusSettings.TimeOut = 1500;              //millisecond
    radiusSettings.RetryCount = 1;


    //username
    const char* userName = "crazyfull";

    //accounting-start
    EZRadiusClient Accounting(radiusSettings);
    Accounting.AddAttribute(ACCT_STATUS_TYPE, (int)RADIUSAcctStatusType::START);    //Accounting request type

    //set Attribute for Accounting-start
    Accounting.AddAttribute(USER_NAME, userName);
    Accounting.AddAttribute(NAS_IP_ADDRESS, "192.168.1.1");                         //Set NAS-IP
    Accounting.AddAttribute(CALLING_STATION_ID, "192.168.1.10");                    //Set Client-IP
    Accounting.AddAttribute(ACCT_SESSION_ID, "----my-seassion----");                //set Client Seassion

    //send ACCOUNTING_REQUEST request
    Accounting.SendRequest(RADIUSClientRequestType::C_ACCOUNTING_REQUEST);

    //dump accounting response
    Accounting.DumpResponse();

    LOG("ResponseType [%d][%s]", Accounting.GetResponseType(), Accounting.GetResponseTypeDescription());
    LOG("USER_NAME [%s]", Accounting.GetAttribute(USER_NAME).strValue.c_str());


/*
    //account
    const char* userName = "crazyfull";
    const char* password = "mypass";

    //set authentication attribute request
    EZRadiusClient AuthRequest(radiusSettings);
    AuthRequest.AddAttribute(USER_NAME, userName);
    //AuthRequest.AddAttribute(USER_PASSWORD, password);     //PAP-Protocol
    AuthRequest.AddAttribute(CHAP_PASSWORD, password);       //CHAP-Protocol

    //send ACCESS_REQUEST request
    AuthRequest.SendRequest(C_ACCESS_REQUEST);

    //dump response (if exist)
    AuthRequest.DumpResponse();


    //get server response code
    LOG("ResponseType [%u][%s]", AuthRequest.GetResponseType(), AuthRequest.GetResponseTypeDescription());

    //print attribute values (if exist)
    if(AuthRequest.GetResponseType() != ACCESS_ACCEPT){
        LOG("REPLY_MESSAGE [%s]", AuthRequest.GetAttribute(REPLY_MESSAGE).strValue.c_str());
    }else{
        LOG("Authentication OK");
    }
*/

    /**/


    getchar();
    return 0;
}
