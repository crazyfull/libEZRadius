#include <unordered_set>
#include <iostream>
#include <typeinfo>
#include <Wrench/clsUDPSocket.h>
#include <Wrench/log.h>
#include <EZRadius/EZRadiusClient.h>
using namespace std;

int main(){
    EZClientSettings radiusSettings;
    radiusSettings.Host = "198.244.189.2";  //198.244.189.2
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
