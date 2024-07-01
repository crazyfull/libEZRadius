
#include <EZRadius/EZClientSettings.h>
#include <EZRadius/EZCoA.h>


RADIUSPacketTypeCodes OnCoACallback(RADIUSPacketTypeCodes type, RadiusPacket& request, EZResponse &response, void *p){

    //LOG("OnCoACallback [%u]--------------------------------------------------------------------------------", type);
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
    radiusSettings.CoAPort = 3799;

    EZCoA CoA(radiusSettings);
    CoA.SetGetRequests(OnCoACallback, nullptr);
    CoA.Start();


    for(;;){
        getchar();
    }
    return 0;
}
