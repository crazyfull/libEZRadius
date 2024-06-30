#include "EZClientSettings.h"

EZClientSettings::EZClientSettings() {
    //set default setting
    if(RetryCount <=0){
        RetryCount = 1;
    }

    if(TimeOut <= 0){
        TimeOut = 2200;
    }

    if(AccountingPort <= 0){
        AccountingPort = 1812;
    }

    if(AuthenticationPort <= 0){
        AuthenticationPort = 1813;
    }

    if(CoAPort <= 0){
        CoAPort = 3799;
    }
}
