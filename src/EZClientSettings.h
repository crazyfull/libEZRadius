#ifndef EZCLIENTSETTINGS_H
#define EZCLIENTSETTINGS_H
#include <string>

class EZClientSettings
{
public:
    int TimeOut;
    int RetryCount;
    int AuthenticationPort;
    int AccountingPort;
    int CoAPort;
    std::string Host;
    std::string Secret;
    std::string NAS_IP;

    EZClientSettings();
};

#endif // EZCLIENTSETTINGS_H
