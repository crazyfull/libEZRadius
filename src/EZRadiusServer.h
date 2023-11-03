#ifndef EZRADIUSSERVER_H
#define EZRADIUSSERVER_H
#include "src/RadiusPacket.h"
#include "src/RadiusSecret.h"
#include <functional>

class clsUDPServer;
class clsUDPSocket;
class clsUDPListener;
class EZRadiusServer;
typedef std::function<void(PacketTypeCodes, RadiusPacket &, clsUDPSocket &, EZRadiusServer *pRadiusServer)> RADIUSCallback;
class EZRadiusServer
{
    //udp server
    clsUDPServer *m_pUDPServer;

    // uin
    uint16_t m_AuthPort;
    uint16_t m_AccPort;

    // Secret key
    RadiusSecret  m_secret;

    // Request received from the network
    RadiusPacket  m_request;

    //callbacl
    RADIUSCallback _radiusallback;


    static void onReceiveUDPData(clsUDPListener* pListener, void*p, clsUDPSocket& UDPClient, const char*Data, int DataLength);

public:
    EZRadiusServer();
    ~EZRadiusServer();
    void setSecret(const char* secret);
    void setAuthenticationPort(uint16_t newAuthenticationPort);
    void setAccountingPort(uint16_t newAccountingPort);

    //void on
    void Start();
    uint16_t AuthenticatorPort() const;
    uint16_t AccountingPort() const;
    RadiusSecret *Secret();

    virtual void onReceiveRequest(PacketTypeCodes PacketType, RadiusPacket &pRequest, clsUDPSocket &UDPClient, EZRadiusServer *pRadiusServer);
    void onReceiveRequest(const RADIUSCallback &callback);
};

#endif // EZRADIUSSERVER_H
