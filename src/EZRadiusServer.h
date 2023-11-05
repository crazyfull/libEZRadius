#ifndef EZRADIUSSERVER_H
#define EZRADIUSSERVER_H
#include "RadiusPacket.h"
#include "EZRASList.h"
#include <functional>

class clsUDPServer;
class clsUDPSocket;
class clsUDPListener;
class EZRadiusServer;
class EZRadiusClientIdentify;
typedef std::function<void(RADIUSPacketTypeCodes, RadiusPacket &, EZRadiusClientIdentify &ClientIdentify, EZRadiusServer *pRadiusServer)> RADIUSCallback;
class EZRadiusServer
{
    //RAS list
    EZRASList m_RASList;

    //udp server
    clsUDPServer *m_pUDPServer;

    // uin
    uint16_t m_AuthPort;
    uint16_t m_AccPort;

    //callbacl
    RADIUSCallback _radiusallback;

    static void onReceiveUDPData(clsUDPListener* pListener, void*p, clsUDPSocket& UDPClient, const char*Data, int DataLength);

public:
    EZRadiusServer();
    ~EZRadiusServer();
    void setAuthenticationPort(uint16_t newAuthenticationPort);
    void setAccountingPort(uint16_t newAccountingPort);

    //void on
    void Start();
    uint16_t AuthenticatorPort() const;
    uint16_t AccountingPort() const;
    EZRASList *RASList();

    virtual void onReceiveRequest(RADIUSPacketTypeCodes PacketType, RadiusPacket &pRequest, EZRadiusClientIdentify &ClientIdentify, EZRadiusServer *pRadiusServer);
    void onReceiveRequest(const RADIUSCallback &callback);
};

#endif // EZRADIUSSERVER_H
