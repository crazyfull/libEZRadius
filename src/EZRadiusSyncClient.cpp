#include "EZRadiusSyncClient.h"
#include "clsEpollReactor.h"

EZRadiusSyncClient::EZRadiusSyncClient(const EZClientSettings &Settings)
    : m_reactor(new netrector::EpollReactor(0, 16)), m_client(new EZRadiusClient(m_reactor.get(), Settings)), m_settings(Settings)
{
}

EZRadiusSyncClient::~EZRadiusSyncClient()
{
    // the client must go before its reactor
    m_client.reset();
    m_reactor.reset();
}

void EZRadiusSyncClient::Reset()
{
    m_client->Reset();
    m_result = EZResult::NONE;
}

EZResult EZRadiusSyncClient::Send(RADIUSClientRequestType RequestType)
{
    m_stop = false;
    m_result = EZResult::NONE;

    const bool started = m_client->Send(RequestType, [this](EZRadiusClient &, EZResult r){
        m_result = r;
        m_stop = true;      // the reactor loop ends after this event batch
    });
    if(!started){
        m_result = EZResult::SEND_FAILED;
        return m_result;
    }

    m_reactor->run(m_stop);
    return m_result;
}
