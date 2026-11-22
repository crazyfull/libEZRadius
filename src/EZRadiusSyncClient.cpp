#include "EZRadiusSyncClient.h"
#include "clsEpollReactor.h"

EZRadiusSyncClient::EZRadiusSyncClient(const EZClientSettings &Settings)
    : m_reactor(new netrector::EpollReactor(0, 16)), m_settings(Settings)
{
    m_settings.Pool.reset();            // a pool belongs to another reactor: the blocking client has its own
    m_client.reset(new EZRadiusClient(m_reactor.get(), m_settings));
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
