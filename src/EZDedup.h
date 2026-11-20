#ifndef EZDEDUP_H
#define EZDEDUP_H
// Internal: cache of recently received requests, to detect retransmissions (RFC 5080 section 2.2.2).
// A retransmitted request (same source address+port, ID and Request Authenticator) must not be processed
// twice: if the answer is known it is sent again, otherwise the duplicate is dropped.
#include <chrono>
#include <deque>
#include <string>
#include <unordered_map>
#include <utility>

class EZDedupCache
{
    typedef std::chrono::steady_clock Clock;
    struct Entry {
        Clock::time_point time;
        bool hasResponse = false;
        std::string response;
    };

    std::unordered_map<std::string, Entry> m_map;
    std::deque<std::pair<Clock::time_point, std::string>> m_order;
    int m_windowMs = 30000;
    size_t m_maxEntries = 8192;

    void purge(Clock::time_point now)
    {
        const auto window = std::chrono::milliseconds(m_windowMs);
        while(!m_order.empty() && (now - m_order.front().first > window || m_order.size() > m_maxEntries)){
            auto it = m_map.find(m_order.front().second);
            // erase only if the entry was not replaced by a newer one with the same key
            if(it != m_map.end() && it->second.time == m_order.front().first)
                m_map.erase(it);
            m_order.pop_front();
        }
    }

public:
    enum Result { NEW_REQUEST, IN_PROGRESS, REPLAY };

    // 0 disables the cache
    void setWindow(int ms) { m_windowMs = ms; if(ms <= 0){ m_map.clear(); m_order.clear(); } }
    int window() const { return m_windowMs; }

    // register a request. REPLAY: *response holds the stored answer
    Result check(const std::string &key, const std::string **response)
    {
        if(m_windowMs <= 0)
            return NEW_REQUEST;

        const auto now = Clock::now();
        purge(now);

        auto it = m_map.find(key);
        if(it != m_map.end()){
            if(it->second.hasResponse){
                *response = &it->second.response;
                return REPLAY;
            }
            return IN_PROGRESS;
        }

        Entry e;
        e.time = now;
        m_map.emplace(key, std::move(e));
        m_order.emplace_back(now, key);
        return NEW_REQUEST;
    }

    void storeResponse(const std::string &key, const void *data, size_t len)
    {
        auto it = m_map.find(key);
        if(it != m_map.end()){
            it->second.hasResponse = true;
            it->second.response.assign((const char*)data, len);
        }
    }
};

#endif
