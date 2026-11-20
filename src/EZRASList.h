#ifndef EZRASLIST_H
#define EZRASLIST_H
#include "RadiusSecret.h"
#include <cstdint>
#include <memory>
#include <netinet/in.h>
#include <string>
#include <unordered_map>

// RAS (NAS) item: the shared secret of one client address
struct RASItem{
    RadiusSecret Secret;
    in_addr_t IP = 0;       // network byte order (as in sockaddr_in)

    RASItem();
    RASItem(const char* secret, uint32_t RASIP);
};

// List of the NAS (RAS) addresses that are allowed to talk with the server.
//
// Not thread safe on purpose: like everything else in libEZRadius it must be used from the
// netRector reactor thread (use reactor->post() from other threads).
// GetRASByIP() returns a shared_ptr, so a RASItem stays valid while a request that uses it is
// handled, even if the RAS is removed meanwhile.
class EZRASList
{
    std::unordered_map<in_addr_t, std::shared_ptr<RASItem>> m_map;

public:
    EZRASList() = default;

    // add a RAS. false: invalid IP, empty / too long secret, or the IP exists already
    bool AddRAS(const char*Secret, const char *IPAddress);
    bool AddRAS(const char*Secret, in_addr_t IPAddress);

    // add a RAS or change the secret of an existing one
    bool SetRAS(const char*Secret, const char *IPAddress);
    bool SetRAS(const char*Secret, in_addr_t IPAddress);

    std::shared_ptr<RASItem> GetRASByIP(uint32_t IPAddress) const;
    bool removeRASByIP(uint32_t IPAddress);
    bool removeRASByIP(const char *IPAddress);
    bool isExist(in_addr_t IPAddress) const;
    bool isExist(const char *IPAddress) const;
    size_t count() const { return m_map.size(); }
    void clear() { m_map.clear(); }
};

#endif // EZRASLIST_H
