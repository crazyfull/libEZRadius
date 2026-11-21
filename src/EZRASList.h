/*
 * libEZRadius
 *
 * Copyright (c) 2023-2026 Mojtaba Kahvand.
 * All rights reserved.
 *
 * Licensed under the GNU Lesser General Public License v2.1.
 * See LICENSE for details.
 */

#ifndef EZRASLIST_H
#define EZRASLIST_H
#include "RadiusSecret.h"
#include <cstdint>
#include <memory>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <unordered_map>

// RAS (NAS) item: the shared secret of one client address
struct RASItem{
    RadiusSecret Secret;
    in_addr_t IP = 0;       // IPv4 address, network byte order (0 for an IPv6 RAS)
    std::string Address;    // text form of the address (IPv4 or IPv6)

    RASItem();
    RASItem(const char* secret, uint32_t RASIP);
    RASItem(const char* secret, const std::string &address);
};

// List of the NAS (RAS) addresses that are allowed to talk with the server (IPv4 and IPv6).
//
// Not thread safe on purpose: like everything else in libEZRadius it must be used from the
// netRector reactor thread (use reactor->post() from other threads).
// GetRAS*() returns a shared_ptr, so a RASItem stays valid while a request that uses it is
// handled, even if the RAS is removed meanwhile.
class EZRASList
{
    std::unordered_map<std::string, std::shared_ptr<RASItem>> m_map;     // key: 16 byte address (IPv4-mapped)

public:
    EZRASList() = default;

    // add a RAS (IPv4 or IPv6 text). false: invalid IP, empty / too long secret, or the IP exists already
    bool AddRAS(const char*Secret, const char *IPAddress);
    bool AddRAS(const char*Secret, in_addr_t IPAddress);

    // add a RAS or change the secret of an existing one
    bool SetRAS(const char*Secret, const char *IPAddress);
    bool SetRAS(const char*Secret, in_addr_t IPAddress);

    std::shared_ptr<RASItem> GetRASByIP(uint32_t IPAddress) const;
    std::shared_ptr<RASItem> GetRASByIP(const char *IPAddress) const;
    std::shared_ptr<RASItem> GetRAS(const struct sockaddr *address) const;     // IPv4 or IPv6 sender address
    bool removeRASByIP(uint32_t IPAddress);
    bool removeRASByIP(const char *IPAddress);
    bool isExist(in_addr_t IPAddress) const;
    bool isExist(const char *IPAddress) const;
    size_t count() const { return m_map.size(); }
    void clear() { m_map.clear(); }
};

#endif // EZRASLIST_H
