#include "EZRASList.h"
#include <arpa/inet.h>
#include <cstring>

RASItem::RASItem()
{

}

RASItem::RASItem(const char *secret, uint32_t RASIP)
{
    IP = RASIP;
    if(secret)
        Secret.setSecret(secret, (uint16_t)strnlen(secret, D_SECRET_MAX_LENGTH + 1));
}

// dotted IPv4 text -> network byte order. false: not a valid IPv4 address
// (inet_addr() can not be used: it returns INADDR_NONE for errors, which is also 255.255.255.255)
static bool parseIPv4(const char *text, in_addr_t &out)
{
    if(!text)
        return false;

    struct in_addr addr;
    if(inet_pton(AF_INET, text, &addr) != 1)
        return false;

    out = addr.s_addr;
    return true;
}

bool EZRASList::AddRAS(const char *Secret, const char* IPAddress)
{
    in_addr_t ip;
    if(!parseIPv4(IPAddress, ip))
        return false;

    return AddRAS(Secret, ip);
}

bool EZRASList::AddRAS(const char *Secret, in_addr_t IPAddress)
{
    if(m_map.find(IPAddress) != m_map.end())
        return false;

    return SetRAS(Secret, IPAddress);
}

bool EZRASList::SetRAS(const char *Secret, const char *IPAddress)
{
    in_addr_t ip;
    if(!parseIPv4(IPAddress, ip))
        return false;

    return SetRAS(Secret, ip);
}

bool EZRASList::SetRAS(const char *Secret, in_addr_t IPAddress)
{
    auto item = std::make_shared<RASItem>(Secret, IPAddress);

    // a RAS without a (valid) secret can never authenticate anything
    if(item->Secret.isEmpty())
        return false;

    m_map[IPAddress] = std::move(item);
    return true;
}

std::shared_ptr<RASItem> EZRASList::GetRASByIP(uint32_t IPAddress) const
{
    auto it = m_map.find(IPAddress);
    if(it == m_map.end())
        return nullptr;

    return it->second;
}

bool EZRASList::removeRASByIP(uint32_t IPAddress)
{
    return m_map.erase(IPAddress) > 0;
}

bool EZRASList::removeRASByIP(const char *IPAddress)
{
    in_addr_t ip;
    return parseIPv4(IPAddress, ip) && removeRASByIP(ip);
}

bool EZRASList::isExist(in_addr_t IPAddress) const
{
    return m_map.find(IPAddress) != m_map.end();
}

bool EZRASList::isExist(const char *IPAddress) const
{
    in_addr_t ip;
    return parseIPv4(IPAddress, ip) && isExist(ip);
}
