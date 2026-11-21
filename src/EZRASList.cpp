#include "EZRASList.h"
#include "EZAddr.h"
#include <arpa/inet.h>
#include <cstring>

RASItem::RASItem()
{

}

RASItem::RASItem(const char *secret, uint32_t RASIP)
{
    IP = RASIP;
    struct in_addr a;
    a.s_addr = RASIP;
    char buf[INET_ADDRSTRLEN] = {0};
    inet_ntop(AF_INET, &a, buf, sizeof(buf));
    Address = buf;
    if(secret)
        Secret.setSecret(secret, (uint16_t)strnlen(secret, D_SECRET_MAX_LENGTH + 1));
}

RASItem::RASItem(const char *secret, const std::string &address) : Address(address)
{
    struct in_addr a;
    if(inet_pton(AF_INET, address.c_str(), &a) == 1)
        IP = a.s_addr;
    if(secret)
        Secret.setSecret(secret, (uint16_t)strnlen(secret, D_SECRET_MAX_LENGTH + 1));
}

// IPv4 / IPv6 text -> 16 byte key. false: not a valid address
static bool keyFromText(const char *text, std::string &key)
{
    struct sockaddr_storage ss;
    socklen_t len;
    if(!ezaddr::parse(text, 0, ss, len))
        return false;
    key = ezaddr::keyOf((const struct sockaddr*)&ss);
    return !key.empty();
}

static std::string keyFromV4(in_addr_t ip)
{
    // IPv4-mapped IPv6 form: ::ffff:a.b.c.d
    unsigned char k[16] = {0,0,0,0,0,0,0,0,0,0,0xff,0xff};
    memcpy(k + 12, &ip, 4);
    return std::string((const char*)k, 16);
}

bool EZRASList::AddRAS(const char *Secret, const char* IPAddress)
{
    std::string key;
    if(!keyFromText(IPAddress, key) || m_map.find(key) != m_map.end())
        return false;
    return SetRAS(Secret, IPAddress);
}

bool EZRASList::AddRAS(const char *Secret, in_addr_t IPAddress)
{
    if(m_map.find(keyFromV4(IPAddress)) != m_map.end())
        return false;
    return SetRAS(Secret, IPAddress);
}

bool EZRASList::SetRAS(const char *Secret, const char *IPAddress)
{
    std::string key;
    if(!keyFromText(IPAddress, key))
        return false;

    auto item = std::make_shared<RASItem>(Secret, std::string(IPAddress));
    // a RAS without a (valid) secret can never authenticate anything
    if(item->Secret.isEmpty())
        return false;

    m_map[key] = std::move(item);
    return true;
}

bool EZRASList::SetRAS(const char *Secret, in_addr_t IPAddress)
{
    auto item = std::make_shared<RASItem>(Secret, IPAddress);
    if(item->Secret.isEmpty())
        return false;

    m_map[keyFromV4(IPAddress)] = std::move(item);
    return true;
}

std::shared_ptr<RASItem> EZRASList::GetRASByIP(uint32_t IPAddress) const
{
    auto it = m_map.find(keyFromV4(IPAddress));
    return it == m_map.end() ? nullptr : it->second;
}

std::shared_ptr<RASItem> EZRASList::GetRASByIP(const char *IPAddress) const
{
    std::string key;
    if(!keyFromText(IPAddress, key))
        return nullptr;
    auto it = m_map.find(key);
    return it == m_map.end() ? nullptr : it->second;
}

std::shared_ptr<RASItem> EZRASList::GetRAS(const struct sockaddr *address) const
{
    std::string key = ezaddr::keyOf(address);
    if(key.empty())
        return nullptr;
    auto it = m_map.find(key);
    return it == m_map.end() ? nullptr : it->second;
}

bool EZRASList::removeRASByIP(uint32_t IPAddress)
{
    return m_map.erase(keyFromV4(IPAddress)) > 0;
}

bool EZRASList::removeRASByIP(const char *IPAddress)
{
    std::string key;
    return keyFromText(IPAddress, key) && m_map.erase(key) > 0;
}

bool EZRASList::isExist(in_addr_t IPAddress) const
{
    return m_map.find(keyFromV4(IPAddress)) != m_map.end();
}

bool EZRASList::isExist(const char *IPAddress) const
{
    std::string key;
    return keyFromText(IPAddress, key) && m_map.find(key) != m_map.end();
}
