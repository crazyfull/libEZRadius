/*
 * libEZRadius
 *
 * Copyright (c) 2023-2026 Mojtaba Kahvand.
 * All rights reserved.
 *
 * Licensed under the GNU Lesser General Public License v2.1.
 * See LICENSE for details.
 */

#ifndef EZADDR_H
#define EZADDR_H
// Internal address helpers (IPv4 / IPv6, IPv4 is handled as an IPv4-mapped IPv6 address)
#include <arpa/inet.h>
#include <cstdint>
#include <cstring>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>

namespace ezaddr {

// 16 byte key of an address: IPv4 -> ::ffff:a.b.c.d. false: not an IP socket address
inline bool toKey(const struct sockaddr *sa, unsigned char key[16])
{
    if(!sa)
        return false;
    if(sa->sa_family == AF_INET){
        memset(key, 0, 10);
        key[10] = key[11] = 0xff;
        memcpy(key + 12, &((const struct sockaddr_in*)sa)->sin_addr, 4);
        return true;
    }
    if(sa->sa_family == AF_INET6){
        memcpy(key, &((const struct sockaddr_in6*)sa)->sin6_addr, 16);
        return true;
    }
    return false;
}

inline std::string keyOf(const struct sockaddr *sa)
{
    unsigned char k[16];
    return toKey(sa, k) ? std::string((const char*)k, 16) : std::string();
}

inline uint16_t portOf(const struct sockaddr *sa)
{
    if(sa->sa_family == AF_INET)
        return ntohs(((const struct sockaddr_in*)sa)->sin_port);
    if(sa->sa_family == AF_INET6)
        return ntohs(((const struct sockaddr_in6*)sa)->sin6_port);
    return 0;
}

// text (IPv4 or IPv6 literal) + port -> socket address. false: not an IP literal
inline bool parse(const char *text, uint16_t port, struct sockaddr_storage &out, socklen_t &len)
{
    if(!text)
        return false;
    memset(&out, 0, sizeof(out));
    struct sockaddr_in *a4 = (struct sockaddr_in*)&out;
    if(inet_pton(AF_INET, text, &a4->sin_addr) == 1){
        a4->sin_family = AF_INET;
        a4->sin_port = htons(port);
        len = sizeof(*a4);
        return true;
    }
    struct sockaddr_in6 *a6 = (struct sockaddr_in6*)&out;
    if(inet_pton(AF_INET6, text, &a6->sin6_addr) == 1){
        a6->sin6_family = AF_INET6;
        a6->sin6_port = htons(port);
        len = sizeof(*a6);
        return true;
    }
    memset(&out, 0, sizeof(out));
    return false;
}

inline std::string toString(const struct sockaddr *sa)
{
    char buf[INET6_ADDRSTRLEN] = {0};
    if(sa->sa_family == AF_INET)
        inet_ntop(AF_INET, &((const struct sockaddr_in*)sa)->sin_addr, buf, sizeof(buf));
    else if(sa->sa_family == AF_INET6)
        inet_ntop(AF_INET6, &((const struct sockaddr_in6*)sa)->sin6_addr, buf, sizeof(buf));
    return buf;
}

}

#endif
