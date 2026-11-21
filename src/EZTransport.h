/*
 * libEZRadius
 *
 * Copyright (c) 2023-2026 Mojtaba Kahvand.
 * All rights reserved.
 *
 * Licensed under the GNU Lesser General Public License v2.1.
 * See LICENSE for details.
 */

#ifndef EZTRANSPORT_H
#define EZTRANSPORT_H
// RADIUS transports: UDP (RFC 2865), TCP (RFC 6613), TLS = RadSec (RFC 6614), DTLS (RFC 7360).
// Shared helpers: transport enum, reply channel (how a server answers a request) and the stream framer.
#include <cstddef>
#include <cstdint>
#include <string>

enum class EZTransport {
    UDP = 0,        // RFC 2865 / 2866
    TCP,            // RFC 6613 (no security: shared secret protocol only, use on trusted links)
    TLS,            // RFC 6614 RadSec (needs EZRADIUS_HAS_TLS)
    DTLS            // RFC 7360 (needs EZRADIUS_HAS_TLS)
};

// default ports (IANA)
enum : uint16_t { D_RADSEC_PORT = 2083 };

class EZRadiusClientIdentify;

// How the server sends a response back for a request that did not arrive on a plain UDP socket
// (a TCP / TLS connection or a DTLS session). The channel stays safe to use after the connection
// closed: send() then just returns false.
class EZReplyChannel
{
public:
    virtual ~EZReplyChannel() = default;
    // packet: a complete classic RADIUS packet (RFC 2865 layout). The channel converts it when the
    // connection uses another wire format (RADIUS/1.1) and sends it.
    virtual bool send(const uint8_t *packet, size_t len, const EZRadiusClientIdentify &request) = 0;
    // true when the request arrived on the accounting port (decides the Status-Server answer code)
    virtual bool isAccountingPort() const { return false; }
};

// Splits a byte stream into RADIUS packets using the Length field (RFC 6613 section 2.6.4).
class EZStreamFramer
{
    std::string m_buf;
    size_t m_pos = 0;

public:
    enum Result { NEED_MORE = 0, PACKET = 1, INVALID = -1 };
    static const size_t MIN_PACKET = 20;
    static const size_t MAX_PACKET = 4096;

    void append(const uint8_t *data, size_t len) { m_buf.append((const char*)data, len); }
    // INVALID: the Length field is outside 20..4096: the connection must be closed
    Result next(std::string &packet);
    void clear() { m_buf.clear(); m_pos = 0; }
    size_t buffered() const { return m_buf.size() - m_pos; }
};

#endif // EZTRANSPORT_H
