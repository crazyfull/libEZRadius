#ifndef EZRADIUS11_H
#define EZRADIUS11_H
// RADIUS/1.1 (RFC 9765): the wire format used on TLS 1.3 connections that negotiated ALPN "radius/1.1".
//
//   Code (1) | Reserved-1 = 0 (1) | Length (2) | Token (4) | Reserved-2 = 0 (12) | Attributes
//
// The Identifier is replaced by a 4 byte Token, there are no Request / Response Authenticators and no
// Message-Authenticator; obfuscated attributes (User-Password, MS-MPPE keys) are sent as plain strings because
// the TLS tunnel protects them.
//
// The library processes classic (RADIUS/1.0) packets everywhere. These functions convert a packet between the two
// formats at the transport boundary: the classic form uses the Token (+ zero bytes) as its Request Authenticator,
// so retransmission detection and Token matching work unchanged.
#ifdef EZRADIUS_HAS_TLS

#include <cstddef>
#include <cstdint>
#include <string>

namespace ezradius11 {

// client, sending: classic request -> wire. The Token is the first 4 bytes of the request's Request Authenticator.
bool classicRequestToWire(const uint8_t *pkt, size_t len, const std::string &secret, std::string &wire);
// server, receiving: wire request -> classic request (Request Authenticator = Token + 12 zero bytes, ID = last Token byte)
bool wireRequestToClassic(const uint8_t *wire, size_t len, const std::string &secret, std::string &classic);
// server, sending: classic response -> wire. requestAuth: Request Authenticator of the request it answers.
bool classicResponseToWire(const uint8_t *pkt, size_t len, const uint8_t requestAuth[16], const std::string &secret, std::string &wire);
// client, receiving: wire response -> classic response with a valid Response Authenticator for the request
// (requestId / requestAuth). false when the Token does not match the request or the packet is malformed.
bool wireResponseToClassic(const uint8_t *wire, size_t len, uint8_t requestId, const uint8_t requestAuth[16], const std::string &secret, std::string &classic);

} // namespace ezradius11

#endif // EZRADIUS_HAS_TLS
#endif // EZRADIUS11_H
