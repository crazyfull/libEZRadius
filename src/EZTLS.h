/*
 * libEZRadius
 *
 * Copyright (c) 2023-2026 Mojtaba Kahvand.
 * All rights reserved.
 *
 * Licensed under the GNU Lesser General Public License v2.1.
 * See LICENSE for details.
 */

#ifndef EZTLS_H
#define EZTLS_H
// TLS / DTLS engine for RadSec (RFC 6614) and RADIUS/DTLS (RFC 7360), on BoringSSL with memory BIOs
// (the sockets stay plain netRector sockets). Needs EZRADIUS_HAS_TLS.
//
//   - mutual authentication: both sides must present a certificate (X.509, path validation against caPem,
//     optional SAN name check, optional pinning of the SHA-256 fingerprint of the peer certificate)
//   - TLS 1.2 and 1.3 (RFC 9325 profile: no compression, no 0-RTT, no tickets / resumption), DTLS 1.2
//   - ALPN "radius/1.0" / "radius/1.1" (RFC 9765)
#ifdef EZRADIUS_HAS_TLS

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

struct EZTLSConfig
{
    std::string certChainPem;           // own certificate (+ intermediates), PEM
    std::string privateKeyPem;          // own private key, PEM
    std::string caPem;                  // trusted CA certificates, PEM (the peer certificate must chain to one)
    bool verifyPeer = true;             // validate the peer certificate chain against caPem
    // SHA-256 fingerprints (hex, any case, ':' allowed) of acceptable peer certificates (DER). When the list is
    // not empty the peer certificate must match one of them, in addition to verifyPeer. With verifyPeer = false
    // the fingerprint list alone authenticates the peer (self-signed certificates).
    std::vector<std::string> pinnedSHA256;
    // client: DNS name or IP address that must be present in the server certificate subjectAltName (the Common Name
    // is never used, bis section 3.3.1); also sent as SNI. Empty: the name is not checked.
    std::string serverName;
    // RADIUS/1.1 negotiation (RFC 9765 section 3.3): "" = no ALPN (historic RADIUS/TLS), "1.0", "1.0,1.1" (default),
    // "1.1" (TLS 1.3 only). RADIUS/1.1 needs TLS 1.3, so a TLS 1.2 connection always ends up as RADIUS/1.0.
    std::string radiusVersions = "1.0,1.1";
    // allow a connection without any peer authentication (verifyPeer = false and no fingerprints). Do not use it.
    bool insecureSkipVerify = false;
    size_t mtu = 1400;                  // DTLS handshake record size (application records may be larger)

    static std::string readFile(const std::string &path);
};

struct ezeap_tls_ctx;
class EZTLSContext
{
public:
    ~EZTLSContext();
    static std::shared_ptr<EZTLSContext> create(const EZTLSConfig &cfg, bool server, bool dtls, std::string *error = nullptr);
    const EZTLSConfig &config() const { return m_cfg; }
    void *native() const { return m_ctx; }          // SSL_CTX*
    bool server() const { return m_server; }
    bool dtls() const { return m_dtls; }
    bool allow10 = true, allow11 = true, alpn = true;       // parsed radiusVersions
private:
    EZTLSContext() = default;
    void *m_ctx = nullptr;
    EZTLSConfig m_cfg;
    bool m_server = false, m_dtls = false;
};

class EZTLSEngine
{
public:
    ~EZTLSEngine();
    static std::unique_ptr<EZTLSEngine> create(const std::shared_ptr<EZTLSContext> &ctx, std::string *error = nullptr);

    // client: start the handshake (produces the ClientHello); server: nothing to do
    bool start();
    // data from the network: a chunk of the TLS byte stream, or one DTLS datagram.
    // false: fatal error (handshake failure, bad certificate, alert): close the connection
    bool feed(const uint8_t *data, size_t len);
    // application data to send (queued until the handshake is done)
    bool write(const uint8_t *data, size_t len);
    // bytes for the network (TLS: usually one chunk; DTLS: one entry per datagram). Always call after feed / write / start / handleTimeout.
    std::vector<std::string> takeOutput();
    // decrypted application data received so far (TLS byte stream)
    std::string takePlain();
    // DTLS: the decrypted records, one RADIUS packet each
    std::vector<std::string> takeRecords();

    bool established() const { return m_established; }
    bool peerClosed() const { return m_peerClosed; }
    // negotiated RADIUS version: 10 or 11 (after established())
    int radiusVersion() const { return m_radiusVersion; }
    std::string peerFingerprint() const { return m_fingerprint; }       // SHA-256 of the peer certificate, lowercase hex
    std::string peerCommonName() const { return m_commonName; }
    std::string errorText() const { return m_error; }
    bool close();                                                       // queue close_notify

    // DTLS retransmission timer: milliseconds until handleTimeout() must be called (-1: no timer)
    int msUntilTimeout();
    bool handleTimeout();

private:
    EZTLSEngine() = default;
    bool advance();
    bool afterHandshake();
    void drain();
    void fail(const char *what);

    std::shared_ptr<EZTLSContext> m_ctx;
    void *m_ssl = nullptr;              // SSL*
    void *m_rbio = nullptr;             // BIO* (owned by the SSL)
    void *m_wbio = nullptr;
    void *m_dgram = nullptr;            // DTLS datagram queues (owned)
    std::vector<std::string> m_out;
    std::string m_plain;
    std::vector<std::string> m_records;
    std::string m_pendingWrite;
    bool m_established = false, m_peerClosed = false, m_failed = false;
    int m_radiusVersion = 10;
    std::string m_fingerprint, m_commonName, m_error;
};

#endif // EZRADIUS_HAS_TLS
#endif // EZTLS_H
