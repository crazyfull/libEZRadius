# libEZRadius

**An asynchronous, single-threaded RADIUS client, server and Dynamic Authorization (CoA / Disconnect) library for C++ on Linux, built on [netRector](https://github.com/crazyfull/netRector).**

libEZRadius provides RADIUS packet encoding and validation, client and server functionality, Authentication and Accounting, RFC 5176 Dynamic Authorization, PAP / EAP-MD5 / EAP-TLS / CHAP / MS-CHAPv1 / MS-CHAPv2 helpers, and MPPE key handling. Its asynchronous API integrates with a netRector `EpollReactor`; a blocking client wrapper is also available for applications that do not use an event loop.

---

## Table of contents

1. [Why libEZRadius?](#why-libezradius)
2. [Features](#features)
3. [Supported standards](#supported-standards)
4. [Architecture and threading model](#architecture-and-threading-model)
5. [Building](#building)
6. [Quick start](#quick-start)
7. [API overview](#api-overview)
8. [Supported attributes](#supported-attributes)
9. [Security notes](#security-notes)
10. [Testing](#testing)
11. [Limitations](#limitations)
12. [Project layout and credits](#project-layout-and-credits)

---

## Why libEZRadius?

libEZRadius is intended for Linux applications that need RADIUS client and server functionality without introducing a separate networking event loop or an internal thread pool.

- **Native event-loop integration:** asynchronous RADIUS operations use the application's `netrector::EpollReactor`.
- **No internal worker threads:** the asynchronous core does not create threads or use mutex-based synchronization. Callbacks execute on the reactor thread, so application callbacks must not perform long blocking work.
- **Asynchronous network operations:** UDP/TCP I/O, reactor timers, and DNS resolution are integrated with netRector. TLS and DTLS run on BoringSSL memory BIOs over the same non-blocking sockets.
- **Client and server roles:** the library includes an asynchronous client, a blocking client wrapper, an Authentication/Accounting server, and RFC 5176 Dynamic Authorization listener and sender functionality.
- **Built-in authentication helpers:** PAP, CHAP, MS-CHAPv1/v2, MS-CHAPv2 mutual authentication, and MPPE key handling are provided.
- **Low-level packet access:** applications can construct and inspect RADIUS attributes and vendor-specific data directly.

The asynchronous API is designed to be driven by an existing reactor. `EZRadiusSyncClient` is available when a blocking call is more appropriate.

---

## Features

### Client

- Asynchronous `EZRadiusClient`: `Send()` returns immediately; the result is delivered by callback from the reactor.
- Blocking `EZRadiusSyncClient`: `Send()` returns when the answer or timeout is received. It drives a private reactor synchronously on the calling thread.
- Request types: Access-Request, Accounting-Request, Status-Server, Disconnect-Request, and CoA-Request.
- Timeouts and retransmissions on reactor timers. Retransmissions reuse the same Identifier and Request Authenticator.
- Asynchronous DNS resolution for the server name (A, then AAAA fallback); IPv4 and IPv6 literals are supported.
- A fresh UDP socket with a random source port per request.
- Response validation: source address and port, packet code, Identifier, Response Authenticator, and Message-Authenticator when present or required.
- PAP, CHAP, MS-CHAPv1, and MS-CHAPv2 login helpers; MS-CHAPv2 mutual-authentication verification and client-side MPPE key decryption.
- Message-Authenticator on every Access-Request by default.

### Server

- `EZRadiusServer`: UDP listeners on Authentication and Accounting ports (IPv4, IPv6, or dual stack); optional RADIUS over TCP, RadSec (TLS) and RADIUS over DTLS (see [Transports](#transports)).
- Per-NAS shared secrets (`EZRASList`) and IPv4/IPv6 NAS addresses; unknown senders are dropped silently.
- Request validation before the application callback: packet structure, Request Authenticator where applicable, and Message-Authenticator according to packet type and configuration.
- Duplicate request detection: a duplicate is not processed twice; the cached response is sent again.
- Automatic Status-Server answers.
- `EZResponse` builds responses with attributes, vendor-specific attributes, MS-CHAPv2 success/error, MPPE keys, Response Authenticator, Message-Authenticator, and Proxy-State copying.

### Transports

| Transport | Standard | Enable | Shared secret | Default port |
|---|---|---|---|---|
| UDP | RFC 2865 / 2866 / 5176 | always on | per NAS (`EZRASList`) | 1812 / 1813 / 3799 |
| TCP | RFC 6613 | `server.EnableTCP()`, `Transport = TCP` | per NAS | same numbers as UDP, over TCP |
| TLS (RadSec) | RFC 6614 | `server.EnableTLS(cfg)`, `Transport = TLS` | fixed `radsec` | 2083/tcp |
| DTLS | RFC 7360 | `server.EnableDTLS(cfg)`, `Transport = DTLS` | fixed `radius/dtls` | 2083/udp |
| RADIUS/1.1 over TLS 1.3 | RFC 9765 | negotiated with ALPN (`EZTLSConfig::radiusVersions`) | not used | 2083/tcp |

- **TCP (RFC 6613):** stream framing with the Length field (packets below 20 or above 4096 bytes close the connection), invalid packets close the connection, connection limit and idle timeout on the server, one reusable connection per async client object. RADIUS over TCP has no retransmission on a connection: `RetryCount` means "reconnect and send again". TCP has no encryption: use it on trusted links only.
- **RadSec (RFC 6614) and DTLS (RFC 7360):** implemented on BoringSSL (`EZTLS.h`). Both sides authenticate with X.509 certificates (mutual authentication): chain validation against `caPem`, server name check against the certificate subjectAltName (DNS or IP, the Common Name is never used), optional SHA-256 fingerprint pinning (also usable instead of a CA for self-signed certificates). TLS 1.2 and 1.3, DTLS 1.2, no compression, no 0-RTT, no session tickets or resumption (every connection is authorized in full). The server only accepts addresses from `RASList()` unless `setRadSecIPFilter(false)`.
- **DTLS server:** one DTLS session per peer address and port, one RADIUS packet per record, retransmission timers, partial-handshake and session limits, idle timeout. Packets up to 4096 bytes are supported.
- **RADIUS/1.1 (RFC 9765):** on TLS 1.3 the ALPN protocols `radius/1.0` and `radius/1.1` are negotiated (default offer: both). RADIUS/1.1 replaces the Identifier and the authenticators with a 4-byte Token and sends User-Password and MPPE keys as plain strings inside the tunnel; there is no Message-Authenticator. The library converts at the transport boundary, so request handling, `EZResponse`, MS-CHAP and EAP work unchanged. Servers set `radiusVersions` to `"1.0"` to disable it. A client that offers only `"1.1"` fails against servers that do not support it.

### Vendor-specific attributes (modular dictionary)

- `EZVendorRegistry` (`EZVendorDict.h`): a data-driven registry of vendors and vendor attributes. Adding a vendor needs no change to the core.
- Built-in dictionaries (`src/vendors/`): MikroTik (14988), Cisco (9), Juniper (2636), Huawei (2011), and Microsoft (311).
- Add your own vendor at run time from FreeRADIUS-style dictionary text or a file (`VENDOR`, `BEGIN-VENDOR` / `END-VENDOR`, `ATTRIBUTE`, `VALUE`, `format=t,l`), or from code with `registerVendor()` / `registerAttribute()`.
- Attributes are addressed by name and converted by type (string, integer, IPv4/IPv6 address, octets, symbolic `VALUE` names); decoded back with `decode()` / `find()`.
- Vendor sub-attribute headers with 1, 2 or 4 byte type and 0, 1 or 2 byte length are supported.

### EAP (RFC 3748 / RFC 3579)

- `EZEAPServer`: EAP over RADIUS state machine (State sessions, EAP-Message fragmentation, Message-Authenticator, Access-Challenge / Accept / Reject, MPPE keys from the MSK).
- Methods: **EAP-MD5** and **EAP-TLS** (RFC 5216, TLS 1.2, mutual certificate authentication, MSK export). EAP-Nak method negotiation.
- Pluggable `EZEAPMethod` interface for additional methods; accept / reject hooks for adding reply attributes (for example vendor attributes).
- `EZEAPPeer`: a small supplicant (MD5 + TLS) for tools and tests; `EZRadiusClient` / `EZRadiusSyncClient` carry the EAP exchange (`AddEAPMessage()`, `GetEAPMessage()`, `GetState()`).
- Needs BoringSSL (`libcrypto`; EAP-TLS also `libssl`).

### Dynamic Authorization (RFC 5176)

- `EZCoA`: listener for Disconnect-Request and CoA-Request from a RADIUS server; replies with ACK or NAK.
- `EZRadiusClient` with `C_DISCONNECT_REQUEST` / `C_COA_REQUEST`: sends Dynamic Authorization requests to a NAS.

### Protocol core

- Packet parser validates packet and attribute lengths before use.
- Constant-time authenticator comparison and secure random Identifier / Request Authenticator generation.
- PAP passwords up to 128 bytes, secrets up to 256 bytes, and RADIUS packet-size limits are enforced.
- Passwords are not printed by `dump()` unless explicitly enabled; temporary buffers are wiped.

---

## Supported standards

| Standard | Title | Implementation scope |
|---|---|---|
| [RFC 2865](https://www.rfc-editor.org/rfc/rfc2865) | RADIUS | Packet format, Access-Request / Accept / Reject / Challenge, Request and Response Authenticator, PAP User-Password encryption, CHAP, common attributes, Vendor-Specific (26), Proxy-State copying, UDP port 1812 |
| [RFC 2866](https://www.rfc-editor.org/rfc/rfc2866) | RADIUS Accounting | Accounting-Request / Response, Accounting Request Authenticator, common Accounting attributes, UDP port 1813 |
| [RFC 2867](https://www.rfc-editor.org/rfc/rfc2867) | RADIUS Accounting Modifications for Tunnel Protocol Support | Acct-Tunnel-Connection as a string attribute |
| [RFC 2868](https://www.rfc-editor.org/rfc/rfc2868) | RADIUS Attributes for Tunnel Protocol Support | Supported Tunnel attributes as typed attributes; Tunnel-Password is not decrypted |
| [RFC 2869](https://www.rfc-editor.org/rfc/rfc2869) | RADIUS Extensions | Acct-Input/Output-Gigawords, Event-Timestamp, Acct-Interim-Interval, ARAP and other listed attributes |
| [RFC 3579](https://www.rfc-editor.org/rfc/rfc3579) | RADIUS Support for EAP | Message-Authenticator, EAP-Message fragmentation and reassembly, State handling, MPPE keys from the MSK |
| [RFC 3748](https://www.rfc-editor.org/rfc/rfc3748) | Extensible Authentication Protocol (EAP) | Packet format, Identity, Nak, Notification, EAP-MD5 |
| [RFC 5216](https://www.rfc-editor.org/rfc/rfc5216) | The EAP-TLS Authentication Protocol | EAP-TLS over TLS 1.2: fragmentation, Start / ACK, mutual certificates, MSK / EMSK export |
| [RFC 5176](https://www.rfc-editor.org/rfc/rfc5176) | Dynamic Authorization Extensions to RADIUS | Disconnect-Request / ACK / NAK and CoA-Request / ACK / NAK; listener and sender; UDP port 3799 |
| [RFC 5997](https://www.rfc-editor.org/rfc/rfc5997) | Use of Status-Server Packets in RADIUS | Automatic server answer and client health check |
| [RFC 5080](https://www.rfc-editor.org/rfc/rfc5080) | Common RADIUS Implementation Issues and Suggested Fixes | Duplicate request detection, response validation, retransmission behavior, source-port randomization |
| [RFC 4675](https://www.rfc-editor.org/rfc/rfc4675) | RADIUS Attributes for VLAN and Priority Support | Attributes 56–59 |
| [RFC 2433](https://www.rfc-editor.org/rfc/rfc2433) | Microsoft PPP CHAP Extensions | MS-CHAPv1 NT response; legacy LM response is not supported |
| [RFC 2759](https://www.rfc-editor.org/rfc/rfc2759) | Microsoft PPP CHAP Extensions, Version 2 | MS-CHAPv2 verification and generation, authenticator response, mutual authentication |
| [RFC 2548](https://www.rfc-editor.org/rfc/rfc2548) | Microsoft Vendor-specific RADIUS Attributes | MS-CHAP and MPPE vendor attributes, including MPPE key encryption |
| [RFC 3079](https://www.rfc-editor.org/rfc/rfc3079) | Deriving Keys for use with Microsoft Point-to-Point Encryption (MPPE) | MPPE master and session key derivation for MS-CHAPv2 |

The test suite includes vectors from RFC 2202 (HMAC-MD5), RFC 2865 §7.1 (PAP), RFC 2759 §9.2 (MS-CHAPv2), and RFC 3079 §3.5.3 (MPPE master key).

| [RFC 6613](https://www.rfc-editor.org/rfc/rfc6613) | RADIUS over TCP | Stream framing, connection handling, server listeners, client transport |
| [RFC 6614](https://www.rfc-editor.org/rfc/rfc6614) | TLS Encryption for RADIUS (RadSec) | Mutual certificate authentication, fixed secret `radsec`, port 2083 |
| [RFC 7360](https://www.rfc-editor.org/rfc/rfc7360) | Datagram Transport Layer Security (DTLS) as a Transport Layer for RADIUS | DTLS 1.2 sessions, one packet per record, port 2083/udp |
| [RFC 9765](https://www.rfc-editor.org/rfc/rfc9765) | RADIUS/1.1: Leveraging Connection-Oriented Transports | ALPN `radius/1.0` / `radius/1.1`, Token header, no authenticators, plain obfuscated attributes |

Where the Internet-Draft `draft-ietf-radext-radiusdtls-bis` (which updates RFC 6614 and RFC 7360) is clear, the implementation follows it: no CN matching, no resumption, TLS 1.2 minimum, connection and partial-session limits, 0.5 s reconnect delay.

**Transport scope:** UDP, TCP, TLS and DTLS (see [Transports](#transports)). EAP is supported through EAP-MD5 and EAP-TLS (see [EAP](#eap-server-and-peer)); PEAP, EAP-TTLS and EAP-TLS 1.3 (RFC 9190) are not implemented.

---

## Architecture and threading model

```text
 your program
     |
     +-- EZRadiusClient ---+
     +-- EZRadiusServer ---+----> netrector::EpollReactor
     +-- EZCoA ------------+      (application-owned event loop)

 EZRadiusSyncClient ------------> private EpollReactor
                                  (runs on calling thread)
```

- Every asynchronous object belongs to one reactor and **must be used from that reactor's thread**. From another thread, use `reactor.post([]{ ... })`.
- The asynchronous core does not create threads, use mutex-based synchronization, or perform blocking network operations.
- Callbacks execute on the reactor thread. A slow database lookup or other blocking work inside a callback stalls that reactor. Use an asynchronous database client, or hand work to an application-managed worker thread and post the result back with `reactor.post()`.
- Objects must be destroyed before their reactor (or before `run()` returns). Destroying a client with a request in flight cancels it silently.
- `EZRadiusSyncClient` owns its reactor and blocks the calling thread while waiting for a result. Independent synchronous clients can be used from different threads, subject to the application's own object/thread-safety rules.
- One `EZRadiusClient` object handles one request at a time. Call `Reset()` before building another request on that object.

---

## Building

Requirements: Linux, a C++17 compiler, CMake 3.14 or newer, and [netRector](https://github.com/crazyfull/netRector). BoringSSL is optional and is required for the MS-CHAP and MPPE cryptographic functionality. EAP and EAP-TLS are not implemented.

```sh
git clone https://github.com/crazyfull/netRector third_party/netRector
# Alternatively, configure EZRADIUS_NETRECTOR_DIR or EZRADIUS_FETCH_NETRECTOR.

# Optional: build BoringSSL. netRector provides a helper script:
# third_party/netRector/scripts/build_boringssl.sh /opt/bssl

cmake -S . -B build -G Ninja \
  -DNETRECTOR_ENABLE_TLS=OFF \
  -DBORINGSSL_DIR=/opt/bssl

cmake --build build
(cd build && ctest --output-on-failure)
```

### CMake options

| Option | Default | Description |
|---|---:|---|
| `EZRADIUS_NETRECTOR_DIR` | — | netRector source directory |
| `EZRADIUS_FETCH_NETRECTOR` | `OFF` | Fetch netRector with FetchContent when it is not found |
| `BORINGSSL_DIR` | — | BoringSSL prefix containing `include/` and `lib/libcrypto.a`; can also be supplied through the environment |
| `EZRADIUS_ENABLE_CRYPTO` | `ON` | Use BoringSSL when found. Without it, PAP, CHAP, Accounting, CoA, Status-Server, and RADIUS over TCP remain available; MS-CHAP and EAP are compiled out (`EZRADIUS_HAS_CRYPTO` is not defined). EAP-TLS, RadSec, DTLS and RADIUS/1.1 additionally need `libssl` next to `libcrypto` (`EZRADIUS_HAS_TLS`) |
| `EZRADIUS_BUILD_EXAMPLES` | `ON` | Build examples |
| `EZRADIUS_BUILD_TESTS` | `ON` | Build tests |
| `EZRADIUS_BUILD_FUZZER` | `OFF` | Build the libFuzzer target (requires Clang) |
| `EZRADIUS_SANITIZE` | `OFF` | Enable AddressSanitizer and UndefinedBehaviorSanitizer |

Use the library from another CMake project:

```cmake
add_subdirectory(libEZRadius)
target_link_libraries(myapp PRIVATE EZRadius)
```

The `EZRadius` target also brings in the configured netRector and, when enabled, BoringSSL dependencies.

---

## Quick start

The asynchronous examples below assume an application-owned reactor:

```cpp
netrector::EpollReactor reactor(0, 1024);
std::atomic<bool> stop{false};
```

### Asynchronous client (PAP)

```cpp
EZClientSettings settings;
settings.Host = "radius.example.com";
settings.Secret = "shared-secret";
settings.TimeOut = 1500; // milliseconds per attempt
settings.RetryCount = 3;

EZRadiusClient client(&reactor, settings);
client.AddAttribute(USER_NAME, "alice");
client.AddAttribute(USER_PASSWORD, "wonderland");
client.AddAttribute(NAS_IP_ADDRESS, "192.168.1.1");

client.Send(C_ACCESS_REQUEST, [](EZRadiusClient &c, EZResult result) {
    if (result == EZResult::OK && c.GetResponseType() == ACCESS_ACCEPT) {
        // Authentication accepted.
    }
});

reactor.run(stop);
```

`EZResult` includes `OK`, `TIMEOUT`, `DNS_FAILED`, `SEND_FAILED`, and `CANCELED`. One client object handles one request at a time; call `Reset()` to build another request.

### Blocking client

```cpp
EZRadiusSyncClient client(settings);
client.AddAttribute(USER_NAME, "alice");
client.AddAttribute(USER_PASSWORD, "wonderland");

if (client.Send(C_ACCESS_REQUEST) == EZResult::OK &&
    client.GetResponseType() == ACCESS_ACCEPT) {
    // Authentication accepted.
}
```

### Accounting

```cpp
EZRadiusClient accounting(&reactor, settings);
accounting.AddAttribute(ACCT_STATUS_TYPE,
                        (int)RADIUSAcctStatusType::START);
accounting.AddAttribute(USER_NAME, "alice");
accounting.AddAttribute(ACCT_SESSION_ID, "session-1");
accounting.AddAttribute(FRAMED_IP_ADDRESS, "10.0.0.5");

accounting.Send(C_ACCOUNTING_REQUEST,
    [](EZRadiusClient &c, EZResult result) {
        // Check result and Accounting-Response.
    });
```

### MS-CHAPv2 client

```cpp
client.AddMSCHAPv2("alice", "wonderland");
client.Send(C_ACCESS_REQUEST, [](EZRadiusClient &c, EZResult result) {
    if (result == EZResult::OK &&
        c.GetResponseType() == ACCESS_ACCEPT &&
        c.MSCHAPv2ServerVerified()) {
        uint8_t sendKey[16], recvKey[16];
        c.GetMPPEKeys(sendKey, recvKey);
    }
});
```

### Server

```cpp
EZRadiusServer server(&reactor);
server.RASList()->AddRAS("nas-secret", "10.0.0.1");
server.setBindAddress("::"); // Optional dual-stack bind.

server.SeRequestCallback(
    [](RADIUSPacketTypeCodes type, RadiusPacket &request,
       EZRadiusClientIdentify &from, EZRadiusServer *, void *) {
        EZResponse response;

        if (type == ACCESS_REQUEST) {
            response.AddAttribute(SERVICE_TYPE, 2);
            response.AddAttribute(ACCT_INTERIM_INTERVAL, 300);
            response.AddVendorAttribute(14988, 8, "10M/10M");
            response.Send(ACCESS_ACCEPT, &from);
        } else if (type == ACCOUNTING_REQUEST) {
            response.Send(ACCOUNTING_RESPONSE, &from);
        }
    }, nullptr);

server.Start();
```

PAP passwords can be read from `request.getAttribute(USER_PASSWORD).strValue` after decryption with the NAS shared secret. For CHAP, inspect `CHAP_PASSWORD` and `CHAP_CHALLENGE`; when the challenge attribute is absent, the Request Authenticator is used as the challenge.

### MS-CHAPv2 server verification

```cpp
switch (EZMSCHAP::Detect(request)) {
case EZMSCHAP::V2: {
    EZMSCHAPv2Result result;
    if (EZMSCHAP::VerifyV2(request, plainPassword, result)) {
        response.AddMSCHAPv2Result(result);
        response.Send(ACCESS_ACCEPT, &from);
    } else {
        response.AddMSCHAPError(0); // E=691
        response.Send(ACCESS_REJECT, &from);
    }
    break;
}
case EZMSCHAP::V1:
    // EZMSCHAP::VerifyV1(...)
    break;
default:
    break;
}
```

MS-CHAP verification requires the plain-text password or the user's NT hash (`EZMSCHAP::NtPasswordHash`). It cannot be verified against bcrypt or PBKDF2 password hashes. Applications that need MS-CHAP must store an appropriate NT hash or otherwise obtain the plain-text password.

### CoA / Disconnect listener

```cpp
EZClientSettings settings;
settings.Host = "10.0.0.2";
settings.Secret = "secret";
settings.CoAPort = 3799;

EZCoA coa(&reactor, settings);
coa.SetGetRequests(
    [](RADIUSPacketTypeCodes type, RadiusPacket &request,
       EZResponse &response, void *) {
        return type == DISCONNECT_REQUEST
            ? DISCONNECT_ACK
            : COA_NAK;
    }, nullptr);

coa.Start();
```

### CoA / Disconnect sender

```cpp
EZClientSettings nas;
nas.Host = "10.0.0.1";
nas.Secret = "nas-secret";
nas.CoAPort = 3799;

EZRadiusClient kick(&reactor, nas);
kick.AddAttribute(USER_NAME, "alice");
kick.AddAttribute(ACCT_SESSION_ID, "session-1");

kick.Send(C_DISCONNECT_REQUEST,
    [](EZRadiusClient &c, EZResult result) {
        // Check DISCONNECT_ACK / DISCONNECT_NAK and Error-Cause (101).
    });
```

### Status-Server

```cpp
client.Send(C_STATUS_SERVER, ...);
```

The library server can answer Status-Server requests automatically.

### TCP, RadSec (TLS) and DTLS

```cpp
#include "EZTLS.h"

// Server: UDP + TCP + RadSec + DTLS on one reactor
EZRadiusServer server(&reactor);
server.EnableTCP();                                        // TCP on the Authentication / Accounting ports

EZTLSConfig tls;
tls.certChainPem  = EZTLSConfig::readFile("server.pem");
tls.privateKeyPem = EZTLSConfig::readFile("server.key");
tls.caPem         = EZTLSConfig::readFile("clients-ca.pem");   // clients must present a certificate from this CA
std::string err;
if(!server.EnableTLS(tls, 2083, &err)) { /* err */ }       // RadSec
if(!server.EnableDTLS(tls, 2083, &err)) { /* err */ }      // RADIUS over DTLS (UDP 2083)
server.RASList()->AddRAS("unused", "192.0.2.10");          // allowed NAS address (the secret is fixed over TLS / DTLS)
server.Start();

// Client
EZClientSettings s;
s.Host = "radius.example.net";
s.Transport = EZTransport::TLS;                            // or TCP / DTLS
s.TLS.certChainPem  = EZTLSConfig::readFile("nas.pem");
s.TLS.privateKeyPem = EZTLSConfig::readFile("nas.key");
s.TLS.caPem         = EZTLSConfig::readFile("server-ca.pem");
s.TLS.serverName    = "radius.example.net";                // must be in the server certificate subjectAltName
EZRadiusSyncClient client(s);                              // or EZRadiusClient on your reactor
```

Instead of a CA you can pin certificates: `tls.verifyPeer = false; tls.pinnedSHA256 = {"<sha256 hex of the peer certificate>"};`. In the request callback `from.isRadius11()` tells whether the connection speaks RADIUS/1.1; `client.UsedRadius11()` reports it on the client.

An async `EZRadiusClient` keeps its TCP / TLS connection open for the following requests of the same object (`ReuseConnection`, default on). The blocking `EZRadiusSyncClient` runs a private reactor only while `Send()` waits, which closes the sockets afterwards, so it uses a new connection (and TLS handshake) for every `Send()`. DTLS always uses one session per request.

### Vendor-specific attributes

```cpp
// By number (no dictionary needed):
response.AddVendorAttribute(14988, 8, "10M/10M");            // text payload
response.AddVendorAttribute(vendorId, type, data, length);   // binary payload

// By dictionary name (MikroTik, Cisco, Juniper, Huawei and Microsoft are built in):
response.AddVendorAttribute("Mikrotik-Rate-Limit", "10M/10M");
response.AddVendorAttribute("Mikrotik-Total-Limit", 1000000u);
response.AddVendorAttribute("Cisco-AVPair", "shell:priv-lvl=15");
client.AddVendorAttribute("Mikrotik-Group", "gold");          // clients too

// Read: decode every Vendor-Specific attribute of a packet
for(const EZVSAValue &v : EZVendorRegistry::instance().decode(request))
    printf("%s (%s) = %s\n", v.name.c_str(), v.vendorName.c_str(), v.text.c_str());
EZVSAValue v;
if(EZVendorRegistry::instance().find(request, "Mikrotik-Group", v)) { /* v.text, v.number */ }
```

#### Adding a vendor without touching the core

Load a dictionary at start-up (FreeRADIUS dictionary syntax):

```cpp
std::string err;
EZVendorRegistry::instance().loadDictionary(R"(
VENDOR Acme 99999 format=2,2        # 2 byte type, 2 byte length (default is 1,1)
BEGIN-VENDOR Acme
ATTRIBUTE Acme-Level  300 byte
ATTRIBUTE Acme-Mode   301 integer
ATTRIBUTE Acme-Addr6  302 ipv6addr
ATTRIBUTE Acme-Blob   303 octets
ATTRIBUTE Acme-Name   304 string
VALUE Acme-Mode Fast 7
END-VENDOR Acme
)", &err);
// or: EZVendorRegistry::instance().loadDictionaryFile("/etc/ezradius/acme.dict", &err);

response.AddVendorAttribute("Acme-Mode", "Fast");
```

To ship a vendor with the library, add `src/vendors/<vendor>.cpp` with the dictionary text; the CMake glob picks it up. Attribute numbers in the built-in dictionaries follow the vendors' public documentation; verify them against your device's firmware before relying on them.

### EAP (server and peer)

```cpp
#include "EZEAP.h"

EZEAPServer eap;

// EAP-TLS: server certificate + the CA that signed the client certificates
EZEAPTLSConfig tls;
tls.certChainPem  = EZEAPTLSConfig::readFile("server.pem");
tls.privateKeyPem = EZEAPTLSConfig::readFile("server.key");
tls.caPem         = EZEAPTLSConfig::readFile("ca.pem");
std::string err;
if(!eap.enableTLS(tls, &err)) { /* err */ }

// EAP-MD5 (optional, no keys, no mutual authentication)
eap.enableMD5([](const std::string &user, std::string &password) { return lookup(user, password); });

// extra reply attributes on success
eap.setAcceptHook([](EZResponse &r, const EZEAPSessionInfo &info) {
    r.AddVendorAttribute("Mikrotik-Rate-Limit", "10M/10M");     // info.identity, info.peerName (certificate CN)
});

// in the request callback of EZRadiusServer:
if(type == ACCESS_REQUEST && eap.Process(request, from) != EZEAPResult::NOT_EAP)
    return;                                  // the response was sent
// ... otherwise handle PAP / CHAP / MS-CHAP as usual
```

On success the Access-Accept carries `MS-MPPE-Recv-Key` (MSK bytes 0..31) and `MS-MPPE-Send-Key` (MSK bytes 32..63). Methods registered first are offered first; a peer can choose another registered method with EAP-Nak. Own methods: implement `EZEAPMethod` and call `registerMethod()`.

Client side (a NAS or a test tool) with the built-in supplicant:

```cpp
EZEAPPeer peer("bob");
peer.setTLS(clientTlsConfig);                // or peer.setPassword("...") for EAP-MD5
// loop: Send(C_ACCESS_REQUEST) with AddEAPMessage(response) and the State of the last challenge;
//       response = peer.handle(client.GetEAPMessage());   until Access-Accept / Reject
```

See `tests/test_eap.cpp` for the complete conversation loop.

More complete programs are available in [`example/`](example/), including server, asynchronous client, blocking client, and CoA examples.

---

## API overview

| Class | Purpose |
|---|---|
| `EZClientSettings` | Host, shared secret, Authentication / Accounting / CoA ports, timeout, retry count, NAS/RAS addresses, Message-Authenticator options |
| `EZRadiusClient` | Asynchronous client: `AddAttribute`, `AddVendorAttribute`, `AddMSCHAPv1/v2`, `Send`, `Cancel`, `Reset`, response getters, MS-CHAPv2 verification, MPPE key retrieval |
| `EZRadiusSyncClient` | Blocking client wrapper; `Send(type)` returns an `EZResult` |
| `EZRadiusServer` | UDP Authentication and Accounting server; NAS list, request callback, start/stop, bind and port configuration, Message-Authenticator and duplicate-detection settings |
| `EZRASList` / `RASItem` | Allowed NAS addresses and shared secrets |
| `EZRadiusClientIdentify` | Request origin information passed to the server callback and response sender |
| `EZResponse` | Builds and sends RADIUS responses, including attributes, VSA, MS-CHAPv2 success/error, and MPPE keys |
| `EZCoA` | RFC 5176 Dynamic Authorization listener |
| `EZMSCHAP` | MS-CHAPv1/v2 helpers, verification, and MPPE key derivation (requires BoringSSL) |
| `EZCrypto` | BoringSSL wrapper for MD4, MD5, SHA-1, SHA-256, HMAC, DES block operations, random generation, and constant-time comparison |
| `RadiusPacket`, `RadiusAttribute`, `RadiusSecret` | Low-level packet, attribute, and shared-secret functionality |

Supported packet codes include Access-Request / Accept / Reject / Challenge (1, 2, 3, 11), Accounting-Request / Response (4, 5), Status-Server (12), Disconnect-Request / ACK / NAK (40–42), and CoA-Request / ACK / NAK (43–45).

Message-Authenticator behavior is configurable. By default, clients add and sign Message-Authenticator on Access-Requests. The client can require a valid Message-Authenticator in responses. The server verifies it when present, requires it for Status-Server, and can be configured to require it for Access-Requests.

---

## Supported attributes

Attribute numbers are available as enum constants (`USER_NAME`, `NAS_IP_ADDRESS`, and others). Other attribute numbers can be supplied by casting to `RADIUSAttribute`; generic values are handled as string/octet data, except for the documented `NAS-IPv6-Address` special case.

### Attribute dictionary model

Attribute identifiers and built-in constants are defined in the library headers. libEZRadius does **not** currently provide a FreeRADIUS-style runtime dictionary engine:

- It cannot load standard or vendor dictionaries from files or memory buffers.
- It does not provide runtime name-to-number, number-to-name, or symbolic OID lookup.
- It does not provide a general runtime API for registering new typed attribute definitions.
- For attributes without a dedicated built-in definition, the generic path treats values as string/octet data, subject to the packet format and setter validation.
- Vendor-Specific payloads can be added using vendor ID, vendor type, and raw data. Vendor dictionaries and symbolic vendor-attribute lookup remain the application's responsibility.

This is separate from support for the RADIUS Vendor-Specific attribute container (type 26) itself.

### Built-in attributes

The built-in constants cover common attributes from RFC 2865, RFC 2866, RFC 2868, RFC 2869, and RFC 4675, including:

| Attribute number | Name | Constant |
|---:|---|---|
| 1 | User-Name | `USER_NAME` |
| 2 | User-Password | `USER_PASSWORD` |
| 3 | CHAP-Password | `CHAP_PASSWORD` |
| 4 | NAS-IP-Address | `NAS_IP_ADDRESS` |
| 5 | NAS-Port | `NAS_PORT` |
| 6 | Service-Type | `SERVICE_TYPE` |
| 7 | Framed-Protocol | `FRAMED_PROTOCOL` |
| 8 | Framed-IP-Address | `FRAMED_IP_ADDRESS` |
| 9 | Framed-IP-Netmask | `FRAMED_IP_NETMASK` |
| 11 | Filter-Id | `FILTER_ID` |
| 18 | Reply-Message | `REPLY_MESSAGE` |
| 24 | State | `STATE` |
| 25 | Class | `CLASS` |
| 26 | Vendor-Specific | `VENDOR_SPECIFIC` |
| 27 | Session-Timeout | `SESSION_TIMEOUT` |
| 28 | Idle-Timeout | `IDLE_TIMEOUT` |
| 30 | Called-Station-Id | `CALLED_STATION_ID` |
| 31 | Calling-Station-Id | `CALLING_STATION_ID` |
| 32 | NAS-Identifier | `NAS_IDENTIFIER` |
| 33 | Proxy-State | `PROXY_STATE` |
| 40 | Acct-Status-Type | `ACCT_STATUS_TYPE` |
| 41 | Acct-Delay-Time | `ACCT_DELAY_TIME` |
| 42 | Acct-Input-Octets | `ACCT_INPUT_OCTETS` |
| 43 | Acct-Output-Octets | `ACCT_OUTPUT_OCTETS` |
| 44 | Acct-Session-Id | `ACCT_SESSION_ID` |
| 45 | Acct-Authentic | `ACCT_AUTHENTIC` |
| 46 | Acct-Session-Time | `ACCT_SESSION_TIME` |
| 47 | Acct-Input-Packets | `ACCT_INPUT_PACKETS` |
| 48 | Acct-Output-Packets | `ACCT_OUTPUT_PACKETS` |
| 49 | Acct-Terminate-Cause | `ACCT_TERMINATE_CAUSE` |
| 50 | Acct-Multi-Session-Id | `ACCT_MULTI_SESSION_ID` |
| 51 | Acct-Link-Count | `ACCT_LINK_COUNT` |
| 52 | Acct-Input-Gigawords | `ACCT_INPUT_GIGAWORDS` |
| 53 | Acct-Output-Gigawords | `ACCT_OUTPUT_GIGAWORDS` |
| 55 | Event-Timestamp | `EVENT_TIMESTAMP` |
| 56–59 | VLAN / priority attributes | `EGRESS_VLANID`, `INGRESS_FILTERS`, `EGRESS_VLAN_NAME`, `USER_PRIORITY_TABLE` |
| 60 | CHAP-Challenge | `CHAP_CHALLENGE` |
| 61 | NAS-Port-Type | `NAS_PORT_TYPE` |
| 62 | Port-Limit | `PORT_LIMIT` |
| 63 | Login-LAT-Port | `LOGIN_LAT_PORT` |
| 64–67 | Tunnel attributes | `TUNNEL_TYPE`, `TUNNEL_MEDIUM_TYPE`, `TUNNEL_CLIENT_ENDPOINT`, `TUNNEL_SERVER_ENDPOINT` |
| 68 | Acct-Tunnel-Connection | `ACCT_TUNNEL_CONNECTION` |
| 69 | Tunnel-Password | `TUNNEL_PASSWORD` |
| 70–78 | ARAP and related attributes | Corresponding `ARAP_*`, `PASSWORD_RETRY`, `PROMPT`, `CONNECT_INFO`, `CONFIGURATION_TOKEN` constants |
| 79 | EAP-Message | `EAP_MESSAGE` |
| 80 | Message-Authenticator | `MESSAGE_AUTHENTICATOR` |
| 81–83 | Tunnel attributes | `TUNNEL_PRIVATE_GROUP_ID`, `TUNNEL_ASSIGNMENT_ID`, `TUNNEL_PREFERENCE` |
| 84 | ARAP-Challenge-Response | `ARAP_CHALLENGE_RESPONSE` |
| 85 | Acct-Interim-Interval | `ACCT_INTERIM_INTERVAL` |

### Value handling

- **Integer:** 32-bit unsigned (`AddAttribute(type, uint32_t)`).
- **IPv4 address:** dotted text input/output; invalid text is rejected.
- **String/octet:** up to 253 bytes; binary data is supported.
- **PAP password:** encrypted on the wire using the shared secret and Request Authenticator; up to 128 bytes.
- **CHAP:** identifier plus 16-byte response.

Setters validate values and return `false` when an attribute cannot be added in the requested form.

### Special attributes

| Attribute | Handling |
|---|---|
| Message-Authenticator (80) | Generated and verified by the library according to client/server configuration; cannot be added manually through the normal attribute setter |
| Proxy-State (33) | Copied from request to response automatically |
| Acct-Input/Output-Gigawords (52/53) | Typed integers; combine with Acct-*-Octets for traffic counters above 4 GiB |
| Vendor-Specific (26) | Add with `AddVendorAttribute(vendorId, type, ...)`; generic VSA payload access is available through attribute accessors |

### Microsoft vendor attributes (Vendor ID 311, RFC 2548)

With BoringSSL enabled, the library supports the MS-CHAP and MPPE attributes used by its helpers, including MS-CHAP-Response, MS-CHAP-Error, MS-MPPE-Encryption-Policy / Types, MS-CHAP-Challenge, MS-MPPE-Send-Key / Recv-Key, MS-CHAP2-Response, and MS-CHAP2-Success.

---

## Security notes

- **Use Message-Authenticator.** It is enabled by default for client Access-Requests. On servers, enable `setRequireMessageAuthenticator(true)` when the NAS devices are patched and support the requirement.
- **MD5 is part of the RADIUS protocol.** RADIUS over UDP provides authentication/integrity mechanisms based on a shared secret but does not provide strong confidentiality. Use long random shared secrets and keep RADIUS traffic on trusted networks or protected tunnels.
- **Use RadSec or DTLS for confidentiality.** RADIUS over UDP and TCP does not encrypt the conversation. RadSec (TLS) and DTLS authenticate both peers with certificates; keep the CA small, set `serverName`, and prefer TLS 1.3 / RADIUS/1.1. Certificate revocation (CRL / OCSP) is not checked; pin fingerprints or rotate short-lived certificates instead.
- **DTLS cookies:** BoringSSL's DTLS server has no HelloVerifyRequest cookie exchange. The server therefore only starts a handshake for addresses in `RASList()` (`setRadSecIPFilter(true)`, default) and limits partial sessions; do not expose a DTLS listener to the open Internet with `setRadSecIPFilter(false)`.
- **Passwords:** password logging is disabled by default; `RadiusAttribute::setDumpPasswords(true)` is a debugging switch and should be used carefully.
- **EAP-MD5 is weak.** It has no mutual authentication and exports no keys; prefer EAP-TLS and keep EAP-MD5 for trusted links.
- **EAP-TLS** verifies the client certificate against the configured CA (`verifyPeer`); certificate revocation (CRL / OCSP) is not checked.
- **MS-CHAPv1 and MS-CHAPv2 are cryptographically weak.** They rely on legacy DES-based constructions. Enable them only when required by the access protocol.
- **Duplicate detection** stores recent authenticated requests in memory. The default window and cache capacity are implementation settings.
- Unknown senders and invalid packets are dropped without a response.

---

## Testing

The repository includes tests for packet parsing, malformed packets, PAP and authenticator vectors, Message-Authenticator, VSA, loopback client/server behavior, Accounting, CoA, Status-Server, IPv6, timeout/cancel behavior, MS-CHAPv1/v2, MPPE key derivation, the vendor dictionary (built-in and run-time vendors), and EAP-MD5 / EAP-TLS conversations (with fragmentation, Nak, rejected certificates), RADIUS over TCP (framing, connection reuse, invalid lengths), RadSec (mutual TLS, name checks, pinning, untrusted CAs, IP filter), DTLS (handshake, 3 kB packets, refused peers), and RADIUS/1.1 (wire conversion, ALPN negotiation matrix, EAP over RADIUS/1.1, random-input robustness). A libFuzzer target is available for packet-parser fuzzing.

```sh
cmake -S . -B build -DEZRADIUS_SANITIZE=ON
cmake --build build
(cd build && ctest --output-on-failure)
```

To build the libFuzzer target, enable `EZRADIUS_BUILD_FUZZER` and use Clang.

---

## Limitations

- Linux only (epoll through netRector).
- EAP: only EAP-MD5 and EAP-TLS (TLS 1.2). PEAP, EAP-TTLS, EAP-TLS with TLS 1.3, session resumption and CRL / OCSP checks are not implemented.
- TCP / TLS / DTLS: no Status-Server watchdog and no multi-server failover on a connection, no TLS-PSK, no dynamic peer discovery (RFC 7585), no connection pool (one connection per client object), no DTLS session reuse between requests. DTLS is DTLS 1.2 only. RADIUS/1.1 does not convert Tunnel-Password and does not implement Protocol-Error / Original-Packet-Code handling.
- The dictionary covers vendor-specific attributes only; standard attributes (RFC 2865 etc.) use the compiled-in table. Dictionary `tlv` / `struct` / extended types are not supported.
- Extended attributes (RFC 6929), Tunnel-Password decryption, and the IPv6 attribute set (RFC 3162 / RFC 4818) beyond NAS-IPv6-Address are not decoded.
- MS-CHAPv1 supports the NT response only; the LM response is not supported. MPPE keys are derived for MS-CHAPv2.
- One request at a time per client object.
- Server duplicate detection and the NAS list are per-process and in memory.
- The server runs on one reactor. To use multiple cores, run one reactor per thread; `SO_REUSEPORT` multi-reactor binding is not currently wired up.

---

## Project layout and credits

```text
src/        Library sources (packet core, RADIUS attributes, crypto and network layer)
example/    Server, asynchronous client, blocking client, and CoA examples
tests/      Unit, loopback, MS-CHAP, and protocol tests
fuzz/       libFuzzer target
```

The packet core (`RadiusPacket`, `RadiusAttribute`, `RadiusSecret`, and MD5-related code) derives from the *ace-radius-linux* library by Alex Agranov; see the relevant source-file headers for its BSD license notice. Networking is provided by [netRector](https://github.com/crazyfull/netRector), and optional cryptographic functionality uses [BoringSSL](https://boringssl.googlesource.com/boringssl/).

The license of this repository as a whole must be determined and documented separately; third-party notices do not by themselves define the project's license.
