# libEZRadius

**An asynchronous, single-threaded RADIUS client, server and dynamic-authorization (CoA / Disconnect) library for C++17 on Linux, built on [netRector](https://github.com/crazyfull/netRector).**

libEZRadius implements the RADIUS protocol family end to end: packet encoding and validation, all the authenticators, PAP / CHAP / MS-CHAPv1 / MS-CHAPv2, accounting, Status-Server, RFC 5176 Dynamic Authorization (as listener *and* as sender), vendor-specific attributes, IPv4 and IPv6. Everything runs on a netRector epoll reactor: **no threads, no mutexes, no blocking calls** inside the library. A blocking client wrapper is provided for programs that do not run a reactor.

---

## Table of contents

1. [Features](#features)
2. [Supported standards](#supported-standards)
3. [Architecture and threading model](#architecture-and-threading-model)
4. [Building](#building)
5. [Quick start](#quick-start)
6. [API overview](#api-overview)
7. [Supported attributes](#supported-attributes)
8. [Security notes](#security-notes)
9. [Testing](#testing)
10. [Limitations](#limitations)
11. [Project layout and credits](#project-layout-and-credits)

---

## Features

**Client**
- Asynchronous `EZRadiusClient`: `Send()` returns immediately, the result is delivered by callback from the reactor.
- Blocking `EZRadiusSyncClient`: `Send()` returns when the answer (or the timeout) is there. Same engine, driven synchronously; usable from scripts, CLI tools and worker threads.
- Request types: Access-Request, Accounting-Request, Status-Server, Disconnect-Request, CoA-Request.
- Timeouts and retransmissions on reactor timers (same ID and authenticator on retransmission, as required by the RFC).
- Asynchronous DNS for the server name (A, then AAAA fallback); IPv4 and IPv6 literals.
- A fresh UDP socket with a random source port per request.
- Responses are accepted only if source address and port, packet code, Identifier and Response Authenticator (and Message-Authenticator when present or required) are valid.
- PAP, CHAP, MS-CHAPv1 and MS-CHAPv2 login helpers; MS-CHAPv2 mutual authentication check and MPPE key decryption on the client side.
- Message-Authenticator on every Access-Request by default (mitigates BlastRADIUS, CVE-2024-3596).

**Server**
- `EZRadiusServer`: UDP listeners on the authentication and accounting ports (IPv4, IPv6 or dual stack).
- Per-NAS shared secrets (`EZRASList`), IPv4 and IPv6 addresses; unknown senders are dropped silently.
- Every request is validated before your callback runs: well-formed packet, Request Authenticator (accounting / CoA / Disconnect), Message-Authenticator (mandatory for Status-Server, optional or required for Access-Request).
- Retransmission detection (RFC 5080): a duplicate request is not processed twice; the stored answer is sent again.
- Automatic Status-Server answers (RFC 5997).
- `EZResponse` builds responses: attributes, vendor-specific attributes, MS-CHAPv2 success / error, MPPE keys, automatic Response Authenticator, Message-Authenticator and Proxy-State copying (RFC 2865 §5.33).

**Dynamic authorization (RFC 5176)**
- `EZCoA`: listener for Disconnect-Request and CoA-Request from the RADIUS server (replies ACK / NAK).
- `EZRadiusClient` with `C_DISCONNECT_REQUEST` / `C_COA_REQUEST`: send them to a NAS (for example to kick a user from a MikroTik router).

**Protocol core**
- Hardened packet parser: every length is validated before use; malformed packets are rejected (fuzzed under ASan/UBSan).
- Constant-time authenticator comparison, secure random Identifier and Request Authenticator.
- PAP passwords up to 128 bytes, secrets up to 256 bytes; the 4096-byte packet limit is enforced.
- Passwords are never printed by `dump()` unless explicitly enabled; temporary buffers are wiped.

---

## Supported standards

| Standard | Title | What libEZRadius implements |
|---|---|---|
| [RFC 2865](https://www.rfc-editor.org/rfc/rfc2865) | Remote Authentication Dial In User Service (RADIUS) | Packet format, Access-Request / Accept / Reject / Challenge, Request and Response Authenticator, User-Password (PAP) encryption, CHAP, attributes 1–39 and 60–63, Vendor-Specific (26), Proxy-State copying, UDP ports 1812 |
| [RFC 2866](https://www.rfc-editor.org/rfc/rfc2866) | RADIUS Accounting | Accounting-Request / Response, Accounting Request Authenticator, attributes 40–51, port 1813 |
| [RFC 2867](https://www.rfc-editor.org/rfc/rfc2867) | RADIUS Accounting Modifications for Tunnel Protocol Support | Acct-Tunnel-Connection (68) as a string attribute |
| [RFC 2868](https://www.rfc-editor.org/rfc/rfc2868) | RADIUS Attributes for Tunnel Protocol Support | Tunnel attributes 64–67, 69, 81–83 (as typed attributes; Tunnel-Password is not decrypted) |
| [RFC 2869](https://www.rfc-editor.org/rfc/rfc2869) | RADIUS Extensions | Acct-Input/Output-Gigawords (52/53), Event-Timestamp (55), Acct-Interim-Interval (85), ARAP, Connect-Info, Password-Retry, Prompt, Configuration-Token |
| [RFC 3579](https://www.rfc-editor.org/rfc/rfc3579) | RADIUS Support for EAP | **Message-Authenticator (HMAC-MD5)** generation and verification; EAP-Message (79) is carried as an opaque attribute |
| [RFC 5176](https://www.rfc-editor.org/rfc/rfc5176) | Dynamic Authorization Extensions to RADIUS | Disconnect-Request / ACK / NAK and CoA-Request / ACK / NAK, listener (`EZCoA`) and sender, port 3799 |
| [RFC 5997](https://www.rfc-editor.org/rfc/rfc5997) | Use of Status-Server Packets in RADIUS | Automatic server answer, client health check (`C_STATUS_SERVER`) |
| [RFC 5080](https://www.rfc-editor.org/rfc/rfc5080) | Common RADIUS Implementation Issues and Suggested Fixes | Duplicate request detection, response validation, retransmission with unchanged ID / authenticator, source port randomization |
| [RFC 4675](https://www.rfc-editor.org/rfc/rfc4675) | RADIUS Attributes for VLAN and Priority Support | Attributes 56–59 |
| [RFC 2433](https://www.rfc-editor.org/rfc/rfc2433) | Microsoft PPP CHAP Extensions | MS-CHAPv1 (NT response; the legacy LM response is not supported) |
| [RFC 2759](https://www.rfc-editor.org/rfc/rfc2759) | Microsoft PPP CHAP Extensions, Version 2 | MS-CHAPv2 verification and generation, authenticator response (`S=`), mutual authentication |
| [RFC 2548](https://www.rfc-editor.org/rfc/rfc2548) | Microsoft Vendor-specific RADIUS Attributes | MS-CHAP-Challenge / Response / CHAP2-Response / CHAP2-Success / Error, MS-MPPE-Send/Recv-Key and Encryption-Policy/Types, key encryption with the shared secret |
| [RFC 3079](https://www.rfc-editor.org/rfc/rfc3079) | Deriving Keys for use with Microsoft PPE (MPPE) | MPPE master and session key derivation for MS-CHAPv2 |
| [CVE-2024-3596](https://www.kb.cert.org/vuls/id/456537) | BlastRADIUS | Message-Authenticator is added to Access-Requests by default and can be required on both sides |

Test vectors from RFC 2202 (HMAC-MD5), RFC 2865 §7.1 (PAP), RFC 2759 §9.2 (MS-CHAPv2) and RFC 3079 §3.5.3 (MPPE master key) are part of the test suite.

---

## Architecture and threading model

```
 your program
     │
     ├── EZRadiusClient ──┐        callbacks, timers, DNS, sockets
     ├── EZRadiusServer ──┼──►  netrector::EpollReactor  (one thread)
     └── EZCoA ───────────┘
 EZRadiusSyncClient ──► private EpollReactor, run on the calling thread while Send() waits
```

- Every object lives on one reactor and **must be used from that reactor's thread**. From another thread, use `reactor.post([]{ ... })`.
- The library itself never starts a thread, takes a lock or blocks. A slow database lookup inside a request callback would block the reactor: use an asynchronous database client, or hand the work to a worker thread and send the response from the reactor with `reactor.post()`.
- Objects must be destroyed before their reactor (or before `run()` returns). Destroying a client with a request in flight cancels it silently.
- `EZRadiusSyncClient` owns its reactor; independent objects can be used from different threads at the same time.

---

## Building

Requirements: Linux, a C++17 compiler, CMake ≥ 3.14, [netRector](https://github.com/crazyfull/netRector). BoringSSL is optional (needed for MS-CHAP; later for EAP / EAP-TLS).

```sh
git clone https://github.com/crazyfull/netRector third_party/netRector      # or -DEZRADIUS_NETRECTOR_DIR=<path> or -DEZRADIUS_FETCH_NETRECTOR=ON

# optional: BoringSSL (MS-CHAP). netRector ships a helper that builds it:
#   third_party/netRector/scripts/build_boringssl.sh /opt/bssl

cmake -S . -B build -G Ninja -DNETRECTOR_ENABLE_TLS=OFF -DBORINGSSL_DIR=/opt/bssl
cmake --build build
(cd build && ctest --output-on-failure)
```

| CMake option | Default | Meaning |
|---|---|---|
| `EZRADIUS_NETRECTOR_DIR` | – | netRector source directory (built together with the library) |
| `EZRADIUS_FETCH_NETRECTOR` | OFF | Download netRector with FetchContent when it is not found |
| `BORINGSSL_DIR` | – | BoringSSL prefix (`include/` and `lib/libcrypto.a`); also read from the environment |
| `EZRADIUS_ENABLE_CRYPTO` | ON | Use BoringSSL when found. Without it PAP, CHAP, accounting, CoA, Status-Server all work; MS-CHAP is compiled out (`EZRADIUS_HAS_CRYPTO` is not defined) |
| `EZRADIUS_BUILD_EXAMPLES` | ON | Build `example/` |
| `EZRADIUS_BUILD_TESTS` | ON | Build `tests/` |
| `EZRADIUS_BUILD_FUZZER` | OFF | Build the libFuzzer target (needs clang) |
| `EZRADIUS_SANITIZE` | OFF | AddressSanitizer + UndefinedBehaviorSanitizer |

Use it from your own project:

```cmake
add_subdirectory(libezradius)
target_link_libraries(myapp PRIVATE EZRadius)      # also brings netRector and (if enabled) BoringSSL
```

---

## Quick start

All snippets assume `netrector::EpollReactor reactor(0, 1024);` and a `std::atomic<bool> stop` for `reactor.run(stop)`.

### Asynchronous client (PAP)

```cpp
EZClientSettings s;
s.Host = "radius.example.com";    // IPv4, IPv6 or a name (resolved asynchronously)
s.Secret = "shared-secret";
s.TimeOut = 1500;                 // ms per attempt
s.RetryCount = 3;                 // attempts

EZRadiusClient c(&reactor, s);
c.AddAttribute(USER_NAME, "alice");
c.AddAttribute(USER_PASSWORD, "wonderland");
c.AddAttribute(NAS_IP_ADDRESS, "192.168.1.1");
c.Send(C_ACCESS_REQUEST, [](EZRadiusClient &c, EZResult r) {
    if (r == EZResult::OK && c.GetResponseType() == ACCESS_ACCEPT)
        printf("welcome, %s\n", c.GetAttribute(REPLY_MESSAGE).strValue.c_str());
});
reactor.run(stop);
```

`EZResult`: `OK`, `TIMEOUT`, `DNS_FAILED`, `SEND_FAILED`, `CANCELED`. One object = one request; call `Reset()` to build another.

### Blocking client

```cpp
EZRadiusSyncClient c(settings);               // no reactor needed
c.AddAttribute(USER_NAME, "alice");
c.AddAttribute(USER_PASSWORD, "wonderland");
if (c.Send(C_ACCESS_REQUEST) == EZResult::OK && c.GetResponseType() == ACCESS_ACCEPT) { /* ... */ }
```

### Accounting

```cpp
EZRadiusClient acct(&reactor, s);
acct.AddAttribute(ACCT_STATUS_TYPE, (int)RADIUSAcctStatusType::START);
acct.AddAttribute(USER_NAME, "alice");
acct.AddAttribute(ACCT_SESSION_ID, "session-1");
acct.AddAttribute(FRAMED_IP_ADDRESS, "10.0.0.5");
acct.Send(C_ACCOUNTING_REQUEST, [](EZRadiusClient &c, EZResult r) { /* ACCOUNTING_RESPONSE */ });
```

### MS-CHAPv2 login (client)

```cpp
c.AddMSCHAPv2("alice", "wonderland");          // adds User-Name, MS-CHAP-Challenge, MS-CHAP2-Response
c.Send(C_ACCESS_REQUEST, [](EZRadiusClient &c, EZResult r) {
    if (r == EZResult::OK && c.GetResponseType() == ACCESS_ACCEPT && c.MSCHAPv2ServerVerified()) {
        uint8_t sendKey[16], recvKey[16];
        c.GetMPPEKeys(sendKey, recvKey);       // decrypted MS-MPPE-Send/Recv-Key
    }
});
```

### Server

```cpp
EZRadiusServer server(&reactor);
server.RASList()->AddRAS("nas-secret", "10.0.0.1");        // IPv4 or IPv6, one secret per NAS
server.setBindAddress("::");                                // optional: dual stack
server.SeRequestCallback([](RADIUSPacketTypeCodes type, RadiusPacket &req,
                            EZRadiusClientIdentify &from, EZRadiusServer *, void *) {
    EZResponse resp;
    if (type == ACCESS_REQUEST) {
        resp.AddAttribute(SERVICE_TYPE, 2);                           // Framed
        resp.AddAttribute(ACCT_INTERIM_INTERVAL, 300);
        resp.AddVendorAttribute(14988, 8, "10M/10M");                 // MikroTik Rate-Limit
        resp.Send(ACCESS_ACCEPT, &from);
    } else if (type == ACCOUNTING_REQUEST) {
        resp.Send(ACCOUNTING_RESPONSE, &from);
    }
}, nullptr);
server.Start();
```

PAP passwords are available with `req.getAttribute(USER_PASSWORD).strValue` (decrypted with the NAS secret). CHAP: `req.getAttribute(CHAP_PASSWORD)` (identifier in `intValue`, response in `strValue`) and `CHAP_CHALLENGE` (or the Request Authenticator when absent); the check is `MD5(id + password + challenge)`.

### MS-CHAPv2 verification (server)

```cpp
switch (EZMSCHAP::Detect(req)) {
case EZMSCHAP::V2: {
    EZMSCHAPv2Result r;
    if (EZMSCHAP::VerifyV2(req, plainPassword, r)) {        // or VerifyV2WithNtHash(req, ntHash, r)
        resp.AddMSCHAPv2Result(r);                           // MS-CHAP2-Success + MS-MPPE-Send/Recv-Key
        resp.Send(ACCESS_ACCEPT, &from);
    } else {
        resp.AddMSCHAPError(0);                              // E=691
        resp.Send(ACCESS_REJECT, &from);
    }
    break; }
case EZMSCHAP::V1: /* EZMSCHAP::VerifyV1(...) */ break;
default: break;
}
```

MS-CHAP needs the plain-text password or the NT hash (`EZMSCHAP::NtPasswordHash`) of the user: it cannot be verified against bcrypt / PBKDF2 hashes. Store the NT hash if you need MS-CHAP (PPTP / L2TP / SSTP on MikroTik).

### CoA / Disconnect: listener

```cpp
EZClientSettings cs; cs.Host = "10.0.0.2"; cs.Secret = "secret"; cs.CoAPort = 3799;   // Host / RAS_IP: allowed senders
EZCoA coa(&reactor, cs);
coa.SetGetRequests([](RADIUSPacketTypeCodes type, RadiusPacket &req, EZResponse &resp, void *) {
    // type is DISCONNECT_REQUEST or COA_REQUEST
    return type == DISCONNECT_REQUEST ? DISCONNECT_ACK : COA_NAK;
}, nullptr);
coa.Start();
```

### CoA / Disconnect: sender (kick a user)

```cpp
EZClientSettings ns; ns.Host = "10.0.0.1"; ns.Secret = "nas-secret"; ns.CoAPort = 3799;   // Host = the NAS
EZRadiusClient kick(&reactor, ns);
kick.AddAttribute(USER_NAME, "alice");
kick.AddAttribute(ACCT_SESSION_ID, "session-1");
kick.Send(C_DISCONNECT_REQUEST, [](EZRadiusClient &c, EZResult r) {
    // c.GetResponseType() == DISCONNECT_ACK or DISCONNECT_NAK (Error-Cause is attribute 101)
});
```

### Status-Server

```cpp
client.Send(C_STATUS_SERVER, ...);     // health check; the library server answers it automatically
```

### Vendor-specific attributes

```cpp
resp.AddVendorAttribute(14988, 8, "10M/10M");                     // text
resp.AddVendorAttribute(vendorId, type, data, length);            // binary
// reading: AttrValue v = req.getAttribute(VENDOR_SPECIFIC);       // intValue = Vendor-Id, strValue = sub-attributes
```

More complete programs are in [`example/`](example/): `server.cpp`, `client.cpp`, `client_sync.cpp`, `coa.cpp`.

---

## API overview

| Class | Purpose |
|---|---|
| `EZClientSettings` | Host, Secret, ports (`AuthenticationPort` 1812, `AccountingPort` 1813, `CoAPort` 3799), `TimeOut` (ms), `RetryCount`, `NAS_IP`, `RAS_IP`, `UseMessageAuthenticator`, `RequireMessageAuthenticator` |
| `EZRadiusClient` | Asynchronous client. `AddAttribute`, `AddVendorAttribute`, `AddMSCHAPv1/v2`, `Send(type, callback)`, `Cancel`, `Reset`, response getters, `MSCHAPv2ServerVerified`, `GetMPPEKeys` |
| `EZRadiusSyncClient` | Blocking client with the same request-building API; `Send(type)` returns an `EZResult` |
| `EZRadiusServer` | UDP server. `RASList()`, `SeRequestCallback`, `Start/Stop`, `setAuthenticationPort/AccountingPort/BindAddress`, `setRequireMessageAuthenticator`, `setDuplicateWindow`, `setAutoStatusServer` |
| `EZRASList` / `RASItem` | Allowed NAS addresses (IPv4 / IPv6) and their secrets |
| `EZRadiusClientIdentify` | Who sent the request: peer address, socket, ID, authenticator, RAS; passed to the callback and to `EZResponse::Send` |
| `EZResponse` | Builds and sends a response (attributes, VSA, MS-CHAPv2 success/error, MPPE keys) |
| `EZCoA` | RFC 5176 listener |
| `EZMSCHAP` | MS-CHAPv1/v2 primitives, verification, MPPE keys (needs BoringSSL) |
| `EZCrypto` | BoringSSL wrapper: MD4, MD5, SHA-1, SHA-256, HMAC, DES block, random, constant-time compare |
| `RadiusPacket`, `RadiusAttribute`, `RadiusSecret` | Low-level packet / attribute / secret classes (parser, authenticators, Message-Authenticator) |

Packet codes handled: Access-Request/Accept/Reject/Challenge (1,2,3,11), Accounting-Request/Response (4,5), Status-Server (12), Disconnect-Request/ACK/NAK (40–42), CoA-Request/ACK/NAK (43–45). Other codes are parsed and passed to your callback as received.

`EZClientSettings` Message-Authenticator behavior: `UseMessageAuthenticator` (default on) adds and signs it in every Access-Request; `RequireMessageAuthenticator` drops Access responses without a valid one. The server verifies it whenever present, requires it for Status-Server, and for Access-Request when `setRequireMessageAuthenticator(true)`.

---

## Supported attributes

Attribute numbers are available as enum constants (`USER_NAME`, `NAS_IP_ADDRESS`, ...). Any other attribute number can be used by casting (`(RADIUSAttribute)95`); it is then treated as a string / octets attribute, except NAS-IPv6-Address (95), which `AddAttribute` encodes from an IPv6 literal.

| # | Name | Constant | Value type | Defined in |
|---|---|---|---|---|
| 1 | User-Name | `USER_NAME` | string / octets | RFC 2865 |
| 2 | User-Password | `USER_PASSWORD` | password (PAP, encrypted) | RFC 2865 |
| 3 | CHAP-Password | `CHAP_PASSWORD` | CHAP (id + 16 byte response) | RFC 2865 |
| 4 | NAS-IP-Address | `NAS_IP_ADDRESS` | IPv4 address | RFC 2865 |
| 5 | NAS-Port | `NAS_PORT` | integer (32 bit) | RFC 2865 |
| 6 | Service-Type | `SERVICE_TYPE` | integer (32 bit) | RFC 2865 |
| 7 | Framed-Protocol | `FRAMED_PROTOCOL` | integer (32 bit) | RFC 2865 |
| 8 | Framed-IP-Address | `FRAMED_IP_ADDRESS` | IPv4 address | RFC 2865 |
| 9 | Framed-IP-Netmask | `FRAMED_IP_NETMASK` | IPv4 address | RFC 2865 |
| 10 | Framed-Routing | `FRAMED_ROUTING` | integer (32 bit) | RFC 2865 |
| 11 | Filter-Id | `FILTER_ID` | string / octets | RFC 2865 |
| 12 | Framed-MTU | `FRAMED_MTU` | integer (32 bit) | RFC 2865 |
| 13 | Framed-Compression | `FRAMED_COMPRESSION` | integer (32 bit) | RFC 2865 |
| 14 | Login-IP-Host | `LOGIN_IP_HOST` | IPv4 address | RFC 2865 |
| 15 | Login-Service | `LOGIN_SERVICE` | integer (32 bit) | RFC 2865 |
| 16 | Login-TCP-Port | `LOGIN_TCP_PORT` | integer (32 bit) | RFC 2865 |
| 17 | Old-Password (reserved) | `OLD_PASSWORD` | string / octets | RFC 2865 |
| 18 | Reply-Message | `REPLY_MESSAGE` | string / octets | RFC 2865 |
| 19 | Callback-Number | `CALLBACK_NUMBER` | string / octets | RFC 2865 |
| 20 | Callback-Id | `CALLBACK_ID` | string / octets | RFC 2865 |
| 22 | Framed-Route | `FRAMED_ROUTE` | string / octets | RFC 2865 |
| 23 | Framed-IPX-Network | `FRAMED_IPX_NETWORK` | integer (32 bit) | RFC 2865 |
| 24 | State | `STATE` | string / octets | RFC 2865 |
| 25 | Class | `CLASS` | string / octets | RFC 2865 |
| 26 | Vendor-Specific | `VENDOR_SPECIFIC` | vendor-specific | RFC 2865 |
| 27 | Session-Timeout | `SESSION_TIMEOUT` | integer (32 bit) | RFC 2865 |
| 28 | Idle-Timeout | `IDLE_TIMEOUT` | integer (32 bit) | RFC 2865 |
| 29 | Termination-Action | `TERMINATION_ACTION` | integer (32 bit) | RFC 2865 |
| 30 | Called-Station-Id | `CALLED_STATION_ID` | string / octets | RFC 2865 |
| 31 | Calling-Station-Id | `CALLING_STATION_ID` | string / octets | RFC 2865 |
| 32 | NAS-Identifier | `NAS_IDENTIFIER` | string / octets | RFC 2865 |
| 33 | Proxy-State | `PROXY_STATE` | string / octets | RFC 2865 |
| 34 | Login-LAT-Service | `LOGIN_LAT_SERVICE` | string / octets | RFC 2865 |
| 35 | Login-LAT-Node | `LOGIN_LAT_NODE` | string / octets | RFC 2865 |
| 36 | Login-LAT-Group | `LOGIN_LAT_GROUP` | string / octets | RFC 2865 |
| 37 | Framed-AppleTalk-Link | `FRAMED_APPLETALK_LINK` | integer (32 bit) | RFC 2865 |
| 38 | Framed-AppleTalk-Network | `FRAMED_APPLETALK_NETWORK` | integer (32 bit) | RFC 2865 |
| 39 | Framed-AppleTalk-Zone | `FRAMED_APPLETALK_ZONE` | string / octets | RFC 2865 |
| 40 | Acct-Status-Type | `ACCT_STATUS_TYPE` | integer (32 bit) | RFC 2866 |
| 41 | Acct-Delay-Time | `ACCT_DELAY_TIME` | integer (32 bit) | RFC 2866 |
| 42 | Acct-Input-Octets | `ACCT_INPUT_OCTETS` | integer (32 bit) | RFC 2866 |
| 43 | Acct-Output-Octets | `ACCT_OUTPUT_OCTETS` | integer (32 bit) | RFC 2866 |
| 44 | Acct-Session-Id | `ACCT_SESSION_ID` | string / octets | RFC 2866 |
| 45 | Acct-Authentic | `ACCT_AUTHENTIC` | integer (32 bit) | RFC 2866 |
| 46 | Acct-Session-Time | `ACCT_SESSION_TIME` | integer (32 bit) | RFC 2866 |
| 47 | Acct-Input-Packets | `ACCT_INPUT_PACKETS` | integer (32 bit) | RFC 2866 |
| 48 | Acct-Output-Packets | `ACCT_OUTPUT_PACKETS` | integer (32 bit) | RFC 2866 |
| 49 | Acct-Terminate-Cause | `ACCT_TERMINATE_CAUSE` | integer (32 bit) | RFC 2866 |
| 50 | Acct-Multi-Session-Id | `ACCT_MULTI_SESSION_ID` | string / octets | RFC 2866 |
| 51 | Acct-Link-Count | `ACCT_LINK_COUNT` | integer (32 bit) | RFC 2866 |
| 52 | Acct-Input-Gigawords | `ACCT_INPUT_GIGAWORDS` | integer (32 bit) | RFC 2869 |
| 53 | Acct-Output-Gigawords | `ACCT_OUTPUT_GIGAWORDS` | integer (32 bit) | RFC 2869 |
| 55 | Event-Timestamp | `EVENT_TIMESTAMP` | integer (32 bit) | RFC 2869 |
| 56 | Egress-VLANID | `EGRESS_VLANID` | integer (32 bit) | RFC 4675 |
| 57 | Ingress-Filters | `INGRESS_FILTERS` | integer (32 bit) | RFC 4675 |
| 58 | Egress-VLAN-Name | `EGRESS_VLAN_NAME` | string / octets | RFC 4675 |
| 59 | User-Priority-Table | `USER_PRIORITY_TABLE` | string / octets | RFC 4675 |
| 60 | CHAP-Challenge | `CHAP_CHALLENGE` | string / octets | RFC 2865 |
| 61 | NAS-Port-Type | `NAS_PORT_TYPE` | integer (32 bit) | RFC 2865 |
| 62 | Port-Limit | `PORT_LIMIT` | integer (32 bit) | RFC 2865 |
| 63 | Login-LAT-Port | `LOGIN_LAT_PORT` | string / octets | RFC 2865 |
| 64 | Tunnel-Type | `TUNNEL_TYPE` | integer (32 bit) | RFC 2868 |
| 65 | Tunnel-Medium-Type | `TUNNEL_MEDIUM_TYPE` | integer (32 bit) | RFC 2868 |
| 66 | Tunnel-Client-Endpoint | `TUNNEL_CLIENT_ENDPOINT` | string / octets | RFC 2868 |
| 67 | Tunnel-Server-Endpoint | `TUNNEL_SERVER_ENDPOINT` | string / octets | RFC 2868 |
| 68 | Acct-Tunnel-Connection | `ACCT_TUNNEL_CONNECTION` | string / octets | RFC 2867 |
| 69 | Tunnel-Password | `TUNNEL_PASSWORD` | string / octets | RFC 2868 |
| 70 | ARAP-Password | `ARAP_PASSWORD` | string / octets | RFC 2869 |
| 71 | ARAP-Features | `ARAP_FEATURES` | string / octets | RFC 2869 |
| 72 | ARAP-Zone-Access | `ARAP_ZONE_ACCESS` | integer (32 bit) | RFC 2869 |
| 73 | ARAP-Security | `ARAP_SECURITY` | integer (32 bit) | RFC 2869 |
| 74 | ARAP-Security-Data | `ARAP_SECURITY_DATA` | string / octets | RFC 2869 |
| 75 | Password-Retry | `PASSWORD_RETRY` | integer (32 bit) | RFC 2869 |
| 76 | Prompt | `PROMPT` | integer (32 bit) | RFC 2869 |
| 77 | Connect-Info | `CONNECT_INFO` | string / octets | RFC 2869 |
| 78 | Configuration-Token | `CONFIGURATION_TOKEN` | string / octets | RFC 2869 |
| 79 | EAP-Message | `EAP_MESSAGE` | string / octets | RFC 3579 |
| 80 | Message-Authenticator | `MESSAGE_AUTHENTICATOR` | octets (16), added and signed automatically | RFC 3579 |
| 81 | Tunnel-Private-Group-Id | `TUNNEL_PRIVATE_GROUP_ID` | string / octets | RFC 2868 |
| 82 | Tunnel-Assignment-Id | `TUNNEL_ASSIGNMENT_ID` | string / octets | RFC 2868 |
| 83 | Tunnel-Preference | `TUNNEL_PREFERENCE` | integer (32 bit) | RFC 2868 |
| 84 | ARAP-Challenge-Response | `ARAP_CHALLENGE_RESPONSE` | string / octets | RFC 2869 |
| 85 | Acct-Interim-Interval | `ACCT_INTERIM_INTERVAL` | integer (32 bit) | RFC 2869 |

**Type handling.** *integer*: 32-bit unsigned (`AddAttribute(type, uint32_t)`). *IPv4 address*: dotted text in, dotted text out (`inet_pton` / `inet_ntop`, invalid text is rejected). *string / octets*: up to 253 bytes, binary safe. *password*: PAP, encrypted on the wire with the shared secret and the Request Authenticator (up to 128 bytes, padded to 16). *CHAP*: identifier plus 16-byte response. Setters validate every value and return `false` instead of adding a broken attribute.

**Special attributes**

| Attribute | Handling |
|---|---|
| Message-Authenticator (80) | Added and signed by the library (client: `UseMessageAuthenticator`; server responses: when the request had one); cannot be added manually |
| Proxy-State (33) | Copied from request to response automatically |
| Acct-Input/Output-Gigawords (52/53) | Typed integers; combine with Acct-*-Octets for traffic above 4 GiB |
| Vendor-Specific (26) | `AddVendorAttribute(vendorId, type, ...)`; reading through `getAttribute(VENDOR_SPECIFIC)` / `getAttributes(...)` |

**Microsoft vendor attributes (vendor 311, RFC 2548), with BoringSSL**

| # | Name | Handling |
|---|---|---|
| 1 | MS-CHAP-Response | MS-CHAPv1; generated by `AddMSCHAPv1`, verified by `EZMSCHAP::VerifyV1` |
| 2 | MS-CHAP-Error | `EZResponse::AddMSCHAPError` |
| 7 / 8 | MS-MPPE-Encryption-Policy / -Types | `EZResponse::AddMPPEKeys(..., policy, types)` |
| 10 | MS-CHAP-Domain | passed through (domain prefix of the user name is ignored for the challenge hash) |
| 11 | MS-CHAP-Challenge | generated by `AddMSCHAPv1/v2`; the Request Authenticator is used when it is absent |
| 16 / 17 | MS-MPPE-Send-Key / -Recv-Key | derived (RFC 3079) and encrypted (RFC 2548) by `EZResponse`; decrypted by `EZRadiusClient::GetMPPEKeys` |
| 25 | MS-CHAP2-Response | generated by `AddMSCHAPv2`, verified by `EZMSCHAP::VerifyV2` |
| 26 | MS-CHAP2-Success | `EZResponse::AddMSCHAP2Success` / `AddMSCHAPv2Result`; checked by `MSCHAPv2ServerVerified` |

---

## Security notes

- **Use Message-Authenticator.** It is on by default for clients. Enable `setRequireMessageAuthenticator(true)` on servers whose NAS devices are patched against BlastRADIUS.
- **MD5 is part of the protocol.** RADIUS over UDP provides authentication and integrity with a shared secret, but weak confidentiality. Use long random shared secrets (up to 256 bytes are accepted) and keep RADIUS traffic on trusted networks or inside IPsec / TLS tunnels (RadSec is not implemented).
- **Passwords:** the library never logs passwords (`RadiusAttribute::setDumpPasswords(true)` is a debugging switch) and wipes temporary copies.
- **MS-CHAPv1 and MS-CHAPv2 are cryptographically weak** (DES based, equivalent to a single DES key search). Enable them only for protocols that require them (PPTP / SSTP / some L2TP setups).
- **Duplicate detection** keeps recent requests in memory (default window 30 s, at most 8192 entries) and only for requests that already passed authentication.
- Unknown senders and invalid packets are dropped without any answer.

---

## Testing

| Test | What it covers |
|---|---|
| `test_packet` | Parser limits and malformed packets, PAP round trip, RFC 2202 / RFC 2865 test vectors, authenticators, Message-Authenticator, VSA |
| `test_loopback` | Server, clients and CoA on one reactor: PAP, CHAP, accounting, Status-Server, Proxy-State, duplicate requests, timeouts, cancel, wrong secret, unknown NAS, Disconnect / CoA sender and listener, IPv6 (skipped when the host has no IPv6 loopback) |
| `test_mschap` | RFC 2759 / RFC 3079 vectors, MS-CHAPv1 / v2 end to end, MPPE key round trip, blocking client (success, reject, timeout, DNS, `Reset()`) |
| `fuzz_packet` | Mutation fuzzing of the packet parser |
| `fuzz/fuzz_libfuzzer.cpp` | libFuzzer target (`-DEZRADIUS_BUILD_FUZZER=ON`, clang) |

```sh
cmake -S . -B build -DEZRADIUS_SANITIZE=ON ... && cmake --build build && (cd build && ctest --output-on-failure)
```

---

## Limitations

- Linux only (epoll, via netRector).
- EAP (EAP-Message is carried, but no EAP methods) and EAP-TLS are not implemented yet; `EZCrypto` and the BoringSSL integration are the foundation for them.
- RadSec (RADIUS over TLS, RFC 6614) and RADIUS over TCP are not implemented.
- MS-CHAPv1 supports the NT response only (no LM response); MPPE keys are derived for MS-CHAPv2 only.
- Extended attributes (RFC 6929), Tunnel-Password decryption and the IPv6 attribute set (RFC 3162 / 4818) beyond NAS-IPv6-Address are not decoded.
- One request per client object; there is no connection / request pool.
- Server duplicate detection and the RAS list are per process and in memory.
- The server runs on one reactor; to use several cores, run one reactor per thread (bind with `SO_REUSEPORT` is not wired up yet).

---

## Project layout and credits

```
src/        library sources (Radius*.cpp packet core, EZ*.cpp network layer, EZMSCHAP / EZCrypto)
example/    server, async client, blocking client, CoA listener
tests/      unit, loopback, MS-CHAP and fuzz tests
fuzz/       libFuzzer target
```

The packet core (`RadiusPacket`, `RadiusAttribute`, `RadiusSecret`, MD5) derives from the *ace-radius-linux* library by Alex Agranov (BSD license, see the file headers), rewritten and hardened here. Networking is provided by [netRector](https://github.com/crazyfull/netRector); cryptography by [BoringSSL](https://boringssl.googlesource.com/boringssl/).
