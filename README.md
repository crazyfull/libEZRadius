# libEZRadius

**An asynchronous, single-threaded RADIUS client, server and Dynamic Authorization (CoA / Disconnect) library for C++ on Linux, built on [netRector](https://github.com/crazyfull/netRector).**

libEZRadius provides RADIUS packet encoding and validation, client and server functionality, Authentication and Accounting, RFC 5176 Dynamic Authorization, PAP / CHAP / MS-CHAPv1 / MS-CHAPv2 helpers, and MPPE key handling. Its asynchronous API integrates with a netRector `EpollReactor`; a blocking client wrapper is also available for applications that do not use an event loop.

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
- **Asynchronous network operations:** UDP I/O, reactor timers, and DNS resolution are integrated with netRector.
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

- `EZRadiusServer`: UDP listeners on Authentication and Accounting ports (IPv4, IPv6, or dual stack).
- Per-NAS shared secrets (`EZRASList`) and IPv4/IPv6 NAS addresses; unknown senders are dropped silently.
- Request validation before the application callback: packet structure, Request Authenticator where applicable, and Message-Authenticator according to packet type and configuration.
- Duplicate request detection: a duplicate is not processed twice; the cached response is sent again.
- Automatic Status-Server answers.
- `EZResponse` builds responses with attributes, vendor-specific attributes, MS-CHAPv2 success/error, MPPE keys, Response Authenticator, Message-Authenticator, and Proxy-State copying.

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
| [RFC 3579](https://www.rfc-editor.org/rfc/rfc3579) | RADIUS Support for EAP | Message-Authenticator generation and verification; EAP-Message is carried as an opaque attribute only |
| [RFC 5176](https://www.rfc-editor.org/rfc/rfc5176) | Dynamic Authorization Extensions to RADIUS | Disconnect-Request / ACK / NAK and CoA-Request / ACK / NAK; listener and sender; UDP port 3799 |
| [RFC 5997](https://www.rfc-editor.org/rfc/rfc5997) | Use of Status-Server Packets in RADIUS | Automatic server answer and client health check |
| [RFC 5080](https://www.rfc-editor.org/rfc/rfc5080) | Common RADIUS Implementation Issues and Suggested Fixes | Duplicate request detection, response validation, retransmission behavior, source-port randomization |
| [RFC 4675](https://www.rfc-editor.org/rfc/rfc4675) | RADIUS Attributes for VLAN and Priority Support | Attributes 56–59 |
| [RFC 2433](https://www.rfc-editor.org/rfc/rfc2433) | Microsoft PPP CHAP Extensions | MS-CHAPv1 NT response; legacy LM response is not supported |
| [RFC 2759](https://www.rfc-editor.org/rfc/rfc2759) | Microsoft PPP CHAP Extensions, Version 2 | MS-CHAPv2 verification and generation, authenticator response, mutual authentication |
| [RFC 2548](https://www.rfc-editor.org/rfc/rfc2548) | Microsoft Vendor-specific RADIUS Attributes | MS-CHAP and MPPE vendor attributes, including MPPE key encryption |
| [RFC 3079](https://www.rfc-editor.org/rfc/rfc3079) | Deriving Keys for use with Microsoft Point-to-Point Encryption (MPPE) | MPPE master and session key derivation for MS-CHAPv2 |

The test suite includes vectors from RFC 2202 (HMAC-MD5), RFC 2865 §7.1 (PAP), RFC 2759 §9.2 (MS-CHAPv2), and RFC 3079 §3.5.3 (MPPE master key).

**Transport scope:** libEZRadius currently implements RADIUS over UDP only. It does not implement RADIUS over TCP, RadSec (TLS), or DTLS. Carrying the EAP-Message attribute does not mean that EAP methods or EAP-TLS are implemented.

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
| `EZRADIUS_ENABLE_CRYPTO` | `ON` | Use BoringSSL when found. Without it, PAP, CHAP, Accounting, CoA, and Status-Server remain available; MS-CHAP is compiled out (`EZRADIUS_HAS_CRYPTO` is not defined) |
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

### Vendor-specific attributes

```cpp
response.AddVendorAttribute(14988, 8, "10M/10M"); // Text payload.
response.AddVendorAttribute(vendorId, type, data, length); // Binary payload.

// Read the Vendor-Specific attribute container:
AttrValue value = request.getAttribute(VENDOR_SPECIFIC);
```

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
- **RadSec is not implemented.** If transport confidentiality is required, protect traffic externally (for example with IPsec) until a TLS-based RADIUS transport is available.
- **Passwords:** password logging is disabled by default; `RadiusAttribute::setDumpPasswords(true)` is a debugging switch and should be used carefully.
- **MS-CHAPv1 and MS-CHAPv2 are cryptographically weak.** They rely on legacy DES-based constructions. Enable them only when required by the access protocol.
- **Duplicate detection** stores recent authenticated requests in memory. The default window and cache capacity are implementation settings.
- Unknown senders and invalid packets are dropped without a response.

---

## Testing

The repository includes tests for packet parsing, malformed packets, PAP and authenticator vectors, Message-Authenticator, VSA, loopback client/server behavior, Accounting, CoA, Status-Server, IPv6, timeout/cancel behavior, MS-CHAPv1/v2, and MPPE key derivation. A libFuzzer target is available for packet-parser fuzzing.

```sh
cmake -S . -B build -DEZRADIUS_SANITIZE=ON
cmake --build build
(cd build && ctest --output-on-failure)
```

To build the libFuzzer target, enable `EZRADIUS_BUILD_FUZZER` and use Clang.

---

## Limitations

- Linux only (epoll through netRector).
- EAP methods and EAP-TLS are not implemented. EAP-Message (attribute 79) is carried as an opaque attribute only.
- RADIUS over TCP, RadSec (TLS), and RADIUS over DTLS are not implemented; the current transport is UDP.
- There is no runtime-loadable attribute dictionary or general runtime typed-attribute registration API.
- Extended attributes (RFC 6929), Tunnel-Password decryption, and the IPv6 attribute set (RFC 3162 / RFC 4818) beyond NAS-IPv6-Address are not decoded.
- MS-CHAPv1 supports the NT response only; the LM response is not supported. MPPE keys are derived for MS-CHAPv2.
- One request per client object; there is no connection/request pool.
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
