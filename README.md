# libEZRadius 2.0

Ketabkhane-ye RADIUS (client / server / CoA-Disconnect) ruye **netRector**: tamam-e shabake
async va non-blocking, ru-ye yek reactor, **bedoon thread, mutex ya call-e blocking** (Wrench hazf shod).

Protocol: RFC 2865 / 2866 / 3579 (Message-Authenticator, BlastRADIUS) / 5176 (CoA, Disconnect), VSA (masalan MikroTik 14988).

## Build

```
git clone https://github.com/crazyfull/netRector third_party/netRector      # ya -DEZRADIUS_NETRECTOR_DIR=<path>
cmake -S . -B build -G Ninja -DNETRECTOR_ENABLE_TLS=OFF      # -DEZRADIUS_SANITIZE=ON baraye ASan/UBSan
cmake --build build && (cd build && ctest --output-on-failure)
```

Dar proje-ye khodet: `add_subdirectory(libezradius)` va `target_link_libraries(app PRIVATE EZRadius)`.

## Client (async)

```cpp
netrector::EpollReactor reactor(0, 1024);
EZClientSettings s; s.Host = "radius.example.com"; s.Secret = "..."; s.TimeOut = 1500; s.RetryCount = 3;

EZRadiusClient c(&reactor, s);               // Host: IPv4 ya esm (DNS async)
c.AddAttribute(USER_NAME, "user");
c.AddAttribute(USER_PASSWORD, "pass");       // PAP; CHAP_PASSWORD baraye CHAP
c.Send(C_ACCESS_REQUEST, [](EZRadiusClient &c, EZResult r){
    if(r == EZResult::OK && c.GetResponseType() == ACCESS_ACCEPT) { /* ... */ }
});
reactor.run(stop);
```

- `Send()` fori bar migarde; natije (OK / TIMEOUT / DNS_FAILED / SEND_FAILED / CANCELED) ba callback az reactor miad.
- Retry/timeout ba timer-e reactor; har darkhast socket va source port-e tasadofi-ye khodesh ro dare.
- Response faghat ba ID + Response Authenticator (+ Message-Authenticator) motabar ghabul mishe.
- Har object = yek darkhast; baraye darkhast-e jadid `Reset()`.

## Server

```cpp
EZRadiusServer server(&reactor);
server.RASList()->AddRAS("secret", "10.0.0.1");
server.SeRequestCallback(onRequest, nullptr);
server.Start();
```

Packet-e na-motabar, RAS-e na-shenakhte, Request/Message-Authenticator-e ghalat ghabl az callback drop mishe.
Javab: `EZResponse r; r.AddAttribute(...); r.AddVendorAttribute(14988, 8, "10M/10M"); r.Send(ACCESS_ACCEPT, &from);`

## CoA / Disconnect

`EZCoA coa(&reactor, settings); coa.SetGetRequests(cb, nullptr); coa.Start();`  (Host / RAS_IP = addressha-ye mojaz)

## Ghavaed

- Hame chiz faghat az thread-e reactor; az thread-e dige ba `reactor.post()`.
- Object haye client/server/CoA bayad ghabl az reactor (ya ghabl az payan-e `run()`) nabud beshan.
- Password dar log chap nemishe (`RadiusAttribute::setDumpPasswords(true)` baraye debug).

Test ha: `test_packet` (unit), `test_loopback` (server + client + CoA ru-ye yek reactor), `fuzz_packet`.
