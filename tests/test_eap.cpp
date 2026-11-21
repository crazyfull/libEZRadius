// EAP: packets, MPPE keys of any length, EAP-MD5, EAP-Nak, EAP-TLS (with fragmentation) through a real
// RADIUS server / client conversation on the loopback interface.
#include "EZEAP.h"
#include "EZRadiusSyncClient.h"
#include "EZRadiusServer.h"
#include "EZRadiusClientIdentify.h"
#include "EZMSCHAP.h"
#include "EZResponse.h"
#include "clsEpollReactor.h"
#include <atomic>
#include <cstdio>
#include <cstring>
#include <thread>

#ifdef EZRADIUS_HAS_TLS
#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#endif

static int g_fail = 0;
#define CHECK(c) do { if(!(c)){ printf("FAIL line %d: %s\n", __LINE__, #c); g_fail++; } } while(0)

static void test_packets_and_keys()
{
    ezeap::Packet p;
    p.code = ezeap::CODE_REQUEST; p.id = 7; p.type = ezeap::TYPE_MD5; p.data = "abc";
    std::string b = p.serialize();
    CHECK(b == std::string("\x01\x07\x00\x08\x04" "abc", 8));
    ezeap::Packet q;
    CHECK(ezeap::Packet::parse(b, q) && q.code == 1 && q.id == 7 && q.type == 4 && q.data == "abc");
    CHECK(ezeap::Packet::parse(b + "pad", q) && q.data == "abc");              // trailing padding is ignored
    CHECK(!ezeap::Packet::parse(b.substr(0, 7), q));                            // length larger than the data
    CHECK(!ezeap::Packet::parse(std::string("\x03\x01\x00\x05\x00", 5), q));   // Success with data
    CHECK(!ezeap::Packet::parse(std::string("\x09\x01\x00\x04", 4), q));       // unknown code
    ezeap::Packet s;
    s.code = ezeap::CODE_SUCCESS; s.id = 9;
    CHECK(s.serialize() == std::string("\x03\x09\x00\x04", 4));

    // EAP-Message fragmentation: 600 bytes -> 253 + 253 + 94
    RadiusSecret sec("s");
    RadiusPacket rp(1);
    rp.setSecret(&sec);
    std::string big(600, 'x');
    for(int i = 0; i < 600; i++) big[i] = (char)i;
    CHECK(ezeap::addMessage(rp, big));
    RadiusPacket rq;
    CHECK(rq.setRawData((const char*)rp.getRawData(), rp.getLength()));
    CHECK(rq.getAttributes((RADIUSAttribute)ezeap::ATTR_EAP_MESSAGE).size() == 3);
    CHECK(ezeap::extractMessage(rq) == big);

    // MPPE keys: 16 and 32 bytes
    uint8_t ra[16], key[32];
    for(int i = 0; i < 16; i++) ra[i] = (uint8_t)(i * 3);
    for(int i = 0; i < 32; i++) key[i] = (uint8_t)(0xA0 + i);
    std::string enc = EZMSCHAP::EncodeMppeKey(key, 32, "secret", 6, ra), dec;
    CHECK(enc.size() == 2 + 48);
    CHECK(EZMSCHAP::DecodeMppeKey(enc, "secret", 6, ra, dec) && dec == std::string((const char*)key, 32));
    CHECK(!EZMSCHAP::DecodeMppeKey(enc, "other!", 6, ra, dec) || dec != std::string((const char*)key, 32));
    enc = EZMSCHAP::EncodeMppeKey(key, 16, "secret", 6, ra);
    CHECK(enc.size() == 34);
    uint8_t k16[16];
    CHECK(EZMSCHAP::DecodeMppeKey(enc, "secret", 6, ra, k16) && memcmp(k16, key, 16) == 0);
    CHECK(EZMSCHAP::EncodeMppeKey(key, 0, "s", 1, ra).empty());
    CHECK(!EZMSCHAP::DecodeMppeKey(std::string(17, 'x'), "s", 1, ra, dec));
}

#ifdef EZRADIUS_HAS_TLS
// ---- certificates generated in memory ---------------------------------------------------------
struct Cert
{
    std::string certPem, keyPem; X509 *x509 = nullptr; EVP_PKEY *pkey = nullptr;
    Cert() = default;
    Cert(const Cert&) = delete;
    Cert(Cert &&o) noexcept : certPem(std::move(o.certPem)), keyPem(std::move(o.keyPem)), x509(o.x509), pkey(o.pkey) { o.x509 = nullptr; o.pkey = nullptr; }
    ~Cert() { if(x509) X509_free(x509); if(pkey) EVP_PKEY_free(pkey); }
};

static Cert makeCert(const char *cn, Cert *issuer)
{
    Cert c;
    EC_KEY *ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY_generate_key(ec);
    c.pkey = EVP_PKEY_new();
    EVP_PKEY_assign_EC_KEY(c.pkey, ec);
    c.x509 = X509_new();
    ASN1_INTEGER_set(X509_get_serialNumber(c.x509), (long)rand());
    X509_gmtime_adj(X509_getm_notBefore(c.x509), -60);
    X509_gmtime_adj(X509_getm_notAfter(c.x509), 3600);
    X509_set_pubkey(c.x509, c.pkey);
    X509_NAME *name = X509_get_subject_name(c.x509);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)cn, -1, -1, 0);
    X509_set_issuer_name(c.x509, issuer ? X509_get_subject_name(issuer->x509) : name);
    X509_sign(c.x509, issuer ? issuer->pkey : c.pkey, EVP_sha256());

    BIO *b = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(b, c.x509);
    char *d; long n = BIO_get_mem_data(b, &d);
    c.certPem.assign(d, (size_t)n);
    BIO_free(b);
    b = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(b, c.pkey, nullptr, nullptr, 0, nullptr, nullptr);
    n = BIO_get_mem_data(b, &d);
    c.keyPem.assign(d, (size_t)n);
    BIO_free(b);
    return c;
}
#endif

// ---- server ---------------------------------------------------------------------------------
static EZEAPServer *g_eap = nullptr;
static std::atomic<int> g_accepts{0}, g_rejects{0};

static void onRequest(RADIUSPacketTypeCodes type, RadiusPacket &req, EZRadiusClientIdentify &from, EZRadiusServer *, void *)
{
    if(type == ACCESS_REQUEST)
        g_eap->Process(req, from);
}

struct Outcome
{
    RADIUSPacketTypeCodes type = (RADIUSPacketTypeCodes)0;
    std::string sendKey, recvKey;
    int rounds = 0;
    EZEAPPeer::State peerState = EZEAPPeer::RUNNING;
    std::string peerMsk;
};

static Outcome converse(uint16_t port, EZEAPPeer &peer, const std::string &identity)
{
    Outcome o;
    EZClientSettings s;
    s.Host = "127.0.0.1"; s.Secret = "eap-secret"; s.AuthenticationPort = port; s.TimeOut = 500; s.RetryCount = 2;
    EZRadiusSyncClient c(s);

    ezeap::Packet first;
    first.code = ezeap::CODE_RESPONSE; first.id = 1; first.type = ezeap::TYPE_IDENTITY; first.data = identity;
    std::string eapOut = first.serialize(), state;

    for(int round = 0; round < 80; round++){
        c.Reset();
        c.AddAttribute(USER_NAME, identity.c_str());
        if(!state.empty())
            c.AddRawAttribute((RADIUSAttribute)ezeap::ATTR_STATE, state.data(), state.size());
        if(!c.AddEAPMessage(eapOut) || c.Send(C_ACCESS_REQUEST) != EZResult::OK)
            break;
        o.rounds = round + 1;
        o.type = c.GetResponseType();
        const std::string eapIn = c.GetEAPMessage();
        if(o.type == ACCESS_CHALLENGE){
            state = c.GetState();
            eapOut = peer.handle(eapIn);
            if(eapOut.empty())
                break;
            continue;
        }
        peer.handle(eapIn);
        if(o.type == ACCESS_ACCEPT)
            c.GetMPPEKeys(o.sendKey, o.recvKey);
        break;
    }
    o.peerState = peer.state();
    o.peerMsk = peer.msk();
    return o;
}

int main()
{
    test_packets_and_keys();

    EZEAPServer eap;
    g_eap = &eap;
    eap.enableMD5([](const std::string &id, std::string &pw) {
        if(id == "alice"){ pw = "wonderland"; return true; }
        return false;
    });
    eap.setRejectHook([](const std::string &, uint8_t) { g_rejects++; });
    eap.setAcceptHook([](EZResponse &r, const EZEAPSessionInfo &) {
        g_accepts++;
        r.AddVendorAttribute("Mikrotik-Rate-Limit", "1M/1M");
    });

#ifdef EZRADIUS_HAS_TLS
    Cert ca = makeCert("Test CA", nullptr);
    Cert srvCert = makeCert("radius.test", &ca);
    Cert cliCert = makeCert("bob", &ca);
    Cert rogueCa = makeCert("Rogue CA", nullptr);
    Cert rogue = makeCert("mallory", &rogueCa);

    EZEAPTLSConfig sc;
    sc.certChainPem = srvCert.certPem; sc.privateKeyPem = srvCert.keyPem; sc.caPem = ca.certPem;
    sc.fragmentSize = 200;                   // forces fragmentation of the certificate flight
    std::string err;
    CHECK(eap.enableTLS(sc, &err));
    CHECK(err.empty());
    EZEAPTLSConfig bad;
    CHECK(!EZEAPTLSContext::create(bad, true, &err) && !err.empty());      // server without certificate
#endif

    std::atomic<bool> stop{false};
    std::atomic<int> started{0};
    std::thread server([&]{
        netrector::EpollReactor reactor(0, 16);
        EZRadiusServer srv(&reactor);
        srv.setAuthenticationPort(18420);
        srv.setAccountingPort(18430);
        srv.SeRequestCallback(onRequest, nullptr);
        srv.RASList()->AddRAS("eap-secret", "127.0.0.1");
        started = srv.Start() ? 1 : -1;
        reactor.run(stop);
    });
    while(started == 0) std::this_thread::sleep_for(std::chrono::milliseconds(5));
    CHECK(started == 1);

#ifdef EZRADIUS_HAS_TLS
    // TLS is registered first, so a peer that only knows a password answers EAP-Nak and falls back to MD5
    {
        EZEAPPeer peer("alice");
        peer.setPassword("wonderland");
        Outcome o = converse(18420, peer, "alice");
        CHECK(o.type == ACCESS_ACCEPT);
        CHECK(o.peerState == EZEAPPeer::SUCCESS);
        CHECK(o.sendKey.empty());                       // EAP-MD5 exports no keys
    }
#endif
    {
        EZEAPPeer peer("alice");
        peer.setPassword("wrong");
        Outcome o = converse(18420, peer, "alice");
        CHECK(o.type == ACCESS_REJECT);
        CHECK(o.peerState == EZEAPPeer::FAILURE);
    }
    {
        EZEAPPeer peer("nobody");
        peer.setPassword("x");
        Outcome o = converse(18420, peer, "nobody");
        CHECK(o.type == ACCESS_REJECT);
    }

#ifdef EZRADIUS_HAS_TLS
    {
        EZEAPTLSConfig cc;
        cc.certChainPem = cliCert.certPem; cc.privateKeyPem = cliCert.keyPem; cc.caPem = ca.certPem;
        cc.fragmentSize = 300;
        EZEAPPeer peer("bob");
        CHECK(peer.setTLS(cc, &err));
        Outcome o = converse(18420, peer, "bob");
        CHECK(o.type == ACCESS_ACCEPT);
        CHECK(o.peerState == EZEAPPeer::SUCCESS);
        CHECK(o.rounds > 4);                            // the handshake needed several fragments
        CHECK(o.peerMsk.size() == 64);
        // MS-MPPE-Recv-Key = MSK[0..32), MS-MPPE-Send-Key = MSK[32..64) of the Access-Accept; same MSK on both sides
        CHECK(o.recvKey == o.peerMsk.substr(0, 32));
        CHECK(o.sendKey == o.peerMsk.substr(32, 32));
        printf("EAP-TLS finished in %d RADIUS round trips\n", o.rounds);
    }
    {
        // client certificate of an unknown CA is rejected
        EZEAPTLSConfig cc;
        cc.certChainPem = rogue.certPem; cc.privateKeyPem = rogue.keyPem; cc.caPem = ca.certPem;
        EZEAPPeer peer("mallory");
        CHECK(peer.setTLS(cc, &err));
        Outcome o = converse(18420, peer, "mallory");
        CHECK(o.type == ACCESS_REJECT);
        CHECK(o.peerState != EZEAPPeer::SUCCESS);
    }
    {
        // no client certificate at all
        EZEAPTLSConfig cc;
        cc.caPem = ca.certPem;
        EZEAPPeer peer("nocert");
        CHECK(peer.setTLS(cc, &err));
        Outcome o = converse(18420, peer, "nocert");
        CHECK(o.type == ACCESS_REJECT);
    }
#endif

    CHECK(g_accepts >= 1);
    CHECK(g_rejects >= 2);
    CHECK(eap.activeSessions() == 0);
    stop = true;
    server.join();
    printf(g_fail ? "FAILED (%d)\n" : "all EAP tests passed\n", g_fail);
    return g_fail ? 1 : 0;
}
