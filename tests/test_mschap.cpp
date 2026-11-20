// MS-CHAPv1/v2 (RFC 2759, RFC 2433, RFC 3079, RFC 2548) and the blocking client.
#include "EZRadiusClient.h"
#include "EZRadiusSyncClient.h"
#include "EZRadiusServer.h"
#include "EZRadiusClientIdentify.h"
#include "EZResponse.h"
#include "clsEpollReactor.h"
#include <atomic>
#include <cstdio>
#include <cstring>
#include <thread>

#ifdef EZRADIUS_HAS_CRYPTO
#include "EZCrypto.h"
#include "EZMSCHAP.h"
#endif

static int g_fail = 0;
#define CHECK(c) do { if(!(c)){ printf("FAIL line %d: %s\n", __LINE__, #c); g_fail++; } } while(0)

static const int AUTH_PORT = 18220, ACCT_PORT = 18230;
static const char *SECRET = "ms-secret";

#ifdef EZRADIUS_HAS_CRYPTO
static std::string unhexs(const char *h)
{
    std::string out;
    for(size_t i = 0; h[i] && h[i+1]; i += 2){
        unsigned v; sscanf(h + i, "%2x", &v); out.push_back((char)v);
    }
    return out;
}
static std::string hexs(const void *d, size_t n) { return EZCrypto::ToHex(d, n, true); }

static void test_vectors()
{
    // RFC 2759 section 9.2
    const std::string auth = unhexs("5B5D7C7D7B3F2F3E3C2C602132262628");
    const std::string peer = unhexs("21402324255E262A28295F2B3A337C7E");
    uint8_t ch[8], h[16], hh[16], nt[24];

    EZMSCHAP::ChallengeHash((const uint8_t*)peer.data(), (const uint8_t*)auth.data(), "User", ch);
    CHECK(hexs(ch, 8) == "D02E4386BCE91226");
    EZMSCHAP::NtPasswordHash("clientPass", h);
    CHECK(hexs(h, 16) == "44EBBA8D5312B8D611474411F56989AE");
    EZMSCHAP::HashNtPasswordHash(h, hh);
    CHECK(hexs(hh, 16) == "41C00C584BD2D91C4017A2A12FA59F3F");
    EZMSCHAP::GenerateNTResponseV2((const uint8_t*)auth.data(), (const uint8_t*)peer.data(), "User", h, nt);
    CHECK(hexs(nt, 24) == "82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF");
    CHECK(EZMSCHAP::AuthenticatorResponseV2(h, nt, (const uint8_t*)peer.data(), (const uint8_t*)auth.data(), "User")
          == "S=407A5589115FD0D6209F510FE9C04566932CDA56");
    // domain prefix is ignored
    EZMSCHAP::ChallengeHash((const uint8_t*)peer.data(), (const uint8_t*)auth.data(), "DOMAIN\\User", ch);
    CHECK(hexs(ch, 8) == "D02E4386BCE91226");

    // RFC 3079 section 3.5.3: master key for the same password / NT response
    uint8_t master[16], s[16], r[16];
    EZMSCHAP::MppeMasterKey(hh, nt, master);
    CHECK(hexs(master, 16) == "FDECE3717A8C838CB388E527AE3CDD31");
    EZMSCHAP::MppeSessionKeys(master, s, r);
    CHECK(memcmp(s, r, 16) != 0);

    // RFC 2548 key encryption round trip
    const uint8_t ra[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    std::string enc = EZMSCHAP::EncodeMppeKey(s, "secret", 6, ra);
    CHECK(enc.size() == 34 && ((uint8_t)enc[0] & 0x80));
    uint8_t back[16];
    CHECK(EZMSCHAP::DecodeMppeKey(enc, "secret", 6, ra, back) && memcmp(back, s, 16) == 0);
    CHECK(!EZMSCHAP::DecodeMppeKey(enc, "other!", 6, ra, back) || memcmp(back, s, 16) != 0);

    // UTF-8 password -> UTF-16LE (non ASCII)
    EZMSCHAP::NtPasswordHash("pa\xC3\xA9", h);       // "paé"
    uint8_t ref[16];
    const char utf16[] = {'p',0,'a',0,(char)0xE9,0};
    EZCrypto::MD4(utf16, 6, ref);
    CHECK(memcmp(h, ref, 16) == 0);

    // well known hashes
    uint8_t d[16];
    EZCrypto::MD4("abc", 3, d);
    CHECK(hexs(d, 16) == "A448017AAF21D8525FC10AE87AA6729D");
    uint8_t sha[20];
    EZCrypto::SHA1("abc", 3, sha);
    CHECK(hexs(sha, 20) == "A9993E364706816ABA3E25717850C26C9CD0D89D");
}

static EZMSCHAPv2Result g_lastV2;

static void onRequest(RADIUSPacketTypeCodes type, RadiusPacket &req, EZRadiusClientIdentify &from, EZRadiusServer *, void *)
{
    if(type != ACCESS_REQUEST)
        return;
    EZResponse resp;
    bool ok = false;
    switch(EZMSCHAP::Detect(req)){
    case EZMSCHAP::V2: {
        EZMSCHAPv2Result r;
        ok = req.getAttribute(USER_NAME).strValue == "User" && EZMSCHAP::VerifyV2(req, "clientPass", r);
        if(ok){ g_lastV2 = r; resp.AddMSCHAPv2Result(r); }
        else resp.AddMSCHAPError(0);
        break; }
    case EZMSCHAP::V1:
        ok = EZMSCHAP::VerifyV1(req, "clientPass");
        if(!ok) resp.AddMSCHAPError(0);
        break;
    default:
        break;
    }
    resp.Send(ok ? ACCESS_ACCEPT : ACCESS_REJECT, &from);
}

static EZClientSettings settings()
{
    EZClientSettings s;
    s.Host = "127.0.0.1"; s.Secret = SECRET; s.AuthenticationPort = AUTH_PORT; s.AccountingPort = ACCT_PORT;
    s.TimeOut = 400; s.RetryCount = 2;
    return s;
}

static void test_blocking_and_mschap()
{
    // the server runs on its own thread (test only); the clients block in this thread
    std::atomic<bool> stop{false};
    std::atomic<int> started{0};
    std::thread server([&]{
        netrector::EpollReactor reactor(0, 64);
        EZRadiusServer srv(&reactor);
        srv.setAuthenticationPort(AUTH_PORT);
        srv.setAccountingPort(ACCT_PORT);
        srv.SeRequestCallback(onRequest, nullptr);
        srv.RASList()->AddRAS(SECRET, "127.0.0.1");
        started = srv.Start() ? 1 : -1;
        reactor.run(stop);
    });
    while(started == 0) std::this_thread::sleep_for(std::chrono::milliseconds(5));
    CHECK(started == 1);

    // MS-CHAPv2 ok
    {
        EZRadiusSyncClient c(settings());
        CHECK(c.AddMSCHAPv2("User", "clientPass"));
        CHECK(c.Send(C_ACCESS_REQUEST) == EZResult::OK);
        CHECK(c.GetResponseType() == ACCESS_ACCEPT);
        CHECK(c.MSCHAPv2ServerVerified());
        uint8_t sk[16], rk[16];
        CHECK(c.GetMPPEKeys(sk, rk));
        CHECK(memcmp(sk, g_lastV2.mppeSendKey, 16) == 0 && memcmp(rk, g_lastV2.mppeRecvKey, 16) == 0);
    }
    // MS-CHAPv2 wrong password
    {
        EZRadiusSyncClient c(settings());
        CHECK(c.AddMSCHAPv2("User", "bad"));
        CHECK(c.Send(C_ACCESS_REQUEST) == EZResult::OK);
        CHECK(c.GetResponseType() == ACCESS_REJECT);
        CHECK(!c.MSCHAPv2ServerVerified());
    }
    // MS-CHAPv1 ok / bad
    {
        EZRadiusSyncClient c(settings());
        CHECK(c.AddMSCHAPv1("User", "clientPass"));
        CHECK(c.Send(C_ACCESS_REQUEST) == EZResult::OK && c.GetResponseType() == ACCESS_ACCEPT);
        EZRadiusSyncClient c2(settings());
        CHECK(c2.AddMSCHAPv1("User", "nope"));
        CHECK(c2.Send(C_ACCESS_REQUEST) == EZResult::OK && c2.GetResponseType() == ACCESS_REJECT);
    }
    // the same sync client object, two requests in a row (Reset in between)
    {
        EZRadiusSyncClient c(settings());
        c.AddMSCHAPv2("User", "clientPass");
        CHECK(c.Send(C_ACCESS_REQUEST) == EZResult::OK);
        c.Reset();
        c.AddMSCHAPv2("User", "bad");
        CHECK(c.Send(C_ACCESS_REQUEST) == EZResult::OK && c.GetResponseType() == ACCESS_REJECT);
    }
    // blocking timeout: nobody listens on that port
    {
        EZClientSettings s = settings(); s.AuthenticationPort = 18999; s.TimeOut = 100; s.RetryCount = 3;
        EZRadiusSyncClient c(s);
        c.AddAttribute(USER_NAME, "x");
        auto t0 = std::chrono::steady_clock::now();
        CHECK(c.Send(C_ACCESS_REQUEST) == EZResult::TIMEOUT);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        CHECK(ms >= 280 && ms < 900);
    }
    // hostname through the async DNS inside the blocking call
    {
        EZClientSettings s = settings(); s.Host = "localhost";
        EZRadiusSyncClient c(s);
        c.AddMSCHAPv2("User", "clientPass");
        CHECK(c.Send(C_ACCESS_REQUEST) == EZResult::OK && c.GetResponseType() == ACCESS_ACCEPT);
    }
    // PAP / accounting through the blocking client
    {
        EZRadiusSyncClient c(settings());
        c.AddAttribute(ACCT_STATUS_TYPE, 1); c.AddAttribute(USER_NAME, "User");
        EZResult r = c.Send(C_ACCOUNTING_REQUEST);
        CHECK(r == EZResult::TIMEOUT);          // the test server does not answer accounting
    }
    stop = true;
    server.join();
}
#endif

int main()
{
#ifdef EZRADIUS_HAS_CRYPTO
    test_vectors();
    test_blocking_and_mschap();
    printf(g_fail ? "FAILED (%d)\n" : "all mschap / blocking tests passed\n", g_fail);
    return g_fail ? 1 : 0;
#else
    printf("built without BoringSSL: skipped\n");
    return 0;
#endif
}
