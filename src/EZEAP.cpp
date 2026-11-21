#include "EZEAP.h"
#ifdef EZRADIUS_HAS_CRYPTO

#include "EZCrypto.h"
#include "EZResponse.h"
#include "EZRadiusClientIdentify.h"
#include "EZAddr.h"
#include "EZAttrUtil.h"
#include <cstring>
#include <fstream>
#include <sstream>

#ifdef EZRADIUS_HAS_TLS
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#endif

// =============================================================================================
// packets
namespace ezeap {

std::string Packet::serialize() const
{
    const size_t len = 4 + (hasType() ? 1 + data.size() : 0);
    std::string s;
    s.push_back((char)code);
    s.push_back((char)id);
    s.push_back((char)(len >> 8));
    s.push_back((char)len);
    if(hasType()){
        s.push_back((char)type);
        s.append(data);
    }
    return s;
}

bool Packet::parse(const std::string &b, Packet &out)
{
    if(b.size() < 4)
        return false;
    const size_t len = ((uint8_t)b[2] << 8) | (uint8_t)b[3];
    // the length field may be smaller than the received data (padding), never larger
    if(len < 4 || len > b.size())
        return false;
    out = Packet();
    out.code = (uint8_t)b[0];
    out.id = (uint8_t)b[1];
    if(out.code < CODE_REQUEST || out.code > CODE_FAILURE)
        return false;
    if(out.hasType()){
        if(len < 5)
            return false;
        out.type = (uint8_t)b[4];
        out.data.assign(b, 5, len - 5);
    }else if(len != 4){
        return false;           // Success / Failure carry no data
    }
    return true;
}

std::string extractMessage(RadiusPacket &pck)
{
    std::string all;
    for(const AttrValue &v : pck.getAttributes((RADIUSAttribute)ATTR_EAP_MESSAGE))
        all.append(v.strValue);
    return all;
}

bool addMessage(RadiusPacket &pck, const std::string &eap)
{
    if(eap.empty() || eap.size() > 65535)
        return false;
    for(size_t pos = 0; pos < eap.size(); pos += D_ATTR_MAX_VALUE_LENGTH){
        const size_t n = std::min<size_t>(D_ATTR_MAX_VALUE_LENGTH, eap.size() - pos);
        if(!ezutil::addOctets(pck, ATTR_EAP_MESSAGE, eap.data() + pos, n))
            return false;
    }
    return true;
}

} // namespace ezeap

// =============================================================================================
// EAP-MD5 (RFC 3748 section 5.4)
namespace {

std::string md5Response(uint8_t id, const std::string &password, const std::string &challenge)
{
    std::string in;
    in.push_back((char)id);
    in.append(password);
    in.append(challenge);
    uint8_t h[16];
    EZCrypto::MD5(in.data(), in.size(), h);
    return std::string((const char*)h, 16);
}

class MD5Method : public EZEAPMethod
{
    std::string m_identity;
    EZEAPServer::PasswordLookup m_lookup;
    std::string m_challenge;
    uint8_t m_id = 0;
public:
    MD5Method(const std::string &identity, EZEAPServer::PasswordLookup lookup) : m_identity(identity), m_lookup(std::move(lookup)) {}
    uint8_t type() const override { return ezeap::TYPE_MD5; }

    EZEAPStep start(uint8_t requestId) override
    {
        EZEAPStep st;
        m_id = requestId;
        uint8_t ch[16];
        if(!EZCrypto::Random(ch, 16))
            return st;
        m_challenge.assign((const char*)ch, 16);
        st.status = EZEAPStep::CONTINUE;
        st.data.push_back(16);
        st.data.append(m_challenge);
        return st;
    }

    EZEAPStep handle(uint8_t responseId, const std::string &td) override
    {
        EZEAPStep st;
        // Value-Size (1) + Value (16) [+ Name]
        if(responseId != m_id || td.size() < 17 || (uint8_t)td[0] != 16 || m_challenge.empty())
            return st;
        std::string password;
        if(!m_lookup || !m_lookup(m_identity, password))
            return st;
        const std::string expected = md5Response(m_id, password, m_challenge);
        EZCrypto::Wipe(&password[0], password.size());
        m_challenge.clear();                // one try per challenge
        if(EZCrypto::Equal(expected.data(), td.data() + 1, 16))
            st.status = EZEAPStep::SUCCESS;
        return st;
    }
};

} // namespace

// =============================================================================================
// EAP-TLS (RFC 5216)
#ifdef EZRADIUS_HAS_TLS

struct ezeap_tls_ctx { SSL_CTX *ctx = nullptr; };

std::string EZEAPTLSConfig::readFile(const std::string &path)
{
    std::ifstream f(path, std::ios::binary);
    if(!f)
        return std::string();
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

EZEAPTLSContext::~EZEAPTLSContext()
{
    if(m_impl){
        if(m_impl->ctx)
            SSL_CTX_free(m_impl->ctx);
        delete m_impl;
    }
}

namespace {

struct BioDeleter { void operator()(BIO *b) const { BIO_free(b); } };
using BioPtr = std::unique_ptr<BIO, BioDeleter>;

BioPtr pemBio(const std::string &pem)
{
    return BioPtr(BIO_new_mem_buf(pem.data(), (int)pem.size()));
}

enum : uint8_t { TLS_FLAG_LENGTH = 0x80, TLS_FLAG_MORE = 0x40, TLS_FLAG_START = 0x20 };
const size_t TLS_MAX_MESSAGE = 1024 * 1024;           // sanity limit of one reassembled TLS flight

} // namespace

std::shared_ptr<EZEAPTLSContext> EZEAPTLSContext::create(const EZEAPTLSConfig &cfg, bool server, std::string *error)
{
    auto fail = [&](const char *msg) -> std::shared_ptr<EZEAPTLSContext> {
        if(error)
            *error = msg;
        return nullptr;
    };

    if(server && (cfg.certChainPem.empty() || cfg.privateKeyPem.empty()))
        return fail("a server needs certChainPem and privateKeyPem");
    if(cfg.certChainPem.empty() != cfg.privateKeyPem.empty())
        return fail("certChainPem and privateKeyPem must be set together");
    if(cfg.verifyPeer && cfg.caPem.empty())
        return fail("verifyPeer needs caPem (trusted CA certificates)");

    std::shared_ptr<EZEAPTLSContext> c(new EZEAPTLSContext());
    c->m_impl = new ezeap_tls_ctx();
    c->m_fragmentSize = cfg.fragmentSize < 64 ? 64 : (cfg.fragmentSize > 16000 ? 16000 : cfg.fragmentSize);
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    if(!ctx)
        return fail("SSL_CTX_new failed");
    c->m_impl->ctx = ctx;

    // RFC 5216 + RFC 9190: TLS 1.2 here (TLS 1.3 keys / framing are not implemented)
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);

    if(!cfg.certChainPem.empty()){
        BioPtr cb = pemBio(cfg.certChainPem);
        X509 *leaf = cb ? PEM_read_bio_X509(cb.get(), nullptr, nullptr, nullptr) : nullptr;
        if(!leaf)
            return fail("can not parse the certificate");
        const int ok = SSL_CTX_use_certificate(ctx, leaf);
        X509_free(leaf);
        if(ok != 1)
            return fail("can not use the certificate");
        while(X509 *extra = PEM_read_bio_X509(cb.get(), nullptr, nullptr, nullptr)){
            if(SSL_CTX_add_extra_chain_cert(ctx, extra) != 1){          // takes ownership on success
                X509_free(extra);
                return fail("can not add a chain certificate");
            }
        }
        BioPtr kb = pemBio(cfg.privateKeyPem);
        EVP_PKEY *key = kb ? PEM_read_bio_PrivateKey(kb.get(), nullptr, nullptr, nullptr) : nullptr;
        if(!key)
            return fail("can not parse the private key");
        const int kok = SSL_CTX_use_PrivateKey(ctx, key);
        EVP_PKEY_free(key);
        if(kok != 1 || SSL_CTX_check_private_key(ctx) != 1)
            return fail("the private key does not match the certificate");
    }

    if(!cfg.caPem.empty()){
        BioPtr ab = pemBio(cfg.caPem);
        X509_STORE *store = SSL_CTX_get_cert_store(ctx);
        int n = 0;
        while(ab){
            X509 *ca = PEM_read_bio_X509(ab.get(), nullptr, nullptr, nullptr);
            if(!ca)
                break;
            X509_STORE_add_cert(store, ca);
            X509_free(ca);
            n++;
        }
        if(n == 0)
            return fail("can not parse caPem");
    }

    if(cfg.verifyPeer)
        SSL_CTX_set_verify(ctx, server ? (SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT) : SSL_VERIFY_PEER, nullptr);
    else
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
    return c;
}

namespace {

// TLS record exchange + EAP-TLS fragmentation, shared by the server method and the peer
class TlsEngine
{
    SSL *m_ssl = nullptr;
    BIO *m_rbio = nullptr, *m_wbio = nullptr;       // owned by m_ssl
    size_t m_frag = 1000;
    std::string m_out;                              // TLS bytes waiting to be sent
    size_t m_outPos = 0;
    std::string m_in;                               // reassembly buffer
    size_t m_inTotal = 0;
    bool m_inActive = false;

public:
    ~TlsEngine() { if(m_ssl) SSL_free(m_ssl); }

    bool init(const std::shared_ptr<EZEAPTLSContext> &ctx, bool server)
    {
        if(m_ssl || !ctx || !ctx->impl())
            return false;
        m_frag = ctx->fragmentSize();
        m_ssl = SSL_new(ctx->impl()->ctx);
        if(!m_ssl)
            return false;
        m_rbio = BIO_new(BIO_s_mem());
        m_wbio = BIO_new(BIO_s_mem());
        if(!m_rbio || !m_wbio){
            if(m_rbio) BIO_free(m_rbio);
            if(m_wbio) BIO_free(m_wbio);
            SSL_free(m_ssl);
            m_ssl = nullptr;
            return false;
        }
        BIO_set_mem_eof_return(m_rbio, -1);         // an empty read buffer means "retry", not EOF
        SSL_set_bio(m_ssl, m_rbio, m_wbio);
        if(server) SSL_set_accept_state(m_ssl); else SSL_set_connect_state(m_ssl);
        return true;
    }

    enum Rx { RX_MORE, RX_COMPLETE, RX_BAD };

    // one EAP-TLS Response / Request body (flags + [length] + data)
    Rx receive(const std::string &td, std::string &records)
    {
        if(td.empty())
            return RX_BAD;
        const uint8_t flags = (uint8_t)td[0];
        size_t pos = 1;
        if(flags & TLS_FLAG_LENGTH){
            if(td.size() < 5)
                return RX_BAD;
            const size_t total = ((size_t)(uint8_t)td[1] << 24) | ((size_t)(uint8_t)td[2] << 16) | ((size_t)(uint8_t)td[3] << 8) | (uint8_t)td[4];
            pos = 5;
            if(total > TLS_MAX_MESSAGE)
                return RX_BAD;
            if(!m_inActive){
                m_inTotal = total;
                m_inActive = true;
                m_in.clear();
            }
        }
        m_in.append(td, pos, std::string::npos);
        if(m_in.size() > TLS_MAX_MESSAGE)
            return RX_BAD;
        if(flags & TLS_FLAG_MORE){
            m_inActive = true;
            return RX_MORE;
        }
        const bool sizeOk = (m_inTotal == 0 || m_in.size() == m_inTotal);
        records.swap(m_in);
        m_in.clear();
        m_inActive = false;
        m_inTotal = 0;
        return sizeOk ? RX_COMPLETE : RX_BAD;
    }

    // feed TLS records (may be empty: client start) and collect what TLS wants to send
    bool pump(const std::string &records)
    {
        if(!m_ssl)
            return false;
        if(!records.empty()){
            if(SSL_is_init_finished(m_ssl))
                return false;                       // no data is expected after the handshake
            if(BIO_write(m_rbio, records.data(), (int)records.size()) != (int)records.size())
                return false;
        }
        bool ok = true;
        if(!SSL_is_init_finished(m_ssl)){
            const int r = SSL_do_handshake(m_ssl);
            if(r <= 0){
                const int e = SSL_get_error(m_ssl, r);
                ok = (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE);
            }
        }
        const size_t pending = BIO_ctrl_pending(m_wbio);
        if(pending){
            std::string buf(pending, '\0');
            const int n = BIO_read(m_wbio, &buf[0], (int)pending);
            if(n > 0)
                m_out.append(buf, 0, (size_t)n);
        }
        return ok;
    }

    bool finished() const { return m_ssl && SSL_is_init_finished(m_ssl); }
    bool hasOutput() const { return m_outPos < m_out.size(); }

    // body of the next EAP-TLS packet carrying TLS bytes
    std::string nextFragment()
    {
        const size_t remaining = m_out.size() - m_outPos;
        const size_t chunk = remaining < m_frag ? remaining : m_frag;
        const bool first = (m_outPos == 0);
        const bool more = chunk < remaining;
        std::string td;
        uint8_t flags = 0;
        if(first && more)
            flags |= TLS_FLAG_LENGTH;
        if(more)
            flags |= TLS_FLAG_MORE;
        td.push_back((char)flags);
        if(flags & TLS_FLAG_LENGTH){
            const size_t total = m_out.size();
            td.push_back((char)(total >> 24)); td.push_back((char)(total >> 16));
            td.push_back((char)(total >> 8));  td.push_back((char)total);
        }
        td.append(m_out, m_outPos, chunk);
        m_outPos += chunk;
        if(m_outPos >= m_out.size()){
            m_out.clear();
            m_outPos = 0;
        }
        return td;
    }

    std::string msk()
    {
        uint8_t k[128];
        std::string out;
        static const char label[] = "client EAP encryption";
        if(finished() && SSL_export_keying_material(m_ssl, k, sizeof(k), label, sizeof(label) - 1, nullptr, 0, 0) == 1)
            out.assign((const char*)k, 64);                 // MSK = first 64 bytes, EMSK = last 64
        EZCrypto::Wipe(k, sizeof(k));
        return out;
    }

    std::string peerCommonName()
    {
        std::string cn;
        if(!m_ssl)
            return cn;
        X509 *x = SSL_get_peer_certificate(m_ssl);
        if(x){
            char buf[256];
            const int n = X509_NAME_get_text_by_NID(X509_get_subject_name(x), NID_commonName, buf, sizeof(buf));
            if(n > 0)
                cn.assign(buf, (size_t)n);
            X509_free(x);
        }
        return cn;
    }
};

class TLSServerMethod : public EZEAPMethod
{
    std::shared_ptr<EZEAPTLSContext> m_ctx;
    TlsEngine m_tls;
    bool m_finalSent = false;
    std::string m_peerName;

    EZEAPStep sendNext()
    {
        EZEAPStep st;
        st.status = EZEAPStep::CONTINUE;
        st.data = m_tls.nextFragment();
        if(!m_tls.hasOutput() && m_tls.finished())
            m_finalSent = true;                 // the peer acknowledges the last flight, then EAP-Success follows
        return st;
    }

public:
    explicit TLSServerMethod(std::shared_ptr<EZEAPTLSContext> ctx) : m_ctx(std::move(ctx)) {}
    uint8_t type() const override { return ezeap::TYPE_TLS; }

    EZEAPStep start(uint8_t) override
    {
        EZEAPStep st;
        if(!m_tls.init(m_ctx, true))
            return st;
        st.status = EZEAPStep::CONTINUE;
        st.data.assign(1, (char)TLS_FLAG_START);
        return st;
    }

    EZEAPStep handle(uint8_t, const std::string &td) override
    {
        EZEAPStep fail;
        if(td.empty()){                          // acknowledgement
            if(m_finalSent){
                EZEAPStep ok;
                if(!m_tls.finished())
                    return fail;
                m_peerName = m_tls.peerCommonName();
                ok.status = EZEAPStep::SUCCESS;
                return ok;
            }
            return m_tls.hasOutput() ? sendNext() : fail;
        }
        if(m_tls.hasOutput() || m_finalSent)    // the peer must acknowledge our fragments first
            return fail;

        std::string records;
        switch(m_tls.receive(td, records)){
        case TlsEngine::RX_BAD:
            return fail;
        case TlsEngine::RX_MORE: {
            EZEAPStep ack;
            ack.status = EZEAPStep::CONTINUE;   // empty Request = acknowledgement
            return ack;
        }
        case TlsEngine::RX_COMPLETE:
            break;
        }
        if(!m_tls.pump(records))
            return fail;
        if(m_tls.hasOutput())
            return sendNext();
        return fail;                            // nothing to answer: the peer is stuck
    }

    std::string msk() const override { return const_cast<TlsEngine&>(m_tls).msk(); }
    std::string peerName() const override { return m_peerName; }
};

} // namespace

#endif // EZRADIUS_HAS_TLS

// =============================================================================================
// server
EZEAPServer::EZEAPServer() : m_lastPurge(std::chrono::steady_clock::now()) {}
EZEAPServer::~EZEAPServer() = default;

void EZEAPServer::registerMethod(uint8_t type, MethodFactory factory)
{
    for(MethodEntry &e : m_methods){
        if(e.type == type){
            e.factory = std::move(factory);
            return;
        }
    }
    m_methods.push_back({type, std::move(factory)});
}

void EZEAPServer::enableMD5(PasswordLookup lookup)
{
    registerMethod(ezeap::TYPE_MD5, [lookup](const std::string &identity) {
        return std::unique_ptr<EZEAPMethod>(new MD5Method(identity, lookup));
    });
}

#ifdef EZRADIUS_HAS_TLS
bool EZEAPServer::enableTLS(const EZEAPTLSConfig &cfg, std::string *error)
{
    std::shared_ptr<EZEAPTLSContext> ctx = EZEAPTLSContext::create(cfg, true, error);
    if(!ctx)
        return false;
    registerMethod(ezeap::TYPE_TLS, [ctx](const std::string &) {
        return std::unique_ptr<EZEAPMethod>(new TLSServerMethod(ctx));
    });
    return true;
}
#endif

void EZEAPServer::purge()
{
    const auto now = std::chrono::steady_clock::now();
    if(now - m_lastPurge < std::chrono::seconds(1) && m_sessions.size() < m_maxSessions)
        return;
    m_lastPurge = now;
    for(auto it = m_sessions.begin(); it != m_sessions.end();){
        if(it->second.deadline <= now)
            it = m_sessions.erase(it);
        else
            ++it;
    }
}

bool EZEAPServer::send(EZEAPResult result, EZResponse &resp, const std::string &state, const std::string &eap, EZRadiusClientIdentify &from, const EZEAPSessionInfo *info)
{
    resp.ForceMessageAuthenticator();
    if(!resp.AddEAPMessage(eap))
        return false;
    RADIUSPacketTypeCodes code = ACCESS_REJECT;
    if(result == EZEAPResult::CHALLENGE){
        code = ACCESS_CHALLENGE;
        if(!resp.AddRawAttribute((RADIUSAttribute)ezeap::ATTR_STATE, state.data(), state.size()))
            return false;
    }else if(result == EZEAPResult::ACCEPT){
        code = ACCESS_ACCEPT;
        if(info){
            // RFC 3579 section 2.1: MS-MPPE-Recv-Key = first 32 bytes of the MSK, MS-MPPE-Send-Key = next 32 bytes
            if(info->msk.size() >= 64 && !resp.AddMPPEKeys(info->msk.substr(32, 32), info->msk.substr(0, 32)))
                return false;
            if(m_acceptHook)
                m_acceptHook(resp, *info);
        }
    }
    return resp.Send(code, &from);
}

EZEAPResult EZEAPServer::reject(EZRadiusClientIdentify &from, uint8_t responseId, const Session *s)
{
    if(s && m_rejectHook)
        m_rejectHook(s->identity, s->method ? s->method->type() : 0);
    ezeap::Packet f;
    f.code = ezeap::CODE_FAILURE;
    f.id = responseId;
    EZResponse resp;
    send(EZEAPResult::REJECT, resp, std::string(), f.serialize(), from, nullptr);
    return EZEAPResult::REJECT;
}

EZEAPResult EZEAPServer::Process(RadiusPacket &request, EZRadiusClientIdentify &from)
{
    const std::string eap = ezeap::extractMessage(request);
    if(eap.empty())
        return EZEAPResult::NOT_EAP;

    // RFC 3579 section 3.2: an Access-Request with EAP-Message must be authenticated by a Message-Authenticator
    if(!from.RequestHadMessageAuthenticator() && !from.isRadius11())
        return EZEAPResult::ERROR;

    purge();

    ezeap::Packet pk;
    if(!ezeap::Packet::parse(eap, pk) || pk.code != ezeap::CODE_RESPONSE || !pk.hasType())
        return reject(from, 0, nullptr);

    std::string state;
    for(const AttrValue &v : request.getAttributes((RADIUSAttribute)ezeap::ATTR_STATE)){
        state = v.strValue;
        break;
    }
    const std::string peerKey = ezaddr::keyOf(from.Peer());

    Session *sess = nullptr;
    std::string key;
    if(state.empty()){
        // start of a conversation: EAP-Response/Identity
        if(pk.type != ezeap::TYPE_IDENTITY || pk.data.empty())
            return reject(from, pk.id, nullptr);
        if(m_sessions.size() >= m_maxSessions)
            return reject(from, pk.id, nullptr);

        Session s;
        s.identity = pk.data;
        s.peerKey = peerKey;
        for(MethodEntry &e : m_methods){
            s.method = e.factory(s.identity);
            if(s.method)
                break;
        }
        if(!s.method)
            return reject(from, pk.id, &s);

        uint8_t raw[16];
        if(!EZCrypto::Random(raw, sizeof(raw)))
            return EZEAPResult::ERROR;
        key.assign((const char*)raw, sizeof(raw));
        s.lastId = (uint8_t)(pk.id + 1);
        s.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(m_timeoutSec);
        sess = &(m_sessions[key] = std::move(s));

        EZEAPStep st = sess->method->start(sess->lastId);
        if(st.status != EZEAPStep::CONTINUE){
            EZEAPResult r = reject(from, pk.id, sess);
            m_sessions.erase(key);
            return r;
        }
        ezeap::Packet req;
        req.code = ezeap::CODE_REQUEST;
        req.id = sess->lastId;
        req.type = sess->method->type();
        req.data = st.data;
        EZResponse resp;
        return send(EZEAPResult::CHALLENGE, resp, key, req.serialize(), from, nullptr) ? EZEAPResult::CHALLENGE : EZEAPResult::ERROR;
    }

    key = state;
    auto it = m_sessions.find(key);
    if(it == m_sessions.end() || it->second.peerKey != peerKey || it->second.deadline <= std::chrono::steady_clock::now()){
        if(it != m_sessions.end())
            m_sessions.erase(it);
        return reject(from, pk.id, nullptr);
    }
    sess = &it->second;

    // a Response with another identifier is a stale / duplicate packet: ignore it
    if(pk.id != sess->lastId)
        return EZEAPResult::ERROR;

    EZEAPStep st;
    if(pk.type == ezeap::TYPE_NAK){
        // the peer wants another method: first registered method it lists (and that is not the current one)
        std::unique_ptr<EZEAPMethod> alt;
        for(MethodEntry &e : m_methods){
            if(e.type == sess->method->type() || pk.data.find((char)e.type) == std::string::npos)
                continue;
            alt = e.factory(sess->identity);
            if(alt)
                break;
        }
        if(!alt){
            EZEAPResult r = reject(from, pk.id, sess);
            m_sessions.erase(key);
            return r;
        }
        sess->method = std::move(alt);
        sess->lastId = (uint8_t)(sess->lastId + 1);
        st = sess->method->start(sess->lastId);
    }else if(pk.type != sess->method->type()){
        EZEAPResult r = reject(from, pk.id, sess);
        m_sessions.erase(key);
        return r;
    }else{
        st = sess->method->handle(pk.id, pk.data);
        if(st.status == EZEAPStep::CONTINUE)
            sess->lastId = (uint8_t)(sess->lastId + 1);
    }

    sess->deadline = std::chrono::steady_clock::now() + std::chrono::seconds(m_timeoutSec);

    if(st.status == EZEAPStep::CONTINUE){
        ezeap::Packet req;
        req.code = ezeap::CODE_REQUEST;
        req.id = sess->lastId;
        req.type = sess->method->type();
        req.data = st.data;
        EZResponse resp;
        return send(EZEAPResult::CHALLENGE, resp, key, req.serialize(), from, nullptr) ? EZEAPResult::CHALLENGE : EZEAPResult::ERROR;
    }

    if(st.status == EZEAPStep::SUCCESS){
        EZEAPSessionInfo info;
        info.identity = sess->identity;
        info.methodType = sess->method->type();
        info.peerName = sess->method->peerName();
        info.msk = sess->method->msk();
        ezeap::Packet ok;
        ok.code = ezeap::CODE_SUCCESS;
        ok.id = pk.id;
        EZResponse resp;
        const bool sent = send(EZEAPResult::ACCEPT, resp, std::string(), ok.serialize(), from, &info);
        EZCrypto::Wipe(&info.msk[0], info.msk.size());
        m_sessions.erase(key);
        return sent ? EZEAPResult::ACCEPT : EZEAPResult::ERROR;
    }

    EZEAPResult r = reject(from, pk.id, sess);
    m_sessions.erase(key);
    return r;
}

// =============================================================================================
// supplicant
struct EZEAPPeer::Impl
{
#ifdef EZRADIUS_HAS_TLS
    std::shared_ptr<EZEAPTLSContext> ctx;
    TlsEngine tls;
    bool started = false;
    bool usedTls = false;
#endif
};

EZEAPPeer::EZEAPPeer(const std::string &identity) : m_impl(new Impl()), m_identity(identity) {}
EZEAPPeer::~EZEAPPeer() = default;

void EZEAPPeer::setPassword(const std::string &password)
{
    m_password = password;
    m_hasPassword = true;
}

#ifdef EZRADIUS_HAS_TLS
bool EZEAPPeer::setTLS(const EZEAPTLSConfig &cfg, std::string *error)
{
    m_impl->ctx = EZEAPTLSContext::create(cfg, false, error);
    return m_impl->ctx != nullptr;
}
#endif

std::string EZEAPPeer::handle(const std::string &eapPacket)
{
    ezeap::Packet in;
    if(m_state != RUNNING || !ezeap::Packet::parse(eapPacket, in)){
        m_state = FAILURE;
        return std::string();
    }

    if(in.code == ezeap::CODE_FAILURE){
        m_state = FAILURE;
        return std::string();
    }
    if(in.code == ezeap::CODE_SUCCESS){
#ifdef EZRADIUS_HAS_TLS
        if(m_impl->usedTls){
            m_msk = m_impl->tls.msk();
            m_state = m_msk.empty() ? FAILURE : SUCCESS;        // Success before the TLS handshake finished is bogus
            return std::string();
        }
#endif
        m_state = SUCCESS;
        return std::string();
    }
    if(in.code != ezeap::CODE_REQUEST){
        m_state = FAILURE;
        return std::string();
    }

    ezeap::Packet out;
    out.code = ezeap::CODE_RESPONSE;
    out.id = in.id;
    out.type = in.type;

    switch(in.type){
    case ezeap::TYPE_IDENTITY:
        out.data = m_identity;
        return out.serialize();
    case ezeap::TYPE_NOTIFICATION:
        return out.serialize();
    case ezeap::TYPE_MD5:
        if(m_hasPassword && in.data.size() >= 17 && (uint8_t)in.data[0] == 16){
            out.data.push_back(16);
            out.data.append(md5Response(in.id, m_password, in.data.substr(1, 16)));
            return out.serialize();
        }
        break;
#ifdef EZRADIUS_HAS_TLS
    case ezeap::TYPE_TLS:
        if(m_impl->ctx){
            TlsEngine &tls = m_impl->tls;
            m_impl->usedTls = true;
            if(!in.data.empty() && ((uint8_t)in.data[0] & TLS_FLAG_START)){
                if(m_impl->started || !tls.init(m_impl->ctx, false) || !tls.pump(std::string())){
                    m_state = FAILURE;
                    return std::string();
                }
                m_impl->started = true;
            }else if(!m_impl->started){
                m_state = FAILURE;
                return std::string();
            }else if(in.data.empty()){
                // the server acknowledges our fragment: send the next one
            }else{
                std::string records;
                const TlsEngine::Rx rx = tls.receive(in.data, records);
                if(rx == TlsEngine::RX_BAD || (rx == TlsEngine::RX_COMPLETE && !tls.pump(records))){
                    m_state = FAILURE;
                    return std::string();
                }
            }
            if(tls.hasOutput())
                out.data = tls.nextFragment();
            // else: empty Response = acknowledgement
            return out.serialize();
        }
        break;
#endif
    default:
        break;
    }

    // EAP-Nak (RFC 3748 section 5.3): list the methods this peer can do
    out.type = ezeap::TYPE_NAK;
    out.data.clear();
#ifdef EZRADIUS_HAS_TLS
    if(m_impl->ctx)
        out.data.push_back((char)ezeap::TYPE_TLS);
#endif
    if(m_hasPassword)
        out.data.push_back((char)ezeap::TYPE_MD5);
    if(out.data.empty())
        out.data.push_back(0);              // no alternative
    return out.serialize();
}

// =============================================================================================
// EZResponse / EZRadiusClient helpers
bool EZResponse::AddEAPMessage(const std::string &eapPacket)
{
    return ezeap::addMessage(m_Pck, eapPacket);
}

#endif // EZRADIUS_HAS_CRYPTO
