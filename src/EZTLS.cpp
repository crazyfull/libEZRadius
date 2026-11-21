#include "EZTLS.h"
#ifdef EZRADIUS_HAS_TLS

#include "EZCrypto.h"
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <algorithm>
#include <cstring>
#include <deque>
#include <fstream>
#include <sstream>
#include <sys/time.h>

std::string EZTLSConfig::readFile(const std::string &path)
{
    std::ifstream f(path, std::ios::binary);
    if(!f)
        return std::string();
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

namespace {

struct BioDeleter { void operator()(BIO *b) const { BIO_free(b); } };
using BioPtr = std::unique_ptr<BIO, BioDeleter>;
BioPtr pemBio(const std::string &pem) { return BioPtr(BIO_new_mem_buf(pem.data(), (int)pem.size())); }

const char ALPN_10[] = "radius/1.0";
const char ALPN_11[] = "radius/1.1";

int acceptAllCertificates(int, X509_STORE_CTX *) { return 1; }      // the fingerprint list decides

std::string normalizeFingerprint(const std::string &in)
{
    std::string out;
    for(char c : in){
        if(c == ':' || c == ' ')
            continue;
        out.push_back((char)tolower((unsigned char)c));
    }
    return out;
}

std::string toHex(const uint8_t *d, size_t n)
{
    static const char h[] = "0123456789abcdef";
    std::string s;
    for(size_t i = 0; i < n; i++){ s.push_back(h[d[i] >> 4]); s.push_back(h[d[i] & 15]); }
    return s;
}

// server side ALPN selection (RFC 9765 section 3.3)
int alpnSelect(SSL *ssl, const uint8_t **out, uint8_t *outlen, const uint8_t *in, unsigned inlen, void *arg)
{
    const EZTLSContext *c = static_cast<const EZTLSContext*>(arg);
    bool offer10 = false, offer11 = false;
    for(unsigned i = 0; i < inlen;){
        const unsigned n = in[i];
        if(i + 1 + n > inlen)
            break;
        if(n == sizeof(ALPN_10) - 1 && memcmp(in + i + 1, ALPN_10, n) == 0) offer10 = true;
        if(n == sizeof(ALPN_11) - 1 && memcmp(in + i + 1, ALPN_11, n) == 0) offer11 = true;
        i += 1 + n;
    }
    // RADIUS/1.1 only on TLS 1.3 (and never on DTLS 1.2)
    const bool tls13 = SSL_version(ssl) >= TLS1_3_VERSION && SSL_version(ssl) != DTLS1_2_VERSION;
    if(offer11 && c->allow11 && tls13){
        *out = (const uint8_t*)ALPN_11; *outlen = sizeof(ALPN_11) - 1;
        return SSL_TLSEXT_ERR_OK;
    }
    if(offer10 && c->allow10){
        *out = (const uint8_t*)ALPN_10; *outlen = sizeof(ALPN_10) - 1;
        return SSL_TLSEXT_ERR_OK;
    }
    return SSL_TLSEXT_ERR_ALERT_FATAL;          // no_application_protocol (RFC 9765 section 3.3)
}

// datagram preserving BIO for DTLS: every write is one datagram, every read returns one datagram
struct DgramQ { std::deque<std::string> in; std::vector<std::string> out; };

int dgWrite(BIO *b, const char *buf, int len)
{
    DgramQ *q = static_cast<DgramQ*>(BIO_get_data(b));
    if(!q || len < 0)
        return -1;
    q->out.emplace_back(buf, (size_t)len);
    return len;
}

int dgRead(BIO *b, char *buf, int len)
{
    BIO_clear_retry_flags(b);
    DgramQ *q = static_cast<DgramQ*>(BIO_get_data(b));
    if(!q || q->in.empty()){
        BIO_set_retry_read(b);
        return -1;
    }
    std::string d = std::move(q->in.front());
    q->in.pop_front();
    const size_t n = std::min<size_t>((size_t)len, d.size());
    memcpy(buf, d.data(), n);
    return (int)n;
}

long dgCtrl(BIO *, int cmd, long, void *)
{
    return cmd == BIO_CTRL_FLUSH ? 1 : 0;
}

BIO_METHOD *dgramMethod()
{
    static BIO_METHOD *m = []{
        BIO_METHOD *x = BIO_meth_new(BIO_TYPE_SOURCE_SINK, "ezdtls");
        BIO_meth_set_write(x, dgWrite);
        BIO_meth_set_read(x, dgRead);
        BIO_meth_set_ctrl(x, dgCtrl);
        return x;
    }();
    return m;
}

} // namespace

// =============================================================================================
EZTLSContext::~EZTLSContext()
{
    if(m_ctx)
        SSL_CTX_free((SSL_CTX*)m_ctx);
}

std::shared_ptr<EZTLSContext> EZTLSContext::create(const EZTLSConfig &cfg, bool server, bool dtls, std::string *error)
{
    auto fail = [&](const char *msg) -> std::shared_ptr<EZTLSContext> {
        if(error)
            *error = msg;
        return nullptr;
    };

    const bool authenticated = cfg.verifyPeer || !cfg.pinnedSHA256.empty();
    if(!authenticated && !cfg.insecureSkipVerify)
        return fail("peer authentication is required: set caPem (verifyPeer) or pinnedSHA256");
    if(cfg.verifyPeer && cfg.caPem.empty())
        return fail("verifyPeer needs caPem (trusted CA certificates)");
    if(cfg.certChainPem.empty() != cfg.privateKeyPem.empty())
        return fail("certChainPem and privateKeyPem must be set together");
    if(server && cfg.certChainPem.empty())
        return fail("a server needs a certificate and a private key");

    std::shared_ptr<EZTLSContext> c(new EZTLSContext());
    c->m_cfg = cfg;
    c->m_server = server;
    c->m_dtls = dtls;

    // radiusVersions: "", "1.0", "1.0,1.1", "1.1"
    c->allow10 = c->allow11 = false;
    {
        std::stringstream ss(cfg.radiusVersions);
        std::string tok;
        while(std::getline(ss, tok, ',')){
            tok.erase(std::remove_if(tok.begin(), tok.end(), [](char ch){ return ch == ' '; }), tok.end());
            if(tok == "1.0") c->allow10 = true;
            else if(tok == "1.1") c->allow11 = true;
            else if(!tok.empty()) return fail("radiusVersions: use \"\", \"1.0\", \"1.0,1.1\" or \"1.1\"");
        }
        c->alpn = c->allow10 || c->allow11;
        if(!c->alpn)
            c->allow10 = true;                   // historic RADIUS/TLS
        if(dtls && cfg.radiusVersions == "1.1")
            return fail("RADIUS/1.1 needs TLS 1.3; DTLS 1.2 can not do it");
    }

    SSL_CTX *ctx = SSL_CTX_new(dtls ? DTLS_method() : TLS_method());
    if(!ctx)
        return fail("SSL_CTX_new failed");
    c->m_ctx = ctx;

    if(dtls){
        SSL_CTX_set_min_proto_version(ctx, DTLS1_2_VERSION);
        SSL_CTX_set_max_proto_version(ctx, DTLS1_2_VERSION);
        SSL_CTX_set_options(ctx, SSL_OP_NO_QUERY_MTU);
    }else{
        SSL_CTX_set_min_proto_version(ctx, (c->alpn && !c->allow10) ? TLS1_3_VERSION : TLS1_2_VERSION);
        SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    }
    SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);          // no resumption: every connection is authorized in full
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
            if(SSL_CTX_add_extra_chain_cert(ctx, extra) != 1){
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
    else if(!cfg.pinnedSHA256.empty())
        SSL_CTX_set_verify(ctx, server ? (SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT) : SSL_VERIFY_PEER, acceptAllCertificates);
    else
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);

    if(server && c->alpn)
        SSL_CTX_set_alpn_select_cb(ctx, alpnSelect, c.get());
    return c;
}

// =============================================================================================
EZTLSEngine::~EZTLSEngine()
{
    if(m_ssl)
        SSL_free((SSL*)m_ssl);                  // frees the BIOs too
    delete static_cast<DgramQ*>(m_dgram);
}

std::unique_ptr<EZTLSEngine> EZTLSEngine::create(const std::shared_ptr<EZTLSContext> &ctx, std::string *error)
{
    auto fail = [&](const char *msg) -> std::unique_ptr<EZTLSEngine> {
        if(error)
            *error = msg;
        return nullptr;
    };
    if(!ctx || !ctx->native())
        return fail("no TLS context");

    std::unique_ptr<EZTLSEngine> e(new EZTLSEngine());
    e->m_ctx = ctx;
    SSL *ssl = SSL_new((SSL_CTX*)ctx->native());
    if(!ssl)
        return fail("SSL_new failed");
    e->m_ssl = ssl;

    if(ctx->dtls()){
        DgramQ *q = new DgramQ();
        e->m_dgram = q;
        BIO *b = BIO_new(dgramMethod());
        if(!b)
            return fail("BIO_new failed");
        BIO_set_data(b, q);
        BIO_set_init(b, 1);
        SSL_set_bio(ssl, b, b);
        SSL_set_mtu(ssl, (unsigned)ctx->config().mtu);
    }else{
        BIO *r = BIO_new(BIO_s_mem()), *w = BIO_new(BIO_s_mem());
        if(!r || !w){
            if(r) BIO_free(r);
            if(w) BIO_free(w);
            return fail("BIO_new failed");
        }
        BIO_set_mem_eof_return(r, -1);          // an empty buffer means "retry", not EOF
        SSL_set_bio(ssl, r, w);
        e->m_rbio = r;
        e->m_wbio = w;
    }

    if(ctx->server()){
        SSL_set_accept_state(ssl);
    }else{
        SSL_set_connect_state(ssl);
        const std::string &name = ctx->config().serverName;
        if(!name.empty()){
            // an IP address goes into the IP SAN check, a DNS name into the DNS SAN check (+ SNI)
            X509_VERIFY_PARAM *param = SSL_get0_param(ssl);
            if(X509_VERIFY_PARAM_set1_ip_asc(param, name.c_str()) != 1){
                ERR_clear_error();
                SSL_set_tlsext_host_name(ssl, name.c_str());
                SSL_set_hostflags(ssl, X509_CHECK_FLAG_NEVER_CHECK_SUBJECT | X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
                if(SSL_set1_host(ssl, name.c_str()) != 1)
                    return fail("invalid serverName");
            }
        }
        if(ctx->alpn){
            std::string wire;
            if(ctx->allow10){ wire.push_back((char)(sizeof(ALPN_10) - 1)); wire.append(ALPN_10); }
            if(ctx->allow11 && !ctx->dtls()){ wire.push_back((char)(sizeof(ALPN_11) - 1)); wire.append(ALPN_11); }
            if(!wire.empty() && SSL_set_alpn_protos(ssl, (const uint8_t*)wire.data(), (unsigned)wire.size()) != 0)
                return fail("SSL_set_alpn_protos failed");
        }
    }
    return e;
}

void EZTLSEngine::fail(const char *what)
{
    if(m_failed)
        return;
    m_failed = true;
    m_error = what;
    char buf[200];
    const unsigned long err = ERR_get_error();
    if(err){
        ERR_error_string_n(err, buf, sizeof(buf));
        m_error += ": ";
        m_error += buf;
    }
    ERR_clear_error();
}

void EZTLSEngine::drain()
{
    if(m_dgram){
        DgramQ *q = static_cast<DgramQ*>(m_dgram);
        for(std::string &d : q->out)
            m_out.push_back(std::move(d));
        q->out.clear();
        return;
    }
    BIO *w = (BIO*)m_wbio;
    const size_t pending = BIO_ctrl_pending(w);
    if(pending){
        std::string buf(pending, '\0');
        const int n = BIO_read(w, &buf[0], (int)pending);
        if(n > 0){
            buf.resize((size_t)n);
            m_out.push_back(std::move(buf));
        }
    }
}

bool EZTLSEngine::afterHandshake()
{
    SSL *ssl = (SSL*)m_ssl;
    const EZTLSConfig &cfg = m_ctx->config();

    X509 *x = SSL_get_peer_certificate(ssl);
    if(x){
        uint8_t *der = nullptr;
        const int n = i2d_X509(x, &der);
        if(n > 0){
            uint8_t h[SHA256_DIGEST_LENGTH];
            SHA256(der, (size_t)n, h);
            m_fingerprint = toHex(h, sizeof(h));
            OPENSSL_free(der);
        }
        char buf[256];
        const int cn = X509_NAME_get_text_by_NID(X509_get_subject_name(x), NID_commonName, buf, sizeof(buf));
        if(cn > 0)
            m_commonName.assign(buf, (size_t)cn);
        X509_free(x);
    }else if(!cfg.insecureSkipVerify){
        fail("the peer sent no certificate");
        return false;
    }

    if(!cfg.pinnedSHA256.empty()){
        bool match = false;
        for(const std::string &p : cfg.pinnedSHA256)
            if(!m_fingerprint.empty() && normalizeFingerprint(p) == m_fingerprint)
                match = true;
        if(!match){
            fail("peer certificate fingerprint is not in the accepted list");
            return false;
        }
    }

    const uint8_t *sel = nullptr;
    unsigned selLen = 0;
    SSL_get0_alpn_selected(ssl, &sel, &selLen);
    m_radiusVersion = 10;
    if(sel && selLen == sizeof(ALPN_11) - 1 && memcmp(sel, ALPN_11, selLen) == 0){
        if(SSL_version(ssl) < TLS1_3_VERSION || m_ctx->dtls() || !m_ctx->allow11){
            fail("radius/1.1 was selected without TLS 1.3");
            return false;
        }
        m_radiusVersion = 11;
    }else if(sel && selLen == sizeof(ALPN_10) - 1 && memcmp(sel, ALPN_10, selLen) == 0){
        if(!m_ctx->allow10){
            fail("radius/1.0 was selected but is not allowed");
            return false;
        }
    }else if(sel && selLen){
        fail("unknown ALPN protocol selected");
        return false;
    }else if(!m_ctx->allow10){
        fail("the peer does not support ALPN radius/1.1");        // 1.1 only and no ALPN answer (RFC 9765 table 1)
        return false;
    }

    if(m_ctx->dtls())
        SSL_set_mtu(ssl, 4800);             // RADIUS packets up to 4096 bytes travel in one record
    m_established = true;
    return true;
}

bool EZTLSEngine::advance()
{
    if(m_failed)
        return false;
    SSL *ssl = (SSL*)m_ssl;

    if(!m_established){
        const int r = SSL_do_handshake(ssl);
        if(r == 1){
            if(!afterHandshake()){
                drain();
                return false;
            }
        }else{
            const int e = SSL_get_error(ssl, r);
            if(e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE){
                fail("TLS handshake failed");
                drain();                    // an alert may be waiting
                return false;
            }
        }
    }

    if(m_established){
        while(!m_pendingWrite.empty()){
            const int n = SSL_write(ssl, m_pendingWrite.data(), (int)m_pendingWrite.size());
            if(n <= 0){
                fail("TLS write failed");
                drain();
                return false;
            }
            m_pendingWrite.erase(0, (size_t)n);
        }
        uint8_t buf[16384];
        for(;;){
            const int n = SSL_read(ssl, buf, sizeof(buf));
            if(n > 0){
                if(m_dgram)
                    m_records.emplace_back((const char*)buf, (size_t)n);      // one record = one RADIUS packet
                else
                    m_plain.append((const char*)buf, (size_t)n);
                continue;
            }
            const int e = SSL_get_error(ssl, n);
            if(e == SSL_ERROR_ZERO_RETURN){
                m_peerClosed = true;
                break;
            }
            if(e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE)
                break;
            fail("TLS read failed");
            drain();
            return false;
        }
    }
    drain();
    return true;
}

bool EZTLSEngine::start()
{
    return advance();
}

bool EZTLSEngine::feed(const uint8_t *data, size_t len)
{
    if(m_failed)
        return false;
    if(m_dgram){
        static_cast<DgramQ*>(m_dgram)->in.emplace_back((const char*)data, len);
    }else if(len && BIO_write((BIO*)m_rbio, data, (int)len) != (int)len){
        fail("BIO_write failed");
        return false;
    }
    return advance();
}

bool EZTLSEngine::write(const uint8_t *data, size_t len)
{
    if(m_failed)
        return false;
    if(m_dgram && len > 16384)
        return false;
    m_pendingWrite.append((const char*)data, len);
    return advance();
}

std::vector<std::string> EZTLSEngine::takeOutput()
{
    std::vector<std::string> o;
    o.swap(m_out);
    return o;
}

std::string EZTLSEngine::takePlain()
{
    std::string p;
    p.swap(m_plain);
    return p;
}

std::vector<std::string> EZTLSEngine::takeRecords()
{
    std::vector<std::string> r;
    r.swap(m_records);
    return r;
}

bool EZTLSEngine::close()
{
    if(m_failed || !m_ssl)
        return false;
    SSL_shutdown((SSL*)m_ssl);
    drain();
    return true;
}

int EZTLSEngine::msUntilTimeout()
{
    if(!m_dgram || !m_ssl)
        return -1;
    struct timeval tv;
    if(DTLSv1_get_timeout((SSL*)m_ssl, &tv) != 1)
        return -1;
    return (int)(tv.tv_sec * 1000 + tv.tv_usec / 1000);
}

bool EZTLSEngine::handleTimeout()
{
    if(!m_dgram || !m_ssl || m_failed)
        return !m_failed;
    if(DTLSv1_handle_timeout((SSL*)m_ssl) < 0){
        fail("DTLS retransmission failed");
        return false;
    }
    drain();
    return true;
}

#endif // EZRADIUS_HAS_TLS
