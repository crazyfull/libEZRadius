// Test certificates generated in memory (BoringSSL): CA, server (SAN: radius.test, 127.0.0.1), client.
#ifndef TEST_CERTS_H
#define TEST_CERTS_H
#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <cstdlib>
#include <string>

struct TestCert
{
    std::string certPem, keyPem, fingerprint;
    X509 *x509 = nullptr;
    EVP_PKEY *pkey = nullptr;
    TestCert() = default;
    TestCert(const TestCert&) = delete;
    TestCert(TestCert &&o) noexcept : certPem(std::move(o.certPem)), keyPem(std::move(o.keyPem)), fingerprint(std::move(o.fingerprint)), x509(o.x509), pkey(o.pkey) { o.x509 = nullptr; o.pkey = nullptr; }
    ~TestCert() { if(x509) X509_free(x509); if(pkey) EVP_PKEY_free(pkey); }
};

// san: e.g. "DNS:radius.test,IP:127.0.0.1" (empty: none). issuer null: self signed CA (basicConstraints CA:TRUE)
static inline TestCert makeTestCert(const char *cn, TestCert *issuer, const char *san = "")
{
    TestCert c;
    EC_KEY *ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY_generate_key(ec);
    c.pkey = EVP_PKEY_new();
    EVP_PKEY_assign_EC_KEY(c.pkey, ec);
    c.x509 = X509_new();
    X509_set_version(c.x509, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(c.x509), (long)rand() + 1);
    X509_gmtime_adj(X509_getm_notBefore(c.x509), -60);
    X509_gmtime_adj(X509_getm_notAfter(c.x509), 3600);
    X509_set_pubkey(c.x509, c.pkey);
    X509_NAME *name = X509_get_subject_name(c.x509);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)cn, -1, -1, 0);
    X509_set_issuer_name(c.x509, issuer ? X509_get_subject_name(issuer->x509) : name);

    X509V3_CTX ctx;
    X509V3_set_ctx(&ctx, issuer ? issuer->x509 : c.x509, c.x509, nullptr, nullptr, 0);
    auto addExt = [&](int nid, const char *value){
        X509_EXTENSION *ex = X509V3_EXT_nconf_nid(nullptr, &ctx, nid, value);
        if(ex){ X509_add_ext(c.x509, ex, -1); X509_EXTENSION_free(ex); }
    };
    if(!issuer)
        addExt(NID_basic_constraints, "critical,CA:TRUE");
    if(san && *san)
        addExt(NID_subject_alt_name, san);

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

    uint8_t *der = nullptr;
    const int dn = i2d_X509(c.x509, &der);
    uint8_t h[SHA256_DIGEST_LENGTH];
    SHA256(der, (size_t)dn, h);
    OPENSSL_free(der);
    static const char hx[] = "0123456789abcdef";
    for(unsigned char x : h){ c.fingerprint.push_back(hx[x >> 4]); c.fingerprint.push_back(hx[x & 15]); }
    return c;
}
#endif
