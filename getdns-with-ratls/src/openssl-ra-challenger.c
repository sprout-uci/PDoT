/* Challenger implementation using OpenSSL. */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "ra.h"
#include "ra-challenger.h"
#include "ra-challenger_private.h"

#include "debug.h"

#define SGX_GROUP_OUT_OF_DATE 1

extern unsigned char ias_sign_ca_cert_der[];
extern unsigned int ias_sign_ca_cert_der_len;

/* EVP_DecodeBlock pads its output with \0 if the output length is not
   a multiple of 3. Check if the base64 string is padded at the end
   and adjust the output length. */
static
int EVP_DecodeBlock_wrapper
(
    unsigned char *out,
    const unsigned char *in,
    int in_len
)
{
    /* Use a temporary output buffer. We do not want to disturb the
       original output buffer with extraneous \0 bytes. */
    unsigned char buf[in_len];
    
    int ret = EVP_DecodeBlock(buf, in, in_len);
    assert(ret != -1);
    if (in[in_len-1] == '=' && in[in_len-2] == '=') {
        ret -= 2;
    } else if (in[in_len-1] == '=') {
        ret -= 1;
    }

    memcpy(out, buf, ret);
    return ret;
}

/**
 * Given an X509 extension OID, return its data.
 */
static
void get_extension
(
    const X509* crt,            /* in */
    const unsigned char* oid,   /* in */
    int oid_len,                /* in */
    const unsigned char** data,       /* out */
    int* data_len               /* out */
)
{
    // https://zakird.com/2013/10/13/certificate-parsing-with-openssl
    STACK_OF(X509_EXTENSION) *exts = crt->cert_info->extensions;

    int num_of_exts;
    if (exts) {
        num_of_exts = sk_X509_EXTENSION_num(exts);
    } else {
        num_of_exts = 0;
    }

    assert(num_of_exts >= 0);

    for (int i=0; i < num_of_exts; i++) {
        X509_EXTENSION *ex = sk_X509_EXTENSION_value(exts, i);
        assert(ex != NULL);
        ASN1_OBJECT *obj = X509_EXTENSION_get_object(ex);
        assert(obj != NULL);

        if (oid_len != obj->length) continue;
        
        if (0 == memcmp(obj->data, oid, obj->length)) {
            *data = ex->value->data;
            *data_len = ex->value->length;
            break;
        }
    }
}

static
void get_and_decode_ext
(
 const X509* crt,
 const unsigned char* oid,
 int oid_len,
 unsigned char* data,
 int data_max_len,
 unsigned int* data_len
)
{
    const unsigned char* ext;
    int ext_len;
    
    get_extension(crt, oid, oid_len, &ext, &ext_len);
    
    assert(ext_len * 3 <= data_max_len * 4);
    int ret = EVP_DecodeBlock_wrapper(data, ext, ext_len);
    
    assert(ret != -1);
    *data_len = ret;
}

/* Extract extensions from X509 and decode base64. */
static
void extract_x509_extensions
(
    const X509* crt,
    attestation_verification_report_t* attn_report
)
{
    bzero(attn_report, sizeof(*attn_report));

    get_and_decode_ext(crt,
                       ias_response_body_oid + 2, ias_oid_len - 2,
                       attn_report->ias_report, sizeof(attn_report->ias_report),
                       &attn_report->ias_report_len);
    
    get_and_decode_ext(crt,
                       ias_root_cert_oid + 2, ias_oid_len - 2,
                       attn_report->ias_sign_ca_cert, sizeof(attn_report->ias_sign_ca_cert),
                       &attn_report->ias_sign_ca_cert_len);

    get_and_decode_ext(crt,
                       ias_leaf_cert_oid + 2, ias_oid_len - 2,
                       attn_report->ias_sign_cert, sizeof(attn_report->ias_sign_cert),
                       &attn_report->ias_sign_cert_len);

    get_and_decode_ext(crt,
                       ias_report_signature_oid + 2, ias_oid_len - 2,
                       attn_report->ias_report_signature, sizeof(attn_report->ias_report_signature),
                       &attn_report->ias_report_signature_len);

    // Assert we got all of our extensions.
    assert(attn_report->ias_report_signature_len != 0 &&
           attn_report->ias_sign_cert_len != 0 &&
           attn_report->ias_sign_ca_cert_len != 0 &&
           attn_report->ias_report_len != 0);
}

void get_quote_from_cert
(
    const uint8_t* der_crt,
    uint32_t der_crt_len,
    sgx_quote_t* q
)
{
    (void) q;
    X509* crt = NULL;

    crt = d2i_X509(NULL, &der_crt, der_crt_len);
    assert(crt != NULL);

    STACK_OF(X509_EXTENSION) *exts = crt->cert_info->extensions;
    assert(exts != 0);

    int num_of_exts = sk_X509_EXTENSION_num(exts);
    assert(num_of_exts >= 0);

    unsigned char ias_report[2048];
    int ias_report_len;
    
    for (int i=0; i < num_of_exts; i++) {
        X509_EXTENSION *ex = sk_X509_EXTENSION_value(exts, i);
        assert(ex != NULL);
        ASN1_OBJECT *obj = X509_EXTENSION_get_object(ex);
        assert(obj != NULL);

        if (0 == memcmp(obj->data, ias_response_body_oid + 2, obj->length)) {
            
            assert(ex->value->length * 3 <= (int) sizeof(ias_report) * 4);
            int ret = EVP_DecodeBlock_wrapper(ias_report,
                                              ex->value->data,
                                              ex->value->length);
            assert(ret != -1);
            ias_report_len = ret;
            break;
        }
    }
    
    get_quote_from_report(ias_report, ias_report_len, q);
}

void get_quote_from_report
(
    const uint8_t* report /* in */,
    const int report_len  /* in */,
    sgx_quote_t* quote
)
{
    // Move report into \0 terminated buffer such that we can work
    // with str* functions.
    char buf[report_len + 1];
    memcpy(buf, report, report_len);
    buf[report_len] = '\0';

    const char* json_string = "\"isvEnclaveQuoteBody\":\"";
    char* p_begin = strstr(buf, json_string);
    assert(p_begin != NULL);
    p_begin += strlen(json_string);
    const char* p_end = strchr(p_begin, '"');
    assert(p_end != NULL);

    const int quote_base64_len = p_end - p_begin;
    uint8_t* quote_bin = malloc(quote_base64_len);
    uint32_t quote_bin_len = quote_base64_len;

    int ret = EVP_DecodeBlock(quote_bin, (unsigned char*) p_begin, quote_base64_len);
    assert(ret != -1);
    quote_bin_len = ret;
    
    assert(quote_bin_len <= sizeof(sgx_quote_t));
    memset(quote, 0, sizeof(sgx_quote_t));
    memcpy(quote, quote_bin, quote_bin_len);
    free(quote_bin);
}

static
int verify_report_data_against_server_cert
(
    X509* crt,
    sgx_quote_t* quote
)
{
    unsigned char md[EVP_MAX_MD_SIZE] = {0, };
    unsigned int md_len;
    int ret = X509_pubkey_digest(crt, EVP_sha256(), md, &md_len);
    assert(ret == 1);
    assert(md_len == (256 / 8)); // focus on sha256 for now
    
#ifdef DEBUG
    fprintf(stderr, "SHA256 of server's public key:\n");
    for (int i=0; i < SHA256_DIGEST_SIZE; ++i) fprintf(stderr, "%02x", md[i]);
    fprintf(stderr, "\n");

    fprintf(stderr, "Quote's report data:\n");
    for (int i=0; i < SGX_REPORT_DATA_SIZE; ++i) fprintf(stderr, "%02x", quote->report_body.report_data.d[i]);
    fprintf(stderr, "\n");
#endif
    
    assert(md_len <= SGX_REPORT_DATA_SIZE);
    ret = memcmp(quote->report_body.report_data.d, md, md_len);
    assert(ret == 0);

    return ret;
}

static
int verify_ias_report_signature
(
    attestation_verification_report_t* attn_report
)
{
    X509* crt = NULL;
    int ret;

    const unsigned char* p = attn_report->ias_sign_cert;
    crt = d2i_X509(NULL,
                   &p,
                   attn_report->ias_sign_cert_len);
    assert(crt != NULL);

    EVP_PKEY* key = X509_get_pubkey(crt);
    assert(key != NULL);

    EVP_MD_CTX* ctx = EVP_MD_CTX_create();
    ret = EVP_VerifyInit_ex(ctx, EVP_sha256(), NULL);
    assert(ret == 1);

    ret = EVP_VerifyUpdate(ctx, attn_report->ias_report, attn_report->ias_report_len);
    assert(ret == 1);

    ret = EVP_VerifyFinal(ctx,
                          attn_report->ias_report_signature,
                          attn_report->ias_report_signature_len,
                          key);
    assert(ret == 1);

    EVP_MD_CTX_destroy(ctx);

    return 0;                   /* success */
}

static
int verify_ias_certificate_chain(attestation_verification_report_t* attn_report) {
    (void) attn_report;

    const unsigned char* p = attn_report->ias_sign_cert;
    X509* crt = d2i_X509(NULL, &p, attn_report->ias_sign_cert_len);
    assert(crt != NULL);

    p = ias_sign_ca_cert_der;
    X509* cacrt = d2i_X509(NULL, &p, ias_sign_ca_cert_der_len);
    assert(crt != NULL);

    X509_STORE* s = X509_STORE_new();
    X509_STORE_add_cert(s, cacrt);
    X509_STORE_CTX* ctx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(ctx, s, crt, NULL);

    int rc = X509_verify_cert(ctx);
    assert(rc == 1);
    
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(s);
    
    return 0;                   /* 1 .. fail, 0 .. success */
}

/**
 * Check if isvEnclaveQuoteStatus is "OK"
 * (cf. https://software.intel.com/sites/default/files/managed/7e/3b/ias-api-spec.pdf,
 * pg. 24).
 *
 * @return 0 if verified successfully, 1 otherwise.
 */
static
int verify_enclave_quote_status
(
    const char* ias_report,
    int   ias_report_len
)
{
    // Move ias_report into \0 terminated buffer such that we can work
    // with str* functions.
    char buf[ias_report_len + 1];
    memcpy(buf, ias_report, ias_report_len);
    buf[ias_report_len] = '\0';
    
    const char* json_string = "\"isvEnclaveQuoteStatus\":\"";
    char* p_begin = strstr(buf, json_string);
    assert(p_begin != NULL);
    p_begin += strlen(json_string);

    const char* status_OK = "OK\"";
    if (0 == strncmp(p_begin, status_OK, strlen(status_OK))) return 0;
#ifdef SGX_GROUP_OUT_OF_DATE
    const char* status_outdated = "GROUP_OUT_OF_DATE\"";
    if (0 == strncmp(p_begin, status_outdated, strlen(status_outdated))) {
        DEBUG_STUB("WARNING: isvEnclaveQuoteStatus is GROUP_OUT_OF_DATE\n");
        return 0;
    }
#endif
    return 1;
}

/**
 * @return 0 if verified successfully, 1 otherwise.
 */
int verify_sgx_cert_extensions
(
    uint8_t* der_crt,
    uint32_t der_crt_len
)
{
    attestation_verification_report_t attn_report;

    int ret;

    const unsigned char* p = der_crt;
    X509* crt = d2i_X509(NULL, &p, der_crt_len);
    assert(crt != NULL);

    extract_x509_extensions(crt, &attn_report);

    ret = verify_ias_certificate_chain(&attn_report);
    assert(ret == 0);

    ret = verify_ias_report_signature(&attn_report);
    assert(ret == 0);

    ret = verify_enclave_quote_status((const char*) attn_report.ias_report,
                                      attn_report.ias_report_len);
    assert(ret == 0);
    
    sgx_quote_t quote = {0, };
    get_quote_from_report(attn_report.ias_report,
                          attn_report.ias_report_len,
                          &quote);
    ret = verify_report_data_against_server_cert(crt, &quote);
    assert(ret == 0);

    return 0;
}
