#ifndef WOLFSSL_ENCLAVE_U_H__
#define WOLFSSL_ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_satus_t etc. */

#include "wolfssl/ssl.h"
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfcrypt/test/test.h"
#include "wolfcrypt/benchmark/benchmark.h"
#include "dns.h"
#include "ra.h"
#include "ra-attester.h"
#include "sgx_report.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));
time_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_time, (time_t* time));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_current_time, (double* time));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_low_res_time, (int* time));
size_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_recv, (int sockfd, void* buf, size_t len, int flags));
size_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_send, (int sockfd, const void* buf, size_t len, int flags));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_connect, (int __fd, struct sockaddr* __addr, socklen_t __len));
size_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_close, (int sockfd));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_socket, (int __domain, int __type, int __protocol));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_bind, (int __fd, struct sockaddr* __addr, socklen_t __len));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_gethostname, (char* __name, size_t __len));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_getpeername, (int __fd, struct sockaddr* __addr, socklen_t __len));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_random, ());
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_select, (int __nfds, fd_set* __readfds, fd_set* __writefds, fd_set* __exceptfds, struct timeval* __timeout, size_t __len));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_init_quote, (sgx_target_info_t* target_info));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_remote_attestation, (sgx_report_t* report, const struct ra_tls_options* opts, attestation_verification_report_t* attn_report));
void SGX_UBRIDGE(SGX_CDECL, sgx_oc_cpuidex, (int cpuinfo[4], int leaf, int subleaf));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));

sgx_status_t wc_test(sgx_enclave_id_t eid, int* retval, void* args);
sgx_status_t wc_benchmark_test(sgx_enclave_id_t eid, int* retval, void* args);
sgx_status_t enc_wolfSSL_Init(sgx_enclave_id_t eid, int* retval);
sgx_status_t enc_wolfSSL_Debugging_ON(sgx_enclave_id_t eid);
sgx_status_t enc_wolfSSL_Debugging_OFF(sgx_enclave_id_t eid);
sgx_status_t enc_wolfTLSv1_2_client_method(sgx_enclave_id_t eid, WOLFSSL_METHOD** retval);
sgx_status_t enc_wolfTLSv1_2_server_method(sgx_enclave_id_t eid, WOLFSSL_METHOD** retval);
sgx_status_t enc_wolfSSL_CTX_new(sgx_enclave_id_t eid, WOLFSSL_CTX** retval, WOLFSSL_METHOD* method);
sgx_status_t enc_wolfSSL_CTX_use_PrivateKey_buffer(sgx_enclave_id_t eid, int* retval, WOLFSSL_CTX* ctx, const unsigned char* buf, long int sz, int type);
sgx_status_t enc_wolfSSL_CTX_load_verify_buffer(sgx_enclave_id_t eid, int* retval, WOLFSSL_CTX* ctx, const unsigned char* buf, long int sz, int type);
sgx_status_t enc_wolfSSL_CTX_use_certificate_chain_buffer_format(sgx_enclave_id_t eid, int* retval, WOLFSSL_CTX* ctx, const unsigned char* buf, long int sz, int type);
sgx_status_t enc_wolfSSL_CTX_use_certificate_buffer(sgx_enclave_id_t eid, int* retval, WOLFSSL_CTX* ctx, const unsigned char* buf, long int sz, int type);
sgx_status_t enc_wolfSSL_CTX_set_cipher_list(sgx_enclave_id_t eid, int* retval, WOLFSSL_CTX* ctx, const char* list);
sgx_status_t enc_wolfSSL_new(sgx_enclave_id_t eid, WOLFSSL** retval, WOLFSSL_CTX* ctx);
sgx_status_t enc_wolfSSL_set_using_nonblock(sgx_enclave_id_t eid, WOLFSSL* ssl, int i);
sgx_status_t enc_wolfSSL_set_fd(sgx_enclave_id_t eid, int* retval, WOLFSSL* ssl, int fd);
sgx_status_t enc_wolfSSL_connect(sgx_enclave_id_t eid, int* retval, WOLFSSL* ssl);
sgx_status_t enc_wolfSSL_write(sgx_enclave_id_t eid, int* retval, WOLFSSL* ssl, const void* in, int sz);
sgx_status_t enc_wolfSSL_get_error(sgx_enclave_id_t eid, int* retval, WOLFSSL* ssl, int ret);
sgx_status_t enc_wolfSSL_is_init_finished(sgx_enclave_id_t eid, int* retval, WOLFSSL* ssl);
sgx_status_t enc_mutex_init(sgx_enclave_id_t eid, int* retval);
sgx_status_t enc_mutex_destroy(sgx_enclave_id_t eid, int* retval);
sgx_status_t enc_wolfSSL_read_from_client(sgx_enclave_id_t eid, int* retval, WOLFSSL* ssl, int connd);
sgx_status_t enc_wolfSSL_write_to_client(sgx_enclave_id_t eid, int* retval, WOLFSSL* ssl, int connd);
sgx_status_t enc_wolfSSL_read(sgx_enclave_id_t eid, int* retval, WOLFSSL* ssl);
sgx_status_t enc_wolfSSL_process_query(sgx_enclave_id_t eid, int* retval, int tid);
sgx_status_t enc_wolfSSL_free(sgx_enclave_id_t eid, WOLFSSL* ssl);
sgx_status_t enc_wolfSSL_CTX_free(sgx_enclave_id_t eid, WOLFSSL_CTX* ctx);
sgx_status_t enc_wolfSSL_Cleanup(sgx_enclave_id_t eid, int* retval);
sgx_status_t enc_load_resconf(sgx_enclave_id_t eid, struct dns_resolv_conf* resconf);
sgx_status_t enc_load_hosts(sgx_enclave_id_t eid, struct dns_hosts* hosts);
sgx_status_t enc_load_hints(sgx_enclave_id_t eid, struct dns_hints* hints);
sgx_status_t enc_create_key_and_x509(sgx_enclave_id_t eid, WOLFSSL_CTX* ctx);
sgx_status_t dummy(sgx_enclave_id_t eid);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
