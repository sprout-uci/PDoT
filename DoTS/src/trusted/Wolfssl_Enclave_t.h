#ifndef WOLFSSL_ENCLAVE_T_H__
#define WOLFSSL_ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

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

int wc_test(void* args);
int wc_benchmark_test(void* args);
int enc_wolfSSL_Init();
void enc_wolfSSL_Debugging_ON();
void enc_wolfSSL_Debugging_OFF();
WOLFSSL_METHOD* enc_wolfTLSv1_2_client_method();
WOLFSSL_METHOD* enc_wolfTLSv1_2_server_method();
WOLFSSL_CTX* enc_wolfSSL_CTX_new(WOLFSSL_METHOD* method);
int enc_wolfSSL_CTX_use_PrivateKey_buffer(WOLFSSL_CTX* ctx, const unsigned char* buf, long int sz, int type);
int enc_wolfSSL_CTX_load_verify_buffer(WOLFSSL_CTX* ctx, const unsigned char* buf, long int sz, int type);
int enc_wolfSSL_CTX_use_certificate_chain_buffer_format(WOLFSSL_CTX* ctx, const unsigned char* buf, long int sz, int type);
int enc_wolfSSL_CTX_use_certificate_buffer(WOLFSSL_CTX* ctx, const unsigned char* buf, long int sz, int type);
int enc_wolfSSL_CTX_set_cipher_list(WOLFSSL_CTX* ctx, const char* list);
WOLFSSL* enc_wolfSSL_new(WOLFSSL_CTX* ctx);
void enc_wolfSSL_set_using_nonblock(WOLFSSL* ssl, int i);
int enc_wolfSSL_set_fd(WOLFSSL* ssl, int fd);
int enc_wolfSSL_connect(WOLFSSL* ssl);
int enc_wolfSSL_write(WOLFSSL* ssl, const void* in, int sz);
int enc_wolfSSL_get_error(WOLFSSL* ssl, int ret);
int enc_wolfSSL_is_init_finished(WOLFSSL* ssl);
int enc_mutex_init();
int enc_mutex_destroy();
int enc_wolfSSL_read_from_client(WOLFSSL* ssl, int connd);
int enc_wolfSSL_write_to_client(WOLFSSL* ssl, int connd);
int enc_wolfSSL_read(WOLFSSL* ssl);
int enc_wolfSSL_process_query(int tid);
void enc_wolfSSL_free(WOLFSSL* ssl);
void enc_wolfSSL_CTX_free(WOLFSSL_CTX* ctx);
int enc_wolfSSL_Cleanup();
void enc_load_resconf(struct dns_resolv_conf* resconf);
void enc_load_hosts(struct dns_hosts* hosts);
void enc_load_hints(struct dns_hints* hints);
void enc_create_key_and_x509(WOLFSSL_CTX* ctx);
void dummy();

sgx_status_t SGX_CDECL ocall_print_string(const char* str);
sgx_status_t SGX_CDECL ocall_time(time_t* retval, time_t* time);
sgx_status_t SGX_CDECL ocall_current_time(double* time);
sgx_status_t SGX_CDECL ocall_low_res_time(int* time);
sgx_status_t SGX_CDECL ocall_recv(size_t* retval, int sockfd, void* buf, size_t len, int flags);
sgx_status_t SGX_CDECL ocall_send(size_t* retval, int sockfd, const void* buf, size_t len, int flags);
sgx_status_t SGX_CDECL ocall_connect(int* retval, int __fd, struct sockaddr* __addr, socklen_t __len);
sgx_status_t SGX_CDECL ocall_close(size_t* retval, int sockfd);
sgx_status_t SGX_CDECL ocall_socket(int* retval, int __domain, int __type, int __protocol);
sgx_status_t SGX_CDECL ocall_bind(int* retval, int __fd, struct sockaddr* __addr, socklen_t __len);
sgx_status_t SGX_CDECL ocall_gethostname(int* retval, char* __name, size_t __len);
sgx_status_t SGX_CDECL ocall_getpeername(int* retval, int __fd, struct sockaddr* __addr, socklen_t __len);
sgx_status_t SGX_CDECL ocall_random(int* retval);
sgx_status_t SGX_CDECL ocall_select(int* retval, int __nfds, fd_set* __readfds, fd_set* __writefds, fd_set* __exceptfds, struct timeval* __timeout, size_t __len);
sgx_status_t SGX_CDECL ocall_sgx_init_quote(sgx_target_info_t* target_info);
sgx_status_t SGX_CDECL ocall_remote_attestation(sgx_report_t* report, const struct ra_tls_options* opts, attestation_verification_report_t* attn_report);
sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
