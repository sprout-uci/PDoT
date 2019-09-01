#include "Wolfssl_Enclave_u.h"
#include <errno.h>

typedef struct ms_wc_test_t {
	int ms_retval;
	void* ms_args;
} ms_wc_test_t;

typedef struct ms_wc_benchmark_test_t {
	int ms_retval;
	void* ms_args;
} ms_wc_benchmark_test_t;

typedef struct ms_enc_wolfSSL_Init_t {
	int ms_retval;
} ms_enc_wolfSSL_Init_t;

typedef struct ms_enc_wolfTLSv1_2_client_method_t {
	WOLFSSL_METHOD* ms_retval;
} ms_enc_wolfTLSv1_2_client_method_t;

typedef struct ms_enc_wolfTLSv1_2_server_method_t {
	WOLFSSL_METHOD* ms_retval;
} ms_enc_wolfTLSv1_2_server_method_t;

typedef struct ms_enc_wolfSSL_CTX_new_t {
	WOLFSSL_CTX* ms_retval;
	WOLFSSL_METHOD* ms_method;
} ms_enc_wolfSSL_CTX_new_t;

typedef struct ms_enc_wolfSSL_CTX_use_PrivateKey_buffer_t {
	int ms_retval;
	WOLFSSL_CTX* ms_ctx;
	unsigned char* ms_buf;
	long int ms_sz;
	int ms_type;
} ms_enc_wolfSSL_CTX_use_PrivateKey_buffer_t;

typedef struct ms_enc_wolfSSL_CTX_load_verify_buffer_t {
	int ms_retval;
	WOLFSSL_CTX* ms_ctx;
	unsigned char* ms_buf;
	long int ms_sz;
	int ms_type;
} ms_enc_wolfSSL_CTX_load_verify_buffer_t;

typedef struct ms_enc_wolfSSL_CTX_use_certificate_chain_buffer_format_t {
	int ms_retval;
	WOLFSSL_CTX* ms_ctx;
	unsigned char* ms_buf;
	long int ms_sz;
	int ms_type;
} ms_enc_wolfSSL_CTX_use_certificate_chain_buffer_format_t;

typedef struct ms_enc_wolfSSL_CTX_use_certificate_buffer_t {
	int ms_retval;
	WOLFSSL_CTX* ms_ctx;
	unsigned char* ms_buf;
	long int ms_sz;
	int ms_type;
} ms_enc_wolfSSL_CTX_use_certificate_buffer_t;

typedef struct ms_enc_wolfSSL_CTX_set_cipher_list_t {
	int ms_retval;
	WOLFSSL_CTX* ms_ctx;
	char* ms_list;
	size_t ms_list_len;
} ms_enc_wolfSSL_CTX_set_cipher_list_t;

typedef struct ms_enc_wolfSSL_new_t {
	WOLFSSL* ms_retval;
	WOLFSSL_CTX* ms_ctx;
} ms_enc_wolfSSL_new_t;

typedef struct ms_enc_wolfSSL_set_using_nonblock_t {
	WOLFSSL* ms_ssl;
	int ms_i;
} ms_enc_wolfSSL_set_using_nonblock_t;

typedef struct ms_enc_wolfSSL_set_fd_t {
	int ms_retval;
	WOLFSSL* ms_ssl;
	int ms_fd;
} ms_enc_wolfSSL_set_fd_t;

typedef struct ms_enc_wolfSSL_connect_t {
	int ms_retval;
	WOLFSSL* ms_ssl;
} ms_enc_wolfSSL_connect_t;

typedef struct ms_enc_wolfSSL_write_t {
	int ms_retval;
	WOLFSSL* ms_ssl;
	void* ms_in;
	int ms_sz;
} ms_enc_wolfSSL_write_t;

typedef struct ms_enc_wolfSSL_get_error_t {
	int ms_retval;
	WOLFSSL* ms_ssl;
	int ms_ret;
} ms_enc_wolfSSL_get_error_t;

typedef struct ms_enc_wolfSSL_is_init_finished_t {
	int ms_retval;
	WOLFSSL* ms_ssl;
} ms_enc_wolfSSL_is_init_finished_t;

typedef struct ms_enc_mutex_init_t {
	int ms_retval;
} ms_enc_mutex_init_t;

typedef struct ms_enc_mutex_destroy_t {
	int ms_retval;
} ms_enc_mutex_destroy_t;

typedef struct ms_enc_wolfSSL_read_from_client_t {
	int ms_retval;
	WOLFSSL* ms_ssl;
	int ms_connd;
} ms_enc_wolfSSL_read_from_client_t;

typedef struct ms_enc_wolfSSL_write_to_client_t {
	int ms_retval;
	WOLFSSL* ms_ssl;
	int ms_connd;
} ms_enc_wolfSSL_write_to_client_t;

typedef struct ms_enc_wolfSSL_read_t {
	int ms_retval;
	WOLFSSL* ms_ssl;
} ms_enc_wolfSSL_read_t;

typedef struct ms_enc_wolfSSL_process_query_t {
	int ms_retval;
	int ms_tid;
} ms_enc_wolfSSL_process_query_t;

typedef struct ms_enc_wolfSSL_free_t {
	WOLFSSL* ms_ssl;
} ms_enc_wolfSSL_free_t;

typedef struct ms_enc_wolfSSL_CTX_free_t {
	WOLFSSL_CTX* ms_ctx;
} ms_enc_wolfSSL_CTX_free_t;

typedef struct ms_enc_wolfSSL_Cleanup_t {
	int ms_retval;
} ms_enc_wolfSSL_Cleanup_t;

typedef struct ms_enc_load_resconf_t {
	struct dns_resolv_conf* ms_resconf;
} ms_enc_load_resconf_t;

typedef struct ms_enc_load_hosts_t {
	struct dns_hosts* ms_hosts;
} ms_enc_load_hosts_t;

typedef struct ms_enc_load_hints_t {
	struct dns_hints* ms_hints;
} ms_enc_load_hints_t;

typedef struct ms_enc_create_key_and_x509_t {
	WOLFSSL_CTX* ms_ctx;
} ms_enc_create_key_and_x509_t;

typedef struct ms_ocall_print_string_t {
	char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_ocall_time_t {
	time_t ms_retval;
	time_t* ms_time;
} ms_ocall_time_t;

typedef struct ms_ocall_current_time_t {
	double* ms_time;
} ms_ocall_current_time_t;

typedef struct ms_ocall_low_res_time_t {
	int* ms_time;
} ms_ocall_low_res_time_t;

typedef struct ms_ocall_recv_t {
	size_t ms_retval;
	int ocall_errno;
	int ms_sockfd;
	void* ms_buf;
	size_t ms_len;
	int ms_flags;
} ms_ocall_recv_t;

typedef struct ms_ocall_send_t {
	size_t ms_retval;
	int ocall_errno;
	int ms_sockfd;
	void* ms_buf;
	size_t ms_len;
	int ms_flags;
} ms_ocall_send_t;

typedef struct ms_ocall_connect_t {
	int ms_retval;
	int ms___fd;
	struct sockaddr* ms___addr;
	socklen_t ms___len;
} ms_ocall_connect_t;

typedef struct ms_ocall_close_t {
	size_t ms_retval;
	int ocall_errno;
	int ms_sockfd;
} ms_ocall_close_t;

typedef struct ms_ocall_socket_t {
	int ms_retval;
	int ocall_errno;
	int ms___domain;
	int ms___type;
	int ms___protocol;
} ms_ocall_socket_t;

typedef struct ms_ocall_bind_t {
	int ms_retval;
	int ocall_errno;
	int ms___fd;
	struct sockaddr* ms___addr;
	socklen_t ms___len;
} ms_ocall_bind_t;

typedef struct ms_ocall_gethostname_t {
	int ms_retval;
	char* ms___name;
	size_t ms___len;
} ms_ocall_gethostname_t;

typedef struct ms_ocall_getpeername_t {
	int ms_retval;
	int ms___fd;
	struct sockaddr* ms___addr;
	socklen_t ms___len;
} ms_ocall_getpeername_t;

typedef struct ms_ocall_random_t {
	int ms_retval;
} ms_ocall_random_t;

typedef struct ms_ocall_select_t {
	int ms_retval;
	int ms___nfds;
	fd_set* ms___readfds;
	fd_set* ms___writefds;
	fd_set* ms___exceptfds;
	struct timeval* ms___timeout;
	size_t ms___len;
} ms_ocall_select_t;

typedef struct ms_ocall_sgx_init_quote_t {
	sgx_target_info_t* ms_target_info;
} ms_ocall_sgx_init_quote_t;

typedef struct ms_ocall_remote_attestation_t {
	sgx_report_t* ms_report;
	struct ra_tls_options* ms_opts;
	attestation_verification_report_t* ms_attn_report;
} ms_ocall_remote_attestation_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	void* ms_waiter;
	void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

static sgx_status_t SGX_CDECL Wolfssl_Enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string((const char*)ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Wolfssl_Enclave_ocall_time(void* pms)
{
	ms_ocall_time_t* ms = SGX_CAST(ms_ocall_time_t*, pms);
	ms->ms_retval = ocall_time(ms->ms_time);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Wolfssl_Enclave_ocall_current_time(void* pms)
{
	ms_ocall_current_time_t* ms = SGX_CAST(ms_ocall_current_time_t*, pms);
	ocall_current_time(ms->ms_time);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Wolfssl_Enclave_ocall_low_res_time(void* pms)
{
	ms_ocall_low_res_time_t* ms = SGX_CAST(ms_ocall_low_res_time_t*, pms);
	ocall_low_res_time(ms->ms_time);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Wolfssl_Enclave_ocall_recv(void* pms)
{
	ms_ocall_recv_t* ms = SGX_CAST(ms_ocall_recv_t*, pms);
	ms->ms_retval = ocall_recv(ms->ms_sockfd, ms->ms_buf, ms->ms_len, ms->ms_flags);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Wolfssl_Enclave_ocall_send(void* pms)
{
	ms_ocall_send_t* ms = SGX_CAST(ms_ocall_send_t*, pms);
	ms->ms_retval = ocall_send(ms->ms_sockfd, (const void*)ms->ms_buf, ms->ms_len, ms->ms_flags);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Wolfssl_Enclave_ocall_connect(void* pms)
{
	ms_ocall_connect_t* ms = SGX_CAST(ms_ocall_connect_t*, pms);
	ms->ms_retval = ocall_connect(ms->ms___fd, ms->ms___addr, ms->ms___len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Wolfssl_Enclave_ocall_close(void* pms)
{
	ms_ocall_close_t* ms = SGX_CAST(ms_ocall_close_t*, pms);
	ms->ms_retval = ocall_close(ms->ms_sockfd);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Wolfssl_Enclave_ocall_socket(void* pms)
{
	ms_ocall_socket_t* ms = SGX_CAST(ms_ocall_socket_t*, pms);
	ms->ms_retval = ocall_socket(ms->ms___domain, ms->ms___type, ms->ms___protocol);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Wolfssl_Enclave_ocall_bind(void* pms)
{
	ms_ocall_bind_t* ms = SGX_CAST(ms_ocall_bind_t*, pms);
	ms->ms_retval = ocall_bind(ms->ms___fd, ms->ms___addr, ms->ms___len);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Wolfssl_Enclave_ocall_gethostname(void* pms)
{
	ms_ocall_gethostname_t* ms = SGX_CAST(ms_ocall_gethostname_t*, pms);
	ms->ms_retval = ocall_gethostname(ms->ms___name, ms->ms___len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Wolfssl_Enclave_ocall_getpeername(void* pms)
{
	ms_ocall_getpeername_t* ms = SGX_CAST(ms_ocall_getpeername_t*, pms);
	ms->ms_retval = ocall_getpeername(ms->ms___fd, ms->ms___addr, ms->ms___len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Wolfssl_Enclave_ocall_random(void* pms)
{
	ms_ocall_random_t* ms = SGX_CAST(ms_ocall_random_t*, pms);
	ms->ms_retval = ocall_random();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Wolfssl_Enclave_ocall_select(void* pms)
{
	ms_ocall_select_t* ms = SGX_CAST(ms_ocall_select_t*, pms);
	ms->ms_retval = ocall_select(ms->ms___nfds, ms->ms___readfds, ms->ms___writefds, ms->ms___exceptfds, ms->ms___timeout, ms->ms___len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Wolfssl_Enclave_ocall_sgx_init_quote(void* pms)
{
	ms_ocall_sgx_init_quote_t* ms = SGX_CAST(ms_ocall_sgx_init_quote_t*, pms);
	ocall_sgx_init_quote(ms->ms_target_info);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Wolfssl_Enclave_ocall_remote_attestation(void* pms)
{
	ms_ocall_remote_attestation_t* ms = SGX_CAST(ms_ocall_remote_attestation_t*, pms);
	ocall_remote_attestation(ms->ms_report, (const struct ra_tls_options*)ms->ms_opts, ms->ms_attn_report);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Wolfssl_Enclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Wolfssl_Enclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall((const void*)ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Wolfssl_Enclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall((const void*)ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Wolfssl_Enclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall((const void*)ms->ms_waiter, (const void*)ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Wolfssl_Enclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall((const void**)ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[21];
} ocall_table_Wolfssl_Enclave = {
	21,
	{
		(void*)Wolfssl_Enclave_ocall_print_string,
		(void*)Wolfssl_Enclave_ocall_time,
		(void*)Wolfssl_Enclave_ocall_current_time,
		(void*)Wolfssl_Enclave_ocall_low_res_time,
		(void*)Wolfssl_Enclave_ocall_recv,
		(void*)Wolfssl_Enclave_ocall_send,
		(void*)Wolfssl_Enclave_ocall_connect,
		(void*)Wolfssl_Enclave_ocall_close,
		(void*)Wolfssl_Enclave_ocall_socket,
		(void*)Wolfssl_Enclave_ocall_bind,
		(void*)Wolfssl_Enclave_ocall_gethostname,
		(void*)Wolfssl_Enclave_ocall_getpeername,
		(void*)Wolfssl_Enclave_ocall_random,
		(void*)Wolfssl_Enclave_ocall_select,
		(void*)Wolfssl_Enclave_ocall_sgx_init_quote,
		(void*)Wolfssl_Enclave_ocall_remote_attestation,
		(void*)Wolfssl_Enclave_sgx_oc_cpuidex,
		(void*)Wolfssl_Enclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)Wolfssl_Enclave_sgx_thread_set_untrusted_event_ocall,
		(void*)Wolfssl_Enclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)Wolfssl_Enclave_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};
sgx_status_t wc_test(sgx_enclave_id_t eid, int* retval, void* args)
{
	sgx_status_t status;
	ms_wc_test_t ms;
	ms.ms_args = args;
	status = sgx_ecall(eid, 0, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t wc_benchmark_test(sgx_enclave_id_t eid, int* retval, void* args)
{
	sgx_status_t status;
	ms_wc_benchmark_test_t ms;
	ms.ms_args = args;
	status = sgx_ecall(eid, 1, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_Init(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_enc_wolfSSL_Init_t ms;
	status = sgx_ecall(eid, 2, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_Debugging_ON(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 3, &ocall_table_Wolfssl_Enclave, NULL);
	return status;
}

sgx_status_t enc_wolfSSL_Debugging_OFF(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 4, &ocall_table_Wolfssl_Enclave, NULL);
	return status;
}

sgx_status_t enc_wolfTLSv1_2_client_method(sgx_enclave_id_t eid, WOLFSSL_METHOD** retval)
{
	sgx_status_t status;
	ms_enc_wolfTLSv1_2_client_method_t ms;
	status = sgx_ecall(eid, 5, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfTLSv1_2_server_method(sgx_enclave_id_t eid, WOLFSSL_METHOD** retval)
{
	sgx_status_t status;
	ms_enc_wolfTLSv1_2_server_method_t ms;
	status = sgx_ecall(eid, 6, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_CTX_new(sgx_enclave_id_t eid, WOLFSSL_CTX** retval, WOLFSSL_METHOD* method)
{
	sgx_status_t status;
	ms_enc_wolfSSL_CTX_new_t ms;
	ms.ms_method = method;
	status = sgx_ecall(eid, 7, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_CTX_use_PrivateKey_buffer(sgx_enclave_id_t eid, int* retval, WOLFSSL_CTX* ctx, const unsigned char* buf, long int sz, int type)
{
	sgx_status_t status;
	ms_enc_wolfSSL_CTX_use_PrivateKey_buffer_t ms;
	ms.ms_ctx = ctx;
	ms.ms_buf = (unsigned char*)buf;
	ms.ms_sz = sz;
	ms.ms_type = type;
	status = sgx_ecall(eid, 8, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_CTX_load_verify_buffer(sgx_enclave_id_t eid, int* retval, WOLFSSL_CTX* ctx, const unsigned char* buf, long int sz, int type)
{
	sgx_status_t status;
	ms_enc_wolfSSL_CTX_load_verify_buffer_t ms;
	ms.ms_ctx = ctx;
	ms.ms_buf = (unsigned char*)buf;
	ms.ms_sz = sz;
	ms.ms_type = type;
	status = sgx_ecall(eid, 9, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_CTX_use_certificate_chain_buffer_format(sgx_enclave_id_t eid, int* retval, WOLFSSL_CTX* ctx, const unsigned char* buf, long int sz, int type)
{
	sgx_status_t status;
	ms_enc_wolfSSL_CTX_use_certificate_chain_buffer_format_t ms;
	ms.ms_ctx = ctx;
	ms.ms_buf = (unsigned char*)buf;
	ms.ms_sz = sz;
	ms.ms_type = type;
	status = sgx_ecall(eid, 10, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_CTX_use_certificate_buffer(sgx_enclave_id_t eid, int* retval, WOLFSSL_CTX* ctx, const unsigned char* buf, long int sz, int type)
{
	sgx_status_t status;
	ms_enc_wolfSSL_CTX_use_certificate_buffer_t ms;
	ms.ms_ctx = ctx;
	ms.ms_buf = (unsigned char*)buf;
	ms.ms_sz = sz;
	ms.ms_type = type;
	status = sgx_ecall(eid, 11, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_CTX_set_cipher_list(sgx_enclave_id_t eid, int* retval, WOLFSSL_CTX* ctx, const char* list)
{
	sgx_status_t status;
	ms_enc_wolfSSL_CTX_set_cipher_list_t ms;
	ms.ms_ctx = ctx;
	ms.ms_list = (char*)list;
	ms.ms_list_len = list ? strlen(list) + 1 : 0;
	status = sgx_ecall(eid, 12, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_new(sgx_enclave_id_t eid, WOLFSSL** retval, WOLFSSL_CTX* ctx)
{
	sgx_status_t status;
	ms_enc_wolfSSL_new_t ms;
	ms.ms_ctx = ctx;
	status = sgx_ecall(eid, 13, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_set_using_nonblock(sgx_enclave_id_t eid, WOLFSSL* ssl, int i)
{
	sgx_status_t status;
	ms_enc_wolfSSL_set_using_nonblock_t ms;
	ms.ms_ssl = ssl;
	ms.ms_i = i;
	status = sgx_ecall(eid, 14, &ocall_table_Wolfssl_Enclave, &ms);
	return status;
}

sgx_status_t enc_wolfSSL_set_fd(sgx_enclave_id_t eid, int* retval, WOLFSSL* ssl, int fd)
{
	sgx_status_t status;
	ms_enc_wolfSSL_set_fd_t ms;
	ms.ms_ssl = ssl;
	ms.ms_fd = fd;
	status = sgx_ecall(eid, 15, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_connect(sgx_enclave_id_t eid, int* retval, WOLFSSL* ssl)
{
	sgx_status_t status;
	ms_enc_wolfSSL_connect_t ms;
	ms.ms_ssl = ssl;
	status = sgx_ecall(eid, 16, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_write(sgx_enclave_id_t eid, int* retval, WOLFSSL* ssl, const void* in, int sz)
{
	sgx_status_t status;
	ms_enc_wolfSSL_write_t ms;
	ms.ms_ssl = ssl;
	ms.ms_in = (void*)in;
	ms.ms_sz = sz;
	status = sgx_ecall(eid, 17, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_get_error(sgx_enclave_id_t eid, int* retval, WOLFSSL* ssl, int ret)
{
	sgx_status_t status;
	ms_enc_wolfSSL_get_error_t ms;
	ms.ms_ssl = ssl;
	ms.ms_ret = ret;
	status = sgx_ecall(eid, 18, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_is_init_finished(sgx_enclave_id_t eid, int* retval, WOLFSSL* ssl)
{
	sgx_status_t status;
	ms_enc_wolfSSL_is_init_finished_t ms;
	ms.ms_ssl = ssl;
	status = sgx_ecall(eid, 19, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_mutex_init(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_enc_mutex_init_t ms;
	status = sgx_ecall(eid, 20, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_mutex_destroy(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_enc_mutex_destroy_t ms;
	status = sgx_ecall(eid, 21, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_read_from_client(sgx_enclave_id_t eid, int* retval, WOLFSSL* ssl, int connd)
{
	sgx_status_t status;
	ms_enc_wolfSSL_read_from_client_t ms;
	ms.ms_ssl = ssl;
	ms.ms_connd = connd;
	status = sgx_ecall(eid, 22, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_write_to_client(sgx_enclave_id_t eid, int* retval, WOLFSSL* ssl, int connd)
{
	sgx_status_t status;
	ms_enc_wolfSSL_write_to_client_t ms;
	ms.ms_ssl = ssl;
	ms.ms_connd = connd;
	status = sgx_ecall(eid, 23, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_read(sgx_enclave_id_t eid, int* retval, WOLFSSL* ssl)
{
	sgx_status_t status;
	ms_enc_wolfSSL_read_t ms;
	ms.ms_ssl = ssl;
	status = sgx_ecall(eid, 24, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_process_query(sgx_enclave_id_t eid, int* retval, int tid)
{
	sgx_status_t status;
	ms_enc_wolfSSL_process_query_t ms;
	ms.ms_tid = tid;
	status = sgx_ecall(eid, 25, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_free(sgx_enclave_id_t eid, WOLFSSL* ssl)
{
	sgx_status_t status;
	ms_enc_wolfSSL_free_t ms;
	ms.ms_ssl = ssl;
	status = sgx_ecall(eid, 26, &ocall_table_Wolfssl_Enclave, &ms);
	return status;
}

sgx_status_t enc_wolfSSL_CTX_free(sgx_enclave_id_t eid, WOLFSSL_CTX* ctx)
{
	sgx_status_t status;
	ms_enc_wolfSSL_CTX_free_t ms;
	ms.ms_ctx = ctx;
	status = sgx_ecall(eid, 27, &ocall_table_Wolfssl_Enclave, &ms);
	return status;
}

sgx_status_t enc_wolfSSL_Cleanup(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_enc_wolfSSL_Cleanup_t ms;
	status = sgx_ecall(eid, 28, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_load_resconf(sgx_enclave_id_t eid, struct dns_resolv_conf* resconf)
{
	sgx_status_t status;
	ms_enc_load_resconf_t ms;
	ms.ms_resconf = resconf;
	status = sgx_ecall(eid, 29, &ocall_table_Wolfssl_Enclave, &ms);
	return status;
}

sgx_status_t enc_load_hosts(sgx_enclave_id_t eid, struct dns_hosts* hosts)
{
	sgx_status_t status;
	ms_enc_load_hosts_t ms;
	ms.ms_hosts = hosts;
	status = sgx_ecall(eid, 30, &ocall_table_Wolfssl_Enclave, &ms);
	return status;
}

sgx_status_t enc_load_hints(sgx_enclave_id_t eid, struct dns_hints* hints)
{
	sgx_status_t status;
	ms_enc_load_hints_t ms;
	ms.ms_hints = hints;
	status = sgx_ecall(eid, 31, &ocall_table_Wolfssl_Enclave, &ms);
	return status;
}

sgx_status_t enc_create_key_and_x509(sgx_enclave_id_t eid, WOLFSSL_CTX* ctx)
{
	sgx_status_t status;
	ms_enc_create_key_and_x509_t ms;
	ms.ms_ctx = ctx;
	status = sgx_ecall(eid, 32, &ocall_table_Wolfssl_Enclave, &ms);
	return status;
}

sgx_status_t dummy(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 33, &ocall_table_Wolfssl_Enclave, NULL);
	return status;
}

