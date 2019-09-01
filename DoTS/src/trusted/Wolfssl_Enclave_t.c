#include "Wolfssl_Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <string.h> /* for memcpy etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)


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

static sgx_status_t SGX_CDECL sgx_wc_test(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_wc_test_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_wc_test_t* ms = SGX_CAST(ms_wc_test_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_args = ms->ms_args;



	ms->ms_retval = wc_test(_tmp_args);


	return status;
}

static sgx_status_t SGX_CDECL sgx_wc_benchmark_test(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_wc_benchmark_test_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_wc_benchmark_test_t* ms = SGX_CAST(ms_wc_benchmark_test_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_args = ms->ms_args;



	ms->ms_retval = wc_benchmark_test(_tmp_args);


	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_Init(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_Init_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_Init_t* ms = SGX_CAST(ms_enc_wolfSSL_Init_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = enc_wolfSSL_Init();


	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_Debugging_ON(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	enc_wolfSSL_Debugging_ON();
	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_Debugging_OFF(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	enc_wolfSSL_Debugging_OFF();
	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfTLSv1_2_client_method(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfTLSv1_2_client_method_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfTLSv1_2_client_method_t* ms = SGX_CAST(ms_enc_wolfTLSv1_2_client_method_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = enc_wolfTLSv1_2_client_method();


	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfTLSv1_2_server_method(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfTLSv1_2_server_method_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfTLSv1_2_server_method_t* ms = SGX_CAST(ms_enc_wolfTLSv1_2_server_method_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = enc_wolfTLSv1_2_server_method();


	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_CTX_new(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_CTX_new_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_CTX_new_t* ms = SGX_CAST(ms_enc_wolfSSL_CTX_new_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	WOLFSSL_METHOD* _tmp_method = ms->ms_method;



	ms->ms_retval = enc_wolfSSL_CTX_new(_tmp_method);


	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_CTX_use_PrivateKey_buffer(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_CTX_use_PrivateKey_buffer_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_CTX_use_PrivateKey_buffer_t* ms = SGX_CAST(ms_enc_wolfSSL_CTX_use_PrivateKey_buffer_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	WOLFSSL_CTX* _tmp_ctx = ms->ms_ctx;
	unsigned char* _tmp_buf = ms->ms_buf;
	long int _tmp_sz = ms->ms_sz;
	size_t _len_buf = _tmp_sz;
	unsigned char* _in_buf = NULL;

	CHECK_UNIQUE_POINTER(_tmp_buf, _len_buf);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_buf != NULL && _len_buf != 0) {
		_in_buf = (unsigned char*)malloc(_len_buf);
		if (_in_buf == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_buf, _tmp_buf, _len_buf);
	}

	ms->ms_retval = enc_wolfSSL_CTX_use_PrivateKey_buffer(_tmp_ctx, (const unsigned char*)_in_buf, _tmp_sz, ms->ms_type);
err:
	if (_in_buf) free((void*)_in_buf);

	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_CTX_load_verify_buffer(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_CTX_load_verify_buffer_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_CTX_load_verify_buffer_t* ms = SGX_CAST(ms_enc_wolfSSL_CTX_load_verify_buffer_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	WOLFSSL_CTX* _tmp_ctx = ms->ms_ctx;
	unsigned char* _tmp_buf = ms->ms_buf;
	long int _tmp_sz = ms->ms_sz;
	size_t _len_buf = _tmp_sz;
	unsigned char* _in_buf = NULL;

	CHECK_UNIQUE_POINTER(_tmp_buf, _len_buf);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_buf != NULL && _len_buf != 0) {
		_in_buf = (unsigned char*)malloc(_len_buf);
		if (_in_buf == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_buf, _tmp_buf, _len_buf);
	}

	ms->ms_retval = enc_wolfSSL_CTX_load_verify_buffer(_tmp_ctx, (const unsigned char*)_in_buf, _tmp_sz, ms->ms_type);
err:
	if (_in_buf) free((void*)_in_buf);

	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_CTX_use_certificate_chain_buffer_format(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_CTX_use_certificate_chain_buffer_format_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_CTX_use_certificate_chain_buffer_format_t* ms = SGX_CAST(ms_enc_wolfSSL_CTX_use_certificate_chain_buffer_format_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	WOLFSSL_CTX* _tmp_ctx = ms->ms_ctx;
	unsigned char* _tmp_buf = ms->ms_buf;
	long int _tmp_sz = ms->ms_sz;
	size_t _len_buf = _tmp_sz;
	unsigned char* _in_buf = NULL;

	CHECK_UNIQUE_POINTER(_tmp_buf, _len_buf);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_buf != NULL && _len_buf != 0) {
		_in_buf = (unsigned char*)malloc(_len_buf);
		if (_in_buf == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_buf, _tmp_buf, _len_buf);
	}

	ms->ms_retval = enc_wolfSSL_CTX_use_certificate_chain_buffer_format(_tmp_ctx, (const unsigned char*)_in_buf, _tmp_sz, ms->ms_type);
err:
	if (_in_buf) free((void*)_in_buf);

	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_CTX_use_certificate_buffer(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_CTX_use_certificate_buffer_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_CTX_use_certificate_buffer_t* ms = SGX_CAST(ms_enc_wolfSSL_CTX_use_certificate_buffer_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	WOLFSSL_CTX* _tmp_ctx = ms->ms_ctx;
	unsigned char* _tmp_buf = ms->ms_buf;
	long int _tmp_sz = ms->ms_sz;
	size_t _len_buf = _tmp_sz;
	unsigned char* _in_buf = NULL;

	CHECK_UNIQUE_POINTER(_tmp_buf, _len_buf);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_buf != NULL && _len_buf != 0) {
		_in_buf = (unsigned char*)malloc(_len_buf);
		if (_in_buf == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_buf, _tmp_buf, _len_buf);
	}

	ms->ms_retval = enc_wolfSSL_CTX_use_certificate_buffer(_tmp_ctx, (const unsigned char*)_in_buf, _tmp_sz, ms->ms_type);
err:
	if (_in_buf) free((void*)_in_buf);

	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_CTX_set_cipher_list(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_CTX_set_cipher_list_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_CTX_set_cipher_list_t* ms = SGX_CAST(ms_enc_wolfSSL_CTX_set_cipher_list_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	WOLFSSL_CTX* _tmp_ctx = ms->ms_ctx;
	char* _tmp_list = ms->ms_list;
	size_t _len_list = ms->ms_list_len ;
	char* _in_list = NULL;

	CHECK_UNIQUE_POINTER(_tmp_list, _len_list);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_list != NULL && _len_list != 0) {
		_in_list = (char*)malloc(_len_list);
		if (_in_list == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_list, _tmp_list, _len_list);
		_in_list[_len_list - 1] = '\0';
		if (_len_list != strlen(_in_list) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

	ms->ms_retval = enc_wolfSSL_CTX_set_cipher_list(_tmp_ctx, (const char*)_in_list);
err:
	if (_in_list) free((void*)_in_list);

	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_new(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_new_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_new_t* ms = SGX_CAST(ms_enc_wolfSSL_new_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	WOLFSSL_CTX* _tmp_ctx = ms->ms_ctx;



	ms->ms_retval = enc_wolfSSL_new(_tmp_ctx);


	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_set_using_nonblock(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_set_using_nonblock_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_set_using_nonblock_t* ms = SGX_CAST(ms_enc_wolfSSL_set_using_nonblock_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	WOLFSSL* _tmp_ssl = ms->ms_ssl;



	enc_wolfSSL_set_using_nonblock(_tmp_ssl, ms->ms_i);


	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_set_fd(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_set_fd_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_set_fd_t* ms = SGX_CAST(ms_enc_wolfSSL_set_fd_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	WOLFSSL* _tmp_ssl = ms->ms_ssl;



	ms->ms_retval = enc_wolfSSL_set_fd(_tmp_ssl, ms->ms_fd);


	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_connect(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_connect_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_connect_t* ms = SGX_CAST(ms_enc_wolfSSL_connect_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	WOLFSSL* _tmp_ssl = ms->ms_ssl;



	ms->ms_retval = enc_wolfSSL_connect(_tmp_ssl);


	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_write(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_write_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_write_t* ms = SGX_CAST(ms_enc_wolfSSL_write_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	WOLFSSL* _tmp_ssl = ms->ms_ssl;
	void* _tmp_in = ms->ms_in;
	int _tmp_sz = ms->ms_sz;
	size_t _len_in = _tmp_sz;
	void* _in_in = NULL;

	CHECK_UNIQUE_POINTER(_tmp_in, _len_in);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_in != NULL && _len_in != 0) {
		_in_in = (void*)malloc(_len_in);
		if (_in_in == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_in, _tmp_in, _len_in);
	}

	ms->ms_retval = enc_wolfSSL_write(_tmp_ssl, (const void*)_in_in, _tmp_sz);
err:
	if (_in_in) free((void*)_in_in);

	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_get_error(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_get_error_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_get_error_t* ms = SGX_CAST(ms_enc_wolfSSL_get_error_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	WOLFSSL* _tmp_ssl = ms->ms_ssl;



	ms->ms_retval = enc_wolfSSL_get_error(_tmp_ssl, ms->ms_ret);


	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_is_init_finished(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_is_init_finished_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_is_init_finished_t* ms = SGX_CAST(ms_enc_wolfSSL_is_init_finished_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	WOLFSSL* _tmp_ssl = ms->ms_ssl;



	ms->ms_retval = enc_wolfSSL_is_init_finished(_tmp_ssl);


	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_mutex_init(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_mutex_init_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_mutex_init_t* ms = SGX_CAST(ms_enc_mutex_init_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = enc_mutex_init();


	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_mutex_destroy(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_mutex_destroy_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_mutex_destroy_t* ms = SGX_CAST(ms_enc_mutex_destroy_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = enc_mutex_destroy();


	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_read_from_client(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_read_from_client_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_read_from_client_t* ms = SGX_CAST(ms_enc_wolfSSL_read_from_client_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	WOLFSSL* _tmp_ssl = ms->ms_ssl;



	ms->ms_retval = enc_wolfSSL_read_from_client(_tmp_ssl, ms->ms_connd);


	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_write_to_client(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_write_to_client_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_write_to_client_t* ms = SGX_CAST(ms_enc_wolfSSL_write_to_client_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	WOLFSSL* _tmp_ssl = ms->ms_ssl;



	ms->ms_retval = enc_wolfSSL_write_to_client(_tmp_ssl, ms->ms_connd);


	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_read(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_read_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_read_t* ms = SGX_CAST(ms_enc_wolfSSL_read_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	WOLFSSL* _tmp_ssl = ms->ms_ssl;



	ms->ms_retval = enc_wolfSSL_read(_tmp_ssl);


	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_process_query(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_process_query_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_process_query_t* ms = SGX_CAST(ms_enc_wolfSSL_process_query_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = enc_wolfSSL_process_query(ms->ms_tid);


	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_free(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_free_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_free_t* ms = SGX_CAST(ms_enc_wolfSSL_free_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	WOLFSSL* _tmp_ssl = ms->ms_ssl;



	enc_wolfSSL_free(_tmp_ssl);


	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_CTX_free(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_CTX_free_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_CTX_free_t* ms = SGX_CAST(ms_enc_wolfSSL_CTX_free_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	WOLFSSL_CTX* _tmp_ctx = ms->ms_ctx;



	enc_wolfSSL_CTX_free(_tmp_ctx);


	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_Cleanup(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_Cleanup_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_Cleanup_t* ms = SGX_CAST(ms_enc_wolfSSL_Cleanup_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = enc_wolfSSL_Cleanup();


	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_load_resconf(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_load_resconf_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_load_resconf_t* ms = SGX_CAST(ms_enc_load_resconf_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	struct dns_resolv_conf* _tmp_resconf = ms->ms_resconf;



	enc_load_resconf(_tmp_resconf);


	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_load_hosts(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_load_hosts_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_load_hosts_t* ms = SGX_CAST(ms_enc_load_hosts_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	struct dns_hosts* _tmp_hosts = ms->ms_hosts;



	enc_load_hosts(_tmp_hosts);


	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_load_hints(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_load_hints_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_load_hints_t* ms = SGX_CAST(ms_enc_load_hints_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	struct dns_hints* _tmp_hints = ms->ms_hints;



	enc_load_hints(_tmp_hints);


	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_create_key_and_x509(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_create_key_and_x509_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_create_key_and_x509_t* ms = SGX_CAST(ms_enc_create_key_and_x509_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	WOLFSSL_CTX* _tmp_ctx = ms->ms_ctx;



	enc_create_key_and_x509(_tmp_ctx);


	return status;
}

static sgx_status_t SGX_CDECL sgx_dummy(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	dummy();
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[34];
} g_ecall_table = {
	34,
	{
		{(void*)(uintptr_t)sgx_wc_test, 0},
		{(void*)(uintptr_t)sgx_wc_benchmark_test, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_Init, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_Debugging_ON, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_Debugging_OFF, 0},
		{(void*)(uintptr_t)sgx_enc_wolfTLSv1_2_client_method, 0},
		{(void*)(uintptr_t)sgx_enc_wolfTLSv1_2_server_method, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_CTX_new, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_CTX_use_PrivateKey_buffer, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_CTX_load_verify_buffer, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_CTX_use_certificate_chain_buffer_format, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_CTX_use_certificate_buffer, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_CTX_set_cipher_list, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_new, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_set_using_nonblock, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_set_fd, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_connect, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_write, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_get_error, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_is_init_finished, 0},
		{(void*)(uintptr_t)sgx_enc_mutex_init, 0},
		{(void*)(uintptr_t)sgx_enc_mutex_destroy, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_read_from_client, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_write_to_client, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_read, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_process_query, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_free, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_CTX_free, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_Cleanup, 0},
		{(void*)(uintptr_t)sgx_enc_load_resconf, 0},
		{(void*)(uintptr_t)sgx_enc_load_hosts, 0},
		{(void*)(uintptr_t)sgx_enc_load_hints, 0},
		{(void*)(uintptr_t)sgx_enc_create_key_and_x509, 0},
		{(void*)(uintptr_t)sgx_dummy, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[21][34];
} g_dyn_entry_table = {
	21,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_print_string(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_string_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_string_t);
	void *__tmp = NULL;

	ocalloc_size += (str != NULL && sgx_is_within_enclave(str, _len_str)) ? _len_str : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_string_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_string_t));

	if (str != NULL && sgx_is_within_enclave(str, _len_str)) {
		ms->ms_str = (char*)__tmp;
		memcpy(__tmp, str, _len_str);
		__tmp = (void *)((size_t)__tmp + _len_str);
	} else if (str == NULL) {
		ms->ms_str = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_time(time_t* retval, time_t* time)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_time = sizeof(time_t);

	ms_ocall_time_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_time_t);
	void *__tmp = NULL;

	void *__tmp_time = NULL;
	ocalloc_size += (time != NULL && sgx_is_within_enclave(time, _len_time)) ? _len_time : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_time_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_time_t));

	if (time != NULL && sgx_is_within_enclave(time, _len_time)) {
		ms->ms_time = (time_t*)__tmp;
		__tmp_time = __tmp;
		memset(__tmp_time, 0, _len_time);
		__tmp = (void *)((size_t)__tmp + _len_time);
	} else if (time == NULL) {
		ms->ms_time = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (time) memcpy((void*)time, __tmp_time, _len_time);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_current_time(double* time)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_time = sizeof(double);

	ms_ocall_current_time_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_current_time_t);
	void *__tmp = NULL;

	void *__tmp_time = NULL;
	ocalloc_size += (time != NULL && sgx_is_within_enclave(time, _len_time)) ? _len_time : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_current_time_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_current_time_t));

	if (time != NULL && sgx_is_within_enclave(time, _len_time)) {
		ms->ms_time = (double*)__tmp;
		__tmp_time = __tmp;
		memset(__tmp_time, 0, _len_time);
		__tmp = (void *)((size_t)__tmp + _len_time);
	} else if (time == NULL) {
		ms->ms_time = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
		if (time) memcpy((void*)time, __tmp_time, _len_time);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_low_res_time(int* time)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_time = sizeof(int);

	ms_ocall_low_res_time_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_low_res_time_t);
	void *__tmp = NULL;

	void *__tmp_time = NULL;
	ocalloc_size += (time != NULL && sgx_is_within_enclave(time, _len_time)) ? _len_time : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_low_res_time_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_low_res_time_t));

	if (time != NULL && sgx_is_within_enclave(time, _len_time)) {
		ms->ms_time = (int*)__tmp;
		__tmp_time = __tmp;
		memset(__tmp_time, 0, _len_time);
		__tmp = (void *)((size_t)__tmp + _len_time);
	} else if (time == NULL) {
		ms->ms_time = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
		if (time) memcpy((void*)time, __tmp_time, _len_time);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_recv(size_t* retval, int sockfd, void* buf, size_t len, int flags)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = len;

	ms_ocall_recv_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_recv_t);
	void *__tmp = NULL;

	void *__tmp_buf = NULL;
	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_recv_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_recv_t));

	ms->ms_sockfd = sockfd;
	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (void*)__tmp;
		__tmp_buf = __tmp;
		memset(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_len = len;
	ms->ms_flags = flags;
	status = sgx_ocall(4, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (buf) memcpy((void*)buf, __tmp_buf, _len_buf);
		errno = ms->ocall_errno;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_send(size_t* retval, int sockfd, const void* buf, size_t len, int flags)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = len;

	ms_ocall_send_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_send_t);
	void *__tmp = NULL;

	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_send_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_send_t));

	ms->ms_sockfd = sockfd;
	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (void*)__tmp;
		memcpy(__tmp, buf, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_len = len;
	ms->ms_flags = flags;
	status = sgx_ocall(5, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		errno = ms->ocall_errno;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_connect(int* retval, int __fd, struct sockaddr* __addr, socklen_t __len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len___addr = __len;

	ms_ocall_connect_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_connect_t);
	void *__tmp = NULL;

	ocalloc_size += (__addr != NULL && sgx_is_within_enclave(__addr, _len___addr)) ? _len___addr : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_connect_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_connect_t));

	ms->ms___fd = __fd;
	if (__addr != NULL && sgx_is_within_enclave(__addr, _len___addr)) {
		ms->ms___addr = (struct sockaddr*)__tmp;
		memcpy(__tmp, __addr, _len___addr);
		__tmp = (void *)((size_t)__tmp + _len___addr);
	} else if (__addr == NULL) {
		ms->ms___addr = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms___len = __len;
	status = sgx_ocall(6, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_close(size_t* retval, int sockfd)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_close_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_close_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_close_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_close_t));

	ms->ms_sockfd = sockfd;
	status = sgx_ocall(7, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		errno = ms->ocall_errno;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_socket(int* retval, int __domain, int __type, int __protocol)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_socket_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_socket_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_socket_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_socket_t));

	ms->ms___domain = __domain;
	ms->ms___type = __type;
	ms->ms___protocol = __protocol;
	status = sgx_ocall(8, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		errno = ms->ocall_errno;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_bind(int* retval, int __fd, struct sockaddr* __addr, socklen_t __len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len___addr = __len;

	ms_ocall_bind_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_bind_t);
	void *__tmp = NULL;

	ocalloc_size += (__addr != NULL && sgx_is_within_enclave(__addr, _len___addr)) ? _len___addr : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_bind_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_bind_t));

	ms->ms___fd = __fd;
	if (__addr != NULL && sgx_is_within_enclave(__addr, _len___addr)) {
		ms->ms___addr = (struct sockaddr*)__tmp;
		memcpy(__tmp, __addr, _len___addr);
		__tmp = (void *)((size_t)__tmp + _len___addr);
	} else if (__addr == NULL) {
		ms->ms___addr = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms___len = __len;
	status = sgx_ocall(9, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		errno = ms->ocall_errno;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_gethostname(int* retval, char* __name, size_t __len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len___name = __len;

	ms_ocall_gethostname_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_gethostname_t);
	void *__tmp = NULL;

	ocalloc_size += (__name != NULL && sgx_is_within_enclave(__name, _len___name)) ? _len___name : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_gethostname_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_gethostname_t));

	if (__name != NULL && sgx_is_within_enclave(__name, _len___name)) {
		ms->ms___name = (char*)__tmp;
		memcpy(__tmp, __name, _len___name);
		__tmp = (void *)((size_t)__tmp + _len___name);
	} else if (__name == NULL) {
		ms->ms___name = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms___len = __len;
	status = sgx_ocall(10, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_getpeername(int* retval, int __fd, struct sockaddr* __addr, socklen_t __len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len___addr = __len;

	ms_ocall_getpeername_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_getpeername_t);
	void *__tmp = NULL;

	ocalloc_size += (__addr != NULL && sgx_is_within_enclave(__addr, _len___addr)) ? _len___addr : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_getpeername_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_getpeername_t));

	ms->ms___fd = __fd;
	if (__addr != NULL && sgx_is_within_enclave(__addr, _len___addr)) {
		ms->ms___addr = (struct sockaddr*)__tmp;
		memcpy(__tmp, __addr, _len___addr);
		__tmp = (void *)((size_t)__tmp + _len___addr);
	} else if (__addr == NULL) {
		ms->ms___addr = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms___len = __len;
	status = sgx_ocall(11, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_random(int* retval)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_random_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_random_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_random_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_random_t));

	status = sgx_ocall(12, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_select(int* retval, int __nfds, fd_set* __readfds, fd_set* __writefds, fd_set* __exceptfds, struct timeval* __timeout, size_t __len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len___readfds = 1024;
	size_t _len___writefds = 1024;
	size_t _len___exceptfds = 1024;
	size_t _len___timeout = __len;

	ms_ocall_select_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_select_t);
	void *__tmp = NULL;

	ocalloc_size += (__readfds != NULL && sgx_is_within_enclave(__readfds, _len___readfds)) ? _len___readfds : 0;
	ocalloc_size += (__writefds != NULL && sgx_is_within_enclave(__writefds, _len___writefds)) ? _len___writefds : 0;
	ocalloc_size += (__exceptfds != NULL && sgx_is_within_enclave(__exceptfds, _len___exceptfds)) ? _len___exceptfds : 0;
	ocalloc_size += (__timeout != NULL && sgx_is_within_enclave(__timeout, _len___timeout)) ? _len___timeout : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_select_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_select_t));

	ms->ms___nfds = __nfds;
	if (__readfds != NULL && sgx_is_within_enclave(__readfds, _len___readfds)) {
		ms->ms___readfds = (fd_set*)__tmp;
		memcpy(__tmp, __readfds, _len___readfds);
		__tmp = (void *)((size_t)__tmp + _len___readfds);
	} else if (__readfds == NULL) {
		ms->ms___readfds = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (__writefds != NULL && sgx_is_within_enclave(__writefds, _len___writefds)) {
		ms->ms___writefds = (fd_set*)__tmp;
		memcpy(__tmp, __writefds, _len___writefds);
		__tmp = (void *)((size_t)__tmp + _len___writefds);
	} else if (__writefds == NULL) {
		ms->ms___writefds = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (__exceptfds != NULL && sgx_is_within_enclave(__exceptfds, _len___exceptfds)) {
		ms->ms___exceptfds = (fd_set*)__tmp;
		memcpy(__tmp, __exceptfds, _len___exceptfds);
		__tmp = (void *)((size_t)__tmp + _len___exceptfds);
	} else if (__exceptfds == NULL) {
		ms->ms___exceptfds = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (__timeout != NULL && sgx_is_within_enclave(__timeout, _len___timeout)) {
		ms->ms___timeout = (struct timeval*)__tmp;
		memcpy(__tmp, __timeout, _len___timeout);
		__tmp = (void *)((size_t)__tmp + _len___timeout);
	} else if (__timeout == NULL) {
		ms->ms___timeout = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms___len = __len;
	status = sgx_ocall(13, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_init_quote(sgx_target_info_t* target_info)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_target_info = sizeof(sgx_target_info_t);

	ms_ocall_sgx_init_quote_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_init_quote_t);
	void *__tmp = NULL;

	void *__tmp_target_info = NULL;
	ocalloc_size += (target_info != NULL && sgx_is_within_enclave(target_info, _len_target_info)) ? _len_target_info : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_init_quote_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_init_quote_t));

	if (target_info != NULL && sgx_is_within_enclave(target_info, _len_target_info)) {
		ms->ms_target_info = (sgx_target_info_t*)__tmp;
		__tmp_target_info = __tmp;
		memset(__tmp_target_info, 0, _len_target_info);
		__tmp = (void *)((size_t)__tmp + _len_target_info);
	} else if (target_info == NULL) {
		ms->ms_target_info = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(14, ms);

	if (status == SGX_SUCCESS) {
		if (target_info) memcpy((void*)target_info, __tmp_target_info, _len_target_info);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_remote_attestation(sgx_report_t* report, const struct ra_tls_options* opts, attestation_verification_report_t* attn_report)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_report = sizeof(sgx_report_t);
	size_t _len_opts = sizeof(struct ra_tls_options);
	size_t _len_attn_report = sizeof(attestation_verification_report_t);

	ms_ocall_remote_attestation_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_remote_attestation_t);
	void *__tmp = NULL;

	void *__tmp_attn_report = NULL;
	ocalloc_size += (report != NULL && sgx_is_within_enclave(report, _len_report)) ? _len_report : 0;
	ocalloc_size += (opts != NULL && sgx_is_within_enclave(opts, _len_opts)) ? _len_opts : 0;
	ocalloc_size += (attn_report != NULL && sgx_is_within_enclave(attn_report, _len_attn_report)) ? _len_attn_report : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_remote_attestation_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_remote_attestation_t));

	if (report != NULL && sgx_is_within_enclave(report, _len_report)) {
		ms->ms_report = (sgx_report_t*)__tmp;
		memcpy(__tmp, report, _len_report);
		__tmp = (void *)((size_t)__tmp + _len_report);
	} else if (report == NULL) {
		ms->ms_report = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (opts != NULL && sgx_is_within_enclave(opts, _len_opts)) {
		ms->ms_opts = (struct ra_tls_options*)__tmp;
		memcpy(__tmp, opts, _len_opts);
		__tmp = (void *)((size_t)__tmp + _len_opts);
	} else if (opts == NULL) {
		ms->ms_opts = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (attn_report != NULL && sgx_is_within_enclave(attn_report, _len_attn_report)) {
		ms->ms_attn_report = (attestation_verification_report_t*)__tmp;
		__tmp_attn_report = __tmp;
		memset(__tmp_attn_report, 0, _len_attn_report);
		__tmp = (void *)((size_t)__tmp + _len_attn_report);
	} else if (attn_report == NULL) {
		ms->ms_attn_report = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(15, ms);

	if (status == SGX_SUCCESS) {
		if (attn_report) memcpy((void*)attn_report, __tmp_attn_report, _len_attn_report);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cpuinfo = 4 * sizeof(int);

	ms_sgx_oc_cpuidex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *__tmp = NULL;

	void *__tmp_cpuinfo = NULL;
	ocalloc_size += (cpuinfo != NULL && sgx_is_within_enclave(cpuinfo, _len_cpuinfo)) ? _len_cpuinfo : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));

	if (cpuinfo != NULL && sgx_is_within_enclave(cpuinfo, _len_cpuinfo)) {
		ms->ms_cpuinfo = (int*)__tmp;
		__tmp_cpuinfo = __tmp;
		memset(__tmp_cpuinfo, 0, _len_cpuinfo);
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
	} else if (cpuinfo == NULL) {
		ms->ms_cpuinfo = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_leaf = leaf;
	ms->ms_subleaf = subleaf;
	status = sgx_ocall(16, ms);

	if (status == SGX_SUCCESS) {
		if (cpuinfo) memcpy((void*)cpuinfo, __tmp_cpuinfo, _len_cpuinfo);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));

	ms->ms_self = SGX_CAST(void*, self);
	status = sgx_ocall(17, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));

	ms->ms_waiter = SGX_CAST(void*, waiter);
	status = sgx_ocall(18, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));

	ms->ms_waiter = SGX_CAST(void*, waiter);
	ms->ms_self = SGX_CAST(void*, self);
	status = sgx_ocall(19, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(void*);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;

	ocalloc_size += (waiters != NULL && sgx_is_within_enclave(waiters, _len_waiters)) ? _len_waiters : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));

	if (waiters != NULL && sgx_is_within_enclave(waiters, _len_waiters)) {
		ms->ms_waiters = (void**)__tmp;
		memcpy(__tmp, waiters, _len_waiters);
		__tmp = (void *)((size_t)__tmp + _len_waiters);
	} else if (waiters == NULL) {
		ms->ms_waiters = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_total = total;
	status = sgx_ocall(20, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

