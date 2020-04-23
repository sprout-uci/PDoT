#include <assert.h>
#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */

#include "Wolfssl_Enclave_t.h"

#include "sgx_trts.h"
#include "sgx_thread.h"

/* DNS stuff */
#include "dns.h"
#include <ctype.h>

#include "common.h"

#define TLS_BUFFER_SIZE 514
#define DEBUG_DOTS 1

struct Query {
    char qname[DNS_D_MAXNAME + 1];
    enum dns_type qtype;
    enum dns_class qclass;
    uint16_t qid;
};

struct QueryBuffer {
    char *buffer;
    int idx;
    WOLFSSL* ssl;
    struct QueryBuffer *next;
};

struct InQueryList {
    struct QueryBuffer *head;
    struct QueryBuffer *tail;
};

struct OutQueryList {
    struct QueryBuffer *head;
    struct QueryBuffer *tail;
    int reader_writer_sig; // Used to let reader signal writer that client was disconnected.
    sgx_thread_mutex_t *out_mutex;
};

struct QueryHandlerCleanup {
    int query_processer_sig;
    int cleanup_finished;
};

// Creat QueryList to store incoming requests and outgoing responses
struct InQueryList *inQueryList;
struct OutQueryList *outQueryLists[MAX_CONCURRENT_THREADS];
struct QueryHandlerCleanup *cleanupSet[QUERY_HANDLE_THREADS];

struct dns_resolv_conf *resconf;

struct dns_hosts *hosts;

struct dns_hints *hints;

static sgx_thread_mutex_t *in_mutex;


void printf(const char *fmt, ...)
{
#if DEBUG_DOTS
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
#endif
}

// printf for error purposes
void eprintf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}

int sprintf(char* buf, const char *fmt, ...)
{
    va_list ap;
    int ret;
    va_start(ap, fmt);
    ret = vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    return ret;
}

double current_time(void)
{
    double curr;
    ocall_current_time(&curr);
    return curr;
}

int LowResTimer(void) /* low_res timer */
{
    int time;
    ocall_low_res_time(&time);
    return time;
}

size_t recv(int sockfd, void *buf, size_t len, int flags)
{
    size_t ret;
    int sgxStatus;
    sgxStatus = ocall_recv(&ret, sockfd, buf, len, flags);
    return ret;
}

size_t send(int sockfd, const void *buf, size_t len, int flags)
{
    size_t ret;
    int sgxStatus;
    sgxStatus = ocall_send(&ret, sockfd, buf, len, flags);
    return ret;
}

struct dns_packet *resolve_query(_Bool recurse, struct Query* query) {
	struct dns_resolver *R;
	struct dns_packet *ans;
	int error;
    char *qname = query->qname;
    enum dns_type qtype = query->qtype;
    enum dns_class qclass = query->qclass;

	if (!qname)
		qname = "www.google.com";
	if (!qtype)
		qtype = DNS_T_A;
	if (!qclass)
		qclass = DNS_C_IN;

	resconf->options.recurse = recurse;

	if (!(R = dns_res_open(resconf, hosts, dns_hints_mortal(hints), NULL, dns_opts(), &error))) {
        eprintf("dns_res_open: %s, %s\n", qname, dns_strerror(error));
        return NULL;
    }

	if ((error = dns_res_submit(R, qname, qtype, DNS_C_IN))) {
        eprintf("dns_res_submit: %s, %s\n", qname, dns_strerror(error));
        return NULL;
    }

	while ((error = dns_res_check(R))) {
		if (error != DNS_EAGAIN) {
            eprintf("dns_res_check: %s (%d)\n", dns_strerror(error), error);
            return NULL;
        }
		if (dns_res_elapsed(R) > 4) {
            eprintf("dns_res_elapsed: %s (%d)\n", dns_strerror(error), error);
            return NULL;
        }
	    dns_res_poll(R, 1);
	}

	ans = dns_res_fetch(R, &error);
    if (error == DNS_EUNKNOWN || error == DNS_EFETCHED) {
        eprintf("dns_res_fetch: %s (%d)\n", dns_strerror(error), error);
    }
    dns_header(ans)->qid = query->qid;

	if (!R || 1 < dns_res_release(R))
		return NULL;
	dns_res_close(R);

	return ans;
}

int parse_packet(char* Buffer, size_t Buffer_length, struct Query* query)
{
	struct dns_packet *P	= dns_p_new(512);
	struct dns_packet *Q	= dns_p_new(512);
	enum dns_section section;
	struct dns_rr rr;
	int error;
	union dns_any any;
	char pretty[sizeof any * 2];
	size_t len;

    memcpy((char*)P->data, Buffer, Buffer_length);
    P->end = Buffer_length;

    query->qid = dns_header(P)->qid;

	section	= 0;
    char host[DNS_D_MAXNAME + 1];

	dns_rr_foreach(&rr, P) {
        char *strsection = dns_strsection(rr.section);

		if ((len = dns_rr_print(pretty, sizeof pretty, &rr, P, &error))){

            if (strcmp(strsection, "QUESTION") == 0) {
                if (!(dns_d_expand(host, sizeof(host), rr.dn.p, P, &error))) {
                    eprintf("dns_d_expand: %s", dns_strerror(error));
                    return -1;
                }
                memcpy(query->qname, host, DNS_D_MAXNAME + 1);
                query->qtype = rr.type;
                query->qclass = rr.class;
            }
        }

		dns_rr_copy(Q, &rr, P);

		section	= rr.section;
	}

	return 0;
}

static void hexdump(const unsigned char *src, size_t len) {
	static const unsigned char hex[]	= "0123456789abcdef";
	static const unsigned char tmpl[]	= "                                                    |                |\n";
	unsigned char ln[sizeof tmpl];
	const unsigned char *sp, *se;
	unsigned char *h, *g;
	unsigned i, n;

	sp	= src;
	se	= sp + len;

	while (sp < se) {
		memcpy(ln, tmpl, sizeof ln);

		h	= &ln[2];
		g	= &ln[53];

		for (n = 0; n < 2; n++) {
			for (i = 0; i < 8 && se - sp > 0; i++, sp++) {
				h[0]	= hex[0x0f & (*sp >> 4)];
				h[1]	= hex[0x0f & (*sp >> 0)];
				h	+= 3;

				*g++	= (isgraph(*sp))? *sp : '.';
			}

			h++;
		}

        printf((char *)ln);
	}

	return /* void */;
} /* hexdump() */

void enc_wolfSSL_Debugging_ON(void)
{
    wolfSSL_Debugging_ON();
}

void enc_wolfSSL_Debugging_OFF(void)
{
    wolfSSL_Debugging_OFF();
}

int enc_wolfSSL_Init(void)
{
    inQueryList = (struct QueryList *) malloc(sizeof(struct InQueryList));
    memset(inQueryList, 0, sizeof(struct InQueryList));
    for (int i=0; i < MAX_CONCURRENT_THREADS; i++) {
        outQueryLists[i] = (struct QueryList *) malloc(sizeof(struct OutQueryList));
        memset(outQueryLists[i], 0, sizeof(struct OutQueryList));
        outQueryLists[i]->head = NULL;
        outQueryLists[i]->tail = NULL;
        outQueryLists[i]->reader_writer_sig = 1;
    }
    inQueryList->head = NULL;
    inQueryList->tail = NULL;
    for (int i=0; i < QUERY_HANDLE_THREADS; i++) {
        cleanupSet[i] = (struct QueryHandlerCleanup *) malloc(sizeof(struct QueryHandlerCleanup));
        memset(cleanupSet[i], 0, sizeof(struct QueryHandlerCleanup));
        cleanupSet[i]->query_processer_sig = 1;
        cleanupSet[i]->cleanup_finished = 0;
    }
    return wolfSSL_Init();
}

WOLFSSL_METHOD* enc_wolfTLSv1_2_server_method(void)
{
    return wolfTLSv1_2_server_method();
}


WOLFSSL_CTX* enc_wolfSSL_CTX_new(WOLFSSL_METHOD* method)
{
    if(sgx_is_within_enclave(method, wolfSSL_METHOD_GetObjectSize()) != 1)
        abort();
    return wolfSSL_CTX_new(method);
}

WOLFSSL* enc_wolfSSL_new( WOLFSSL_CTX* ctx)
{
    if(sgx_is_within_enclave(ctx, wolfSSL_CTX_GetObjectSize()) != 1)
        abort();
    return wolfSSL_new(ctx);
}

int enc_wolfSSL_is_init_finished(WOLFSSL* ssl)
{
    if(sgx_is_within_enclave(ssl, wolfSSL_GetObjectSize()) != 1)
        abort();
    return wolfSSL_is_init_finished(ssl);
}

void enc_wolfSSL_set_using_nonblock(WOLFSSL* ssl, int i)
{
    if(sgx_is_within_enclave(ssl, wolfSSL_GetObjectSize()) != 1)
        abort();
    wolfSSL_set_using_nonblock(ssl, i);
}

int enc_wolfSSL_set_fd(WOLFSSL* ssl, int fd)
{
    if(sgx_is_within_enclave(ssl, wolfSSL_GetObjectSize()) != 1)
        abort();
    return wolfSSL_set_fd(ssl, fd);
}

int enc_mutex_init(void)
{
    in_mutex = (sgx_thread_mutex_t *) malloc(sizeof(sgx_thread_mutex_t));
    if (sgx_thread_mutex_init(in_mutex, NULL) != 0) {
        eprintf("Failed to initialize mutex\n");
        return -1;
    }
    for (int i=0; i < MAX_CONCURRENT_THREADS; i++) {
        outQueryLists[i]->out_mutex = (sgx_thread_mutex_t *) malloc(sizeof(sgx_thread_mutex_t));
        if (sgx_thread_mutex_init(outQueryLists[i]->out_mutex, NULL) != 0) {
                eprintf("Failed to initialize mutex\n");
                return -1;
        }
    }
    return 0;
}

int enc_mutex_destroy(void)
{
    if (sgx_thread_mutex_destroy(in_mutex) != 0) {
        eprintf("Failed to destroy in_mutex\n");
        // return -1;
    }
    for (int i=0; i < MAX_CONCURRENT_THREADS; i++) {
        if (sgx_thread_mutex_destroy(outQueryLists[i]->out_mutex) != 0 ) {
                eprintf("Failed to destroy out_mutex[%i]\n", i);
                // return -1;
        }
    }
    return 0;
}

int enc_wolfSSL_read_from_client(WOLFSSL_CTX* ctx, int connd, int idx)
{
    if(sgx_is_within_enclave(ctx, wolfSSL_CTX_GetObjectSize()) != 1)
        abort();

    int ret = 0;

    // Allocate 514 byte buffer array
    char *ssl_buffer = malloc(TLS_BUFFER_SIZE);
    memset(ssl_buffer, 0 , TLS_BUFFER_SIZE);

    // Create new WOLFSSL object
    printf("[ClientReader %i] Create WOLFSSL object.\n", idx);
    WOLFSSL* ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        eprintf("[ClientReader %i] Failed to create new WOLFSSL object.\n", idx);
        return -1;
    }
    // Set SSL socket to nonblock
    printf("[ClientReader %i] Set SSL to nonblock.\n", idx);
    wolfSSL_set_using_nonblock(ssl, 1);
    // Check whether the initialization is finished
    printf("[ClientReader %i] Check whether init is finished.\n", idx);
    ret = wolfSSL_is_init_finished(ssl);
    if (ret == 1) {
        eprintf("[ClientReader %i] Failed to initialize WOLFSSL object.\n", idx);
        return ret;
    }
    // Set FD
    printf("[ClientReader %i] Set FD to WOLFSSL object.\n", idx);
    ret = wolfSSL_set_fd(ssl, connd);
    if (ret != SSL_SUCCESS) {
        eprintf("[ClientReader %i] Failed to set FD to WOLFSSL object.\n", idx);
        return ret;
    }

    while (1) {
        /////////////////////////
        // READ CLIENT REQUEST //
        /////////////////////////

        /* Read the client data into our buff array */
        if (wolfSSL_read(ssl, ssl_buffer, TLS_BUFFER_SIZE) > 0) {
            // Allocate 514 byte buffer array
            char *buffer = malloc(TLS_BUFFER_SIZE);
            memcpy(buffer, ssl_buffer, TLS_BUFFER_SIZE);

            // Extract the qid
            unsigned qid = 0;
            memcpy(&qid, buffer + 2, 2);
            printf("[ClientReader %i] Received query from client with qid: %u\n", idx, qid);

            // Prepare QueryBuffer
            struct QueryBuffer *queryBuffer = (struct QueryBuffer *) malloc(sizeof(struct QueryBuffer));
            memset(queryBuffer, 0, sizeof(struct QueryBuffer));
            queryBuffer->buffer = buffer;
            queryBuffer->ssl = ssl;
            queryBuffer->next = NULL;

            // Wait until we can lock mutex
            printf("[ClientReader %i] Obtain in_head_mutex and in_tail_mutex\n", idx);
            while (sgx_thread_mutex_trylock(in_mutex) != 0) {
            }
            // Store QueryBuffer to linked list
            if (inQueryList->head == NULL && inQueryList->tail == NULL) {
                printf("[ClientReader %i] Adding first elem. to QueryBuffer.\n", idx);
                inQueryList->head = inQueryList->tail = queryBuffer;
            } else if (inQueryList->head == NULL || inQueryList->tail == NULL) {
                // Something is wrong.
                eprintf("[ClientReader %i] Failed to add query to QueryBuffer.\n", idx);
                free(buffer);
                free(queryBuffer);
                outQueryLists[idx]->reader_writer_sig = 0;
                if (sgx_thread_mutex_unlock(in_mutex) != 0) {
                    eprintf("[ClientReader %i] Failed to unlock mutex.\n", idx);
                }
                return -1;
            } else {
                printf("[ClientReader %i] Adding another elem. to QueryBuffer.\n", idx);
                inQueryList->tail->next = queryBuffer;
                inQueryList->tail = queryBuffer;
            }

            // Unlock mutex
            printf("[ClientReader %i] Unlock in_head_mutex and in_tail_mutex\n", idx);
            if (sgx_thread_mutex_unlock(in_mutex) != 0) {
                eprintf("[ClientReader %i] Failed to unlock mutex.\n", idx);
                free(buffer);
                free(queryBuffer);
                outQueryLists[idx]->reader_writer_sig = 0;
                return -1;
            }
    
            memset(ssl_buffer, 0 , TLS_BUFFER_SIZE);

        } else {
            printf("[ClientReader %i] wolfSSL_read failed\n", idx);
            outQueryLists[idx]->reader_writer_sig = 0;
            break;
        }
    }

    printf("[ClientReader %i] Free up some stuff\n", idx);
    free(ssl_buffer);
    if (ssl) wolfSSL_free(ssl);

    return 0;
}

int enc_wolfSSL_process_query(int tid)
{
    while (1) {
        // Wait until there is a query in head and we can lock mutex
        printf("[QueryHandle  %i] waiting for head...\n", tid);
        while (!(inQueryList->head != NULL && sgx_thread_mutex_trylock(in_mutex) == 0)) {
            if (cleanupSet[tid]->query_processer_sig == 0) {
                cleanupSet[tid]->cleanup_finished = 1;
                break;
            }
        }
        if (cleanupSet[tid]->query_processer_sig == 0) {
            cleanupSet[tid]->cleanup_finished = 1;
            break;
        }

        if (inQueryList->head == NULL) { // Sometimes the head is already NULL when a thread gets a mutex.
            // Unlock mutex
            printf("[QueryHandle  %i] Head was NULL\n", tid);
            if (sgx_thread_mutex_unlock(in_mutex) != 0) {
                eprintf("[QueryHandle  %i] Failed to unlock mutex.\n", tid);
                return -1;
            }
            continue;
        }
        printf("[QueryHandle  %i] found head\n", tid);

        // Initialize resconf and hosts
        struct dns_packet *ans = (struct dns_packet *) malloc(sizeof(struct dns_packet));
        memset(ans, 0, sizeof(struct dns_packet));
        struct QueryBuffer* qB = inQueryList->head;
        struct Query* query = (struct Query *) malloc(sizeof(struct Query));
        memset(query, 0, sizeof(struct Query));
        int ret = 0;

        // Update head and tail
        printf("[QueryHandle  %i] update head\n", tid);
        inQueryList->head = qB->next;
        if (inQueryList->head == NULL) {
            // We have reached the end of the queue.
            printf("[QueryHandle  %i] reached end.\n", tid);
            inQueryList->tail = NULL;
        }

        printf("[QueryHandle  %i] unlock mutex\n", tid);
        // Unlock mutex
        if (sgx_thread_mutex_unlock(in_mutex) != 0) {
            eprintf("[QueryHandle  %i] Failed to unlock mutex.\n", tid);
            free(qB->buffer);
            free(ans);
            free(qB);
            free(query);
            return -1;
        }

        // Check whether this client is still connected or not.
        if (outQueryLists[qB->idx]->reader_writer_sig == 0) {
            // Connection to this client has ended.
            printf("[QueryHandle  %i] connection to %i has ended.\n", tid, qB->idx);
            free(query);
            free(ans);
            free(qB->buffer);
            free(qB);
            continue;
        }

        // Extract the qid
        unsigned qid = 0;
        memcpy(&qid, qB->buffer + 2, 2);
        printf("[QueryHandle  %i] inQueryList head qid: %u\n", tid, qid);

        // We extract the packet length from the first two bytes of the packet. Check whenever the packet becomes large.
        uint16_t packet_len = (uint8_t)qB->buffer[1] | (uint16_t)qB->buffer[0] << 8;

        /* Parse DNS packet which client sent */
        printf("[QueryHandle  %i] parse packet\n", tid);
        if (parse_packet(qB->buffer + 2, packet_len, query) == -1){
            eprintf("[QueryHandle  %i] ERROR: failed to parse packet\n", tid);

            // Clean up
            free(qB->buffer);
            free(ans);
            free(qB);
            free(query);
            return -1;
        }

        /* Resolve query */
        printf("[QueryHandle  %i] resolve query\n", tid);
        ans = resolve_query(1, query);
        if (ans == NULL){
            eprintf("[QueryHandle  %i] Failed to resolve query.\n", tid);
            free(qB->buffer);
            free(ans);
            free(qB);
            free(query);
            continue;
        }
        printf("[QueryHandle  %i] obtained answer with qid: %u for client: %i\n", tid, ans->header.qid, qB->idx);

        // Store response to outQueryList
        // TODO: make the following a function. (Same for serve_client function)

        // Prepare QueryBuffer
        struct QueryBuffer *queryBuffer = (struct QueryBuffer *) malloc(sizeof(struct QueryBuffer));
        memset(queryBuffer, 0, sizeof(struct QueryBuffer));
        queryBuffer->buffer = (char *)ans;
        queryBuffer->idx = qB->idx;
        queryBuffer->ssl = qB->ssl;
        queryBuffer->next = NULL;

        // Wait until we can lock mutex
        printf("[QueryHandle  %i] waiting for mutex...\n", tid);
        while (sgx_thread_mutex_trylock(outQueryLists[qB->idx]->out_mutex) != 0) {
            if (cleanupSet[tid]->query_processer_sig == 0) {
                cleanupSet[tid]->cleanup_finished = 1;
                free(qB->buffer);
                free(ans);
                free(qB);
                free(query);
                free(queryBuffer);
                break;
            }
        }
        if (outQueryLists[qB->idx]->reader_writer_sig == 1) {
            // Store QueryBuffer to linked list
            if (outQueryLists[qB->idx]->head == NULL && outQueryLists[qB->idx]->tail == NULL) {
                printf("[QueryHandle  %i] Adding first elem. to QueryBuffer.\n", tid);
                outQueryLists[qB->idx]->head = outQueryLists[qB->idx]->tail = queryBuffer;
            } else if (outQueryLists[qB->idx]->head == NULL || outQueryLists[qB->idx]->tail == NULL) {
                // Something is wrong.
                eprintf("[QueryHandle  %i] Failed to add query to QueryBuffer.\n", tid);
                free(qB->buffer);
                free(ans);
                free(qB);
                free(query);
                free(queryBuffer);
                if (sgx_thread_mutex_unlock(outQueryLists[qB->idx]->out_mutex) != 0) {
                    eprintf("[QueryHandle  %i] Failed to unlock mutex.\n", tid);
                }
                return -1;
            } else {
                printf("[QueryHandle  %i] Adding another elem. to QueryBuffer.\n", tid);
                outQueryLists[qB->idx]->tail->next = queryBuffer;
                outQueryLists[qB->idx]->tail = queryBuffer;
            }
        } else {
            // Connection to this client has ended.
            printf("[QueryHandle  %i] connection to %i has ended.\n", tid, qB->idx);
            free(ans);
            free(queryBuffer);
        }

        // Unlock mutex
        printf("[QueryHandle  %i] unlock mutex out_head_mutex and out_tail_mutex\n", tid);
        if (sgx_thread_mutex_unlock(outQueryLists[qB->idx]->out_mutex) != 0) {
            eprintf("[QueryHandle  %i] Failed to unlock mutex.\n", tid);
            free(qB->buffer);
            free(ans);
            free(qB);
            free(query);
            free(queryBuffer);
            return -1;
        }

        // Clean up
        printf("[QueryHandle  %i] clean up\n", tid);
        free(query);
        free(qB->buffer);
        free(qB);
        if (cleanupSet[tid]->query_processer_sig == 0) {
            cleanupSet[tid]->cleanup_finished = 1;
            free(ans);
            free(queryBuffer);
            break;
        }
    }
}

int enc_wolfSSL_write_to_client(int idx)
{
    // Initialize some variables
    int ret = 0;
    outQueryLists[idx]->reader_writer_sig = 1;
    WOLFSSL* ssl = NULL;

    while (1) {
        /////////////////////////////
        // SEND RESPONSE TO CLIENT //
        /////////////////////////////
        while (sgx_thread_mutex_trylock(outQueryLists[idx]->out_mutex) != 0) {
        }
        if (outQueryLists[idx]->head != NULL) {

            if (outQueryLists[idx]->head == NULL) { // Sometimes the head is already NULL when a thread gets a mutex.
                // Unlock mutex
                if (sgx_thread_mutex_unlock(outQueryLists[idx]->out_mutex) != 0) {
                    eprintf("[ClientWriter %i] Failed to unlock mutex.\n", idx);
                    return -1;
                }
                continue;
            }

            printf("[ClientWriter %i] take head from outQueryList\n", idx);
            struct QueryBuffer* qB = outQueryLists[idx]->head;
            outQueryLists[idx]->head = qB->next;
            if (outQueryLists[idx]->head == NULL) {
                // We have reached the end of the queue.
                printf("[ClientWriter %i] reached end of outQueryList\n", idx);
                outQueryLists[idx]->tail = NULL;
            }

            // Create answer
            struct dns_packet* ans = (struct dns_packet *)qB->buffer;
            char* answer = malloc(ans->end + (size_t)2);
            memset(answer, 0, ans->end + (size_t)2);
            answer[0] = 0xff & (ans->end >> 8);
            answer[1] = 0xff & (ans->end >> 0);
            ans->header.ra = 1;
            ans->header.rd = 1;
            memcpy(answer + 2, ans->data, ans->end);

            /* Send answer back to client */
            printf("[ClientWriter %i] send answer with qid: %u\n", idx, ans->header.qid);
            ret = wolfSSL_write(qB->ssl, answer, ans->end + (size_t)2);
            if (ret != (ans->end + (size_t)2)) {
                eprintf("[ClientWriter %i] ERROR: failed to write. Ret: %i\n", idx, ret);
            }

            // Unlock mutex
            printf("[ClientWriter %i] unlock mutex\n", idx);
            if (sgx_thread_mutex_unlock(outQueryLists[idx]->out_mutex) != 0) {
                eprintf("[ClientWriter %i] Failed to unlock mutex.\n", idx);
                free(qB->buffer);
                free(qB);
                free(answer);
                return -1;
            }

            printf("[ClientWriter %i] clean up\n", idx);
            free(answer);
            free(qB->buffer);
            free(qB);
        } else {
            if (sgx_thread_mutex_unlock(outQueryLists[idx]->out_mutex) != 0) {
                eprintf("[ClientWriter %i] Failed to unlock mutex.\n", idx);
                return -1;
            }
            // There is no QB in outQueryList.
            if (outQueryLists[idx]->reader_writer_sig == 0) // This client has been disconnected.
                break;
        }
    }

    printf("[ClientWriter %i] Free up some stuff\n", idx);
    return 0;
}

void enc_wolfSSL_free(WOLFSSL* ssl)
{
    if(sgx_is_within_enclave(ssl, wolfSSL_GetObjectSize()) != 1)
        abort();
    wolfSSL_free(ssl);
}

void enc_wolfSSL_CTX_free(WOLFSSL_CTX* ctx)
{
    if(sgx_is_within_enclave(ctx, wolfSSL_CTX_GetObjectSize()) != 1)
        abort();
    wolfSSL_CTX_free(ctx);
}

int enc_wolfSSL_Cleanup(void)
{
    printf("stop QueryHandler threads\n");
    for (int i=0; i < QUERY_HANDLE_THREADS; i++) {
        cleanupSet[i]->query_processer_sig = 0;
        while (cleanupSet[i]->cleanup_finished != 1) {}
    }
    printf("clean inQueryList\n");
    int counter = 0;
    while(inQueryList->head != NULL && sgx_thread_mutex_trylock(in_mutex) == 0) {
        struct QueryBuffer* tmp = inQueryList->head;
        inQueryList->head = tmp->next;
        sgx_thread_mutex_unlock(in_mutex);
        free(tmp);
        counter++;
    }
    counter = 0;
    printf("clean outQueryList\n");
    for (int i = 0; i < MAX_CONCURRENT_THREADS; i++) {
        while(outQueryLists[i]->head != NULL && sgx_thread_mutex_trylock(outQueryLists[i]->out_mutex) == 0) {
            struct QueryBuffer* tmp = outQueryLists[i]->head;
            outQueryLists[i]->head = tmp->next;
            sgx_thread_mutex_unlock(outQueryLists[i]->out_mutex);
            free(tmp);
            counter++;
        }
    }
    free(inQueryList);
    for (int i = 0; i < MAX_CONCURRENT_THREADS; i++) {
        free(outQueryLists[i]);
    }
    free(resconf);
    free(hosts);
    free(hints);
    return wolfSSL_Cleanup();
}

void enc_load_resconf(struct dns_resolv_conf *o_resconf) {
    resconf = malloc(sizeof(struct dns_resolv_conf));
    memcpy(resconf, o_resconf, sizeof(struct dns_resolv_conf));
}

void enc_load_hosts(struct dns_hosts *o_hosts) {
    hosts = malloc(sizeof(struct dns_hosts));
    memcpy(hosts, o_hosts, sizeof(struct dns_hosts));
}

void enc_load_hints(struct dns_hints *o_hints) {
    hints = malloc(sizeof(struct dns_hints));
    memcpy(hints, o_hints, sizeof(struct dns_hints));
}

extern struct ra_tls_options my_ra_tls_options;

void enc_create_key_and_x509(WOLFSSL_CTX* ctx) {
    uint8_t der_key[2048];
    uint8_t der_cert[8 * 1024];
    uint32_t der_key_len = sizeof(der_key);
    uint32_t der_cert_len = sizeof(der_cert);

    create_key_and_x509(&der_key, &der_key_len,
                        &der_cert, &der_cert_len,
                        &my_ra_tls_options);

    int ret;
    ret = wolfSSL_CTX_use_certificate_buffer(ctx, der_cert, der_cert_len,
                                             SSL_FILETYPE_ASN1);
    assert(ret == SSL_SUCCESS);

    wolfSSL_CTX_use_PrivateKey_buffer(ctx, der_key, der_key_len,
                                      SSL_FILETYPE_ASN1);
    assert(ret == SSL_SUCCESS);
}
