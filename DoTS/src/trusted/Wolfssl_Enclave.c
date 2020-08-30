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

#if DNS_CACHE
#include "tree.h"
struct rrset {
	char name[DNS_D_MAXNAME + 1];
	enum dns_type type;

	union {
		struct dns_packet packet;
		unsigned char pbuf[dns_p_calcsize(1024)];
	};

	RB_ENTRY(rrset) rbe;
};

static int rrset_init(struct rrset *set, const char *name, enum dns_type type) {
	int error;

	memset(set, 0, sizeof *set);

	dns_strlcpy(set->name, name, sizeof set->name);
	set->type = type;

	dns_p_init(&set->packet, sizeof set->pbuf);

	// if ((error = dns_p_push(&set->packet, DNS_S_QD, name, strlen(name), type, DNS_C_IN, 0, NULL)))
	// 	return error;

	return 0;
} /* rrset_init() */

RB_HEAD(rrcache, rrset);

static inline int rrset_cmp(struct rrset *a, struct rrset *b) {
	int cmp;
	return ((cmp = a->type - b->type))? cmp : strcasecmp(a->name, b->name);
} /* rrset_cmp() */

RB_PROTOTYPE(rrcache, rrset, rbe, rrset_cmp);
RB_GENERATE(rrcache, rrset, rbe, rrset_cmp);

static struct cache {
	struct dns_cache res;
	struct rrcache root;
} *cache; /* struct cache */

void cache_close(void) {
    struct rrset *set;
    if (!cache)
        return;
    while ((set = RB_MIN(rrcache, &cache->root))) {
        RB_REMOVE(rrcache, &cache->root, set);
        free(set);
    }
    free(cache);
}

int cache_init(void) {
    int error;
    if (!(cache = (struct cache *)malloc(sizeof *cache))) {
        cache_close();
        return -1;
    }
    dns_cache_init(&cache->res);
    cache->res.state = cache;
    RB_INIT(&cache->root);
    return 0;
}
#endif /* DNS_CACHE */

struct Query {
    char qname[DNS_D_MAXNAME + 1];
    enum dns_type qtype;
    enum dns_class qclass;
    uint16_t qid;
};

struct QueryBuffer {
    struct Query *query;
    int idx;
    WOLFSSL* ssl;
    int connd;
    struct QueryBuffer *next;
};

struct QueryList {
    struct QueryBuffer *head;
    struct QueryBuffer *tail;
    int reader_writer_sig; // Used to let reader signal writer that client was disconnected.
    int query_handler_exited;
    sgx_thread_mutex_t *queue_mutex;
    sgx_thread_mutex_t *cond_mutex;
    sgx_thread_cond_t *cond;
};

// Create QueryList to store incoming requests and outgoing responses
struct QueryList *queryLists[MAX_CONCURRENT_THREADS];

struct dns_resolv_conf *resconf;

struct dns_hosts *hosts;

struct dns_hints *hints;

#if DNS_CACHE
static sgx_thread_mutex_t *cache_mutex;
#endif

void printf(const char *fmt, ...)
{
#ifdef DEBUG_DOTS
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
    char *qname;
    enum dns_type qtype;
    enum dns_class qclass;

    if (query) {
		qname = query->qname;
		qtype = query->qtype;
		qclass = query->qclass;
    } else {
		qname = "google.com";
		qtype = DNS_T_A;
		qclass = DNS_C_IN;
    }

	resconf->options.recurse = recurse;
    // Disable TCP during measurement to lower the variation in latency
	resconf->options.tcp = DNS_RESCONF_TCP_DISABLE;

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
    for (int i=0; i < MAX_CONCURRENT_THREADS; i++) {
        queryLists[i] = (struct QueryList *) malloc(sizeof(struct QueryList));
        memset(queryLists[i], 0, sizeof(struct QueryList));
        queryLists[i]->head = NULL;
        queryLists[i]->tail = NULL;
        queryLists[i]->reader_writer_sig = 1;
        queryLists[i]->query_handler_exited = 0;
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
    for (int i=0; i < MAX_CONCURRENT_THREADS; i++) {
        queryLists[i]->queue_mutex = (sgx_thread_mutex_t *) calloc(1, sizeof(sgx_thread_mutex_t));
        if (sgx_thread_mutex_init(queryLists[i]->queue_mutex, NULL) != 0) {
                eprintf("Failed to initialize mutex\n");
                return -1;
        }
        queryLists[i]->cond_mutex = (sgx_thread_mutex_t *) calloc(1, sizeof(sgx_thread_mutex_t));
        if (sgx_thread_mutex_init(queryLists[i]->cond_mutex, NULL) != 0) {
                eprintf("Failed to initialize mutex\n");
                return -1;
        }
        queryLists[i]->cond = (sgx_thread_cond_t *) calloc(1, sizeof(sgx_thread_cond_t));
        if (sgx_thread_cond_init(queryLists[i]->cond, NULL) != 0) {
            eprintf("Failed to initialize cond\n");
            return -1;
        }
    }
#if DNS_CACHE
    cache_mutex = (sgx_thread_mutex_t *) malloc(sizeof(sgx_thread_mutex_t));
    if (sgx_thread_mutex_init(cache_mutex, NULL) != 0) {
        eprintf("Failed to initialize mutex\n");
        return -1;
    }
#endif
    return 0;
}

int enc_mutex_destroy(void)
{
    for (int i=0; i < MAX_CONCURRENT_THREADS; i++) {
        if (sgx_thread_mutex_destroy(queryLists[i]->queue_mutex) != 0 ) {
                eprintf("Failed to destroy out_mutex[%i]\n", i);
                // return -1;
        }
        if (sgx_thread_mutex_destroy(queryLists[i]->cond_mutex) != 0 ) {
                eprintf("Failed to destroy out_mutex[%i]\n", i);
                // return -1;
        }
        if (sgx_thread_cond_destroy(queryLists[i]->cond) != 0) {
            eprintf("Failed to destroy cond[%i]\n", i);
            // return -1;
        }
    }
#if DNS_CACHE
    if (sgx_thread_mutex_destroy(cache_mutex) != 0) {
        eprintf("Failed to destroy cache_mutex\n");
        // return -1;
    }
#endif
    return 0;
}

int enc_wolfSSL_read_from_client(WOLFSSL_CTX* ctx, int connd, int idx)
{
    if(sgx_is_within_enclave(ctx, wolfSSL_CTX_GetObjectSize()) != 1)
        abort();

    int ret = 0;

    // Allocate 514 byte buffer array
    char ssl_buffer[TLS_BUFFER_SIZE];
    memset(ssl_buffer, 0 , TLS_BUFFER_SIZE);

    // Create new WOLFSSL object
    printf("[ClientReader %i] Create WOLFSSL object.\n", idx);
    WOLFSSL* ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        eprintf("[ClientReader %i] Failed to create new WOLFSSL object.\n", idx);
        ret = -1;
        return ret;
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
            char *buffer = ssl_buffer;

            struct Query* query = (struct Query *) malloc(sizeof(struct Query));
            memset(query, 0, sizeof(struct Query));

            // We extract the packet length from the first two bytes of the packet. Check whenever the packet becomes large.
            uint16_t packet_len = (uint8_t)buffer[1] | (uint16_t)buffer[0] << 8;

            /* Parse DNS packet which client sent */
            printf("[ClientReader %i] parse packet\n", idx);
            if (parse_packet(buffer + 2, packet_len, query) == -1){
                eprintf("[ClientReader  %i] ERROR: failed to parse packet\n", idx);

                // Clean up
                free(query);
                ret = -1;
                break;
            }

            // Prepare QueryBuffer
            struct QueryBuffer *queryBuffer = (struct QueryBuffer *) malloc(sizeof(struct QueryBuffer));
            memset(queryBuffer, 0, sizeof(struct QueryBuffer));
            printf("[ClientReader %i] QB pointer value: %p\n", idx, queryBuffer);
            queryBuffer->query = query;
            queryBuffer->ssl = ssl;
            queryBuffer->connd = connd;
            queryBuffer->next = NULL;
            queryBuffer->idx = idx;

            // Wait until we can lock mutex
            printf("[ClientReader %i] Obtain in_head_mutex and in_tail_mutex\n", idx);
            sgx_thread_mutex_lock(queryLists[idx]->queue_mutex);
            // Store QueryBuffer to linked list
            if (queryLists[idx]->head == NULL && queryLists[idx]->tail == NULL) {
                printf("[ClientReader %i] Adding first elem. to QueryBuffer.\n", idx);
                queryLists[idx]->head = queryLists[idx]->tail = queryBuffer;
            } else if (queryLists[idx]->head == NULL || queryLists[idx]->tail == NULL) {
                // Something is wrong.
                eprintf("[ClientReader %i] Failed to add query to QueryBuffer.\n", idx);
                free(query);
                free(queryBuffer);
                queryLists[idx]->reader_writer_sig = 0;
                if (sgx_thread_mutex_unlock(queryLists[idx]->queue_mutex) != 0) {
                    eprintf("[ClientReader %i] Failed to unlock mutex.\n", idx);
                }
                ret = -1;
                break;
            } else {
                printf("[ClientReader %i] Adding another elem. to QueryBuffer.\n", idx);
                queryLists[idx]->tail->next = queryBuffer;
                queryLists[idx]->tail = queryBuffer;
            }

            // Unlock mutex
            printf("[ClientReader %i] Unlock in_head_mutex and in_tail_mutex\n", idx);
            if (sgx_thread_mutex_unlock(queryLists[idx]->queue_mutex) != 0) {
                eprintf("[ClientReader %i] Failed to unlock mutex.\n", idx);
                free(query);
                free(queryBuffer);
                queryLists[idx]->reader_writer_sig = 0;
                ret = -1;
                break;
            }

            sgx_thread_mutex_lock(queryLists[idx]->cond_mutex);
            // Signal any QueryHandler thread that a query is ready for resolving
            printf("[ClientReader %i] Send signal to QueryHandler thread\n", idx);
            if (sgx_thread_cond_signal(queryLists[idx]->cond) != 0) {
                eprintf("[ClientReader %i] Failed to send signal.\n", idx);
                free(query);
                free(queryBuffer);
                queryLists[idx]->reader_writer_sig = 0;
                ret = -1;
                break;
            }
            if (sgx_thread_mutex_unlock(queryLists[idx]->cond_mutex) != 0) {
                eprintf("[ClientReader %i] Failed to unlock mutex.\n", idx);
                free(query);
                free(queryBuffer);
                queryLists[idx]->reader_writer_sig = 0;
                ret = -1;
                break;
            }
    
            memset(ssl_buffer, 0 , TLS_BUFFER_SIZE);

        } else {
            printf("[ClientReader %i] wolfSSL_read failed\n", idx);
            while (queryLists[idx]->query_handler_exited != 1) {
                sgx_thread_mutex_lock(queryLists[idx]->cond_mutex);
                sgx_thread_cond_signal(queryLists[idx]->cond);
                queryLists[idx]->reader_writer_sig = 0;
                sgx_thread_mutex_unlock(queryLists[idx]->cond_mutex);
            }
            break;
        }
    }

    printf("[ClientReader %i] Free up some stuff\n", idx);
    wolfSSL_free(ssl);
    ssl = NULL;
    queryLists[idx]->reader_writer_sig = 1;
    queryLists[idx]->query_handler_exited = 0;

    return ret;
}

int enc_wolfSSL_process_query(int idx)
{
    int ret = 0;
    while (1) {
        // Sleep until we receive a signal from ClientReader thread
        if (ret = sgx_thread_mutex_lock(queryLists[idx]->cond_mutex)) {
            eprintf("[QueryHandle  %i] Failed to lock %i.\n", idx, ret);
        }
        printf("[QueryHandle  %i] waiting for signal...\n", idx);
        if (ret = sgx_thread_cond_wait(queryLists[idx]->cond, queryLists[idx]->cond_mutex)) {
            eprintf("[QueryHandle  %i] Failed to wait %i.\n", idx, ret);
        }
        if (sgx_thread_mutex_unlock(queryLists[idx]->cond_mutex) != 0) {
            eprintf("[QueryHandle  %i] Failed to unlock mutex.\n", idx);
            return -1;
        }

        if (queryLists[idx]->reader_writer_sig == 0) {
            queryLists[idx]->query_handler_exited = 1;
            break;
        }

        // Wait until we can lock mutex
        printf("[QueryHandle  %i] waiting for head...\n", idx);
        if (ret = sgx_thread_mutex_lock(queryLists[idx]->queue_mutex)) {
            eprintf("[QueryHandle  %i] Failed to lock %i.\n", idx, ret);
        }

        // Sometimes the head is already NULL when a thread gets a mutex.
        if (queryLists[idx]->head == NULL) {
            // Unlock mutex
            printf("[QueryHandle  %i] Head was NULL\n", idx);
            if (sgx_thread_mutex_unlock(queryLists[idx]->queue_mutex) != 0) {
                eprintf("[QueryHandle  %i] Failed to unlock mutex.\n", idx);
                return -1;
            }
            continue;
        }
        printf("[QueryHandle  %i] found head\n", idx);

        // Initialize resconf and hosts
        struct dns_packet *ans;
        struct QueryBuffer* qB = queryLists[idx]->head;

        // Update head and tail
        printf("[QueryHandle  %i] update head\n", idx);
        queryLists[idx]->head = qB->next;
        if (queryLists[idx]->head == NULL) {
            // We have reached the end of the queue.
            printf("[QueryHandle  %i] reached end.\n", idx);
            queryLists[idx]->tail = NULL;
        }

        printf("[QueryHandle  %i] unlock mutex\n", idx);
        // Unlock mutex
        if (sgx_thread_mutex_unlock(queryLists[idx]->queue_mutex) != 0) {
            eprintf("[QueryHandle  %i] Failed to unlock mutex.\n", idx);
            free(qB->query);
            free(qB);
            return -1;
        }

        // Check whether this client is still connected or not.
        if (queryLists[qB->idx]->reader_writer_sig == 0) {
            // Connection to this client has ended.
            printf("[QueryHandle  %i] connection to %i has ended.\n", idx, qB->idx);
            free(qB->query);
            free(qB);
            queryLists[idx]->query_handler_exited = 1;
            break;
        }

        /* Resolve query */
        printf("[QueryHandle  %i] resolve query\n", idx);
#if DNS_CACHE
        // Find from cache
        struct rrset key, *set;
        int error;
        dns_strlcpy(key.name, qB->query->qname, sizeof key.name);
        key.type = qB->query->qtype;
        // Search from cache
        set = RB_FIND(rrcache, &cache->root, &key);
        if (set == NULL) { // Record not found in cache
            printf("[QueryHandle  %i] Resource not found in cache: %s\n", idx, qB->query->qname);
            // Resolve in the normal way
            ans = resolve_query(1, qB->query);
            if (ans == NULL){
                eprintf("[QueryHandle  %i] Failed to resolve query.\n", idx);
                free(qB->query);
                free(qB);
                continue;
            }
            // Wait for cache mutex
            if (ret = sgx_thread_mutex_lock(cache_mutex)) {
                eprintf("[QueryHandle  %i] Failed to lock cache mutex %i.\n", idx, ret);
            }
            // Prepare to insert record to cache
            set = (struct rrset *)malloc(sizeof *set);
            if ((error = rrset_init(set, qB->query->qname, qB->query->qtype))) {
                eprintf("[QueryHandle  %i] Failed to init rrset.\n", idx);
                continue;
            }
            // TODO: Control the size of the tree.
            dns_p_copy(&set->packet, ans);
            printf("[QueryHandle  %i] %i, %i, %p\n", idx, ans->size, &set->packet.size, &set->packet);
            // Double check whether the record already exists in cache
            if (RB_FIND(rrcache, &cache->root, &key) == NULL) {
                // Insert record to cache
                assert(!RB_INSERT(rrcache, &cache->root, set));
            }
            // Unlock mutex
            if (sgx_thread_mutex_unlock(cache_mutex) != 0) {
                eprintf("[QueryHandle  %i] Failed to unlock mutex.\n", idx);
                free(ans);
                free(qB->query);
                free(qB);
                return -1;
            }
        } else { // Record found in cache
            eprintf("[QueryHandle  %i] Resource found in cache: %s\n", idx, qB->query->qname); // required for now to prevent race condition
            ans = dns_p_make(dns_p_calcsize(1024), &error);
            dns_p_copy(ans, &set->packet);
            ans->header.qid = qB->query->qid;
            printf("[QueryHandle  %i] %p, %p\n", idx, ans, &set->packet);
        }
#else
        ans = resolve_query(1, qB->query);
#endif
        if (ans == NULL){
            eprintf("[QueryHandle  %i] Failed to resolve query.\n", idx);
            free(qB->query);
            free(qB);
            continue;
        }
        printf("[QueryHandle  %i] obtained answer with qid: %u for client: %i\n", idx, ans->header.qid, idx);

        int connd = qB->connd;
        WOLFSSL* ssl = qB->ssl;

        // Create answer
        char answer[ans->end + (size_t)2];
        memset(answer, 0, ans->end + (size_t)2);
        answer[0] = 0xff & (ans->end >> 8);
        answer[1] = 0xff & (ans->end >> 0);
        ans->header.ra = 1;
        ans->header.rd = 1;
        memcpy(answer + 2, ans->data, ans->end);

        /* Send answer back to client */
        printf("[QueryHandle  %i] send answer with qid: %u\n", idx, ans->header.qid);
        ret = wolfSSL_write(ssl, answer, ans->end + (size_t)2);
        if (ret != (ans->end + (size_t)2)) {
            eprintf("[QueryHandle  %i] ERROR: failed to write. Ret: %i, Shutdown: %i\n", idx, ret, wolfSSL_get_shutdown(ssl));
        }

        free(qB->query);
        free(qB);
        free(ans);

        if (queryLists[idx]->reader_writer_sig == 0) {
            queryLists[idx]->query_handler_exited = 1;
            break;
        }
    }
    printf("[QueryHandle  %i] Finish QueryHandle\n", idx);
    return ret;
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
    printf("clean queryLists\n");
    for (int i = 0; i < MAX_CONCURRENT_THREADS; i++) {
        while(queryLists[i]->head != NULL && sgx_thread_mutex_trylock(queryLists[i]->queue_mutex) == 0) {
            struct QueryBuffer* tmp = queryLists[i]->head;
            queryLists[i]->head = tmp->next;
            sgx_thread_mutex_unlock(queryLists[i]->queue_mutex);
            free(tmp);
        }
    }
    for (int i = 0; i < MAX_CONCURRENT_THREADS; i++) {
        free(queryLists[i]);
    }
    free(resconf);
    free(hosts);
    free(hints);
#if DNS_CACHE
    cache_close();
#endif
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

void enc_init_cache(void) {
    int error = 0;
#if DNS_CACHE
    error = cache_init();
#endif
    assert(error == 0);
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
