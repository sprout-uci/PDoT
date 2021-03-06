/* server-tls.c
 *
 * Copyright (C) 2006-2015 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include "server-tls.h"

/* the usual suspects */
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/time.h>

/* socket includes */
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

/* wolfSSL */
#include <wolfssl/ssl.h>
#include <wolfssl/certs_test.h>

/* DNS stuff */
#include "dns.h"

/* threads */
#include <pthread.h>

#include "common.h"

#define DEFAULT_PORT 11111

#define CIPHER_LIST "ECDHE-ECDSA-AES128-GCM-SHA256"

#define F_SETFL 4
#define O_NONBLOCK 04000
#define FIOASYNC 0x5452

/* declare DNS objects */
struct dns_resolv_conf *resconf;
struct dns_hosts *hosts;
struct dns_hints *hints;

/* declare wolfSSL objects */
WOLFSSL_CTX* ctx;
WOLFSSL_METHOD* method;

/* Thread argument package */
struct qtarg_pkg {
    pthread_t tid;
    int       sgx_id;
    int       t_count;
};

/* Thread argument package */
struct ctarg_pkg {
    pthread_t rtid;
    pthread_t wtid;
    int       sgx_id;
    int       connd;
    int       open;
    int       t_count;
};

static volatile sig_atomic_t stop = 0;

int init_resconf(enum eval_type et) {
    int error = 0;

    if (!(resconf = dns_resconf_open(&error)))
        fprintf(stderr, "dns_resconf_open: %s", dns_strerror(error));

    if (et == EVAL_LATENCY)
        error = dns_resconf_loadpath(resconf, "/etc/resolv.conf");
    else if (et == EVAL_THROUGHPUT)
        error = dns_resconf_loadpath(resconf, "resolv.conf");
    else
        error = dns_resconf_loadpath(resconf, "/etc/resolv.conf");

    if (error) {
        fprintf(stderr, "dns_resconf_loadpath: %s", dns_strerror(error));
        return NULL;
    }

    error = dns_nssconf_loadpath(resconf, "/etc/nsswitch.conf");
    if (error) {
        fprintf(stderr, "dns_nssconf_loadpath: %s", dns_strerror(error));
        return NULL;
    }

    return error;
}

int init_hosts(void) {
    int error;

    if (hosts)
        return 0;
    if (!(hosts = dns_hosts_open(&error)))
        fprintf(stderr, "dns_hosts_open: %s", dns_strerror(error));
    if (error = dns_hosts_loadpath(hosts, "/etc/hosts"))
        fprintf(stderr, "dns_hosts_loadpath: %s", dns_strerror(error));

    return error;
}

struct dns_cache *cache(void) { return NULL; }


int init_hints(_Bool recurse) {
    int error;

    struct dns_hints *(*dnshints)() = (recurse) ? &dns_hints_root : &dns_hints_local;
	hints = dnshints(resconf, &error);
    if (!hints) {
        fprintf(stderr, "dns_hints");
        return error;
    }
    return 0;
}

void intHandler(int dummy) {
    printf("\nShutdown command issued!\n");
    stop = 1;
}

void* ClientReader(void* args)
{
    struct ctarg_pkg* pkg = args;
    int               sgxStatus;
    int               ret;

    sgxStatus = enc_wolfSSL_read_from_client(pkg->sgx_id, &ret, ctx, pkg->connd, pkg->t_count);
    if (sgxStatus != SGX_SUCCESS || ret == -1) {
        printf("Server failed to read from client: %i, SGX_STATUS: %i\n", pkg->connd, sgxStatus);
    }

    /* Cleanup after this connection */
    // printf("Clean up ClientHandler\n");
    pkg->open = 1;
    pthread_exit(NULL);
}

void* ClientWriter(void* args)
{
    struct ctarg_pkg* pkg = args;
    int               sgxStatus;
    int               ret;

    sgxStatus = enc_wolfSSL_write_to_client(pkg->sgx_id, &ret, pkg->t_count);
    if (sgxStatus != SGX_SUCCESS || ret == -1) {
        printf("Server failed to write to client: %i, SGX_STATUS: %i\n", pkg->connd, sgxStatus);
    }

    /* Cleanup after this connection */
    // printf("Clean up ClientHandler\n");
    close(pkg->connd);           /* Close the connection to the client   */
    pkg->open = 1;
    pthread_exit(NULL);
}

void *QueryHandler(void* args) {
    struct qtarg_pkg* pkg = args;
    int               sgxStatus;
    int               ret;
    int               counter = 0;

    sgxStatus = enc_wolfSSL_process_query(pkg->sgx_id, &ret, pkg->t_count);
    if (sgxStatus != SGX_SUCCESS || ret == -1) {
        // printf("Server failed to process query\n");
    } else if (ret == 0) {
        printf("QueryHandler %i finished\n", pkg->t_count);
        pthread_exit(NULL);
    }
    pthread_exit(NULL);
}


int server_connect(sgx_enclave_id_t id, enum eval_type et)
{
    int                sgxStatus;
    int                sockfd;
    int                connd;
    struct sockaddr_in servAddr;
    struct sockaddr_in clientAddr;
    socklen_t          size = sizeof(clientAddr);
    int                ret = 0;                        /* variable for error checking */
    _Bool              recurse = 1;

    /* declare thread variable */
    struct ctarg_pkg clientThread[MAX_CONCURRENT_THREADS];
    for (int i=0; i < MAX_CONCURRENT_THREADS; i++) {
        clientThread[i].rtid    = 0;
        clientThread[i].wtid    = 0;
        clientThread[i].sgx_id  = 0;
        clientThread[i].connd   = 0;
        clientThread[i].open    = 0;
        clientThread[i].t_count = 0;
    }
    struct qtarg_pkg queryThread[QUERY_HANDLE_THREADS];
    for (int i=0; i < QUERY_HANDLE_THREADS; i++) {
        queryThread[i].tid     = 0;
        queryThread[i].sgx_id  = 0;
        queryThread[i].t_count = 0;
    }
    int clientIdx;
    int queryIdx;

    /* Initialize wolfSSL */
    enc_wolfSSL_Init(id, &sgxStatus);

    if (0 != init_resconf(et)) {
        printf("init_resconf failure\n");
        return EXIT_FAILURE;
    }
    sgxStatus = enc_load_resconf(id, resconf);
    if (sgxStatus != SGX_SUCCESS || resconf == NULL) {
        printf("load_resconf failure\n");
        return EXIT_FAILURE;
    }

    if (0 != init_hosts()) {
        printf("init_hosts failure\n");
        return EXIT_FAILURE;
    }
    sgxStatus = enc_load_hosts(id, hosts);
    if (sgxStatus != SGX_SUCCESS || hosts == NULL) {
        printf("load_hosts failure\n");
        return EXIT_FAILURE;
    }

    if (et == EVAL_LATENCY)
        recurse = 1;
    else if (et == EVAL_THROUGHPUT)
        recurse = 0;
    else
        recurse = 1;

    if (0 != init_hints(recurse)) {
        printf("init_hints failure\n");
        return EXIT_FAILURE;
    }
    sgxStatus = enc_load_hints(id, hints);
    if (sgxStatus != SGX_SUCCESS || hints == NULL) {
        printf("load_hints failure\n");
        return EXIT_FAILURE;
    }

#ifdef SGX_DEBUG
    enc_wolfSSL_Debugging_ON(id);
#else
    enc_wolfSSL_Debugging_OFF(id);
#endif

    /* Create a socket that uses an internet IPv4 address,
     * Sets the socket to be stream based (TCP),
     * 0 means choose the default protocol. */
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        fprintf(stderr, "ERROR: failed to create the socket\n");
        return -1;
    }

    // if (fcntl(sockfd, F_SETFL, O_NONBLOCK) == -1) {
    //     fprintf(stderr, "ERROR: failed to set socket options\n");
    //     return -1;
    // }

    int enable = 1;
    struct timeval recv_timeout;
    recv_timeout.tv_sec = 5;
    recv_timeout.tv_usec = 0;
    ret = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));
    ret = setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &recv_timeout, sizeof(struct timeval));
    assert(ret != -1);

    /* Create and initialize WOLFSSL_CTX */
    sgxStatus = enc_wolfTLSv1_2_server_method(id, &method);
    if (sgxStatus != SGX_SUCCESS || method == NULL) {
        printf("wolfTLSv1_2_server_method failure\n");
        return EXIT_FAILURE;
    }

    sgxStatus = enc_wolfSSL_CTX_new(id, &ctx, method);
    if (sgxStatus != SGX_SUCCESS || ctx == NULL) {
        printf("wolfSSL_CTX_new failure\n");
        return EXIT_FAILURE;
    }

    /* Create key and certificate within the enclave */
    sgxStatus = enc_create_key_and_x509(id, ctx);
    assert(sgxStatus == SGX_SUCCESS);
    
    /* Initialize the server address struct with zeros */
    memset(&servAddr, 0, sizeof(servAddr));

    /* Fill in the server address */
    servAddr.sin_family      = AF_INET;             /* using IPv4      */
    servAddr.sin_port        = htons(DEFAULT_PORT); /* on DEFAULT_PORT */
    servAddr.sin_addr.s_addr = INADDR_ANY;          /* from anywhere   */

    /* Bind the server socket to our port */
    if (bind(sockfd, (struct sockaddr*)&servAddr, sizeof(servAddr)) == -1) {
        fprintf(stderr, "ERROR: failed to bind\n");
        return -1;
    }

    /* Listen for a new connection, allow 5 pending connections */
    if (listen(sockfd, MAX_CONCURRENT_THREADS) == -1) {
        fprintf(stderr, "ERROR: failed to listen\n");
        return -1;
    }

    /* Initialize thread mutex within the enclave */
    sgxStatus = enc_mutex_init(id, &ret);
    assert(sgxStatus == SGX_SUCCESS && ret == 0);


    /* initialise thread array */
    for (clientIdx = 0; clientIdx < MAX_CONCURRENT_THREADS; clientIdx++) {
        clientThread[clientIdx].t_count = clientIdx;
        clientThread[clientIdx].sgx_id = id;
        clientThread[clientIdx].open = 1;
    }

    for (int i = 0; i < QUERY_HANDLE_THREADS; i++) {
        queryThread[i].sgx_id = id;
        queryThread[i].t_count = i;

        /* Launch a thread to resolve query from new client */
        pthread_create(&queryThread[i].tid, NULL, QueryHandler, &queryThread[i]);
        pthread_detach(queryThread[i].tid);
    }

    // printf("Waiting for a connection...\n");

    while(!stop) {

        signal(SIGINT, intHandler);

        // Check whether we can have new client
        for (clientIdx = 0; (clientIdx < MAX_CONCURRENT_THREADS) && !clientThread[clientIdx].open; clientIdx++);
        if (clientIdx == MAX_CONCURRENT_THREADS) {
            continue;
        }

        /* Accept client connections */
        if ((connd = accept(sockfd, (struct sockaddr*)&clientAddr, &size))
            == -1) {
            continue;
        }

        clientThread[clientIdx].connd = connd;
        clientThread[clientIdx].open = 0;

        /* Launch a reader thread to deal with the new client */
        pthread_create(&clientThread[clientIdx].rtid, NULL, ClientReader, &clientThread[clientIdx]);
        /* State that we won't be joining this thread */
        pthread_detach(clientThread[clientIdx].rtid);

        /* Launch a writer thread to deal with the new client */
        pthread_create(&clientThread[clientIdx].wtid, NULL, ClientWriter, &clientThread[clientIdx]);
        /* State that we won't be joining this thread */
        pthread_detach(clientThread[clientIdx].wtid);
    }

    printf("clean up\n");

    /* Cleanup and return */
    sgxStatus = enc_wolfSSL_CTX_free(id, ctx);  /* Free the wolfSSL context object          */
    assert(sgxStatus == SGX_SUCCESS);
    sgxStatus = enc_wolfSSL_Cleanup(id, &ret);      /* Cleanup the wolfSSL environment          */
    assert(sgxStatus == SGX_SUCCESS && ret == WOLFSSL_SUCCESS);
    sgxStatus = enc_mutex_destroy(id, &ret); /* Initialize thread mutex within the enclave */
    assert(sgxStatus == SGX_SUCCESS && ret == 0);
    close(sockfd);          /* Close the socket listening for clients   */

    printf("Shutdown complete\n");
    return 0;               /* Return reporting a success               */
}

            // pthread_exit(NULL);