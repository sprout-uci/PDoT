/* server-tls.h
*
* Copyright (C) 2006-2016 wolfSSL Inc.
*
* This file is part of wolfSSL.
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
* Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
*/

#ifndef SERVER_TLS_H
#define SERVER_TLS_H

#include "sgx_urts.h"	 /* for enclave_id etc.*/
#include "Wolfssl_Enclave_u.h"   /* contains untrusted wrapper functions used to call enclave functions*/
#include "dns.h"

enum eval_type {
    EVAL_LATENCY = 0,
    EVAL_THROUGHPUT = 1
};

int server_connect(sgx_enclave_id_t id, enum eval_type et);
int init_resconf(enum eval_type et);
int init_hosts(void);
struct dns_cache *cache(void);
int init_hints(_Bool recurse);

#endif /* SERVER_TLS_H */
