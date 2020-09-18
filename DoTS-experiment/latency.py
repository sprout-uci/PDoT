#!/usr/bin/python3
# How to run this script: seq -w 0 999 | parallel ./nameserver.py {}

import sys
import dns.message, dns.query
import time

domain_list = [
    "google.com",
    "facebook.com",
    "youtube.com",
    "twitter.com",
    "microsoft.com",
    "linkedin.com",
    "wikipedia.org",
    "plus.google.com",
    "instagram.com",
    "apple.com"
]
rr_name = sys.argv[1] # The RR we are going to use
setting = sys.argv[2] # Either 'warm' or 'cold'

file_name = "csv/dns_query_time_" + rr_name + "_" + setting + ".csv"

# Write the domains that represent each column
fo = open(file_name, "a")
if int(sys.argv[3]) == 0:
    for e, d in enumerate(domain_list):
        fo.write(d)
        if e != 9:
            fo.write(',')
    fo.write('\n')

# Actual experiment
if setting == 'warm':
    r = dns.message.make_query('bbc.com', dns.rdatatype.A)
    resp = dns.query.udp(r, '127.0.0.1')
for i, domain in enumerate(domain_list):
    answers = []
    #print("searching: " + domain)
    r = dns.message.make_query(domain, dns.rdatatype.A)
    while True:
        start = time.time()
        resp = dns.query.udp(r, '127.0.0.1')
        if resp.answer:
            total_time = time.time() - start
            fo.write(str(total_time))
            if i != 9:
                fo.write(',')
            break
fo.write("\n")
fo.close()
