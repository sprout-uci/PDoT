#!/usr/bin/python3
# How to run this script: ./rate_parallel.py dots 53 1000
# 1000 means 1000 queries per second

import sys
import dns.message, dns.query
import time
from threading import Thread
from multiprocessing import Queue

def dns_client(q, port, ans_time):
    start_time = time.time()
    r = dns.query.udp(q, '127.0.0.1', port=port)
    if r.answer:
        end_time = time.time() - start_time
        ans_time.put_nowait(end_time)
        print(end_time)


if __name__ == '__main__':
    domain = 'example.com'      # which URL we are using to create DNS queries
    rr_name = sys.argv[1]      # which Recursive Resolver we're using
    port = int(sys.argv[2])    # which port we're using
    rate = float(int(sys.argv[3]))    # rate of queries [queries per second per client]
    clients = int(sys.argv[4]) # number of clients
    exp_time = 10              # how long we are doing the experiment [s]

    rang = rate * exp_time
    threads = []
    ans_time = Queue(maxsize=int(rang))

    file_name= 'csv/rate_throughput_' + rr_name + '_' + str(port) + '_' + str(clients) + '.csv'
    fo = open(file_name, 'a')

    keywords = {'port' : port}
    sleep_time = float(1/rate)
    experiment_start = time.time()
    for i in range(int(rang)):
        q = dns.message.make_query(domain, dns.rdatatype.A)
        thread = Thread(target=dns_client, args=(q, port, ans_time))
        threads.append(thread)
        thread.start()
        time.sleep(sleep_time)
    
    for thread in threads:
        thread.join()

    fo.write(str(rate))
    while not ans_time.empty():
        fo.write(',' + str(ans_time.get()))
    fo.write('\n')
    fo.close()
