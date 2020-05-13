#!/usr/bin/python3
# How to run this script: ./rate_parallel.py dots 53 1000
# 1000 means 1000 queries per second

import sys
import dns.message, dns.query
import time
import multiprocessing.pool

id_to_start_time = {}
counter = 0
ans_time = []

def endCall(return_val):
    global counter
    if return_val.answer:
        end_time = time.time() - id_to_start_time[return_val.id]
        ans_time.append(end_time)
        # print(end_time)
        counter += 1


if __name__ == '__main__':
    domain = 'example.com'      # which URL we are using to create DNS queries
    rr_name = sys.argv[1]      # which Recursive Resolver we're using
    port = int(sys.argv[2])    # which port we're using
    rate = float(int(sys.argv[3]))    # rate of queries [queries per second per client]
    clients = int(sys.argv[4]) # number of clients
    exp_time = 60              # how long we are doing the experiment [s]

    rang = rate * exp_time
    pool = multiprocessing.pool.ThreadPool(processes=int(rang))

    file_name= 'csv/rate_throughput_' + rr_name + '_' + str(port) + '_' + str(clients) + '.csv'
    fo = open(file_name, 'a')

    keywords = {'port' : port}
    sleep_time = float(1/rate)
    experiment_start = time.time()
    for i in range(int(rang)):
        r = dns.message.make_query(domain, dns.rdatatype.A)
        thread_start = time.time()
        thread = pool.apply_async(dns.query.udp, (r, '127.0.0.1'), keywords, endCall)
        id_to_start_time[r.id] = thread_start
        time.sleep(sleep_time)
    pool.close()
    pool.join()
    print("[Rate %s] received: %i/%i" % (sys.argv[3], counter, rang))
    fo.write(str(rate))
    fo.write(',' + str(counter))
    fo.write(',' + str(rang))
    for ans in ans_time:
        fo.write(',' + str(ans))
    fo.write('\n')
    fo.close()
