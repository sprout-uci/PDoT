# usage: python3 throughput_plot_rate.py 2
# where 2 is the number of clients used in the evaluation
import sys
import matplotlib as mpl
mpl.use('agg')
mpl.rcParams.update({'font.size': 16})
import matplotlib.pyplot as plt
import numpy as np
import csv

# eval_names = ['unbound', 'dots']
eval_names = ['dots', 'unbound']

# Rate
real_rates = []
fig = plt.figure(1, figsize=(9,6))
ax = fig.add_subplot(111)
clients = sys.argv[1]
box_width = 0.4
img_name = 'images/rate_throughput_' + clients + '_clients.png'
for i, e in enumerate(eval_names):
    port = '53'
    data = {}
    rates = []
    for j in range(int(clients)):
        data_name = 'rate_throughput_' + e + '_' + port + '_' + clients
        file_name = 'csv/' + data_name + '.csv'
        with open(file_name) as f:
            predata = csv.reader(f)
            predata_rates = {}
            for k, row in enumerate(predata):
                count = int(row[1])
                rang = map(float, row[2])
                rate = int(float(row[0])*int(clients))
                #print(rate, np.max(list(map(float, row[3:]))), np.min(list(map(float, row[3:]))), np.mean(list(map(float, row[3:]))))
                if np.mean(list(map(float, row[3:]))) < 1:
                    if rate in data and rate not in predata_rates:
                        for d in list(map(float, row[3:])):
                            data[rate].append(d)
                    elif rate in predata_rates:
                        data[rate] = list(map(float, row[3:]))
                    else:
                        data[rate] = list(map(float, row[3:]))
                        rates.append(rate)
                        predata_rates[rate] = 1
        port = str(int(port) + 1)

    if i == 0:
        bp1 = ax.boxplot([data[y] for y in sorted(rates)], positions=[x + box_width/2 for x in range(0, len(data.values()))], widths=box_width, patch_artist=True, boxprops=dict(facecolor="#ff000d"), medianprops=dict(color='black', linewidth='2'), showfliers=False)
        #ax.errorbar([x + 0.5 for x in rates], [np.mean(data[y]) for y in rates], yerr = [np.std(data[y]) for y in rates], color='r', fmt='o', capsize=5)
        real_rates = rates
    elif i == 1:
        bp0 = ax.boxplot([data[y] for y in sorted(rates)], positions=[x - box_width/2 for x in range(0, len(data.values()))], widths=box_width, patch_artist=True, boxprops=dict(facecolor="#95d0fc"), medianprops=dict(color='black', linewidth='2'), showfliers=False)
        #ax.errorbar([x - 0.5 for x in rates], [np.mean(data[y]) for y in rates], yerr = [np.std(data[y]) for y in rates], color='b', fmt='x', capsize=5)
        if len(rates) > len(real_rates):
            real_rates = rates


#ax.legend([bp1["boxes"][0], bp0["boxes"][0]], eval_names, bbox_to_anchor=(1.18, 0.5))
#ax.legend([bp1["boxes"][0], bp0["boxes"][0]], eval_names, bbox_to_anchor=(1.02, 0.5))
#ax.legend(eval_names, bbox_to_anchor=(1.18, 0.5))

#real_rates = [x for x in range(5, max(real_rates)+5, 5)]
#ax.set_xticks(real_rates)
#ax.set_xticklabels(real_rates)
ax.set_xticks([x for x in range(0, len(real_rates)+1)])
ax.set_xticklabels(sorted(real_rates))
ax.set_ylim(0, 0.8)
#if clients == '1':
#    ax.set_title("Latency with different rates (" + clients + " client)") 
#else:
#    ax.set_title("Latency with different rates (" + clients + " clients)") 
ax.set_xlabel("Rate [queries per second]")
ax.set_ylabel("Response time [s]")
fig.savefig(img_name, bbox_inches='tight')
