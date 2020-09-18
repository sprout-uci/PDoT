import sys
import matplotlib as mpl
mpl.use('agg')
import matplotlib.pyplot as plt
import csv
import numpy as np

def geometric_mean(iterable):
    a = np.array(iterable)
    return a.prod()**(1.0/len(a))

eval_names = ['pdot', 'cloudflare']
setting_names = ['cold', 'warm']

for j, s in enumerate(setting_names):
    fig_name = 'images/dns_query_time_' + s + '_real_world.png'
    fig = plt.figure(j+1, figsize=(9,6))
    ax = fig.add_subplot(111)
    dots_data_avg = []
    cloudflare_data_avg = []
    for i, e in enumerate(eval_names):
        data_name = 'dns_query_time_' + e + '_' + s
        file_name =  'csv/dns_query_time_' + e + '_' + s + '_real_world.csv'
        data = []
        domain = []
        for r in range(10):
            data.append([])
        with open(file_name) as f:
            predata = csv.reader(f)
            for k, row in enumerate(predata):
                if k == 0:
                    domain = row.copy()
                else:
                    for l, d in enumerate(row):
                        data[l].append(float(d))
        
        if i == 0:
            bp0 = ax.boxplot(data, positions=[x - 0.1 for x in range(0, len(data))], widths=0.2, patch_artist=True, boxprops=dict(facecolor="#ff000d"), medianprops=dict(color='black', linewidth='2'), showfliers=False)
            dots_data_avg = [np.mean(d) for d in data]
        elif i == 1:
            bp1 = ax.boxplot(data, positions=[x + 0.1 for x in range(0, len(data))], widths=0.2, patch_artist=True, boxprops=dict(facecolor="#95d0fc"), medianprops=dict(color='black', linewidth='2'), showfliers=False)
            cloudflare_data_avg = [np.mean(d) for d in data]

    data_avg = []
    dots_geomean = geometric_mean(dots_data_avg)
    cloudflare_geomean = geometric_mean(cloudflare_data_avg)
    # for i in range(len(dots_data_avg)):
    #     data_avg.append((dots_data_avg[i] - cloudflare_data_avg[i]) / cloudflare_data_avg[i] * 100)
    # print(np.mean(data_avg), '(', s, ')')
    print(dots_geomean, cloudflare_geomean)
   
    ax.legend([bp0["boxes"][0], bp1["boxes"][0]], ['PDoT', 'Cloudflare'])
    
    #ax.set_title("Latency measurement for " + s + " start (DoTS v.s. Unbound)")
    ax.set_xticks([x for x in range(0, len(domain))])
    #ax.set_xlabel("Domain names")
    ax.set_ylabel("Time to resolve a query [s]")
    if s == 'cold':
        ax.set_ylim(0, 0.55)
    if s == 'warm':
        ax.set_ylim(0, 0.075)
    ax.set_xticklabels(domain, rotation='vertical')
    fig.savefig(fig_name, bbox_inches='tight')
