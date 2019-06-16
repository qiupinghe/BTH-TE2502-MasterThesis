from itertools import islice
import statistics
import numpy
import math
import PyGnuplot as gp
from scipy.stats import sem, t
from scipy import mean, median, stats
import sys

from numpy.random import seed
from numpy.random import randn
from numpy import mean
from numpy import std
from matplotlib import pyplot
from statsmodels.graphics.gofplots import qqplot
from numpy import array, std
from scipy.stats import shapiro
from scipy.stats import normaltest

def read_entries_proc_status(file):
    with open(file, 'r') as f:
        VmHWM = list()
        VmRSS = list()
        roundVmHWM = list()
        roundVmRSS = list()
        for line in f:
            l = line.split()
            if(l[0] == "Round:"):
                if(len(roundVmHWM) is not 0):
                    VmHWM.append(roundVmHWM[:])
                if(len(roundVmRSS) is not 0):
                    VmRSS.append(roundVmRSS[:])
                del roundVmHWM[:]
                del roundVmRSS[:]
            elif(l[0] == "VmHWM:"):
                roundVmHWM.append(int(l[1]))
            elif(l[0] == "VmRSS:"):
                roundVmRSS.append(int(l[1]))
        VmHWM.append(roundVmHWM[:])
        VmRSS.append(roundVmRSS[:])
        return VmHWM, VmRSS

def check_differance_rss(data):
    for l in data:
        if(len(set(l)) != 1 ):
            #print("All elements are not the same")
            return False
    #print("All elements are equal")
    return True

def process_data_rss(peakRSS, RSS):
    #print("Max peak RSS of all rounds: ", max(max(peakRSS, key=max)))
    #print("Min peak RSS of all rounds: ", min(min(peakRSS, key=min)))
    #print("Max RSS of all rounds: ", max(max(RSS, key=max)))
    #print("Min RSS of all rounds: ", min(min(RSS, key=min)))

    mean_list = list()
    for l in RSS:
        mean_list.append(mean(l))
    mean_val = mean(mean_list)
    #print("Mean RSS", mean(mean_val))

    median_list = list()
    for l in RSS:
        median_list.append(median(l))
    median_val = median(median_list)
    #print("Median RSS", median_val)

    standard_dev = stats.tstd(mean_list)
    #print("Standard dev", standard_dev)

    c_interval = confidence_interval(mean_list)
    #print("Conf_low", c_interval[0])
    #print("Conf_high", c_interval[1])
    summary_dict = {
                    "max_peak_rss": max(max(peakRSS, key=max)),
                    "min_peak_rss": min(min(peakRSS, key=min)),
                    "max_rss": max(max(RSS, key=max)),
                    "min_rss": min(min(RSS, key=min)),
                    "mean": mean_val,
                    "median": median_val,
                    "std_dev": standard_dev,
                    "conf_low": c_interval[0],
                    "conf_high": c_interval[1]
    }
    return summary_dict

def process_proc_status_output(file_path, sample_size = 100):
    peakRSS, RSS = read_entries_proc_status(file_path)
    if (check_differance_rss(peakRSS) and check_differance_rss(RSS)):
        # All measurements (RSS and peak) are equal in each test.
        peak_list = list()
        for l in peakRSS:
            peak_list.append(l[0])
        rss_list = list()
        for l in RSS:
            rss_list.append(l[0])
        if (len([i for i, j in zip(peak_list, rss_list) if i != j]) == 0):
            print("Peak RSS and RSS measurements are all equal (for each round) in "\
            + file_path + ". Returning new list. Setting data length to: " + str(len(rss_list[0:sample_size])))
            return rss_list[0:sample_size]
        else:
            print("Peak RSS and RSS is not the same in all rounds.")
    else:
        print("Measurements are not the same in all rounds.")

def process_usrbintime_output(file_path, sample_size=100):
    maxRSS = list()
    with open(file_path, 'r') as f:
        for line in f:
            maxRSS.append(int(line))
    print("Found " + str(len(maxRSS)) + " outputs in " + file_path +\
    ". Setting list to length " + str(len(maxRSS[0:sample_size])))
    return maxRSS[0:sample_size]

def process_usrbintime_output_special(file_path, sample_size=100):
    maxRSS = list()
    with open(file_path, 'r') as f:
        for line in f:
            maxRSS.append(int(line))
    max_rss_combined = list()
    for i in range(0, len(maxRSS), 2):
        max_rss_combined.append((maxRSS[i]+maxRSS[i+1])/2)
    print("Found " + str(len(maxRSS)) + " outputs in " + file_path + \
    ". Combining outputs into list of length " + str(len(max_rss_combined)) +\
    ". Setting list to length " + str(len(max_rss_combined[0:sample_size])))
    return max_rss_combined[0:sample_size]

def read_entries(file, no_lines_per_entry):
    list_entries = []
    with open(file, 'r') as f:
        while True:
            entry = [x.strip() for x in islice(f, no_lines_per_entry)]
            if(entry == []):
                break
            list_entries.append(entry)
    return list_entries

def gather_cpu_clock(list_entries, column):
    cpu_time_list = []
    for entry in list_entries:
        cpu_clock = float(entry[column].split()[0].replace(',', '.'))
        cpu_time_list.append(cpu_clock)
    return cpu_time_list

def gather_real_time(list_entries, column):
    real_time_list = []
    for entry in list_entries:
        real_time = float(entry[column].split()[0].replace(',', '.'))
        real_time_list.append(real_time)
    real_time_list = [x*1000 for x in real_time_list]
    return real_time_list

def gather_cpu_cycles(list_entries, column):
    cpu_cycle_list = []
    for entry in list_entries:
        cycles = ''
        for x in entry[column].split():
            if(x == 'cycles'):
                break
            cycles += x
        cpu_cycle_list.append(int(cycles))
    return cpu_cycle_list

def confidence_interval(list, interval = 0.95):
    mean_val = mean(list)
    n = len(list)
    stdev = stats.tstd(list)
    z = stats.norm.ppf((interval + 1)/2)
    #z = stats.t.ppf((interval + 1)/2, n)
    lower_bound = mean_val - z * stdev / math.sqrt(n)
    upper_bound = mean_val + z *stdev / math.sqrt(n)
    return lower_bound, upper_bound

def confidence_interval_t_dist(list, interval = 0.95):
    data = list
    n = len(data)
    m = mean(data)
    std_err = sem(data)
    h = std_err * t.ppf((1 + interval) / 2, n - 1)
    return m-h, m+h

def add_statistic_values(in_dict):
    data = in_dict["data"]
    in_dict["mean"] = mean(data)
    in_dict["median"] = median(data)
    in_dict["max"] = max(data)
    in_dict["min"] = min(data)
    in_dict["standard_dev"] = numpy.std(data)
    c_interval = confidence_interval(data)
    in_dict["conf_low"] =  c_interval[0]
    in_dict["conf_high"] = c_interval[1]
    return in_dict

def process_perf_stat_output(file_path, divide_value=1):
    list_entries = read_entries(file_path, 10)
    #for entry in list_entries:
        #print(entry)
    print(str(len(list_entries)) + " perf stat outputs found in file " + file_path + "." \
    + " Removing 30 first entries from list. New length: " + str(len(list_entries[30:])))
    list_entries = list_entries[30:]
    real_time_values = {}
    cpu_time_values = {}
    cpu_cycles_values = {}

    real_time_values["data"] = gather_real_time(list_entries, 8)
    cpu_time_values["data"] = gather_cpu_clock(list_entries, 5)
    cpu_cycles_values["data"] = gather_cpu_cycles(list_entries, 6)

    if(divide_value is not 1):
        print("Dividing values from output with " + str(divide_value))
        real_time_values["data"] = [i/divide_value for i in real_time_values["data"]]
        cpu_time_values["data"] = [i/divide_value for i in cpu_time_values["data"]]
        cpu_cycles_values["data"] = [i/divide_value for i in cpu_cycles_values["data"]]

    add_statistic_values(real_time_values)
    add_statistic_values(cpu_time_values)
    add_statistic_values(cpu_cycles_values)
    return real_time_values, cpu_time_values, cpu_cycles_values

def create_normality_graphs(save_file, title, data):
    pyplot.hist(data, bins=50)
    title_obj = pyplot.title(title)
    pyplot.savefig(save_file + '_histogram')
    pyplot.close()
    qqplot(array(data), line='s')
    title_obj = pyplot.title(title)
    pyplot.savefig(save_file + '_qq')
    pyplot.close()

def mannwhitneyu_test(lib, alg1, alg2, measurement, data1, data2):
    alpha = 0.05
    print('\t' + lib +': '+ alg1 + ' and ' + alg2 + ' ' + measurement + ' Mann-Whitney U Test results')
    print('\t' + str(stats.mannwhitneyu(data1, data2, alternative='two-sided')))
    stat, p, u1, u2, ranksum1, ranksum2 = stats.mannwhitneyu(data1, data2, alternative='two-sided')
    if p > alpha:
        print('\t' + 'Same distribution (fail to reject H0)\n')
    else:
        print( '\t' +'Different distribution (reject H0)\n')

if (len(sys.argv) < 2):
    print("No argument input")
    sys.exit()
# generate graphs for real/cpu time, cpu cycles for sm3 and sha256
if (sys.argv[1] == 'hash'):
    #openssl
    sm3_real_time, sm3_cpu_time, sm3_cpu_cycles = process_perf_stat_output("output/hash/sm3_perf_o")
    sha_real_time, sha_cpu_time, sha_cpu_cycles = process_perf_stat_output("output/hash/sha256_perf_o")
    mannwhitneyu_test('OpenSSL', 'SM3', 'SHA256', 'Real Time', sm3_real_time["data"], sha_real_time["data"])
    mannwhitneyu_test('OpenSSL', 'SM3', 'SHA256', 'CPU Time', sm3_cpu_time["data"], sha_cpu_time["data"])
    mannwhitneyu_test('OpenSSL', 'SM3', 'SHA256', 'CPU Cycles', sm3_cpu_cycles["data"], sha_cpu_cycles["data"])
    #botan
    botan_sm3_real_time, botan_sm3_cpu_time, botan_sm3_cpu_cycles = process_perf_stat_output("output/hash/sm3_perf")
    botan_sha_real_time, botan_sha_cpu_time, botan_sha_cpu_cycles = process_perf_stat_output("output/hash/sha256_perf")
    mannwhitneyu_test('Botan', 'SM3', 'SHA256', 'Real Time', botan_sm3_real_time["data"], botan_sha_real_time["data"])
    mannwhitneyu_test('Botan', 'SM3', 'SHA256', 'CPU Time', botan_sm3_cpu_time["data"], botan_sha_cpu_time["data"])
    mannwhitneyu_test('Botan', 'SM3', 'SHA256', 'CPU Cycles', botan_sm3_cpu_cycles["data"], botan_sha_cpu_cycles["data"])

    ### RSS ###
    #OpenSSL
    RSS_sha = process_proc_status_output("output/hash/sha256_rss_o")
    RSS_sm3 = process_proc_status_output("output/hash/sm3_rss_o")
    mannwhitneyu_test('OpenSSL', 'SM3', 'SHA256', 'RSS', RSS_sm3, RSS_sha)
    #Botan
    RSS_sha_botan = process_proc_status_output("output/hash/sha256_rss")
    RSS_sm3_botan = process_proc_status_output("output/hash/sm3_rss")
    mannwhitneyu_test('Botan', 'SM3', 'SHA256', 'RSS', RSS_sm3_botan, RSS_sha_botan)

elif(sys.argv[1] == 'ds'):
    ############ GmSSL ############
    # Key generation, RSA: 10, SM2: 1000, ECDSA: 1000
    rsa_keygen_real_time, rsa_keygen_cpu_time, rsa_keygen_cpu_cycles = process_perf_stat_output("output/ds_perf/rsa_keygen_perf_o", 10)
    sm2_keygen_real_time, sm2_keygen_cpu_time, sm2_keygen_cpu_cycles = process_perf_stat_output("output/ds_perf/sm2_keygen_perf_o", 1000)
    ecdsa_keygen_real_time, ecdsa_keygen_cpu_time, ecdsa_keygen_cpu_cycles = process_perf_stat_output("output/ds_perf/ecdsa_keygen_perf_o", 1000)
    mannwhitneyu_test('GmSSL', 'SM2(keygen)', 'RSA(keygen)', 'Real Time', sm2_keygen_real_time["data"], rsa_keygen_real_time["data"])
    mannwhitneyu_test('GmSSL', 'SM2(keygen)', 'RSA(keygen)', 'CPU Time', sm2_keygen_cpu_time["data"], rsa_keygen_cpu_time["data"])
    mannwhitneyu_test('GmSSL', 'SM2(keygen)', 'RSA(keygen)', 'CPU Cycles', sm2_keygen_cpu_cycles["data"], rsa_keygen_cpu_cycles["data"])
    mannwhitneyu_test('GmSSL', 'SM2(keygen)', 'ECDSA(keygen)', 'Real Time', sm2_keygen_real_time["data"], ecdsa_keygen_real_time["data"])
    mannwhitneyu_test('GmSSL', 'SM2(keygen)', 'ECDSA(keygen)', 'CPU Time', sm2_keygen_cpu_time["data"], ecdsa_keygen_cpu_time["data"])
    mannwhitneyu_test('GmSSL', 'SM2(keygen)', 'ECDSA(keygen)', 'CPU Cycles', sm2_keygen_cpu_cycles["data"], ecdsa_keygen_cpu_cycles["data"])
    # Signing, RSA: 1000, SM2: 1000, ECDSA: 1000
    rsa_sign_real_time, rsa_sign_cpu_time, rsa_sign_cpu_cycles = process_perf_stat_output("output/ds_perf/rsa_sign_perf_o", 1000)
    sm2_sign_real_time, sm2_sign_cpu_time, sm2_sign_cpu_cycles = process_perf_stat_output("output/ds_perf/sm2_sign_perf_o", 1000)
    ecdsa_sign_real_time, ecdsa_sign_cpu_time, ecdsa_sign_cpu_cycles = process_perf_stat_output("output/ds_perf/ecdsa_sign_perf_o", 1000)
    mannwhitneyu_test('GmSSL', 'SM2(signing)', 'RSA(signing)', 'Real Time', sm2_sign_real_time["data"], rsa_sign_real_time["data"])
    mannwhitneyu_test('GmSSL', 'SM2(signing)', 'RSA(signing)', 'CPU Time', sm2_sign_cpu_time["data"], rsa_sign_cpu_time["data"])
    mannwhitneyu_test('GmSSL', 'SM2(signing)', 'RSA(signing)', 'CPU Cycles', sm2_sign_cpu_cycles["data"], rsa_sign_cpu_cycles["data"])
    mannwhitneyu_test('GmSSL', 'SM2(signing)', 'ECDSA(signing)', 'Real Time', sm2_sign_real_time["data"], ecdsa_sign_real_time["data"])
    mannwhitneyu_test('GmSSL', 'SM2(signing)', 'ECDSA(signing)', 'CPU Time', sm2_sign_cpu_time["data"], ecdsa_sign_cpu_time["data"])
    mannwhitneyu_test('GmSSL', 'SM2(signing)', 'ECDSA(signing)', 'CPU Cycles', sm2_sign_cpu_cycles["data"], ecdsa_sign_cpu_cycles["data"])

    # Verifying, RSA: 1000, SM2: 1000, ECDSA: 1000
    rsa_verify_real_time, rsa_verify_cpu_time, rsa_verify_cpu_cycles = process_perf_stat_output("output/ds_perf/rsa_verify_perf_o", 1000)
    sm2_verify_real_time, sm2_verify_cpu_time, sm2_verify_cpu_cycles = process_perf_stat_output("output/ds_perf/sm2_verify_perf_o", 1000)
    ecdsa_verify_real_time, ecdsa_verify_cpu_time, ecdsa_verify_cpu_cycles = process_perf_stat_output("output/ds_perf/ecdsa_verify_perf_o", 1000)
    mannwhitneyu_test('GmSSL', 'SM2(verify)', 'RSA(verify)', 'Real Time', sm2_verify_real_time["data"], rsa_verify_real_time["data"])
    mannwhitneyu_test('GmSSL', 'SM2(verify)', 'RSA(verify)', 'CPU Time', sm2_verify_cpu_time["data"], rsa_verify_cpu_time["data"])
    mannwhitneyu_test('GmSSL', 'SM2(verify)', 'RSA(verify)', 'CPU Cycles', sm2_verify_cpu_cycles["data"], rsa_verify_cpu_cycles["data"])
    mannwhitneyu_test('GmSSL', 'SM2(verify)', 'ECDSA(verify)', 'Real Time', sm2_verify_real_time["data"], ecdsa_verify_real_time["data"])
    mannwhitneyu_test('GmSSL', 'SM2(verify)', 'ECDSA(verify)', 'CPU Time', sm2_verify_cpu_time["data"], ecdsa_verify_cpu_time["data"])
    mannwhitneyu_test('GmSSL', 'SM2(verify)', 'ECDSA(verify)', 'CPU Cycles', sm2_verify_cpu_cycles["data"], ecdsa_verify_cpu_cycles["data"])

    ############ Botan ############
    # Key generation, RSA: 10, SM2: 10000, ECDSA: 10000
    botan_rsa_keygen_real_time, botan_rsa_keygen_cpu_time, botan_rsa_keygen_cpu_cycles = process_perf_stat_output("output/ds_perf/rsa_keygen_perf", 10)
    botan_sm2_keygen_real_time, botan_sm2_keygen_cpu_time, botan_sm2_keygen_cpu_cycles = process_perf_stat_output("output/ds_perf/sm2_keygen_perf", 10000)
    botan_ecdsa_keygen_real_time, botan_ecdsa_keygen_cpu_time, botan_ecdsa_keygen_cpu_cycles = process_perf_stat_output("output/ds_perf/ecdsa_keygen_perf", 10000)
    mannwhitneyu_test('Botan', 'SM2(keygen)', 'RSA(keygen)', 'Real Time', botan_sm2_keygen_real_time["data"], botan_rsa_keygen_real_time["data"])
    mannwhitneyu_test('Botan', 'SM2(keygen)', 'RSA(keygen)', 'CPU Time', botan_sm2_keygen_cpu_time["data"], botan_rsa_keygen_cpu_time["data"])
    mannwhitneyu_test('Botan', 'SM2(keygen)', 'RSA(keygen)', 'CPU Cycles', botan_sm2_keygen_cpu_cycles["data"], botan_rsa_keygen_cpu_cycles["data"])
    mannwhitneyu_test('Botan', 'SM2(keygen)', 'ECDSA(keygen)', 'Real Time', botan_sm2_keygen_real_time["data"], botan_ecdsa_keygen_real_time["data"])
    mannwhitneyu_test('Botan', 'SM2(keygen)', 'ECDSA(keygen)', 'CPU Time', botan_sm2_keygen_cpu_time["data"], botan_ecdsa_keygen_cpu_time["data"])
    mannwhitneyu_test('Botan', 'SM2(keygen)', 'ECDSA(keygen)', 'CPU Cycles', botan_sm2_keygen_cpu_cycles["data"], botan_ecdsa_keygen_cpu_cycles["data"])
    # Signing, RSA: 1000, SM2: 10000, ECDSA: 10000
    botan_rsa_sign_real_time, botan_rsa_sign_cpu_time, botan_rsa_sign_cpu_cycles = process_perf_stat_output("output/ds_perf/rsa_sign_perf", 1000)
    botan_sm2_sign_real_time, botan_sm2_sign_cpu_time, botan_sm2_sign_cpu_cycles = process_perf_stat_output("output/ds_perf/sm2_sign_perf", 10000)
    botan_ecdsa_sign_real_time, botan_ecdsa_sign_cpu_time, botan_ecdsa_sign_cpu_cycles = process_perf_stat_output("output/ds_perf/ecdsa_sign_perf", 10000)
    mannwhitneyu_test('Botan', 'SM2(signing)', 'RSA(signing)', 'Real Time', botan_sm2_sign_real_time["data"], botan_rsa_sign_real_time["data"])
    mannwhitneyu_test('Botan', 'SM2(signing)', 'RSA(signing)', 'CPU Time', botan_sm2_sign_cpu_time["data"], botan_rsa_sign_cpu_time["data"])
    mannwhitneyu_test('Botan', 'SM2(signing)', 'RSA(signing)', 'CPU Cycles', botan_sm2_sign_cpu_cycles["data"], botan_rsa_sign_cpu_cycles["data"])
    mannwhitneyu_test('Botan', 'SM2(signing)', 'ECDSA(signing)', 'Real Time', botan_sm2_sign_real_time["data"], botan_ecdsa_sign_real_time["data"])
    mannwhitneyu_test('Botan', 'SM2(signing)', 'ECDSA(signing)', 'CPU Time', botan_sm2_sign_cpu_time["data"], botan_ecdsa_sign_cpu_time["data"])
    mannwhitneyu_test('Botan', 'SM2(signing)', 'ECDSA(signing)', 'CPU Cycles', botan_sm2_sign_cpu_cycles["data"], botan_ecdsa_sign_cpu_cycles["data"])
    #Verifying, RSA: 10000, SM2: 10000, ECDSA: 10000
    botan_rsa_verify_real_time, botan_rsa_verify_cpu_time, botan_rsa_verify_cpu_cycles = process_perf_stat_output("output/ds_perf/rsa_verify_perf", 10000)
    botan_sm2_verify_real_time, botan_sm2_verify_cpu_time, botan_sm2_verify_cpu_cycles = process_perf_stat_output("output/ds_perf/sm2_verify_perf", 10000)
    botan_ecdsa_verify_real_time, botan_ecdsa_verify_cpu_time, botan_ecdsa_verify_cpu_cycles = process_perf_stat_output("output/ds_perf/ecdsa_verify_perf", 10000)
    mannwhitneyu_test('Botan', 'SM2(verify)', 'RSA(verify)', 'Real Time', botan_sm2_verify_real_time["data"], botan_rsa_verify_real_time["data"])
    mannwhitneyu_test('Botan', 'SM2(verify)', 'RSA(verify)', 'CPU Time', botan_sm2_verify_cpu_time["data"], botan_rsa_verify_cpu_time["data"])
    mannwhitneyu_test('Botan', 'SM2(verify)', 'RSA(verify)', 'CPU Cycles', botan_sm2_verify_cpu_cycles["data"], botan_rsa_verify_cpu_cycles["data"])
    mannwhitneyu_test('Botan', 'SM2(verify)', 'ECDSA(verify)', 'Real Time', botan_sm2_verify_real_time["data"], botan_ecdsa_verify_real_time["data"])
    mannwhitneyu_test('Botan', 'SM2(verify)', 'ECDSA(verify)', 'CPU Time', botan_sm2_verify_cpu_time["data"], botan_ecdsa_verify_cpu_time["data"])
    mannwhitneyu_test('Botan', 'SM2(verify)', 'ECDSA(verify)', 'CPU Cycles', botan_sm2_verify_cpu_cycles["data"], botan_ecdsa_verify_cpu_cycles["data"])

    #GmSSL RSS
    ecdsa_keygen_rss = process_usrbintime_output_special('output/ds_rss/rss_ecdsa_key_gmssl')
    rsa_keygen_rss = process_usrbintime_output_special('output/ds_rss/rss_rsa_key_gmssl')
    sm2_keygen_rss = process_usrbintime_output_special('output/ds_rss/rss_sm2_key_gmssl')
    mannwhitneyu_test('GmSSL', 'SM2(keygen)', 'RSA(keygen)', 'RSS', sm2_keygen_rss, rsa_keygen_rss)
    mannwhitneyu_test('GmSSL', 'SM2(keygen)', 'ECDSA(keygen)', 'RSS', sm2_keygen_rss, ecdsa_keygen_rss)

    ecdsa_sign_rss = process_usrbintime_output('output/ds_rss/rss_ecdsa_sign_gmssl')
    rsa_sign_rss = process_usrbintime_output('output/ds_rss/rss_rsa_sign_gmssl')
    sm2_sign_rss = process_usrbintime_output('output/ds_rss/rss_sm2_sign_gmssl')
    mannwhitneyu_test('GmSSL', 'SM2(sign)', 'RSA(sign)', 'RSS', sm2_sign_rss, rsa_sign_rss)
    mannwhitneyu_test('GmSSL', 'SM2(sign)', 'ECDSA(sign)', 'RSS', sm2_sign_rss, ecdsa_sign_rss)

    ecdsa_verify_rss = process_usrbintime_output('output/ds_rss/rss_ecdsa_verify_gmssl')
    rsa_verify_rss = process_usrbintime_output('output/ds_rss/rss_rsa_verify_gmssl')
    sm2_verify_rss = process_usrbintime_output('output/ds_rss/rss_sm2_verify_gmssl')
    mannwhitneyu_test('GmSSL', 'SM2(verify)', 'RSA(verify)', 'RSS', sm2_verify_rss, rsa_verify_rss)
    mannwhitneyu_test('GmSSL', 'SM2(verify)', 'ECDSA(verify)', 'RSS', sm2_verify_rss, ecdsa_verify_rss)

    #Botan RSS
    ecdsa_keygen_rss_botan = process_usrbintime_output('output/ds_rss/rss_ecdsa_key_botan')
    rsa_keygen_rss_botan = process_usrbintime_output('output/ds_rss/rss_rsa_key_botan')
    sm2_keygen_rss_botan = process_usrbintime_output('output/ds_rss/rss_sm2_key_botan')
    mannwhitneyu_test('Botan', 'SM2(keygen)', 'RSA(keygen)', 'RSS', sm2_keygen_rss_botan, rsa_keygen_rss_botan)
    mannwhitneyu_test('Botan', 'SM2(keygen)', 'ECDSA(keygen)', 'RSS', sm2_keygen_rss_botan, ecdsa_keygen_rss_botan)

    ecdsa_sign_rss_botan = process_usrbintime_output('output/ds_rss/rss_ecdsa_sign_botan')
    rsa_sign_rss_botan = process_usrbintime_output('output/ds_rss/rss_rsa_sign_botan')
    sm2_sign_rss_botan = process_usrbintime_output('output/ds_rss/rss_sm2_sign_botan')
    mannwhitneyu_test('Botan', 'SM2(sign)', 'RSA(sign)', 'RSS', sm2_sign_rss_botan, rsa_sign_rss_botan)
    mannwhitneyu_test('Botan', 'SM2(sign)', 'ECDSA(sign)', 'RSS', sm2_sign_rss_botan, ecdsa_sign_rss_botan)

    ecdsa_verify_rss_botan = process_usrbintime_output('output/ds_rss/rss_ecdsa_verify_botan')
    rsa_verify_rss_botan = process_usrbintime_output('output/ds_rss/rss_rsa_verify_botan')
    sm2_verify_rss_botan = process_usrbintime_output('output/ds_rss/rss_sm2_verify_botan')
    mannwhitneyu_test('Botan', 'SM2(verify)', 'RSA(verify)', 'RSS', sm2_verify_rss_botan, rsa_verify_rss_botan)
    mannwhitneyu_test('Botan', 'SM2(verify)', 'ECDSA(verify)', 'RSS', sm2_verify_rss_botan, ecdsa_verify_rss_botan)

elif (sys.argv[1] == 'block'):
    ############ OpenSSL ECB mode ############
    # Encryption
    ecb_aes_ni_real_time, ecb_aes_ni_cpu_time, ecb_aes_ni_cpu_cycles = process_perf_stat_output("output/block_perf/openssl/aes_ni_ecb")
    ecb_aes_real_time, ecb_aes_cpu_time, ecb_aes_cpu_cycles = process_perf_stat_output("output/block_perf/openssl/aes_ecb")
    ecb_sm4_real_time, ecb_sm4_cpu_time, ecb_sm4_cpu_cycles = process_perf_stat_output("output/block_perf/openssl/sm4_ecb")
    mannwhitneyu_test('Encryption: OpenSSL - ECB mode', 'SM4', 'AES-NI', 'Real Time', ecb_sm4_real_time["data"], ecb_aes_ni_real_time["data"])
    mannwhitneyu_test('Encryption: OpenSSL - ECB mode', 'SM4', 'AES', 'Real Time', ecb_sm4_real_time["data"], ecb_aes_real_time["data"])

    mannwhitneyu_test('Encryption: OpenSSL - ECB mode', 'SM4', 'AES-NI', 'CPU Time', ecb_sm4_cpu_time["data"], ecb_aes_ni_cpu_time["data"])
    mannwhitneyu_test('Encryption: OpenSSL - ECB mode', 'SM4', 'AES', 'CPU Time', ecb_sm4_cpu_time["data"], ecb_aes_cpu_time["data"])

    mannwhitneyu_test('Encryption: OpenSSL - ECB mode', 'SM4', 'AES-NI', 'CPU cycles', ecb_sm4_cpu_cycles["data"], ecb_aes_ni_cpu_cycles["data"])
    mannwhitneyu_test('Encryption: OpenSSL - ECB mode', 'SM4', 'AES', 'CPU cycles', ecb_sm4_cpu_cycles["data"], ecb_aes_cpu_cycles["data"])

    # Decryption
    dec_ecb_aes_ni_real_time, dec_ecb_aes_ni_cpu_time, dec_ecb_aes_ni_cpu_cycles = process_perf_stat_output("output/block_perf/openssl/aes_ni_ecb_decrypt")
    dec_ecb_aes_real_time, dec_ecb_aes_cpu_time, dec_ecb_aes_cpu_cycles = process_perf_stat_output("output/block_perf/openssl/aes_ecb_decrypt")
    dec_ecb_sm4_real_time, dec_ecb_sm4_cpu_time, dec_ecb_sm4_cpu_cycles = process_perf_stat_output("output/block_perf/openssl/sm4_ecb_decrypt")

    mannwhitneyu_test('Decryption: OpenSSL - ECB mode', 'SM4', 'AES-NI', 'Real Time', dec_ecb_sm4_real_time["data"], dec_ecb_aes_ni_real_time["data"])
    mannwhitneyu_test('Decryption: OpenSSL - ECB mode', 'SM4', 'AES', 'Real Time', dec_ecb_sm4_real_time["data"], dec_ecb_aes_real_time["data"])

    mannwhitneyu_test('Decryption: OpenSSL - ECB mode', 'SM4', 'AES-NI', 'CPU Time', dec_ecb_sm4_cpu_time["data"], dec_ecb_aes_ni_cpu_time["data"])
    mannwhitneyu_test('Decryption: OpenSSL - ECB mode', 'SM4', 'AES', 'CPU Time', dec_ecb_sm4_cpu_time["data"], dec_ecb_aes_cpu_time["data"])

    mannwhitneyu_test('Decryption: OpenSSL - ECB mode', 'SM4', 'AES-NI', 'CPU cycles', dec_ecb_sm4_cpu_cycles["data"], dec_ecb_aes_ni_cpu_cycles["data"])
    mannwhitneyu_test('Decryption: OpenSSL - ECB mode', 'SM4', 'AES', 'CPU cycles', dec_ecb_sm4_cpu_cycles["data"], dec_ecb_aes_cpu_cycles["data"])

    ############ OpenSSL CBC mode ############
    # Encryption
    cbc_aes_ni_real_time, cbc_aes_ni_cpu_time, cbc_aes_ni_cpu_cycles = process_perf_stat_output("output/block_perf/openssl/aes_ni_cbc")
    cbc_aes_real_time, cbc_aes_cpu_time, cbc_aes_cpu_cycles = process_perf_stat_output("output/block_perf/openssl/aes_cbc")
    cbc_sm4_real_time, cbc_sm4_cpu_time, cbc_sm4_cpu_cycles = process_perf_stat_output("output/block_perf/openssl/sm4_cbc")

    mannwhitneyu_test('Encryption: OpenSSL - CBC mode', 'SM4', 'AES-NI', 'Real Time', cbc_sm4_real_time["data"], cbc_aes_ni_real_time["data"])
    mannwhitneyu_test('Encryption: OpenSSL - CBC mode', 'SM4', 'AES', 'Real Time', cbc_sm4_real_time["data"], cbc_aes_real_time["data"])

    mannwhitneyu_test('Encryption: OpenSSL - CBC mode', 'SM4', 'AES-NI', 'CPU Time', cbc_sm4_cpu_time["data"], cbc_aes_ni_cpu_time["data"])
    mannwhitneyu_test('Encryption: OpenSSL - CBC mode', 'SM4', 'AES', 'CPU Time', cbc_sm4_cpu_time["data"], cbc_aes_cpu_time["data"])

    mannwhitneyu_test('Encryption: OpenSSL - CBC mode', 'SM4', 'AES-NI', 'CPU cycles', cbc_sm4_cpu_cycles["data"], cbc_aes_ni_cpu_cycles["data"])
    mannwhitneyu_test('Encryption: OpenSSL - CBC mode', 'SM4', 'AES', 'CPU cycles', cbc_sm4_cpu_cycles["data"], cbc_aes_cpu_cycles["data"])

    # Decryption
    dec_cbc_aes_ni_real_time, dec_cbc_aes_ni_cpu_time, dec_cbc_aes_ni_cpu_cycles = process_perf_stat_output("output/block_perf/openssl/aes_ni_cbc_decrypt")
    dec_cbc_aes_real_time, dec_cbc_aes_cpu_time, dec_cbc_aes_cpu_cycles = process_perf_stat_output("output/block_perf/openssl/aes_cbc_decrypt")
    dec_cbc_sm4_real_time, dec_cbc_sm4_cpu_time, dec_cbc_sm4_cpu_cycles = process_perf_stat_output("output/block_perf/openssl/sm4_cbc_decrypt")

    mannwhitneyu_test('Decryption: OpenSSL - CBC mode', 'SM4', 'AES-NI', 'Real Time', dec_cbc_sm4_real_time["data"], dec_cbc_aes_ni_real_time["data"])
    mannwhitneyu_test('Decryption: OpenSSL - CBC mode', 'SM4', 'AES', 'Real Time', dec_cbc_sm4_real_time["data"], dec_cbc_aes_real_time["data"])

    mannwhitneyu_test('Decryption: OpenSSL - CBC mode', 'SM4', 'AES-NI', 'CPU Time', dec_cbc_sm4_cpu_time["data"], dec_cbc_aes_ni_cpu_time["data"])
    mannwhitneyu_test('Decryption: OpenSSL - CBC mode', 'SM4', 'AES', 'CPU Time', dec_cbc_sm4_cpu_time["data"], dec_cbc_aes_cpu_time["data"])

    mannwhitneyu_test('Decryption: OpenSSL - CBC mode', 'SM4', 'AES-NI', 'CPU cycles', dec_cbc_sm4_cpu_cycles["data"], dec_cbc_aes_ni_cpu_cycles["data"])
    mannwhitneyu_test('Decryption: OpenSSL - CBC mode', 'SM4', 'AES', 'CPU cycles', dec_cbc_sm4_cpu_cycles["data"], dec_cbc_aes_cpu_cycles["data"])


    ############ OpenSSL CTR mode ############
    # Encryption
    ctr_aes_ni_real_time, ctr_aes_ni_cpu_time, ctr_aes_ni_cpu_cycles = process_perf_stat_output("output/block_perf/openssl/aes_ni_ctr")
    ctr_aes_real_time, ctr_aes_cpu_time, ctr_aes_cpu_cycles = process_perf_stat_output("output/block_perf/openssl/aes_ctr")
    ctr_sm4_real_time, ctr_sm4_cpu_time, ctr_sm4_cpu_cycles = process_perf_stat_output("output/block_perf/openssl/sm4_ctr")

    mannwhitneyu_test('Encryption: OpenSSL - CTR mode', 'SM4', 'AES-NI', 'Real Time', ctr_sm4_real_time["data"], ctr_aes_ni_real_time["data"])
    mannwhitneyu_test('Encryption: OpenSSL - CTR mode', 'SM4', 'AES', 'Real Time', ctr_sm4_real_time["data"], ctr_aes_real_time["data"])

    mannwhitneyu_test('Encryption: OpenSSL - CTR mode', 'SM4', 'AES-NI', 'CPU Time', ctr_sm4_cpu_time["data"], ctr_aes_ni_cpu_time["data"])
    mannwhitneyu_test('Encryption: OpenSSL - CTR mode', 'SM4', 'AES', 'CPU Time', ctr_sm4_cpu_time["data"], ctr_aes_cpu_time["data"])

    mannwhitneyu_test('Encryption: OpenSSL - CTR mode', 'SM4', 'AES-NI', 'CPU cycles', ctr_sm4_cpu_cycles["data"], ctr_aes_ni_cpu_cycles["data"])
    mannwhitneyu_test('Encryption: OpenSSL - CTR mode', 'SM4', 'AES', 'CPU cycles', ctr_sm4_cpu_cycles["data"], ctr_aes_cpu_cycles["data"])


    # Decryption
    dec_ctr_aes_ni_real_time, dec_ctr_aes_ni_cpu_time, dec_ctr_aes_ni_cpu_cycles = process_perf_stat_output("output/block_perf/openssl/aes_ni_ctr_decrypt")
    dec_ctr_aes_real_time, dec_ctr_aes_cpu_time, dec_ctr_aes_cpu_cycles = process_perf_stat_output("output/block_perf/openssl/aes_ctr_decrypt")
    dec_ctr_sm4_real_time, dec_ctr_sm4_cpu_time, dec_ctr_sm4_cpu_cycles = process_perf_stat_output("output/block_perf/openssl/sm4_ctr_decrypt")

    mannwhitneyu_test('Decryption: OpenSSL - CTR mode', 'SM4', 'AES-NI', 'Real Time', dec_ctr_sm4_real_time["data"], dec_ctr_aes_ni_real_time["data"])
    mannwhitneyu_test('Decryption: OpenSSL - CTR mode', 'SM4', 'AES', 'Real Time', dec_ctr_sm4_real_time["data"], dec_ctr_aes_real_time["data"])

    mannwhitneyu_test('Decryption: OpenSSL - CTR mode', 'SM4', 'AES-NI', 'CPU Time', dec_ctr_sm4_cpu_time["data"], dec_ctr_aes_ni_cpu_time["data"])
    mannwhitneyu_test('Decryption: OpenSSL - CTR mode', 'SM4', 'AES', 'CPU Time', dec_ctr_sm4_cpu_time["data"], dec_ctr_aes_cpu_time["data"])

    mannwhitneyu_test('Decryption: OpenSSL - CTR mode', 'SM4', 'AES-NI', 'CPU cycles', dec_ctr_sm4_cpu_cycles["data"], dec_ctr_aes_ni_cpu_cycles["data"])
    mannwhitneyu_test('Decryption: OpenSSL - CTR mode', 'SM4', 'AES', 'CPU cycles', dec_ctr_sm4_cpu_cycles["data"], dec_ctr_aes_cpu_cycles["data"])


    ###############################################################################################

    ############ Botan ECB mode ############
    # Encryption
    botan_ecb_aes_ni_real_time, botan_ecb_aes_ni_cpu_time, botan_ecb_aes_ni_cpu_cycles = process_perf_stat_output("output/block_perf/botan/botan_aes_ni_ecb")
    botan_ecb_aes_real_time, botan_ecb_aes_cpu_time, botan_ecb_aes_cpu_cycles = process_perf_stat_output("output/block_perf/botan/botan_aes_ecb")
    botan_ecb_sm4_real_time, botan_ecb_sm4_cpu_time, botan_ecb_sm4_cpu_cycles = process_perf_stat_output("output/block_perf/botan/botan_sm4_ecb")

    mannwhitneyu_test('Encryption: Botan - ECB mode', 'SM4', 'AES-NI', 'Real Time', botan_ecb_sm4_real_time["data"], botan_ecb_aes_ni_real_time["data"])
    mannwhitneyu_test('Encryption: Botan - ECB mode', 'SM4', 'AES', 'Real Time', botan_ecb_sm4_real_time["data"], botan_ecb_aes_real_time["data"])

    mannwhitneyu_test('Encryption: Botan - ECB mode', 'SM4', 'AES-NI', 'CPU Time', botan_ecb_sm4_cpu_time["data"], botan_ecb_aes_ni_cpu_time["data"])
    mannwhitneyu_test('Encryption: Botan - ECB mode', 'SM4', 'AES', 'CPU Time', botan_ecb_sm4_cpu_time["data"], botan_ecb_aes_cpu_time["data"])

    mannwhitneyu_test('Encryption: Botan - ECB mode', 'SM4', 'AES-NI', 'CPU cycles', botan_ecb_sm4_cpu_cycles["data"], botan_ecb_aes_ni_cpu_cycles["data"])
    mannwhitneyu_test('Encryption: Botan - ECB mode', 'SM4', 'AES', 'CPU cycles', botan_ecb_sm4_cpu_cycles["data"], botan_ecb_aes_cpu_cycles["data"])


    # Decryption
    botan_dec_ecb_aes_ni_real_time, botan_dec_ecb_aes_ni_cpu_time, botan_dec_ecb_aes_ni_cpu_cycles = process_perf_stat_output("output/block_perf/botan/botan_aes_ni_ecb_decrypt")
    botan_dec_ecb_aes_real_time, botan_dec_ecb_aes_cpu_time, botan_dec_ecb_aes_cpu_cycles = process_perf_stat_output("output/block_perf/botan/botan_aes_ecb_decrypt")
    botan_dec_ecb_sm4_real_time, botan_dec_ecb_sm4_cpu_time, botan_dec_ecb_sm4_cpu_cycles = process_perf_stat_output("output/block_perf/botan/botan_sm4_ecb_decrypt")

    mannwhitneyu_test('Decryption: Botan - ECB mode', 'SM4', 'AES-NI', 'Real Time', botan_dec_ecb_sm4_real_time["data"], botan_dec_ecb_aes_ni_real_time["data"])
    mannwhitneyu_test('Decryption: Botan - ECB mode', 'SM4', 'AES', 'Real Time', botan_dec_ecb_sm4_real_time["data"], botan_dec_ecb_aes_real_time["data"])

    mannwhitneyu_test('Decryption: Botan - ECB mode', 'SM4', 'AES-NI', 'CPU Time', botan_dec_ecb_sm4_cpu_time["data"], botan_dec_ecb_aes_ni_cpu_time["data"])
    mannwhitneyu_test('Decryption: Botan - ECB mode', 'SM4', 'AES', 'CPU Time', botan_dec_ecb_sm4_cpu_time["data"], botan_dec_ecb_aes_cpu_time["data"])

    mannwhitneyu_test('Decryption: Botan - ECB mode', 'SM4', 'AES-NI', 'CPU cycles', botan_dec_ecb_sm4_cpu_cycles["data"], botan_dec_ecb_aes_ni_cpu_cycles["data"])
    mannwhitneyu_test('Decryption: Botan - ECB mode', 'SM4', 'AES', 'CPU cycles', botan_dec_ecb_sm4_cpu_cycles["data"], botan_dec_ecb_aes_cpu_cycles["data"])

    ############ Botan CBC mode ############
    # Encryption
    botan_cbc_aes_ni_real_time, botan_cbc_aes_ni_cpu_time, botan_cbc_aes_ni_cpu_cycles = process_perf_stat_output("output/block_perf/botan/botan_aes_ni_cbc")
    botan_cbc_aes_real_time, botan_cbc_aes_cpu_time, botan_cbc_aes_cpu_cycles = process_perf_stat_output("output/block_perf/botan/botan_aes_cbc")
    botan_cbc_sm4_real_time, botan_cbc_sm4_cpu_time, botan_cbc_sm4_cpu_cycles = process_perf_stat_output("output/block_perf/botan/botan_sm4_cbc")

    mannwhitneyu_test('Encryption: Botan - CBC mode', 'SM4', 'AES-NI', 'Real Time', botan_cbc_sm4_real_time["data"], botan_cbc_aes_ni_real_time["data"])
    mannwhitneyu_test('Encryption: Botan - CBC mode', 'SM4', 'AES', 'Real Time', botan_cbc_sm4_real_time["data"], botan_cbc_aes_real_time["data"])

    mannwhitneyu_test('Encryption: Botan - CBC mode', 'SM4', 'AES-NI', 'CPU Time', botan_cbc_sm4_cpu_time["data"], botan_cbc_aes_ni_cpu_time["data"])
    mannwhitneyu_test('Encryption: Botan - CBC mode', 'SM4', 'AES', 'CPU Time', botan_cbc_sm4_cpu_time["data"], botan_cbc_aes_cpu_time["data"])

    mannwhitneyu_test('Encryption: Botan - CBC mode', 'SM4', 'AES-NI', 'CPU cycles', botan_cbc_sm4_cpu_cycles["data"], botan_cbc_aes_ni_cpu_cycles["data"])
    mannwhitneyu_test('Encryption: Botan - CBC mode', 'SM4', 'AES', 'CPU cycles', botan_cbc_sm4_cpu_cycles["data"], botan_cbc_aes_cpu_cycles["data"])

    # Decryption
    botan_dec_cbc_aes_ni_real_time, botan_dec_cbc_aes_ni_cpu_time, botan_dec_cbc_aes_ni_cpu_cycles = process_perf_stat_output("output/block_perf/botan/botan_aes_ni_cbc_decrypt")
    botan_dec_cbc_aes_real_time, botan_dec_cbc_aes_cpu_time, botan_dec_cbc_aes_cpu_cycles = process_perf_stat_output("output/block_perf/botan/botan_aes_cbc_decrypt")
    botan_dec_cbc_sm4_real_time, botan_dec_cbc_sm4_cpu_time, botan_dec_cbc_sm4_cpu_cycles = process_perf_stat_output("output/block_perf/botan/botan_sm4_cbc_decrypt")

    mannwhitneyu_test('Decryption: Botan - CBC mode', 'SM4', 'AES-NI', 'Real Time', botan_dec_cbc_sm4_real_time["data"], botan_dec_cbc_aes_ni_real_time["data"])
    mannwhitneyu_test('Decryption: Botan - CBC mode', 'SM4', 'AES', 'Real Time', botan_dec_cbc_sm4_real_time["data"], botan_dec_cbc_aes_real_time["data"])

    mannwhitneyu_test('Decryption: Botan - CBC mode', 'SM4', 'AES-NI', 'CPU Time', botan_dec_cbc_sm4_cpu_time["data"], botan_dec_cbc_aes_ni_cpu_time["data"])
    mannwhitneyu_test('Decryption: Botan - CBC mode', 'SM4', 'AES', 'CPU Time', botan_dec_cbc_sm4_cpu_time["data"], botan_dec_cbc_aes_cpu_time["data"])

    mannwhitneyu_test('Decryption: Botan - CBC mode', 'SM4', 'AES-NI', 'CPU cycles', botan_dec_cbc_sm4_cpu_cycles["data"], botan_dec_cbc_aes_ni_cpu_cycles["data"])
    mannwhitneyu_test('Decryption: Botan - CBC mode', 'SM4', 'AES', 'CPU cycles', botan_dec_cbc_sm4_cpu_cycles["data"], botan_dec_cbc_aes_cpu_cycles["data"])

    ############ Botan CTR mode ############
    # Encryption
    botan_ctr_aes_ni_real_time, botan_ctr_aes_ni_cpu_time, botan_ctr_aes_ni_cpu_cycles = process_perf_stat_output("output/block_perf/botan/botan_aes_ni_ctr")
    botan_ctr_aes_real_time, botan_ctr_aes_cpu_time, botan_ctr_aes_cpu_cycles = process_perf_stat_output("output/block_perf/botan/botan_aes_ctr")
    botan_ctr_sm4_real_time, botan_ctr_sm4_cpu_time, botan_ctr_sm4_cpu_cycles = process_perf_stat_output("output/block_perf/botan/botan_sm4_ctr")

    mannwhitneyu_test('Encryption: Botan - CTR mode', 'SM4', 'AES-NI', 'Real Time', botan_ctr_sm4_real_time["data"], botan_ctr_aes_ni_real_time["data"])
    mannwhitneyu_test('Encryption: Botan - CTR mode', 'SM4', 'AES', 'Real Time', botan_ctr_sm4_real_time["data"], botan_ctr_aes_real_time["data"])

    mannwhitneyu_test('Encryption: Botan - CTR mode', 'SM4', 'AES-NI', 'CPU Time', botan_ctr_sm4_cpu_time["data"], botan_ctr_aes_ni_cpu_time["data"])
    mannwhitneyu_test('Encryption: Botan - CTR mode', 'SM4', 'AES', 'CPU Time', botan_ctr_sm4_cpu_time["data"], botan_ctr_aes_cpu_time["data"])

    mannwhitneyu_test('Encryption: Botan - CTR mode', 'SM4', 'AES-NI', 'CPU cycles', botan_ctr_sm4_cpu_cycles["data"], botan_ctr_aes_ni_cpu_cycles["data"])
    mannwhitneyu_test('Encryption: Botan - CTR mode', 'SM4', 'AES', 'CPU cycles', botan_ctr_sm4_cpu_cycles["data"], botan_ctr_aes_cpu_cycles["data"])


    # Decryption
    botan_dec_ctr_aes_ni_real_time, botan_dec_ctr_aes_ni_cpu_time, botan_dec_ctr_aes_ni_cpu_cycles = process_perf_stat_output("output/block_perf/botan/botan_aes_ni_ctr_decrypt")
    botan_dec_ctr_aes_real_time, botan_dec_ctr_aes_cpu_time, botan_dec_ctr_aes_cpu_cycles = process_perf_stat_output("output/block_perf/botan/botan_aes_ctr_decrypt")
    botan_dec_ctr_sm4_real_time, botan_dec_ctr_sm4_cpu_time, botan_dec_ctr_sm4_cpu_cycles = process_perf_stat_output("output/block_perf/botan/botan_sm4_ctr_decrypt")
    #print(botan_dec_ctr_sm4_real_time)
    mannwhitneyu_test('Decryption: Botan - CTR mode', 'SM4', 'AES-NI', 'Real Time', botan_dec_ctr_sm4_real_time["data"], botan_dec_ctr_aes_ni_real_time["data"])
    mannwhitneyu_test('Decryption: Botan - CTR mode', 'SM4', 'AES', 'Real Time', botan_dec_ctr_sm4_real_time["data"], botan_dec_ctr_aes_real_time["data"])

    mannwhitneyu_test('Decryption: Botan - CTR mode', 'SM4', 'AES-NI', 'CPU Time', botan_dec_ctr_sm4_cpu_time["data"], botan_dec_ctr_aes_ni_cpu_time["data"])
    mannwhitneyu_test('Decryption: Botan - CTR mode', 'SM4', 'AES', 'CPU Time', botan_dec_ctr_sm4_cpu_time["data"], botan_dec_ctr_aes_cpu_time["data"])

    mannwhitneyu_test('Decryption: Botan - CTR mode', 'SM4', 'AES-NI', 'CPU cycles', botan_dec_ctr_sm4_cpu_cycles["data"], botan_dec_ctr_aes_ni_cpu_cycles["data"])
    mannwhitneyu_test('Decryption: Botan - CTR mode', 'SM4', 'AES', 'CPU cycles', botan_dec_ctr_sm4_cpu_cycles["data"], botan_dec_ctr_aes_cpu_cycles["data"])

    ###############################################################################################

    ############ RSS OpenSSL ############
    # Encryption
    RSS_aes_ni = process_proc_status_output("output/block_rss/openssl/openssl_aes_ni_rss")
    RSS_aes = process_proc_status_output("output/block_rss/openssl/openssl_aes_rss")
    RSS_sm4 = process_proc_status_output("output/block_rss/openssl/openssl_sm4_rss")
    #print(RSS_sm4)
    mannwhitneyu_test('Encryption: OpenSSL - ECB mode', 'SM4', 'AES-NI', 'RSS', RSS_sm4, RSS_aes_ni)
    mannwhitneyu_test('Encryption: OpenSSL - ECB mode', 'SM4', 'AES', 'RSS', RSS_sm4, RSS_aes)

    # Decryption
    RSS_dec_aes_ni = process_proc_status_output("output/block_rss/openssl/openssl_aes_ni_rss_decrypt")
    RSS_dec_aes = process_proc_status_output("output/block_rss/openssl/openssl_aes_rss_decrypt")
    RSS_dec_sm4 = process_proc_status_output("output/block_rss/openssl/openssl_sm4_rss_decrypt")

    mannwhitneyu_test('Decryption: OpenSSL - ECB mode', 'SM4', 'AES-NI', 'RSS', RSS_dec_sm4, RSS_dec_aes_ni)
    mannwhitneyu_test('Decryption: OpenSSL - ECB mode', 'SM4', 'AES', 'RSS', RSS_dec_sm4, RSS_dec_aes)

    ############ RSS Botan ############
    # Encryption
    botan_RSS_aes_ni = process_proc_status_output("output/block_rss/botan/botan_aes_ni_rss_encrypt")
    botan_RSS_aes = process_proc_status_output("output/block_rss/botan/botan_aes_rss_encrypt")
    botan_RSS_sm4 = process_proc_status_output("output/block_rss/botan/botan_sm4_rss_encrypt")

    mannwhitneyu_test('Encryption: Botan - ECB mode', 'SM4', 'AES-NI', 'RSS', botan_RSS_sm4, botan_RSS_aes_ni)
    mannwhitneyu_test('Encryption: Botan - ECB mode', 'SM4', 'AES', 'RSS', botan_RSS_sm4, botan_RSS_aes)

    # Decryption
    botan_RSS_dec_aes_ni = process_proc_status_output("output/block_rss/botan/botan_aes_ni_rss_decrypt")
    botan_RSS_dec_aes = process_proc_status_output("output/block_rss/botan/botan_aes_rss_decrypt")
    botan_RSS_dec_sm4 = process_proc_status_output("output/block_rss/botan/botan_sm4_rss_decrypt")

    mannwhitneyu_test('Decryption: Botan - ECB mode', 'SM4', 'AES-NI', 'RSS', botan_RSS_dec_sm4, botan_RSS_dec_aes_ni)
    mannwhitneyu_test('Decryption: Botan - ECB mode', 'SM4', 'AES', 'RSS', botan_RSS_dec_sm4, botan_RSS_dec_aes)


else:
    print("No valid argument input")
