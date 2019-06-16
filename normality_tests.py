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
from numpy import array
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

def process_proc_status_output(file_path, sample_size=100):
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
    print("Found " + str(len(maxRSS)) + " outputs in " + file_path + \
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
    #print(len(list_entries))
    #print(len(list_entries[20:]))
    #print(list_entries[20:])
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
    in_dict["standard_dev"] = stats.tstd(data)
    c_interval = confidence_interval(data)
    in_dict["conf_low"] =  c_interval[0]
    in_dict["conf_high"] = c_interval[1]
    return in_dict

def process_perf_stat_output(file_path):
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

if (len(sys.argv) < 2):
    print("No argument input")
    sys.exit()
# generate graphs for real/cpu time, cpu cycles for sm3 and sha256
if (sys.argv[1] == 'hash'):
    #openssl
    sm3_real_time, sm3_cpu_time, sm3_cpu_cycles = process_perf_stat_output("output/hash/sm3_perf_o")
    create_normality_graphs('normality_graphs/hash/openssl/sm3_real_time', 'SM3 Real Time (OpenSSL)', sm3_real_time["data"])
    stat, p = shapiro(sm3_real_time["data"])
    print(stat,p)
    create_normality_graphs('normality_graphs/hash/openssl/sm3_cpu_time', 'SM3 CPU Time (OpenSSL)', sm3_cpu_time["data"])
    create_normality_graphs('normality_graphs/hash/openssl/sm3_cpu_cycles', 'SM3 CPU Cycles (OpenSSL)', sm3_cpu_cycles["data"])

    sha_real_time, sha_cpu_time, sha_cpu_cycles = process_perf_stat_output("output/hash/sha256_perf_o")
    create_normality_graphs('normality_graphs/hash/openssl/sha_real_time', 'SHA256 Real Time (OpenSSL)', sha_real_time["data"])
    stat, p = shapiro(sha_real_time["data"])
    print(stat,p)
    create_normality_graphs('normality_graphs/hash/openssl/sha_cpu_time', 'SHA256 CPU Time (OpenSSL)', sha_cpu_time["data"])
    create_normality_graphs('normality_graphs/hash/openssl/sha_cpu_cycles', 'SHA256 CPU Cycles (OpenSSL)', sha_cpu_cycles["data"])

    #botan
    botan_sm3_real_time, botan_sm3_cpu_time, botan_sm3_cpu_cycles = process_perf_stat_output("output/hash/sm3_perf")
    create_normality_graphs('normality_graphs/hash/botan/sm3_real_time', 'SM3 Real Time (Botan)', botan_sm3_real_time["data"])
    create_normality_graphs('normality_graphs/hash/botan/sm3_cpu_time', 'SM3 CPU Time (Botan)', botan_sm3_cpu_time["data"])
    create_normality_graphs('normality_graphs/hash/botan/sm3_cpu_cycles', 'SM3 CPU Cycles (Botan)', botan_sm3_cpu_cycles["data"])

    botan_sha_real_time, botan_sha_cpu_time, botan_sha_cpu_cycles = process_perf_stat_output("output/hash/sha256_perf")
    create_normality_graphs('normality_graphs/hash/botan/sha_real_time', 'SHA256 Real Time (Botan)', botan_sha_real_time["data"])
    create_normality_graphs('normality_graphs/hash/botan/sha_cpu_time', 'SHA256 CPU Time (Botan)', botan_sha_cpu_time["data"])
    create_normality_graphs('normality_graphs/hash/botan/sha_cpu_cycles', 'SHA256 CPU Cycles (Botan)', botan_sha_cpu_cycles["data"])

    ### RSS ###
    #OpenSSL
    RSS_sha = process_proc_status_output("output/hash/sha256_rss_o")
    create_normality_graphs('normality_graphs/hash/openssl/sha_rss', 'SHA256 RSS (OpenSSL)', RSS_sha)
    RSS_sm3 = process_proc_status_output("output/hash/sm3_rss_o")
    create_normality_graphs('normality_graphs/hash/openssl/sm3_rss', 'SM3 RSS (OpenSSL)', RSS_sm3)
    #Botan
    RSS_sha_botan = process_proc_status_output("output/hash/sha256_rss")
    create_normality_graphs('normality_graphs/hash/botan/sha_rss', 'SHA256 RSS (Botan)', RSS_sha_botan)
    RSS_sm3_botan = process_proc_status_output("output/hash/sm3_rss")
    create_normality_graphs('normality_graphs/hash/botan/sm3_rss', 'SM3 RSS (Botan)', RSS_sm3_botan)

elif(sys.argv[1] == 'ds'):
    ############ GmSSL ############
    # Key generation
    rsa_keygen_real_time, rsa_keygen_cpu_time, rsa_keygen_cpu_cycles = process_perf_stat_output("output/ds_perf/rsa_keygen_perf_o")
    create_normality_graphs('normality_graphs/ds/gmssl/keygen/rsa_keygen_real_time', 'RSA Keygen Real Time (GmSSL)', rsa_keygen_real_time["data"])
    create_normality_graphs('normality_graphs/ds/gmssl/keygen/rsa_keygen_cpu_time', 'RSA Keygen CPU Time (GmSSL)', rsa_keygen_cpu_time["data"])
    create_normality_graphs('normality_graphs/ds/gmssl/keygen/rsa_keygen_cpu_cycles', 'RSA Keygen CPU cycles (GmSSL)', rsa_keygen_cpu_cycles["data"])
    sm2_keygen_real_time, sm2_keygen_cpu_time, sm2_keygen_cpu_cycles = process_perf_stat_output("output/ds_perf/sm2_keygen_perf_o")
    stat, p = shapiro(sm2_keygen_real_time["data"])
    print("sm2 keygen gmssl real",stat,p)
    stat, p = shapiro(sm2_keygen_cpu_time["data"])
    print("sm2 keygen gmssl cpu",stat,p)
    stat, p = shapiro(sm2_keygen_cpu_cycles["data"])
    print("sm2 keygen gmssl cycles",stat,p)
    create_normality_graphs('normality_graphs/ds/gmssl/keygen/sm2_keygen_real_time', 'SM2 Keygen Real Time (GmSSL)', sm2_keygen_real_time["data"])
    create_normality_graphs('normality_graphs/ds/gmssl/keygen/sm2_keygen_cpu_time', 'SM2 Keygen CPU Time (GmSSL)', sm2_keygen_cpu_time["data"])
    create_normality_graphs('normality_graphs/ds/gmssl/keygen/sm2_keygen_cpu_cycles', 'SM2 Keygen CPU cycles (GmSSL)', sm2_keygen_cpu_cycles["data"])
    ecdsa_keygen_real_time, ecdsa_keygen_cpu_time, ecdsa_keygen_cpu_cycles = process_perf_stat_output("output/ds_perf/ecdsa_keygen_perf_o")
    stat, p = shapiro(ecdsa_keygen_real_time["data"])
    print("ecdsa keygen gmssl real",stat,p)
    stat, p = shapiro(ecdsa_keygen_cpu_time["data"])
    print("ecdsa keygen gmssl cpu",stat,p)
    stat, p = shapiro(ecdsa_keygen_cpu_cycles["data"])
    print("ecdsa keygen gmssl cycles",stat,p)
    create_normality_graphs('normality_graphs/ds/gmssl/keygen/ecdsa_keygen_real_time', 'ECDSA Keygen Real Time (GmSSL)', ecdsa_keygen_real_time["data"])
    create_normality_graphs('normality_graphs/ds/gmssl/keygen/ecdsa_keygen_cpu_time', 'ECDSA Keygen CPU Time (GmSSL)', ecdsa_keygen_cpu_time["data"])
    create_normality_graphs('normality_graphs/ds/gmssl/keygen/ecdsa_keygen_cpu_cycles', 'ECDSA Keygen CPU cycles (GmSSL)', ecdsa_keygen_cpu_cycles["data"])

    # Signing
    rsa_sign_real_time, rsa_sign_cpu_time, rsa_sign_cpu_cycles = process_perf_stat_output("output/ds_perf/rsa_sign_perf_o")
    create_normality_graphs('normality_graphs/ds/gmssl/sign/rsa_sign_real_time', 'RSA Sign Real Time (GmSSL)', rsa_sign_real_time["data"])
    create_normality_graphs('normality_graphs/ds/gmssl/sign/rsa_sign_cpu_time', 'RSA Sign CPU Time (GmSSL)', rsa_sign_cpu_time["data"])
    create_normality_graphs('normality_graphs/ds/gmssl/sign/rsa_sign_cpu_cycles', 'RSA Sign CPU cycles (GmSSL)', rsa_sign_cpu_cycles["data"])
    sm2_sign_real_time, sm2_sign_cpu_time, sm2_sign_cpu_cycles = process_perf_stat_output("output/ds_perf/sm2_sign_perf_o")
    create_normality_graphs('normality_graphs/ds/gmssl/sign/sm2_sign_real_time', 'SM2 Sign Real Time (GmSSL)', sm2_sign_real_time["data"])
    create_normality_graphs('normality_graphs/ds/gmssl/sign/sm2_sign_cpu_time', 'SM2 Sign CPU Time (GmSSL)', sm2_sign_cpu_time["data"])
    create_normality_graphs('normality_graphs/ds/gmssl/sign/sm2_sign_cpu_cycles', 'SM2 Sign CPU cycles (GmSSL)', sm2_sign_cpu_cycles["data"])
    ecdsa_sign_real_time, ecdsa_sign_cpu_time, ecdsa_sign_cpu_cycles = process_perf_stat_output("output/ds_perf/ecdsa_sign_perf_o")
    create_normality_graphs('normality_graphs/ds/gmssl/sign/ecdsa_sign_real_time', 'ECDSA Sign Real Time (GmSSL)', ecdsa_sign_real_time["data"])
    create_normality_graphs('normality_graphs/ds/gmssl/sign/ecdsa_sign_cpu_time', 'ECDSA Sign CPU Time (GmSSL)', ecdsa_sign_cpu_time["data"])
    create_normality_graphs('normality_graphs/ds/gmssl/sign/ecdsa_sign_cpu_cycles', 'ECDSA Sign CPU cycles (GmSSL)', ecdsa_sign_cpu_cycles["data"])

    # Verifying
    rsa_verify_real_time, rsa_verify_cpu_time, rsa_verify_cpu_cycles = process_perf_stat_output("output/ds_perf/rsa_verify_perf_o")
    create_normality_graphs('normality_graphs/ds/gmssl/verify/rsa_verify_real_time', 'RSA Verify Real Time (GmSSL)', rsa_verify_real_time["data"])
    create_normality_graphs('normality_graphs/ds/gmssl/verify/rsa_verify_cpu_time', 'RSA Verify CPU Time (GmSSL)', rsa_verify_cpu_time["data"])
    create_normality_graphs('normality_graphs/ds/gmssl/verify/rsa_verify_cpu_cycles', 'RSA Verify CPU cycles (GmSSL)', rsa_verify_cpu_cycles["data"])
    sm2_verify_real_time, sm2_verify_cpu_time, sm2_verify_cpu_cycles = process_perf_stat_output("output/ds_perf/sm2_verify_perf_o")
    create_normality_graphs('normality_graphs/ds/gmssl/verify/sm2_verify_real_time', 'SM2 Verify Real Time (GmSSL)', sm2_verify_real_time["data"])
    create_normality_graphs('normality_graphs/ds/gmssl/verify/sm2_verify_cpu_time', 'SM2 Verify CPU Time (GmSSL)', sm2_verify_cpu_time["data"])
    create_normality_graphs('normality_graphs/ds/gmssl/verify/sm2_verify_cpu_cycles', 'SM2 Verify CPU cycles (GmSSL)', sm2_verify_cpu_cycles["data"])
    ecdsa_verify_real_time, ecdsa_verify_cpu_time, ecdsa_verify_cpu_cycles = process_perf_stat_output("output/ds_perf/ecdsa_verify_perf_o")
    create_normality_graphs('normality_graphs/ds/gmssl/verify/ecdsa_verify_real_time', 'ECDSA Verify Real Time (GmSSL)', ecdsa_verify_real_time["data"])
    create_normality_graphs('normality_graphs/ds/gmssl/verify/ecdsa_verify_cpu_time', 'ECDSA Verify CPU Time (GmSSL)', ecdsa_verify_cpu_time["data"])
    create_normality_graphs('normality_graphs/ds/gmssl/verify/ecdsa_verify_cpu_cycles', 'ECDSA Verify CPU cycles (GmSSL)', ecdsa_verify_cpu_cycles["data"])

    ############ Botan ############
    # Key generation
    botan_rsa_keygen_real_time, botan_rsa_keygen_cpu_time, botan_rsa_keygen_cpu_cycles = process_perf_stat_output("output/ds_perf/rsa_keygen_perf")
    stat, p = shapiro(botan_rsa_keygen_real_time["data"])
    print(stat,p)
    create_normality_graphs('normality_graphs/ds/botan/keygen/rsa_keygen_real_time', 'RSA Keygen Real Time (Botan)', botan_rsa_keygen_real_time["data"])
    create_normality_graphs('normality_graphs/ds/botan/keygen/rsa_keygen_cpu_time', 'RSA Keygen CPU Time (Botan)', botan_rsa_keygen_cpu_time["data"])
    create_normality_graphs('normality_graphs/ds/botan/keygen/rsa_keygen_cpu_cycles', 'RSA Keygen CPU cycles (Botan)', botan_rsa_keygen_cpu_cycles["data"])
    botan_sm2_keygen_real_time, botan_sm2_keygen_cpu_time, botan_sm2_keygen_cpu_cycles = process_perf_stat_output("output/ds_perf/sm2_keygen_perf")
    create_normality_graphs('normality_graphs/ds/botan/keygen/sm2_keygen_real_time', 'SM2 Keygen Real Time (Botan)', botan_sm2_keygen_real_time["data"])
    create_normality_graphs('normality_graphs/ds/botan/keygen/sm2_keygen_cpu_time', 'SM2 Keygen CPU Time (Botan)', botan_sm2_keygen_cpu_time["data"])
    create_normality_graphs('normality_graphs/ds/botan/keygen/sm2_keygen_cpu_cycles', 'SM2 Keygen CPU cycles (Botan)', botan_sm2_keygen_cpu_cycles["data"])
    botan_ecdsa_keygen_real_time, botan_ecdsa_keygen_cpu_time, botan_ecdsa_keygen_cpu_cycles = process_perf_stat_output("output/ds_perf/ecdsa_keygen_perf")
    create_normality_graphs('normality_graphs/ds/botan/keygen/ecdsa_keygen_real_time', 'ECDSA Keygen Real Time (Botan)', botan_ecdsa_keygen_real_time["data"])
    create_normality_graphs('normality_graphs/ds/botan/keygen/ecdsa_keygen_cpu_time', 'ECDSA Keygen CPU Time (Botan)', botan_ecdsa_keygen_cpu_time["data"])
    create_normality_graphs('normality_graphs/ds/botan/keygen/ecdsa_keygen_cpu_cycles', 'ECDSA Keygen CPU cycles (Botan)', botan_ecdsa_keygen_cpu_cycles["data"])
    # Signing
    botan_rsa_sign_real_time, botan_rsa_sign_cpu_time, botan_rsa_sign_cpu_cycles = process_perf_stat_output("output/ds_perf/rsa_sign_perf")
    create_normality_graphs('normality_graphs/ds/botan/sign/rsa_sign_real_time', 'RSA Sign Real Time (Botan)', botan_rsa_sign_real_time["data"])
    create_normality_graphs('normality_graphs/ds/botan/sign/rsa_sign_cpu_time', 'RSA Sign CPU Time (Botan)', botan_rsa_sign_cpu_time["data"])
    create_normality_graphs('normality_graphs/ds/botan/sign/rsa_sign_cpu_cycles', 'RSA Sign CPU cycles (Botan)', botan_rsa_sign_cpu_cycles["data"])
    botan_sm2_sign_real_time, botan_sm2_sign_cpu_time, botan_sm2_sign_cpu_cycles = process_perf_stat_output("output/ds_perf/sm2_sign_perf")
    create_normality_graphs('normality_graphs/ds/botan/sign/sm2_sign_real_time', 'SM2 Sign Real Time (Botan)', botan_sm2_sign_real_time["data"])
    create_normality_graphs('normality_graphs/ds/botan/sign/sm2_sign_cpu_time', 'SM2 Sign CPU Time (Botan)', botan_sm2_sign_cpu_time["data"])
    create_normality_graphs('normality_graphs/ds/botan/sign/sm2_sign_cpu_cycles', 'SM2 Sign CPU cycles (Botan)', botan_sm2_sign_cpu_cycles["data"])
    botan_ecdsa_sign_real_time, botan_ecdsa_sign_cpu_time, botan_ecdsa_sign_cpu_cycles = process_perf_stat_output("output/ds_perf/ecdsa_sign_perf")
    create_normality_graphs('normality_graphs/ds/botan/sign/ecdsa_sign_real_time', 'ECDSA Sign Real Time (Botan)', botan_ecdsa_sign_real_time["data"])
    create_normality_graphs('normality_graphs/ds/botan/sign/ecdsa_sign_cpu_time', 'ECDSA Sign CPU Time (Botan)', botan_ecdsa_sign_cpu_time["data"])
    create_normality_graphs('normality_graphs/ds/botan/sign/ecdsa_sign_cpu_cycles', 'ECDSA Sign CPU cycles (Botan)', botan_ecdsa_sign_cpu_cycles["data"])
    #Verifying
    botan_rsa_verify_real_time, botan_rsa_verify_cpu_time, botan_rsa_verify_cpu_cycles = process_perf_stat_output("output/ds_perf/rsa_verify_perf")
    create_normality_graphs('normality_graphs/ds/botan/verify/rsa_verify_real_time', 'RSA Verify Real Time (Botan)', botan_rsa_verify_real_time["data"])
    create_normality_graphs('normality_graphs/ds/botan/verify/rsa_verify_cpu_time', 'RSA Verify CPU Time (Botan)', botan_rsa_verify_cpu_time["data"])
    create_normality_graphs('normality_graphs/ds/botan/verify/rsa_verify_cpu_cycles', 'RSA Verify CPU cycles (Botan)', botan_rsa_verify_cpu_cycles["data"])
    botan_sm2_verify_real_time, botan_sm2_verify_cpu_time, botan_sm2_verify_cpu_cycles = process_perf_stat_output("output/ds_perf/sm2_verify_perf")
    create_normality_graphs('normality_graphs/ds/botan/verify/sm2_verify_real_time', 'SM2 Verify Real Time (Botan)', botan_sm2_verify_real_time["data"])
    create_normality_graphs('normality_graphs/ds/botan/verify/sm2_verify_cpu_time', 'SM2 Verify CPU Time (Botan)', botan_sm2_verify_cpu_time["data"])
    create_normality_graphs('normality_graphs/ds/botan/verify/sm2_verify_cpu_cycles', 'SM2 Verify CPU cycles (Botan)', botan_sm2_verify_cpu_cycles["data"])
    botan_ecdsa_verify_real_time, botan_ecdsa_verify_cpu_time, botan_ecdsa_verify_cpu_cycles = process_perf_stat_output("output/ds_perf/ecdsa_verify_perf")
    create_normality_graphs('normality_graphs/ds/botan/verify/ecdsa_verify_real_time', 'ECDSA Verify Real Time (Botan)', botan_ecdsa_verify_real_time["data"])
    create_normality_graphs('normality_graphs/ds/botan/verify/ecdsa_verify_cpu_time', 'ECDSA Verify CPU Time (Botan)', botan_ecdsa_verify_cpu_time["data"])
    create_normality_graphs('normality_graphs/ds/botan/verify/ecdsa_verify_cpu_cycles', 'ECDSA Verify CPU cycles (Botan)', botan_ecdsa_verify_cpu_cycles["data"])

    #GmSSL RSS
    ecdsa_keygen_rss = process_usrbintime_output_special('output/ds_rss/rss_ecdsa_key_gmssl')
    create_normality_graphs('normality_graphs/ds/gmssl/rss/ecdsa_keygen_gmssl', 'ECDSA Keygen RSS (GmSSL)', ecdsa_keygen_rss)
    rsa_keygen_rss = process_usrbintime_output_special('output/ds_rss/rss_rsa_key_gmssl')
    create_normality_graphs('normality_graphs/ds/gmssl/rss/rsa_keygen_gmssl', 'RSA Keygen RSS (GmSSL)', rsa_keygen_rss)
    sm2_keygen_rss = process_usrbintime_output_special('output/ds_rss/rss_sm2_key_gmssl')
    create_normality_graphs('normality_graphs/ds/gmssl/rss/sm2_keygen_gmssl', 'SM2 Keygen RSS (GmSSL)', sm2_keygen_rss)

    ecdsa_sign_rss = process_usrbintime_output('output/ds_rss/rss_ecdsa_sign_gmssl')
    create_normality_graphs('normality_graphs/ds/gmssl/rss/ecdsa_sign_gmssl', 'ECDSA Sign RSS (GmSSL)', ecdsa_sign_rss)
    rsa_sign_rss = process_usrbintime_output('output/ds_rss/rss_rsa_sign_gmssl')
    create_normality_graphs('normality_graphs/ds/gmssl/rss/rsa_sign_gmssl', 'RSA Sign RSS (GmSSL)', rsa_sign_rss)
    sm2_sign_rss = process_usrbintime_output('output/ds_rss/rss_sm2_sign_gmssl')
    create_normality_graphs('normality_graphs/ds/gmssl/rss/sm2_sign_gmssl', 'SM2 Sign RSS (GmSSL)', sm2_sign_rss)

    ecdsa_verify_rss = process_usrbintime_output('output/ds_rss/rss_ecdsa_verify_gmssl')
    create_normality_graphs('normality_graphs/ds/gmssl/rss/ecdsa_verify_gmssl', 'ECDSA Verify RSS (GmSSL)', ecdsa_verify_rss)
    rsa_verify_rss = process_usrbintime_output('output/ds_rss/rss_rsa_verify_gmssl')
    create_normality_graphs('normality_graphs/ds/gmssl/rss/rsa_verify_gmssl', 'RSA Verify RSS (GmSSL)', rsa_verify_rss)
    sm2_verify_rss = process_usrbintime_output('output/ds_rss/rss_sm2_verify_gmssl')
    create_normality_graphs('normality_graphs/ds/gmssl/rss/sm2_verify_gmssl', 'SM2 Verify RSS (GmSSL)', sm2_verify_rss)

    #Botan RSS
    ecdsa_keygen_rss_botan = process_usrbintime_output('output/ds_rss/rss_ecdsa_key_botan')
    create_normality_graphs('normality_graphs/ds/botan/rss/ecdsa_keygen', 'ECDSA Keygen RSS (Botan)', ecdsa_keygen_rss_botan)
    rsa_keygen_rss_botan = process_usrbintime_output('output/ds_rss/rss_rsa_key_botan')
    create_normality_graphs('normality_graphs/ds/botan/rss/rsa_keygen', 'RSA Keygen RSS (Botan)', rsa_keygen_rss_botan)
    sm2_keygen_rss_botan = process_usrbintime_output('output/ds_rss/rss_sm2_key_botan')
    create_normality_graphs('normality_graphs/ds/botan/rss/sm2_keygen', 'SM2 Keygen RSS (Botan)', sm2_keygen_rss_botan)

    ecdsa_sign_rss_botan = process_usrbintime_output('output/ds_rss/rss_ecdsa_sign_botan')
    create_normality_graphs('normality_graphs/ds/botan/rss/ecdsa_sign', 'ECDSA Sign RSS (Botan)', ecdsa_sign_rss_botan)
    rsa_sign_rss_botan = process_usrbintime_output('output/ds_rss/rss_rsa_sign_botan')
    create_normality_graphs('normality_graphs/ds/botan/rss/rsa_sign', 'RSA Sign RSS (Botan)', rsa_sign_rss_botan)
    sm2_sign_rss_botan = process_usrbintime_output('output/ds_rss/rss_sm2_sign_botan')
    create_normality_graphs('normality_graphs/ds/botan/rss/sm2_sign', 'SM2 Sign RSS (Botan)', sm2_sign_rss_botan)

    ecdsa_verify_rss_botan = process_usrbintime_output('output/ds_rss/rss_ecdsa_verify_botan')
    create_normality_graphs('normality_graphs/ds/botan/rss/ecdsa_verify', 'ECDSA Verify RSS (Botan)', ecdsa_verify_rss_botan)
    rsa_verify_rss_botan = process_usrbintime_output('output/ds_rss/rss_rsa_verify_botan')
    create_normality_graphs('normality_graphs/ds/botan/rss/rsa_verify', 'RSA Verify RSS (Botan)', rsa_verify_rss_botan)
    sm2_verify_rss_botan = process_usrbintime_output('output/ds_rss/rss_sm2_verify_botan')
    create_normality_graphs('normality_graphs/ds/botan/rss/sm2_verify', 'SM2 Verify RSS (Botan)', sm2_verify_rss_botan)

elif (sys.argv[1] == 'block'):
    print('block')
    ############ OpenSSL ECB mode ############
    # AES-NI Encryption
    ecb_aes_ni_real_time, ecb_aes_ni_cpu_time, ecb_aes_ni_cpu_cycles = process_perf_stat_output("output/block_perf/openssl/aes_ni_ecb")
    create_normality_graphs('normality_graphs/block/openssl/ECB/ecb_aes_ni_real_time_enc', 'Encryption: AES-NI ECB Real time (OpenSSL)', ecb_aes_ni_real_time["data"])
    create_normality_graphs('normality_graphs/block/openssl/ECB/ecb_aes_ni_cpu_time_enc', 'Encryption: AES-NI ECB CPU time (OpenSSL)', ecb_aes_ni_cpu_time["data"])
    create_normality_graphs('normality_graphs/block/openssl/ECB/ecb_aes_ni_cpu_cycles_enc', 'Encryption: AES-NI ECB CPU cycles (OpenSSL)', ecb_aes_ni_cpu_cycles["data"])
    # AES-NI Decryption
    dec_ecb_aes_ni_real_time, dec_ecb_aes_ni_cpu_time, dec_ecb_aes_ni_cpu_cycles = process_perf_stat_output("output/block_perf/openssl/aes_ni_ecb_decrypt")
    create_normality_graphs('normality_graphs/block/openssl/ECB/ecb_aes_ni_real_time_dec', 'Decryption: AES-NI ECB Real time (OpenSSL)', dec_ecb_aes_ni_real_time["data"])
    create_normality_graphs('normality_graphs/block/openssl/ECB/ecb_aes_ni_cpu_time_dec', 'Decryption: AES-NI ECB CPU time (OpenSSL)', dec_ecb_aes_ni_cpu_time["data"])
    create_normality_graphs('normality_graphs/block/openssl/ECB/ecb_aes_ni_cpu_cycles_dec', 'Decryption: AES-NI ECB CPU cycles (OpenSSL)', dec_ecb_aes_ni_cpu_cycles["data"])

    # AES Encryption
    ecb_aes_real_time, ecb_aes_cpu_time, ecb_aes_cpu_cycles = process_perf_stat_output("output/block_perf/openssl/aes_ecb")
    create_normality_graphs('normality_graphs/block/openssl/ECB/ecb_aes_real_time_enc', 'Encryption: AES ECB Real time (OpenSSL)', ecb_aes_real_time["data"])
    create_normality_graphs('normality_graphs/block/openssl/ECB/ecb_aes_cpu_time_enc', 'Encryption: AES ECB CPU time (OpenSSL)', ecb_aes_cpu_time["data"])
    create_normality_graphs('normality_graphs/block/openssl/ECB/ecb_aes_cpu_cycles_enc', 'Encryption: AES ECB CPU cycles (OpenSSL)', ecb_aes_cpu_cycles["data"])
    # AES Decryption
    dec_ecb_aes_real_time, dec_ecb_aes_cpu_time, dec_ecb_aes_cpu_cycles = process_perf_stat_output("output/block_perf/openssl/aes_ecb_decrypt")
    create_normality_graphs('normality_graphs/block/openssl/ECB/ecb_aes_real_time_dec', 'Decryption: AES ECB Real time (OpenSSL)', dec_ecb_aes_real_time["data"])
    create_normality_graphs('normality_graphs/block/openssl/ECB/ecb_aes_cpu_time_dec', 'Decryption: AES ECB CPU time (OpenSSL)', dec_ecb_aes_cpu_time["data"])
    create_normality_graphs('normality_graphs/block/openssl/ECB/ecb_aes_cpu_cycles_dec', 'Decryption: AES ECB CPU cycles (OpenSSL)', dec_ecb_aes_cpu_cycles["data"])

    # SM4 Encryption
    ecb_sm4_real_time, ecb_sm4_cpu_time, ecb_sm4_cpu_cycles = process_perf_stat_output("output/block_perf/openssl/sm4_ecb")
    create_normality_graphs('normality_graphs/block/openssl/ECB/ecb_sm4_real_time', 'Encryption: SM4 ECB Real time (OpenSSL)', ecb_sm4_real_time["data"])
    create_normality_graphs('normality_graphs/block/openssl/ECB/ecb_sm4_cpu_time', 'Encryption: SM4 ECB CPU time (OpenSSL)', ecb_sm4_cpu_time["data"])
    create_normality_graphs('normality_graphs/block/openssl/ECB/ecb_sm4_cpu_cycles', 'Encryption: SM4 ECB CPU cycles (OpenSSL)', ecb_sm4_cpu_cycles["data"])
    # SM4 Decryption
    dec_ecb_sm4_real_time, dec_ecb_sm4_cpu_time, dec_ecb_sm4_cpu_cycles = process_perf_stat_output("output/block_perf/openssl/sm4_ecb_decrypt")
    create_normality_graphs('normality_graphs/block/openssl/ECB/ecb_sm4_real_time_dec', 'Decryption: SM4 ECB Real time (OpenSSL)', dec_ecb_sm4_real_time["data"])
    create_normality_graphs('normality_graphs/block/openssl/ECB/ecb_sm4_cpu_time_dec', 'Decryption: SM4 ECB CPU time (OpenSSL)', dec_ecb_sm4_cpu_time["data"])
    create_normality_graphs('normality_graphs/block/openssl/ECB/ecb_sm4_cpu_cycles_dec', 'Decryption: SM4 ECB CPU cycles (OpenSSL)', dec_ecb_sm4_cpu_cycles["data"])

    ############ OpenSSL CBC mode ############
    # AES-NI Encryption
    cbc_aes_ni_real_time, cbc_aes_ni_cpu_time, cbc_aes_ni_cpu_cycles = process_perf_stat_output("output/block_perf/openssl/aes_ni_cbc")
    create_normality_graphs('normality_graphs/block/openssl/CBC/cbc_aes_ni_real_time_enc', 'Encryption: AES-NI CBC Real time (OpenSSL)', cbc_aes_ni_real_time["data"])
    create_normality_graphs('normality_graphs/block/openssl/CBC/cbc_aes_ni_cpu_time_enc', 'Encryption: AES-NI CBC CPU time (OpenSSL)', cbc_aes_ni_cpu_time["data"])
    create_normality_graphs('normality_graphs/block/openssl/CBC/cbc_aes_ni_cpu_cycles_enc', 'Encryption: AES-NI CBC CPU cycles (OpenSSL)', cbc_aes_ni_cpu_cycles["data"])
    # AES-NI Decryption
    dec_cbc_aes_ni_real_time, dec_cbc_aes_ni_cpu_time, dec_cbc_aes_ni_cpu_cycles = process_perf_stat_output("output/block_perf/openssl/aes_ni_cbc_decrypt")
    create_normality_graphs('normality_graphs/block/openssl/CBC/cbc_aes_ni_real_time_dec', 'Decryption: AES-NI CBC Real time (OpenSSL)', dec_cbc_aes_ni_real_time["data"])
    create_normality_graphs('normality_graphs/block/openssl/CBC/cbc_aes_ni_cpu_time_dec', 'Decryption: AES-NI CBC CPU time (OpenSSL)', dec_cbc_aes_ni_cpu_time["data"])
    create_normality_graphs('normality_graphs/block/openssl/CBC/cbc_aes_ni_cpu_cycles_dec', 'Decryption: AES-NI CBC CPU cycles (OpenSSL)', dec_cbc_aes_ni_cpu_cycles["data"])

    # AES Encryption
    cbc_aes_real_time, cbc_aes_cpu_time, cbc_aes_cpu_cycles = process_perf_stat_output("output/block_perf/openssl/aes_cbc")
    create_normality_graphs('normality_graphs/block/openssl/CBC/cbc_aes_real_time_enc', 'Encryption: AES CBC Real time (OpenSSL)', cbc_aes_real_time["data"])
    create_normality_graphs('normality_graphs/block/openssl/CBC/cbc_aes_cpu_time_enc', 'Encryption: AES CBC CPU time (OpenSSL)', cbc_aes_cpu_time["data"])
    create_normality_graphs('normality_graphs/block/openssl/CBC/cbc_aes_cpu_cycles_enc', 'Encryption: AES CBC CPU cycles (OpenSSL)', cbc_aes_cpu_cycles["data"])
    # AES Decryption
    dec_cbc_aes_real_time, dec_cbc_aes_cpu_time, dec_cbc_aes_cpu_cycles = process_perf_stat_output("output/block_perf/openssl/aes_cbc_decrypt")
    create_normality_graphs('normality_graphs/block/openssl/CBC/cbc_aes_real_time_dec', 'Decryption: AES CBC Real time (OpenSSL)', dec_cbc_aes_real_time["data"])
    create_normality_graphs('normality_graphs/block/openssl/CBC/cbc_aes_cpu_time_dec', 'Decryption: AES CBC CPU time (OpenSSL)', dec_cbc_aes_cpu_time["data"])
    create_normality_graphs('normality_graphs/block/openssl/CBC/cbc_aes_cpu_cycles_dec', 'Decryption: AES CBC CPU cycles (OpenSSL)', dec_cbc_aes_cpu_cycles["data"])

    # SM4 Encryption
    cbc_sm4_real_time, cbc_sm4_cpu_time, cbc_sm4_cpu_cycles = process_perf_stat_output("output/block_perf/openssl/sm4_cbc")
    create_normality_graphs('normality_graphs/block/openssl/CBC/cbc_sm4_real_time', 'Encryption: SM4 CBC Real time (OpenSSL)', cbc_sm4_real_time["data"])
    create_normality_graphs('normality_graphs/block/openssl/CBC/cbc_sm4_cpu_time', 'Encryption: SM4 CBC CPU time (OpenSSL)', cbc_sm4_cpu_time["data"])
    create_normality_graphs('normality_graphs/block/openssl/CBC/cbc_sm4_cpu_cycles', 'Encryption: SM4 CBC CPU cycles (OpenSSL)', cbc_sm4_cpu_cycles["data"])
    # SM4 Decryption
    dec_cbc_sm4_real_time, dec_cbc_sm4_cpu_time, dec_cbc_sm4_cpu_cycles = process_perf_stat_output("output/block_perf/openssl/sm4_cbc_decrypt")
    create_normality_graphs('normality_graphs/block/openssl/CBC/cbc_sm4_real_time_dec', 'Decryption: SM4 CBC Real time (OpenSSL)', dec_cbc_sm4_real_time["data"])
    create_normality_graphs('normality_graphs/block/openssl/CBC/cbc_sm4_cpu_time_dec', 'Decryption: SM4 CBC CPU time (OpenSSL)', dec_cbc_sm4_cpu_time["data"])
    create_normality_graphs('normality_graphs/block/openssl/CBC/cbc_sm4_cpu_cycles_dec', 'Decryption: SM4 CBC CPU cycles (OpenSSL)', dec_cbc_sm4_cpu_cycles["data"])


    ############ OpenSSL CTR mode ############
    # AES-NI Encryption
    ctr_aes_ni_real_time, ctr_aes_ni_cpu_time, ctr_aes_ni_cpu_cycles = process_perf_stat_output("output/block_perf/openssl/aes_ni_ctr")
    create_normality_graphs('normality_graphs/block/openssl/CTR/ctr_aes_ni_real_time_enc', 'Encryption: AES-NI CTR Real time (OpenSSL)', ctr_aes_ni_real_time["data"])
    create_normality_graphs('normality_graphs/block/openssl/CTR/ctr_aes_ni_cpu_time_enc', 'Encryption: AES-NI CTR CPU time (OpenSSL)', ctr_aes_ni_cpu_time["data"])
    create_normality_graphs('normality_graphs/block/openssl/CTR/ctr_aes_ni_cpu_cycles_enc', 'Encryption: AES-NI CTR CPU cycles (OpenSSL)', ctr_aes_ni_cpu_cycles["data"])
    # AES-NI Decryption
    dec_ctr_aes_ni_real_time, dec_ctr_aes_ni_cpu_time, dec_ctr_aes_ni_cpu_cycles = process_perf_stat_output("output/block_perf/openssl/aes_ni_ctr_decrypt")
    create_normality_graphs('normality_graphs/block/openssl/CTR/ctr_aes_ni_real_time_dec', 'Decryption: AES-NI CTR Real time (OpenSSL)', dec_ctr_aes_ni_real_time["data"])
    create_normality_graphs('normality_graphs/block/openssl/CTR/ctr_aes_ni_cpu_time_dec', 'Decryption: AES-NI CTR CPU time (OpenSSL)', dec_ctr_aes_ni_cpu_time["data"])
    create_normality_graphs('normality_graphs/block/openssl/CTR/ctr_aes_ni_cpu_cycles_dec', 'Decryption: AES-NI CTR CPU cycles (OpenSSL)', dec_ctr_aes_ni_cpu_cycles["data"])

    # AES Encryption
    ctr_aes_real_time, ctr_aes_cpu_time, ctr_aes_cpu_cycles = process_perf_stat_output("output/block_perf/openssl/aes_ctr")
    create_normality_graphs('normality_graphs/block/openssl/CTR/ctr_aes_real_time_enc', 'Encryption: AES CTR Real time (OpenSSL)', ctr_aes_real_time["data"])
    create_normality_graphs('normality_graphs/block/openssl/CTR/ctr_aes_cpu_time_enc', 'Encryption: AES CTR CPU time (OpenSSL)', ctr_aes_cpu_time["data"])
    create_normality_graphs('normality_graphs/block/openssl/CTR/ctr_aes_cpu_cycles_enc', 'Encryption: AES CTR CPU cycles (OpenSSL)', ctr_aes_cpu_cycles["data"])
    # AES Decryption
    dec_ctr_aes_real_time, dec_ctr_aes_cpu_time, dec_ctr_aes_cpu_cycles = process_perf_stat_output("output/block_perf/openssl/aes_ctr_decrypt")
    create_normality_graphs('normality_graphs/block/openssl/CTR/ctr_aes_real_time_dec', 'Decryption: AES CTR Real time (OpenSSL)', dec_ctr_aes_real_time["data"])
    create_normality_graphs('normality_graphs/block/openssl/CTR/ctr_aes_cpu_time_dec', 'Decryption: AES CTR CPU time (OpenSSL)', dec_ctr_aes_cpu_time["data"])
    create_normality_graphs('normality_graphs/block/openssl/CTR/ctr_aes_cpu_cycles_dec', 'Decryption: AES CTR CPU cycles (OpenSSL)', dec_ctr_aes_cpu_cycles["data"])

    # SM4 Encryption
    ctr_sm4_real_time, ctr_sm4_cpu_time, ctr_sm4_cpu_cycles = process_perf_stat_output("output/block_perf/openssl/sm4_ctr")
    create_normality_graphs('normality_graphs/block/openssl/CTR/ctr_sm4_real_time', 'Encryption: SM4 CTR Real time (OpenSSL)', ctr_sm4_real_time["data"])
    create_normality_graphs('normality_graphs/block/openssl/CTR/ctr_sm4_cpu_time', 'Encryption: SM4 CTR CPU time (OpenSSL)', ctr_sm4_cpu_time["data"])
    create_normality_graphs('normality_graphs/block/openssl/CTR/ctr_sm4_cpu_cycles', 'Encryption: SM4 CTR CPU cycles (OpenSSL)', ctr_sm4_cpu_cycles["data"])
    # SM4 Decryption
    dec_ctr_sm4_real_time, dec_ctr_sm4_cpu_time, dec_ctr_sm4_cpu_cycles = process_perf_stat_output("output/block_perf/openssl/sm4_ctr_decrypt")
    create_normality_graphs('normality_graphs/block/openssl/CTR/ctr_sm4_real_time_dec', 'Decryption: SM4 CTR Real time (OpenSSL)', dec_ctr_sm4_real_time["data"])
    create_normality_graphs('normality_graphs/block/openssl/CTR/ctr_sm4_cpu_time_dec', 'Decryption: SM4 CTR CPU time (OpenSSL)', dec_ctr_sm4_cpu_time["data"])
    create_normality_graphs('normality_graphs/block/openssl/CTR/ctr_sm4_cpu_cycles_dec', 'Decryption: SM4 CTR CPU cycles (OpenSSL)', dec_ctr_sm4_cpu_cycles["data"])

    ###############################################################################################

    ############ Botan ECB mode ############
    # AES-NI Encryption
    botan_ecb_aes_ni_real_time, botan_ecb_aes_ni_cpu_time, botan_ecb_aes_ni_cpu_cycles = process_perf_stat_output("output/block_perf/botan/botan_aes_ni_ecb")
    create_normality_graphs('normality_graphs/block/botan/ECB/ecb_aes_ni_real_time_enc', 'Encryption: AES-NI ECB Real time (Botan)', botan_ecb_aes_ni_real_time["data"])
    create_normality_graphs('normality_graphs/block/botan/ECB/ecb_aes_ni_cpu_time_enc', 'Encryption: AES-NI ECB CPU time (Botan)', botan_ecb_aes_ni_cpu_time["data"])
    create_normality_graphs('normality_graphs/block/botan/ECB/ecb_aes_ni_cpu_cycles_enc', 'Encryption: AES-NI ECB CPU cycles (Botan)', botan_ecb_aes_ni_cpu_cycles["data"])
    # AES-NI Decryption
    botan_dec_ecb_aes_ni_real_time, botan_dec_ecb_aes_ni_cpu_time, botan_dec_ecb_aes_ni_cpu_cycles = process_perf_stat_output("output/block_perf/botan/botan_aes_ni_ecb_decrypt")
    create_normality_graphs('normality_graphs/block/botan/ECB/ecb_aes_ni_real_time_dec', 'Decryption: AES-NI ECB Real time (Botan)', botan_dec_ecb_aes_ni_real_time["data"])
    create_normality_graphs('normality_graphs/block/botan/ECB/ecb_aes_ni_cpu_time_dec', 'Decryption: AES-NI ECB CPU time (Botan)', botan_dec_ecb_aes_ni_cpu_time["data"])
    create_normality_graphs('normality_graphs/block/botan/ECB/ecb_aes_ni_cpu_cycles_dec', 'Decryption: AES-NI ECB CPU cycles (Botan)', botan_dec_ecb_aes_ni_cpu_cycles["data"])

    # AES Encryption
    botan_ecb_aes_real_time, botan_ecb_aes_cpu_time, botan_ecb_aes_cpu_cycles = process_perf_stat_output("output/block_perf/botan/botan_aes_ecb")
    create_normality_graphs('normality_graphs/block/botan/ECB/ecb_aes_real_time_enc', 'Encryption: AES ECB Real time (Botan)', botan_ecb_aes_real_time["data"])
    create_normality_graphs('normality_graphs/block/botan/ECB/ecb_aes_cpu_time_enc', 'Encryption: AES ECB CPU time (Botan)', botan_ecb_aes_cpu_time["data"])
    create_normality_graphs('normality_graphs/block/botan/ECB/ecb_aes_cpu_cycles_enc', 'Encryption: AES ECB CPU cycles (Botan)', botan_ecb_aes_cpu_cycles["data"])
    # AES Decryption
    botan_dec_ecb_aes_real_time, botan_dec_ecb_aes_cpu_time, botan_dec_ecb_aes_cpu_cycles = process_perf_stat_output("output/block_perf/botan/botan_aes_ecb_decrypt")
    create_normality_graphs('normality_graphs/block/botan/ECB/ecb_aes_real_time_dec', 'Decryption: AES ECB Real time (Botan)', botan_dec_ecb_aes_real_time["data"])
    create_normality_graphs('normality_graphs/block/botan/ECB/ecb_aes_cpu_time_dec', 'Decryption: AES ECB CPU time (Botan)', botan_dec_ecb_aes_cpu_time["data"])
    create_normality_graphs('normality_graphs/block/botan/ECB/ecb_aes_cpu_cycles_dec', 'Decryption: AES ECB CPU cycles (Botan)', botan_dec_ecb_aes_cpu_cycles["data"])

    # SM4 Encryption
    botan_ecb_sm4_real_time, botan_ecb_sm4_cpu_time, botan_ecb_sm4_cpu_cycles = process_perf_stat_output("output/block_perf/botan/botan_sm4_ecb")
    create_normality_graphs('normality_graphs/block/botan/ECB/ecb_sm4_real_time_enc', 'Encryption: SM4 ECB Real time (Botan)', botan_ecb_sm4_real_time["data"])
    create_normality_graphs('normality_graphs/block/botan/ECB/ecb_sm4_cpu_time_enc', 'Encryption: SM4 ECB CPU time (Botan)', botan_ecb_sm4_cpu_time["data"])
    create_normality_graphs('normality_graphs/block/botan/ECB/ecb_sm4_cpu_cycles_enc', 'Encryption: SM4 ECB CPU cycles (Botan)', botan_ecb_sm4_cpu_cycles["data"])
    # SM4 Decryption
    botan_dec_ecb_sm4_real_time, botan_dec_ecb_sm4_cpu_time, botan_dec_ecb_sm4_cpu_cycles = process_perf_stat_output("output/block_perf/botan/botan_sm4_ecb_decrypt")
    create_normality_graphs('normality_graphs/block/botan/ECB/ecb_sm4_real_time_dec', 'Decryption: SM4 ECB Real time (Botan)', botan_dec_ecb_sm4_real_time["data"])
    create_normality_graphs('normality_graphs/block/botan/ECB/ecb_sm4_cpu_time_dec', 'Decryption: SM4 ECB CPU time (Botan)', botan_dec_ecb_sm4_cpu_time["data"])
    create_normality_graphs('normality_graphs/block/botan/ECB/ecb_sm4_cpu_cycles_dec', 'Decryption: SM4 ECB CPU cycles (Botan)', botan_dec_ecb_sm4_cpu_cycles["data"])

    ############ Botan CBC mode ############
    # AES-NI Encryption
    botan_cbc_aes_ni_real_time, botan_cbc_aes_ni_cpu_time, botan_cbc_aes_ni_cpu_cycles = process_perf_stat_output("output/block_perf/botan/botan_aes_ni_cbc")
    create_normality_graphs('normality_graphs/block/botan/CBC/cbc_aes_ni_real_time_enc', 'Encryption: AES-NI CBC Real time (Botan)', botan_cbc_aes_ni_real_time["data"])
    create_normality_graphs('normality_graphs/block/botan/CBC/cbc_aes_ni_cpu_time_enc', 'Encryption: AES-NI CBC CPU time (Botan)', botan_cbc_aes_ni_cpu_time["data"])
    create_normality_graphs('normality_graphs/block/botan/CBC/cbc_aes_ni_cpu_cycles_enc', 'Encryption: AES-NI CBC CPU cycles (Botan)', botan_cbc_aes_ni_cpu_cycles["data"])
    # AES-NI Decryption
    botan_dec_cbc_aes_ni_real_time, botan_dec_cbc_aes_ni_cpu_time, botan_dec_cbc_aes_ni_cpu_cycles = process_perf_stat_output("output/block_perf/botan/botan_aes_ni_cbc_decrypt")
    create_normality_graphs('normality_graphs/block/botan/CBC/cbc_aes_ni_real_time_dec', 'Decryption: AES-NI CBC Real time (Botan)', botan_dec_cbc_aes_ni_real_time["data"])
    create_normality_graphs('normality_graphs/block/botan/CBC/cbc_aes_ni_cpu_time_dec', 'Decryption: AES-NI CBC CPU time (Botan)', botan_dec_cbc_aes_ni_cpu_time["data"])
    create_normality_graphs('normality_graphs/block/botan/CBC/cbc_aes_ni_cpu_cycles_dec', 'Decryption: AES-NI CBC CPU cycles (Botan)', botan_dec_cbc_aes_ni_cpu_cycles["data"])

    # AES Encryption
    botan_cbc_aes_real_time, botan_cbc_aes_cpu_time, botan_cbc_aes_cpu_cycles = process_perf_stat_output("output/block_perf/botan/botan_aes_cbc")
    create_normality_graphs('normality_graphs/block/botan/CBC/cbc_aes_real_time_enc', 'Encryption: AES CBC Real time (Botan)', botan_cbc_aes_real_time["data"])
    create_normality_graphs('normality_graphs/block/botan/CBC/cbc_aes_cpu_time_enc', 'Encryption: AES CBC CPU time (Botan)', botan_cbc_aes_cpu_time["data"])
    create_normality_graphs('normality_graphs/block/botan/CBC/cbc_aes_cpu_cycles_enc', 'Encryption: AES CBC CPU cycles (Botan)', botan_cbc_aes_cpu_cycles["data"])
    # AES Decryption
    botan_dec_cbc_aes_real_time, botan_dec_cbc_aes_cpu_time, botan_dec_cbc_aes_cpu_cycles = process_perf_stat_output("output/block_perf/botan/botan_aes_cbc_decrypt")
    create_normality_graphs('normality_graphs/block/botan/CBC/cbc_aes_real_time_dec', 'Decryption: AES CBC Real time (Botan)', botan_dec_cbc_aes_real_time["data"])
    create_normality_graphs('normality_graphs/block/botan/CBC/cbc_aes_cpu_time_dec', 'Decryption: AES CBC CPU time (Botan)', botan_dec_cbc_aes_cpu_time["data"])
    create_normality_graphs('normality_graphs/block/botan/CBC/cbc_aes_cpu_cycles_dec', 'Decryption: AES CBC CPU cycles (Botan)', botan_dec_cbc_aes_cpu_cycles["data"])

    # SM4 Encryption
    botan_cbc_sm4_real_time, botan_cbc_sm4_cpu_time, botan_cbc_sm4_cpu_cycles = process_perf_stat_output("output/block_perf/botan/botan_sm4_cbc")
    create_normality_graphs('normality_graphs/block/botan/CBC/cbc_sm4_real_time_enc', 'Encryption: SM4 CBC Real time (Botan)', botan_cbc_sm4_real_time["data"])
    create_normality_graphs('normality_graphs/block/botan/CBC/cbc_sm4_cpu_time_enc', 'Encryption: SM4 CBC CPU time (Botan)', botan_cbc_sm4_cpu_time["data"])
    create_normality_graphs('normality_graphs/block/botan/CBC/cbc_sm4_cpu_cycles_enc', 'Encryption: SM4 CBC CPU cycles (Botan)', botan_cbc_sm4_cpu_cycles["data"])
    # SM4 Decryption
    botan_dec_cbc_sm4_real_time, botan_dec_cbc_sm4_cpu_time, botan_dec_cbc_sm4_cpu_cycles = process_perf_stat_output("output/block_perf/botan/botan_sm4_cbc_decrypt")
    create_normality_graphs('normality_graphs/block/botan/CBC/cbc_sm4_real_time_dec', 'Decryption: SM4 CBC Real time (Botan)', botan_dec_cbc_sm4_real_time["data"])
    create_normality_graphs('normality_graphs/block/botan/CBC/cbc_sm4_cpu_time_dec', 'Decryption: SM4 CBC CPU time (Botan)', botan_dec_cbc_sm4_cpu_time["data"])
    create_normality_graphs('normality_graphs/block/botan/CBC/cbc_sm4_cpu_cycles_dec', 'Decryption: SM4 CBC CPU cycles (Botan)', botan_dec_cbc_sm4_cpu_cycles["data"])

    ############ Botan CTR mode ############
    # AES-NI Encryption
    botan_ctr_aes_ni_real_time, botan_ctr_aes_ni_cpu_time, botan_ctr_aes_ni_cpu_cycles = process_perf_stat_output("output/block_perf/botan/botan_aes_ni_ctr")
    create_normality_graphs('normality_graphs/block/botan/CTR/ctr_aes_ni_real_time_enc', 'Encryption: AES-NI CTR Real time (Botan)', botan_ctr_aes_ni_real_time["data"])
    create_normality_graphs('normality_graphs/block/botan/CTR/ctr_aes_ni_cpu_time_enc', 'Encryption: AES-NI CTR CPU time (Botan)', botan_ctr_aes_ni_cpu_time["data"])
    create_normality_graphs('normality_graphs/block/botan/CTR/ctr_aes_ni_cpu_cycles_enc', 'Encryption: AES-NI CTR CPU cycles (Botan)', botan_ctr_aes_ni_cpu_cycles["data"])
    # AES-NI Decryption
    botan_dec_ctr_aes_ni_real_time, botan_dec_ctr_aes_ni_cpu_time, botan_dec_ctr_aes_ni_cpu_cycles = process_perf_stat_output("output/block_perf/botan/botan_aes_ni_ctr_decrypt")
    create_normality_graphs('normality_graphs/block/botan/CTR/ctr_aes_ni_real_time_dec', 'Decryption: AES-NI CTR Real time (Botan)', botan_dec_ctr_aes_ni_real_time["data"])
    create_normality_graphs('normality_graphs/block/botan/CTR/ctr_aes_ni_cpu_time_dec', 'Decryption: AES-NI CTR CPU time (Botan)', botan_dec_ctr_aes_ni_cpu_time["data"])
    create_normality_graphs('normality_graphs/block/botan/CTR/ctr_aes_ni_cpu_cycles_dec', 'Decryption: AES-NI CTR CPU cycles (Botan)', botan_dec_ctr_aes_ni_cpu_cycles["data"])

    # AES Encryption
    botan_ctr_aes_real_time, botan_ctr_aes_cpu_time, botan_ctr_aes_cpu_cycles = process_perf_stat_output("output/block_perf/botan/botan_aes_ctr")
    create_normality_graphs('normality_graphs/block/botan/CTR/ctr_aes_real_time_enc', 'Encryption: AES CTR Real time (Botan)', botan_ctr_aes_real_time["data"])
    create_normality_graphs('normality_graphs/block/botan/CTR/ctr_aes_cpu_time_enc', 'Encryption: AES CTR CPU time (Botan)', botan_ctr_aes_cpu_time["data"])
    create_normality_graphs('normality_graphs/block/botan/CTR/ctr_aes_cpu_cycles_enc', 'Encryption: AES CTR CPU cycles (Botan)', botan_ctr_aes_cpu_cycles["data"])
    # AES Decryption
    botan_dec_ctr_aes_real_time, botan_dec_ctr_aes_cpu_time, botan_dec_ctr_aes_cpu_cycles = process_perf_stat_output("output/block_perf/botan/botan_aes_ctr_decrypt")
    create_normality_graphs('normality_graphs/block/botan/CTR/ctr_aes_real_time_dec', 'Decryption: AES CTR Real time (Botan)', botan_dec_ctr_aes_real_time["data"])
    create_normality_graphs('normality_graphs/block/botan/CTR/ctr_aes_cpu_time_dec', 'Decryption: AES CTR CPU time (Botan)', botan_dec_ctr_aes_cpu_time["data"])
    create_normality_graphs('normality_graphs/block/botan/CTR/ctr_aes_cpu_cycles_dec', 'Decryption: AES CTR CPU cycles (Botan)', botan_dec_ctr_aes_cpu_cycles["data"])

    # SM4 Encryption
    botan_ctr_sm4_real_time, botan_ctr_sm4_cpu_time, botan_ctr_sm4_cpu_cycles = process_perf_stat_output("output/block_perf/botan/botan_sm4_ctr")
    create_normality_graphs('normality_graphs/block/botan/CTR/ctr_sm4_real_time_enc', 'Encryption: SM4 CTR Real time (Botan)', botan_ctr_sm4_real_time["data"])
    create_normality_graphs('normality_graphs/block/botan/CTR/ctr_sm4_cpu_time_enc', 'Encryption: SM4 CTR CPU time (Botan)', botan_ctr_sm4_cpu_time["data"])
    create_normality_graphs('normality_graphs/block/botan/CTR/ctr_sm4_cpu_cycles_enc', 'Encryption: SM4 CTR CPU cycles (Botan)', botan_ctr_sm4_cpu_cycles["data"])
    # SM4 Decryption
    botan_dec_ctr_sm4_real_time, botan_dec_ctr_sm4_cpu_time, botan_dec_ctr_sm4_cpu_cycles = process_perf_stat_output("output/block_perf/botan/botan_sm4_ctr_decrypt")
    create_normality_graphs('normality_graphs/block/botan/CTR/ctr_sm4_real_time_dec', 'Decryption: SM4 CTR Real time (Botan)', botan_dec_ctr_sm4_real_time["data"])
    create_normality_graphs('normality_graphs/block/botan/CTR/ctr_sm4_cpu_time_dec', 'Decryption: SM4 CTR CPU time (Botan)', botan_dec_ctr_sm4_cpu_time["data"])
    create_normality_graphs('normality_graphs/block/botan/CTR/ctr_sm4_cpu_cycles_dec', 'Decryption: SM4 CTR CPU cycles (Botan)', botan_dec_ctr_sm4_cpu_cycles["data"])

    ###############################################################################################

    ############ RSS OpenSSL ############
    # AES-NI Encryption
    RSS_aes_ni = process_proc_status_output("output/block_rss/openssl/openssl_aes_ni_rss")
    create_normality_graphs('normality_graphs/block_rss/openssl/rss_aes_ni', 'Encryption: AES-NI RSS (OpenSSL)', RSS_aes_ni)
    # AES-NI Decryption
    RSS_dec_aes_ni = process_proc_status_output("output/block_rss/openssl/openssl_aes_ni_rss_decrypt")
    create_normality_graphs('normality_graphs/block_rss/openssl/rss_aes_ni_dec', 'Decryption: AES-NI RSS (OpenSSL)', RSS_dec_aes_ni)

    # AES Encryption
    RSS_aes = process_proc_status_output("output/block_rss/openssl/openssl_aes_rss")
    create_normality_graphs('normality_graphs/block_rss/openssl/rss_aes', 'Encryption: AES RSS (OpenSSL)', RSS_aes)
    # AES Decryption
    RSS_dec_aes = process_proc_status_output("output/block_rss/openssl/openssl_aes_rss_decrypt")
    create_normality_graphs('normality_graphs/block_rss/openssl/rss_aes_dec', 'Decryption: AES RSS (OpenSSL)', RSS_dec_aes)

    # SM4 Encryption
    RSS_sm4 = process_proc_status_output("output/block_rss/openssl/openssl_sm4_rss")
    create_normality_graphs('normality_graphs/block_rss/openssl/rss_sm4_ni', 'Encryption: SM4 RSS (OpenSSL)', RSS_sm4)
    # SM4 Decryption
    RSS_dec_sm4 = process_proc_status_output("output/block_rss/openssl/openssl_sm4_rss_decrypt")
    create_normality_graphs('normality_graphs/block_rss/openssl/rss_sm4_ni_dec', 'Decryption: SM4 RSS (OpenSSL)', RSS_dec_sm4)

    ############ RSS Botan ############
    # AES-NI Encryption
    botan_RSS_aes_ni = process_proc_status_output("output/block_rss/botan/botan_aes_ni_rss_encrypt")
    create_normality_graphs('normality_graphs/block_rss/botan/rss_aes_ni', 'Encryption: AES-NI RSS (Botan)', botan_RSS_aes_ni)
    # AES-NI Decryption
    botan_RSS_dec_aes_ni = process_proc_status_output("output/block_rss/botan/botan_aes_ni_rss_decrypt")
    create_normality_graphs('normality_graphs/block_rss/botan/rss_aes_ni_dec', 'Decryption: AES-NI RSS (Botan)', botan_RSS_dec_aes_ni)

    # AES Encryption
    botan_RSS_aes = process_proc_status_output("output/block_rss/botan/botan_aes_rss_encrypt")
    create_normality_graphs('normality_graphs/block_rss/botan/rss_aes', 'Encryption: AES RSS (Botan)', botan_RSS_aes)
    # AES-NI Decryption
    botan_RSS_dec_aes = process_proc_status_output("output/block_rss/botan/botan_aes_rss_decrypt")
    create_normality_graphs('normality_graphs/block_rss/botan/rss_aes_dec', 'Decryption: AES RSS (Botan)', botan_RSS_dec_aes)

    # SM4 Encryption
    botan_RSS_sm4 = process_proc_status_output("output/block_rss/botan/botan_sm4_rss_encrypt")
    create_normality_graphs('normality_graphs/block_rss/botan/rss_sm4', 'Encryption: SM4 RSS (Botan)', botan_RSS_sm4)
    # SM4 Decryption
    botan_RSS_dec_sm4 = process_proc_status_output("output/block_rss/botan/botan_sm4_rss_decrypt")
    create_normality_graphs('normality_graphs/block_rss/botan/rss_sm4_dec', 'Decryption: SM4 RSS (Botan)', botan_RSS_dec_sm4)

else:
    print("No valid argument input")
