from itertools import islice
import statistics
import numpy
import math
import PyGnuplot as gp
from scipy.stats import sem, t
from scipy import mean, median, stats
import sys

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
    in_dict["std_low"] = mean(data) - numpy.std(data)
    in_dict["std_high"] = mean(data) + numpy.std(data)
    #c_interval = confidence_interval(data)
    #in_dict["conf_low"] =  c_interval[0]
    #in_dict["conf_high"] = c_interval[1]
    return in_dict

def process_perf_stat_output(file_path, divide_value=1):
    list_entries = read_entries(file_path, 10)
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

def create_dat_file_for_hash(file_path, alg1, alg2, dict1, dict2):
    f = open(file_path, "w+")
    f.write("# avg,standard_deviation\n")
    s = ','.join(['0', alg1, str(dict1["mean"]), str(dict1["standard_dev"])])
    f.write(s + "\n")
    s = ','.join(['0.5' ,alg2, str(dict2["mean"]), str(dict2["standard_dev"])])
    f.write(s + "\n")
    f.close()

def create_dat_file_for_ds(file_path, dict1_key, dict1_sign, dict1_verify,\
                            dict2_key, dict2_sign, dict2_verify,\
                            dict3_key, dict3_sign, dict3_verify):
    f = open(file_path,"w+")
    f.write("# avg,std,avg,std,avg,std\n")
    s = ','.join(["Key generation",\
        str(dict1_key["mean"]), str(dict1_key["standard_dev"]),\
        str(dict2_key["mean"]), str(dict2_key["standard_dev"]),\
        str(dict3_key["mean"]), str(dict3_key["standard_dev"])])
    f.write(s + "\n")
    s = ','.join(["Sign",\
        str(dict1_sign["mean"]), str(dict1_sign["standard_dev"]),\
        str(dict2_sign["mean"]), str(dict2_sign["standard_dev"]),\
        str(dict3_sign["mean"]), str(dict3_sign["standard_dev"])])
    f.write(s + "\n")
    s = ','.join(["Verify",\
        str(dict1_verify["mean"]), str(dict1_verify["standard_dev"]),\
        str(dict2_verify["mean"]), str(dict2_verify["standard_dev"]),\
        str(dict3_verify["mean"]), str(dict3_verify["standard_dev"])])
    f.write(s + "\n")
    f.close()

def ds_print_table_row(lib, op, alg, measurement,in_dict):
    print(' '.join([lib,op,alg,measurement]) + '\t' + str(in_dict["mean"]) +\
    '\t' + str(in_dict["median"]) + '\t' + str(in_dict["standard_dev"]) + '\t' + str(in_dict["min"])\
    + '\t' + str(in_dict["max"]))

def create_dat_file_for_block(file_path, enc_ecb_dict1, enc_ecb_dict2, enc_ecb_dict3,\
                              enc_cbc_dict1, enc_cbc_dict2, enc_cbc_dict3,\
                              enc_ctr_dict1, enc_ctr_dict2, enc_ctr_dict3,\
                              dec_ecb_dict1, dec_ecb_dict2, dec_ecb_dict3,\
                              dec_cbc_dict1, dec_cbc_dict2, dec_cbc_dict3,\
                              dec_ctr_dict1, dec_ctr_dict2, dec_ctr_dict3,\
):
    f = open(file_path, "w+")
    f.write("# avg,std,avg,std,avg,std\n")
    # Encryption
    s = ','.join(["ECB Encryption", \
        str(enc_ecb_dict1["mean"]), str(enc_ecb_dict1["standard_dev"]),\
        str(enc_ecb_dict2["mean"]), str(enc_ecb_dict2["standard_dev"]),\
        str(enc_ecb_dict3["mean"]), str(enc_ecb_dict3["standard_dev"])])
    f.write(s + "\n")
    s = ','.join(["CBC encryption", \
        str(enc_cbc_dict1["mean"]), str(enc_cbc_dict1["standard_dev"]),\
        str(enc_cbc_dict2["mean"]), str(enc_cbc_dict2["standard_dev"]),\
        str(enc_cbc_dict3["mean"]), str(enc_cbc_dict3["standard_dev"])])
    f.write(s + "\n")
    s = ','.join(["CTR encryption", \
        str(enc_ctr_dict1["mean"]), str(enc_ctr_dict1["standard_dev"]),\
        str(enc_ctr_dict2["mean"]), str(enc_ctr_dict2["standard_dev"]),\
        str(enc_ctr_dict3["mean"]), str(enc_ctr_dict3["standard_dev"])])
    f.write(s + "\n")
    s = ','.join(["ECB Decryption", \
        str(dec_ecb_dict1["mean"]), str(dec_ecb_dict1["standard_dev"]),\
        str(dec_ecb_dict2["mean"]), str(dec_ecb_dict2["standard_dev"]),\
        str(dec_ecb_dict3["mean"]), str(dec_ecb_dict3["standard_dev"])])
    f.write(s + "\n")
    s = ','.join(["CBC Decryption", \
        str(dec_cbc_dict1["mean"]), str(dec_cbc_dict1["standard_dev"]),\
        str(dec_cbc_dict2["mean"]), str(dec_cbc_dict2["standard_dev"]),\
        str(dec_cbc_dict3["mean"]), str(dec_cbc_dict3["standard_dev"])])
    f.write(s + "\n")
    s = ','.join(["CTR Decryption", \
        str(dec_ctr_dict1["mean"]), str(dec_ctr_dict1["standard_dev"]),\
        str(dec_ctr_dict2["mean"]), str(dec_ctr_dict2["standard_dev"]),\
        str(dec_ctr_dict3["mean"]), str(dec_ctr_dict3["standard_dev"])])
    f.write(s + "\n")
    f.close()

if (sys.argv[1] == 'hash'):
    #openssl
    sm3_real_time, sm3_cpu_time, sm3_cpu_cycles = process_perf_stat_output("output/hash/sm3_perf_o")
    sha_real_time, sha_cpu_time, sha_cpu_cycles = process_perf_stat_output("output/hash/sha256_perf_o")

    print('\t\t\t\t\tMean\t\tMedian\t\tStd. Dev\t\tMin\t\tMax')
    ds_print_table_row('OpenSSL', 'Hashing', 'SM3', 'Real-time', sm3_real_time)
    ds_print_table_row('OpenSSL', 'Hashing', 'SM3', 'CPU time', sm3_cpu_time)
    ds_print_table_row('OpenSSL', 'Hashing', 'SM3', 'CPU cycles', sm3_cpu_cycles)

    ds_print_table_row('OpenSSL', 'Hashing', 'SHA', 'Real-time', sha_real_time)
    ds_print_table_row('OpenSSL', 'Hashing', 'SHA', 'CPU time', sha_cpu_time)
    ds_print_table_row('OpenSSL', 'Hashing', 'SHA', 'CPU cycle', sha_cpu_cycles)
    print('\n')

    #botan
    botan_sm3_real_time, botan_sm3_cpu_time, botan_sm3_cpu_cycles = process_perf_stat_output("output/hash/sm3_perf")
    botan_sha_real_time, botan_sha_cpu_time, botan_sha_cpu_cycles = process_perf_stat_output("output/hash/sha256_perf")

    print('\t\t\t\t\tMean\t\tMedian\t\tStd. Dev\t\tMin\t\tMax')
    ds_print_table_row('Botan', 'Hashing', 'SM3', 'Real-time', botan_sm3_real_time)
    ds_print_table_row('Botan', 'Hashing', 'SM3', 'CPU time', botan_sm3_cpu_time)
    ds_print_table_row('Botan', 'Hashing', 'SM3', 'CPU cycles', botan_sm3_cpu_cycles)

    ds_print_table_row('Botan', 'Hashing', 'SHA', 'Real-time', botan_sha_real_time)
    ds_print_table_row('Botan', 'Hashing', 'SHA', 'CPU time', botan_sha_cpu_time)
    ds_print_table_row('Botan', 'Hashing', 'SHA', 'CPUcycles', botan_sha_cpu_cycles)
    print('\n')


    # Real time graphs (openssl and botan)
    create_dat_file_for_hash('graphs/hash/hash_real_time_openssl.dat', 'SM3', 'SHA-256', sm3_real_time, sha_real_time)
    create_dat_file_for_hash('graphs/hash/hash_real_time_botan.dat', 'SM3', 'SHA-256', botan_sm3_real_time, botan_sha_real_time)
    # CPU time graphs (openssl and botan)
    create_dat_file_for_hash('graphs/hash/hash_cpu_time_openssl.dat', 'SM3', 'SHA-256', sm3_cpu_time, sha_cpu_time)
    create_dat_file_for_hash('graphs/hash/hash_cpu_time_botan.dat', 'SM3', 'SHA-256', botan_sm3_cpu_time, botan_sha_cpu_time)
    # CPU cycles graphs (openssl and botan)
    create_dat_file_for_hash('graphs/hash/hash_cpu_cycles_openssl.dat', 'SM3', 'SHA-256', sm3_cpu_cycles, sha_cpu_cycles)
    create_dat_file_for_hash('graphs/hash/hash_cpu_cycles_botan.dat', 'SM3', 'SHA-256', botan_sm3_cpu_cycles, botan_sha_cpu_cycles)

elif(sys.argv[1] == 'ds'):
    ############ GmSSL ############
    # Key generation, RSA: 10, SM2: 1000, ECDSA: 1000
    rsa_keygen_real_time, rsa_keygen_cpu_time, rsa_keygen_cpu_cycles = process_perf_stat_output("output/ds_perf/rsa_keygen_perf_o", 10)
    sm2_keygen_real_time, sm2_keygen_cpu_time, sm2_keygen_cpu_cycles = process_perf_stat_output("output/ds_perf/sm2_keygen_perf_o", 1000)
    ecdsa_keygen_real_time, ecdsa_keygen_cpu_time, ecdsa_keygen_cpu_cycles = process_perf_stat_output("output/ds_perf/ecdsa_keygen_perf_o", 1000)
    # Signing, RSA: 1000, SM2: 1000, ECDSA: 1000
    rsa_sign_real_time, rsa_sign_cpu_time, rsa_sign_cpu_cycles = process_perf_stat_output("output/ds_perf/rsa_sign_perf_o", 1000)
    sm2_sign_real_time, sm2_sign_cpu_time, sm2_sign_cpu_cycles = process_perf_stat_output("output/ds_perf/sm2_sign_perf_o", 1000)
    ecdsa_sign_real_time, ecdsa_sign_cpu_time, ecdsa_sign_cpu_cycles = process_perf_stat_output("output/ds_perf/ecdsa_sign_perf_o", 1000)
    # Verifying, RSA: 1000, SM2: 1000, ECDSA: 1000
    rsa_verify_real_time, rsa_verify_cpu_time, rsa_verify_cpu_cycles = process_perf_stat_output("output/ds_perf/rsa_verify_perf_o", 1000)
    sm2_verify_real_time, sm2_verify_cpu_time, sm2_verify_cpu_cycles = process_perf_stat_output("output/ds_perf/sm2_verify_perf_o", 1000)
    ecdsa_verify_real_time, ecdsa_verify_cpu_time, ecdsa_verify_cpu_cycles = process_perf_stat_output("output/ds_perf/ecdsa_verify_perf_o", 1000)

    print('\t\t\t\t\tMean\t\tMedian\t\tStd. Dev\t\tMin\t\tMax')
    #Keygen GmSSL
    ds_print_table_row('GmSSL', 'KeyGen', 'ECDSA', 'Real-time', ecdsa_keygen_real_time)
    ds_print_table_row('GmSSL', 'KeyGen', 'ECDSA', 'CPU time', ecdsa_keygen_cpu_time)
    ds_print_table_row('GmSSL', 'KeyGen', 'ECDSA', 'CPU cycles', ecdsa_keygen_cpu_cycles)

    ds_print_table_row('GmSSL', 'KeyGen', 'SM2', 'Real-time', sm2_keygen_real_time)
    ds_print_table_row('GmSSL', 'KeyGen', 'SM2', 'CPU time', sm2_keygen_cpu_time)
    ds_print_table_row('GmSSL', 'KeyGen', 'SM2', 'CPU cycles', sm2_keygen_cpu_cycles)

    ds_print_table_row('GmSSL', 'KeyGen', 'RSA', 'Real-time', rsa_keygen_real_time)
    ds_print_table_row('GmSSL', 'KeyGen', 'RSA', 'CPU time', rsa_keygen_cpu_time)
    ds_print_table_row('GmSSL', 'KeyGen', 'RSA', 'CPU cycles', rsa_keygen_cpu_cycles)
    #Sign GmSSL
    ds_print_table_row('GmSSL', 'Signing', 'ECDSA', 'Real-time', ecdsa_sign_real_time)
    ds_print_table_row('GmSSL', 'Signing', 'ECDSA', 'CPU time', ecdsa_sign_cpu_time)
    ds_print_table_row('GmSSL', 'Signing', 'ECDSA', 'CPU cycles', ecdsa_sign_cpu_cycles)

    ds_print_table_row('GmSSL', 'Signing', 'SM2', 'Real-time', sm2_sign_real_time)
    ds_print_table_row('GmSSL', 'Signing', 'SM2', 'CPU time', sm2_sign_cpu_time)
    ds_print_table_row('GmSSL', 'Signing', 'SM2', 'CPU cycles', sm2_sign_cpu_cycles)

    ds_print_table_row('GmSSL', 'Signing', 'RSA', 'Real-time', rsa_sign_real_time)
    ds_print_table_row('GmSSL', 'Signing', 'RSA', 'CPU time', rsa_sign_cpu_time)
    ds_print_table_row('GmSSL', 'Signing', 'RSA', 'CPU cycles', rsa_sign_cpu_cycles)
    #Verify GmSSL
    ds_print_table_row('GmSSL', 'Verify', 'ECDSA', 'Real-time', ecdsa_verify_real_time)
    ds_print_table_row('GmSSL', 'Verify', 'ECDSA', 'CPU time', ecdsa_verify_cpu_time)
    ds_print_table_row('GmSSL', 'Verify', 'ECDSA', 'CPU cycles', ecdsa_verify_cpu_cycles)

    ds_print_table_row('GmSSL', 'Verify', 'SM2', 'Real-time', sm2_verify_real_time)
    ds_print_table_row('GmSSL', 'Verify', 'SM2', 'CPU time', sm2_verify_cpu_time)
    ds_print_table_row('GmSSL', 'Verify', 'SM2', 'CPU cycles', sm2_verify_cpu_cycles)

    ds_print_table_row('GmSSL', 'Verify', 'RSA', 'Real-time', rsa_verify_real_time)
    ds_print_table_row('GmSSL', 'Verify', 'RSA', 'CPU time', rsa_verify_cpu_time)
    ds_print_table_row('GmSSL', 'Verify', 'RSA', 'CPU cycles', rsa_verify_cpu_cycles)

    print('\n')
    ############ Botan ############
    # Key generation, RSA: 10, SM2: 10000, ECDSA: 10000
    botan_rsa_keygen_real_time, botan_rsa_keygen_cpu_time, botan_rsa_keygen_cpu_cycles = process_perf_stat_output("output/ds_perf/rsa_keygen_perf", 10)
    botan_sm2_keygen_real_time, botan_sm2_keygen_cpu_time, botan_sm2_keygen_cpu_cycles = process_perf_stat_output("output/ds_perf/sm2_keygen_perf", 10000)
    botan_ecdsa_keygen_real_time, botan_ecdsa_keygen_cpu_time, botan_ecdsa_keygen_cpu_cycles = process_perf_stat_output("output/ds_perf/ecdsa_keygen_perf", 10000)
    # Signing, RSA: 1000, SM2: 10000, ECDSA: 10000
    botan_rsa_sign_real_time, botan_rsa_sign_cpu_time, botan_rsa_sign_cpu_cycles = process_perf_stat_output("output/ds_perf/rsa_sign_perf", 1000)
    botan_sm2_sign_real_time, botan_sm2_sign_cpu_time, botan_sm2_sign_cpu_cycles = process_perf_stat_output("output/ds_perf/sm2_sign_perf", 10000)
    botan_ecdsa_sign_real_time, botan_ecdsa_sign_cpu_time, botan_ecdsa_sign_cpu_cycles = process_perf_stat_output("output/ds_perf/ecdsa_sign_perf", 10000)
    #Verifying, RSA: 10000, SM2: 10000, ECDSA: 10000
    botan_rsa_verify_real_time, botan_rsa_verify_cpu_time, botan_rsa_verify_cpu_cycles = process_perf_stat_output("output/ds_perf/rsa_verify_perf", 10000)
    botan_sm2_verify_real_time, botan_sm2_verify_cpu_time, botan_sm2_verify_cpu_cycles = process_perf_stat_output("output/ds_perf/sm2_verify_perf", 10000)
    botan_ecdsa_verify_real_time, botan_ecdsa_verify_cpu_time, botan_ecdsa_verify_cpu_cycles = process_perf_stat_output("output/ds_perf/ecdsa_verify_perf", 10000)

    print('\t\t\t\t\tMean\t\tMedian\t\tStd. Dev\t\tMin\t\tMax')
    #Keygen GmSSL
    ds_print_table_row('Botan', 'KeyGen', 'ECDSA', 'Real-time', botan_ecdsa_keygen_real_time)
    ds_print_table_row('Botan', 'KeyGen', 'ECDSA', 'CPU time', botan_ecdsa_keygen_cpu_time)
    ds_print_table_row('Botan', 'KeyGen', 'ECDSA', 'CPU cycles', botan_ecdsa_keygen_cpu_cycles)

    ds_print_table_row('Botan', 'KeyGen', 'SM2', 'Real-time', botan_sm2_keygen_real_time)
    ds_print_table_row('Botan', 'KeyGen', 'SM2', 'CPU time', botan_sm2_keygen_cpu_time)
    ds_print_table_row('Botan', 'KeyGen', 'SM2', 'CPU cycles', botan_sm2_keygen_cpu_cycles)

    ds_print_table_row('Botan', 'KeyGen', 'RSA', 'Real-time', botan_rsa_keygen_real_time)
    ds_print_table_row('Botan', 'KeyGen', 'RSA', 'CPU time', botan_rsa_keygen_cpu_time)
    ds_print_table_row('Botan', 'KeyGen', 'RSA', 'CPU cycles', botan_rsa_keygen_cpu_cycles)
    #Sign GmSSL
    ds_print_table_row('Botan', 'Signing', 'ECDSA', 'Real-time', botan_ecdsa_sign_real_time)
    ds_print_table_row('Botan', 'Signing', 'ECDSA', 'CPU time', botan_ecdsa_sign_cpu_time)
    ds_print_table_row('Botan', 'Signing', 'ECDSA', 'CPU cycles', botan_ecdsa_sign_cpu_cycles)

    ds_print_table_row('Botan', 'Signing', 'SM2', 'Real-time', botan_sm2_sign_real_time)
    ds_print_table_row('Botan', 'Signing', 'SM2', 'CPU time', botan_sm2_sign_cpu_time)
    ds_print_table_row('Botan', 'Signing', 'SM2', 'CPU cycles', botan_sm2_sign_cpu_cycles)

    ds_print_table_row('Botan', 'Signing', 'RSA', 'Real-time', botan_rsa_sign_real_time)
    ds_print_table_row('Botan', 'Signing', 'RSA', 'CPU time', botan_rsa_sign_cpu_time)
    ds_print_table_row('Botan', 'Signing', 'RSA', 'CPU cycles', botan_rsa_sign_cpu_cycles)
    #Verify GmSSL
    ds_print_table_row('Botan', 'Verify', 'ECDSA', 'Real-time', botan_ecdsa_verify_real_time)
    ds_print_table_row('Botan', 'Verify', 'ECDSA', 'CPU time', botan_ecdsa_verify_cpu_time)
    ds_print_table_row('Botan', 'Verify', 'ECDSA', 'CPU cycles', botan_ecdsa_verify_cpu_cycles)

    ds_print_table_row('Botan', 'Verify', 'SM2', 'Real-time', botan_sm2_verify_real_time)
    ds_print_table_row('Botan', 'Verify', 'SM2', 'CPU time', botan_sm2_verify_cpu_time)
    ds_print_table_row('Botan', 'Verify', 'SM2', 'CPU cycles', botan_sm2_verify_cpu_cycles)

    ds_print_table_row('Botan', 'Verify', 'RSA', 'Real-time', botan_rsa_verify_real_time)
    ds_print_table_row('Botan', 'Verify', 'RSA', 'CPU time', botan_rsa_verify_cpu_time)
    ds_print_table_row('Botan', 'Verify', 'RSA', 'CPU cycles', botan_rsa_verify_cpu_cycles)

    print('\n')

    ###### Real time graphs ######
    create_dat_file_for_ds("graphs/ds/ds_real_time_botan.dat",\
                            botan_ecdsa_keygen_real_time, botan_ecdsa_sign_real_time, botan_ecdsa_verify_real_time,\
                            botan_sm2_keygen_real_time, botan_sm2_sign_real_time, botan_sm2_verify_real_time,\
                            botan_rsa_keygen_real_time, botan_rsa_sign_real_time, botan_rsa_verify_real_time)
    create_dat_file_for_ds("graphs/ds/ds_real_time_gmssl.dat",\
                            ecdsa_keygen_real_time, ecdsa_sign_real_time, ecdsa_verify_real_time,\
                            sm2_keygen_real_time, sm2_sign_real_time, sm2_verify_real_time,\
                            rsa_keygen_real_time, rsa_sign_real_time, rsa_verify_real_time)
    ###### CPU time graph ######
    create_dat_file_for_ds("graphs/ds/ds_cpu_time_botan.dat",\
                            botan_ecdsa_keygen_cpu_time, botan_ecdsa_sign_cpu_time, botan_ecdsa_verify_cpu_time,\
                            botan_sm2_keygen_cpu_time, botan_sm2_sign_cpu_time, botan_sm2_verify_cpu_time,\
                            botan_rsa_keygen_cpu_time, botan_rsa_sign_cpu_time, botan_rsa_verify_cpu_time)
    create_dat_file_for_ds("graphs/ds/ds_cpu_time_gmssl.dat",\
                            ecdsa_keygen_cpu_time, ecdsa_sign_cpu_time, ecdsa_verify_cpu_time,\
                            sm2_keygen_cpu_time, sm2_sign_cpu_time, sm2_verify_cpu_time,\
                            rsa_keygen_cpu_time, rsa_sign_cpu_time, rsa_verify_cpu_time)
    ###### CPU cycles graph ######
    create_dat_file_for_ds("graphs/ds/ds_cpu_cycles_botan.dat",\
                            botan_ecdsa_keygen_cpu_cycles, botan_ecdsa_sign_cpu_cycles, botan_ecdsa_verify_cpu_cycles,\
                            botan_sm2_keygen_cpu_cycles, botan_sm2_sign_cpu_cycles, botan_sm2_verify_cpu_cycles,\
                            botan_rsa_keygen_cpu_cycles, botan_rsa_sign_cpu_cycles, botan_rsa_verify_cpu_cycles)
    create_dat_file_for_ds("graphs/ds/ds_cpu_cycles_gmssl.dat",\
                            ecdsa_keygen_cpu_cycles, ecdsa_sign_cpu_cycles, ecdsa_verify_cpu_cycles,\
                            sm2_keygen_cpu_cycles, sm2_sign_cpu_cycles, sm2_verify_cpu_cycles,\
                            rsa_keygen_cpu_cycles, rsa_sign_cpu_cycles, rsa_verify_cpu_cycles)

elif (sys.argv[1] == 'block'):
    ###### OpenSSL Encryption ######
    # ECB mode
    ecb_aes_ni_real_time, ecb_aes_ni_cpu_time, ecb_aes_ni_cpu_cycles = process_perf_stat_output("output/block_perf/openssl/aes_ni_ecb")
    ecb_aes_real_time, ecb_aes_cpu_time, ecb_aes_cpu_cycles = process_perf_stat_output("output/block_perf/openssl/aes_ecb")
    ecb_sm4_real_time, ecb_sm4_cpu_time, ecb_sm4_cpu_cycles = process_perf_stat_output("output/block_perf/openssl/sm4_ecb")

    # CBC mode
    cbc_aes_ni_real_time, cbc_aes_ni_cpu_time, cbc_aes_ni_cpu_cycles = process_perf_stat_output("output/block_perf/openssl/aes_ni_cbc")
    cbc_aes_real_time, cbc_aes_cpu_time, cbc_aes_cpu_cycles = process_perf_stat_output("output/block_perf/openssl/aes_cbc")
    cbc_sm4_real_time, cbc_sm4_cpu_time, cbc_sm4_cpu_cycles = process_perf_stat_output("output/block_perf/openssl/sm4_cbc")

    # CTR mode
    ctr_aes_ni_real_time, ctr_aes_ni_cpu_time, ctr_aes_ni_cpu_cycles = process_perf_stat_output("output/block_perf/openssl/aes_ni_ctr")
    ctr_aes_real_time, ctr_aes_cpu_time, ctr_aes_cpu_cycles = process_perf_stat_output("output/block_perf/openssl/aes_ctr")
    ctr_sm4_real_time, ctr_sm4_cpu_time, ctr_sm4_cpu_cycles = process_perf_stat_output("output/block_perf/openssl/sm4_ctr")

    ###### OpenSSL Decryption ######
    # ECB mode
    dec_ecb_aes_ni_real_time, dec_ecb_aes_ni_cpu_time, dec_ecb_aes_ni_cpu_cycles = process_perf_stat_output("output/block_perf/openssl/aes_ni_ecb_decrypt")
    dec_ecb_aes_real_time, dec_ecb_aes_cpu_time, dec_ecb_aes_cpu_cycles = process_perf_stat_output("output/block_perf/openssl/aes_ecb_decrypt")
    dec_ecb_sm4_real_time, dec_ecb_sm4_cpu_time, dec_ecb_sm4_cpu_cycles = process_perf_stat_output("output/block_perf/openssl/sm4_ecb_decrypt")

    # CBC mode
    dec_cbc_aes_ni_real_time, dec_cbc_aes_ni_cpu_time, dec_cbc_aes_ni_cpu_cycles = process_perf_stat_output("output/block_perf/openssl/aes_ni_cbc_decrypt")
    dec_cbc_aes_real_time, dec_cbc_aes_cpu_time, dec_cbc_aes_cpu_cycles = process_perf_stat_output("output/block_perf/openssl/aes_cbc_decrypt")
    dec_cbc_sm4_real_time, dec_cbc_sm4_cpu_time, dec_cbc_sm4_cpu_cycles = process_perf_stat_output("output/block_perf/openssl/sm4_cbc_decrypt")

    # CTR mode
    dec_ctr_aes_ni_real_time, dec_ctr_aes_ni_cpu_time, dec_ctr_aes_ni_cpu_cycles = process_perf_stat_output("output/block_perf/openssl/aes_ni_ctr_decrypt")
    dec_ctr_aes_real_time, dec_ctr_aes_cpu_time, dec_ctr_aes_cpu_cycles = process_perf_stat_output("output/block_perf/openssl/aes_ctr_decrypt")
    dec_ctr_sm4_real_time, dec_ctr_sm4_cpu_time, dec_ctr_sm4_cpu_cycles = process_perf_stat_output("output/block_perf/openssl/sm4_ctr_decrypt")

    create_dat_file_for_block("graphs/block/openssl/openssl_real_time.dat",\
                              ecb_aes_ni_real_time, ecb_aes_real_time, ecb_sm4_real_time,\
                              cbc_aes_ni_real_time, cbc_aes_real_time, cbc_sm4_real_time,\
                              ctr_aes_ni_real_time, ctr_aes_real_time, ctr_sm4_real_time,
                              dec_ecb_aes_ni_real_time, dec_ecb_aes_real_time, dec_ecb_sm4_real_time,\
                              dec_cbc_aes_ni_real_time, dec_cbc_aes_real_time, dec_cbc_sm4_real_time,\
                              dec_ctr_aes_ni_real_time, dec_ctr_aes_real_time, dec_ctr_sm4_real_time)

    create_dat_file_for_block("graphs/block/openssl/openssl_cpu_time.dat",\
                              ecb_aes_ni_cpu_time, ecb_aes_cpu_time, ecb_sm4_cpu_time,\
                              cbc_aes_ni_cpu_time, cbc_aes_cpu_time, cbc_sm4_cpu_time,\
                              ctr_aes_ni_cpu_time, ctr_aes_cpu_time, ctr_sm4_cpu_time,
                              dec_ecb_aes_ni_cpu_time, dec_ecb_aes_cpu_time, dec_ecb_sm4_cpu_time,\
                              dec_cbc_aes_ni_cpu_time, dec_cbc_aes_cpu_time, dec_cbc_sm4_cpu_time,\
                              dec_ctr_aes_ni_cpu_time, dec_ctr_aes_cpu_time, dec_ctr_sm4_cpu_time)

    create_dat_file_for_block("graphs/block/openssl/openssl_cpu_cycles.dat",\
                              ecb_aes_ni_cpu_cycles, ecb_aes_cpu_cycles, ecb_sm4_cpu_cycles,\
                              cbc_aes_ni_cpu_cycles, cbc_aes_cpu_cycles, cbc_sm4_cpu_cycles,\
                              ctr_aes_ni_cpu_cycles, ctr_aes_cpu_cycles, ctr_sm4_cpu_cycles,
                              dec_ecb_aes_ni_cpu_cycles, dec_ecb_aes_cpu_cycles, dec_ecb_sm4_cpu_cycles,\
                              dec_cbc_aes_ni_cpu_cycles, dec_cbc_aes_cpu_cycles, dec_cbc_sm4_cpu_cycles,\
                              dec_ctr_aes_ni_cpu_cycles, dec_ctr_aes_cpu_cycles, dec_ctr_sm4_cpu_cycles)
    ###### Botan Encryption ######
    # ECB mode
    ecb_botan_aes_ni_real_time, ecb_botan_aes_ni_cpu_time, ecb_botan_aes_ni_cpu_cycles = process_perf_stat_output("output/block_perf/botan/botan_aes_ni_ecb")
    ecb_botan_aes_real_time, ecb_botan_aes_cpu_time, ecb_botan_aes_cpu_cycles = process_perf_stat_output("output/block_perf/botan/botan_aes_ecb")
    ecb_botan_sm4_real_time, ecb_botan_sm4_cpu_time, ecb_botan_sm4_cpu_cycles = process_perf_stat_output("output/block_perf/botan/botan_sm4_ecb")

    # CBC mode
    cbc_botan_aes_ni_real_time, cbc_botan_aes_ni_cpu_time, cbc_botan_aes_ni_cpu_cycles = process_perf_stat_output("output/block_perf/botan/botan_aes_ni_cbc")
    cbc_botan_aes_real_time, cbc_botan_aes_cpu_time, cbc_botan_aes_cpu_cycles = process_perf_stat_output("output/block_perf/botan/botan_aes_cbc")
    cbc_botan_sm4_real_time, cbc_botan_sm4_cpu_time, cbc_botan_sm4_cpu_cycles = process_perf_stat_output("output/block_perf/botan/botan_sm4_cbc")

    # CTR mode
    ctr_botan_aes_ni_real_time, ctr_botan_aes_ni_cpu_time, ctr_botan_aes_ni_cpu_cycles = process_perf_stat_output("output/block_perf/botan/botan_aes_ni_ctr")
    ctr_botan_aes_real_time, ctr_botan_aes_cpu_time, ctr_botan_aes_cpu_cycles = process_perf_stat_output("output/block_perf/botan/botan_aes_ctr")
    ctr_botan_sm4_real_time, ctr_botan_sm4_cpu_time, ctr_botan_sm4_cpu_cycles = process_perf_stat_output("output/block_perf/botan/botan_sm4_ctr")

    ###### Botan Decryption ######
    # ECB mode
    dec_ecb_botan_aes_ni_real_time, dec_ecb_botan_aes_ni_cpu_time, dec_ecb_botan_aes_ni_cpu_cycles = process_perf_stat_output("output/block_perf/botan/botan_aes_ni_ecb_decrypt")
    dec_ecb_botan_aes_real_time, dec_ecb_botan_aes_cpu_time, dec_ecb_botan_aes_cpu_cycles = process_perf_stat_output("output/block_perf/botan/botan_aes_ecb_decrypt")
    dec_ecb_botan_sm4_real_time, dec_ecb_botan_sm4_cpu_time, dec_ecb_botan_sm4_cpu_cycles = process_perf_stat_output("output/block_perf/botan/botan_sm4_ecb_decrypt")

    # CBC mode
    dec_cbc_botan_aes_ni_real_time, dec_cbc_botan_aes_ni_cpu_time, dec_cbc_botan_aes_ni_cpu_cycles = process_perf_stat_output("output/block_perf/botan/botan_aes_ni_cbc_decrypt")
    dec_cbc_botan_aes_real_time, dec_cbc_botan_aes_cpu_time, dec_cbc_botan_aes_cpu_cycles = process_perf_stat_output("output/block_perf/botan/botan_aes_cbc_decrypt")
    dec_cbc_botan_sm4_real_time, dec_cbc_botan_sm4_cpu_time, dec_cbc_botan_sm4_cpu_cycles = process_perf_stat_output("output/block_perf/botan/botan_sm4_cbc_decrypt")

    # CTR mode
    dec_ctr_botan_aes_ni_real_time, dec_ctr_botan_aes_ni_cpu_time, dec_ctr_botan_aes_ni_cpu_cycles = process_perf_stat_output("output/block_perf/botan/botan_aes_ni_ctr_decrypt")
    dec_ctr_botan_aes_real_time, dec_ctr_botan_aes_cpu_time, dec_ctr_botan_aes_cpu_cycles = process_perf_stat_output("output/block_perf/botan/botan_aes_ctr_decrypt")
    dec_ctr_botan_sm4_real_time, dec_ctr_botan_sm4_cpu_time, dec_ctr_botan_sm4_cpu_cycles = process_perf_stat_output("output/block_perf/botan/botan_sm4_ctr_decrypt")


    create_dat_file_for_block("graphs/block/botan/botan_real_time.dat",\
                              ecb_botan_aes_ni_real_time, ecb_botan_aes_real_time, ecb_botan_sm4_real_time,\
                              cbc_botan_aes_ni_real_time, cbc_botan_aes_real_time, cbc_botan_sm4_real_time,\
                              ctr_botan_aes_ni_real_time, ctr_botan_aes_real_time, ctr_botan_sm4_real_time,
                              dec_ecb_botan_aes_ni_real_time, dec_ecb_botan_aes_real_time, dec_ecb_botan_sm4_real_time,\
                              dec_cbc_botan_aes_ni_real_time, dec_cbc_botan_aes_real_time, dec_cbc_botan_sm4_real_time,\
                              dec_ctr_botan_aes_ni_real_time, dec_ctr_botan_aes_real_time, dec_ctr_botan_sm4_real_time)
    create_dat_file_for_block("graphs/block/botan/botan_cpu_time.dat",\
                              ecb_botan_aes_ni_cpu_time, ecb_botan_aes_cpu_time, ecb_botan_sm4_cpu_time,\
                              cbc_botan_aes_ni_cpu_time, cbc_botan_aes_cpu_time, cbc_botan_sm4_cpu_time,\
                              ctr_botan_aes_ni_cpu_time, ctr_botan_aes_cpu_time, ctr_botan_sm4_cpu_time,
                              dec_ecb_botan_aes_ni_cpu_time, dec_ecb_botan_aes_cpu_time, dec_ecb_botan_sm4_cpu_time,\
                              dec_cbc_botan_aes_ni_cpu_time, dec_cbc_botan_aes_cpu_time, dec_cbc_botan_sm4_cpu_time,\
                              dec_ctr_botan_aes_ni_cpu_time, dec_ctr_botan_aes_cpu_time, dec_ctr_botan_sm4_cpu_time)
    create_dat_file_for_block("graphs/block/botan/botan_cpu_cycles.dat",\
                              ecb_botan_aes_ni_cpu_cycles, ecb_botan_aes_cpu_cycles, ecb_botan_sm4_cpu_cycles,\
                              cbc_botan_aes_ni_cpu_cycles, cbc_botan_aes_cpu_cycles, cbc_botan_sm4_cpu_cycles,\
                              ctr_botan_aes_ni_cpu_cycles, ctr_botan_aes_cpu_cycles, ctr_botan_sm4_cpu_cycles,
                              dec_ecb_botan_aes_ni_cpu_cycles, dec_ecb_botan_aes_cpu_cycles, dec_ecb_botan_sm4_cpu_cycles,\
                              dec_cbc_botan_aes_ni_cpu_cycles, dec_cbc_botan_aes_cpu_cycles, dec_cbc_botan_sm4_cpu_cycles,\
                              dec_ctr_botan_aes_ni_cpu_cycles, dec_ctr_botan_aes_cpu_cycles, dec_ctr_botan_sm4_cpu_cycles)

else:
    print("No valid argument input")
