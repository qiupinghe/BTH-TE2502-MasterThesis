from scipy import mean, median, stats
import math
import sys
import numpy

def read_entries(file):
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
        return VmHWM, VmRSS

def confidence_interval(list, interval = 0.95):
    mean_val = mean(list)
    n = len(list)
    stdev = stats.tstd(list)
    z = stats.norm.ppf((interval + 1)/2)
    #z = stats.t.ppf((interval + 1)/2, n)
    lower_bound = mean_val - z * stdev / math.sqrt(n)
    upper_bound = mean_val + z *stdev / math.sqrt(n)
    return lower_bound, upper_bound

def process_data(peakRSS, RSS):
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

def print_stats(dict):
    print("max_peak_rss", dict["max_peak_rss"])
    print("min_peak_rss", dict["min_peak_rss"])
    print("max_rss", dict["max_rss"])
    print("min_rss", dict["min_rss"])
    print("mean", dict["mean"])
    print("median", dict["median"])
    print("std_dev", dict["std_dev"])
    print("conf_low", dict["conf_low"])
    print("conf_high", dict["conf_high"])

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
            + file_path + ". Returning new dict. Setting data length to: " + str(len(rss_list[0:sample_size])))

            rss_values = {}
            rss_values["data"] = rss_list[0:sample_size]
            add_statistic_values(rss_values)
            return rss_values
        else:
            print("Peak RSS and RSS is not the same in all rounds.")
    else:
        print("Measurements are not the same in all rounds.")

def add_statistic_values(in_dict):
    data = in_dict["data"]
    in_dict["mean"] = mean(data)
    in_dict["median"] = median(data)
    in_dict["max"] = max(data)
    in_dict["min"] = min(data)
    in_dict["standard_dev"] = numpy.std(data)
    in_dict["std_low"] = mean(data) - numpy.std(data)
    in_dict["std_high"] = mean(data) + numpy.std(data)
    return in_dict

def check_differance_rss(data):
    for l in data:
        if(len(set(l)) != 1 ):
            #print("All elements are not the same")
            return False
    #print("All elements are equal")
    return True

def process_usrbintime_output(file_path, sample_size=100):
    maxRSS = list()
    with open(file_path, 'r') as f:
        for line in f:
            maxRSS.append(int(line))
    print("Found " + str(len(maxRSS)) + " outputs in " + file_path + ". Setting list length to " + str(len(maxRSS[0:sample_size])))
    rss_dict = {}
    rss_dict["data"] = maxRSS[0:sample_size]
    add_statistic_values(rss_dict)
    return rss_dict

def process_usrbintime_output_special(file_path, sample_size=100):
    maxRSS = list()
    with open(file_path, 'r') as f:
        for line in f:
            maxRSS.append(int(line))
    max_rss_combined = list()
    for i in range(0, len(maxRSS), 2):
        max_rss_combined.append((maxRSS[i]+maxRSS[i+1])/2)
    print("Found " + str(len(maxRSS)) + " outputs in " + file_path + \
    ". Combining outputs into list of length " + str(len(max_rss_combined)) + ". Setting new length to " + str(len(max_rss_combined[0:sample_size])))
    rss_dict = {}
    rss_dict["data"] = max_rss_combined[0:sample_size]
    add_statistic_values(rss_dict)
    return rss_dict

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
def create_dat_file_for_block(file_path, enc_dict1, enc_dict2, enc_dict3,\
                              dec_dict1, dec_dict2, dec_dict3,\
):
    f = open(file_path, "w+")
    f.write("# avg,std,avg,std,avg,std\n")
    # Encryption
    s = ','.join(["Encryption", \
        str(enc_dict1["mean"]), str(enc_dict1["standard_dev"]),\
        str(enc_dict2["mean"]), str(enc_dict2["standard_dev"]),\
        str(enc_dict3["mean"]), str(enc_dict3["standard_dev"])])
    f.write(s + "\n")
    s = ','.join(["Decryption", \
        str(dec_dict1["mean"]), str(dec_dict1["standard_dev"]),\
        str(dec_dict2["mean"]), str(dec_dict2["standard_dev"]),\
        str(dec_dict3["mean"]), str(dec_dict3["standard_dev"])])
    f.write(s + "\n")
    f.close()


def ds_print_table_row(lib, op, alg, measurement,in_dict):
    print(' '.join([lib,op,alg,measurement]) + '\t' + str(in_dict["mean"]) +\
    '\t' + str(in_dict["median"]) + '\t' + str(in_dict["standard_dev"]) + '\t' + str(in_dict["min"])\
    + '\t' + str(in_dict["max"]))

if (len(sys.argv) < 2):
    print("No argument input")
    sys.exit()

if (sys.argv[1] == 'hash'):
    #OpenSSL
    RSS_sha = process_proc_status_output("output/hash/sha256_rss_o")
    RSS_sm3 = process_proc_status_output("output/hash/sm3_rss_o")

    print('\t\t\tMean\tMedian\tStd. Dev\t\tMin\tMax')
    ds_print_table_row('OpenSSL', 'Hashing', 'SM3', 'RSS', RSS_sm3)
    ds_print_table_row('OpenSSL', 'Hashing', 'SHA', 'RSS', RSS_sha)
    print('\n')

    #Botan
    RSS_sha_botan = process_proc_status_output("output/hash/sha256_rss")
    RSS_sm3_botan = process_proc_status_output("output/hash/sm3_rss")

    print('\t\t\tMean\tMedian\tStd. Dev\t\tMin\tMax')
    ds_print_table_row('Botan', 'Hashing', 'SM3', 'RSS', RSS_sm3_botan)
    ds_print_table_row('Botan', 'Hashing', 'SHA', 'RSS', RSS_sha_botan)
    print('\n')

    # RSS Graphs
    create_dat_file_for_hash('graphs/hash/hash_rss_openssl.dat', 'SM3', 'SHA-256', RSS_sm3, RSS_sha)
    create_dat_file_for_hash('graphs/hash/hash_rss_botan.dat', 'SM3', 'SHA-256', RSS_sm3_botan, RSS_sha_botan)
elif(sys.argv[1] == 'ds'):
    # GmSSL
    RSS_ecdsa_keygen_gmssl = process_usrbintime_output_special('output/ds_rss/rss_ecdsa_key_gmssl')
    RSS_sm2_keygen_gmssl = process_usrbintime_output_special('output/ds_rss/rss_sm2_key_gmssl')
    RSS_rsa_keygen_gmssl = process_usrbintime_output_special('output/ds_rss/rss_rsa_key_gmssl')
    RSS_ecdsa_sign_gmssl = process_usrbintime_output('output/ds_rss/rss_ecdsa_sign_gmssl')
    RSS_sm2_sign_gmssl = process_usrbintime_output('output/ds_rss/rss_sm2_sign_gmssl')
    RSS_rsa_sign_gmssl = process_usrbintime_output('output/ds_rss/rss_rsa_sign_gmssl')
    RSS_ecdsa_verify_gmssl = process_usrbintime_output('output/ds_rss/rss_ecdsa_verify_gmssl')
    RSS_sm2_verify_gmssl = process_usrbintime_output('output/ds_rss/rss_sm2_verify_gmssl')
    RSS_rsa_verify_gmssl = process_usrbintime_output('output/ds_rss/rss_rsa_verify_gmssl')
    create_dat_file_for_ds('graphs/ds/ds_rss_gmssl.dat',\
                            RSS_ecdsa_keygen_gmssl, RSS_ecdsa_sign_gmssl, RSS_ecdsa_verify_gmssl,\
                            RSS_sm2_keygen_gmssl, RSS_sm2_sign_gmssl, RSS_sm2_verify_gmssl,\
                            RSS_rsa_keygen_gmssl, RSS_rsa_sign_gmssl, RSS_rsa_verify_gmssl)

    print('\t\t\tMean\tMedian\tStd. Dev\t\tMin\tMax')
    #Keygen GmSSL
    ds_print_table_row('GmSSL', 'KeyGen', 'ECDSA', 'RSS', RSS_ecdsa_keygen_gmssl)
    ds_print_table_row('GmSSL', 'KeyGen', 'SM2', 'RSS', RSS_sm2_keygen_gmssl)
    ds_print_table_row('GmSSL', 'KeyGen', 'RSA', 'RSS', RSS_rsa_keygen_gmssl)
    #Sign GmSSL
    ds_print_table_row('GmSSL', 'Signing', 'ECDSA', 'RSS', RSS_ecdsa_sign_gmssl)
    ds_print_table_row('GmSSL', 'Signing', 'SM2', 'RSS', RSS_sm2_sign_gmssl)
    ds_print_table_row('GmSSL', 'Signing', 'RSA', 'RSS', RSS_rsa_sign_gmssl)
    #Verify GmSSL
    ds_print_table_row('GmSSL', 'Verify', 'ECDSA', 'RSS', RSS_ecdsa_verify_gmssl)
    ds_print_table_row('GmSSL', 'Verify', 'SM2', 'RSS', RSS_sm2_verify_gmssl)
    ds_print_table_row('GmSSL', 'Verify', 'RSA', 'RSS', RSS_rsa_verify_gmssl)
    print('\n')

    # Botan
    RSS_ecdsa_keygen_botan = process_usrbintime_output('output/ds_rss/rss_ecdsa_key_botan')
    RSS_sm2_keygen_botan = process_usrbintime_output('output/ds_rss/rss_sm2_key_botan')
    RSS_rsa_keygen_botan = process_usrbintime_output('output/ds_rss/rss_rsa_key_botan')
    RSS_ecdsa_sign_botan = process_usrbintime_output('output/ds_rss/rss_ecdsa_sign_botan')
    RSS_sm2_sign_botan = process_usrbintime_output('output/ds_rss/rss_sm2_sign_botan')
    RSS_rsa_sign_botan = process_usrbintime_output('output/ds_rss/rss_rsa_sign_botan')
    RSS_ecdsa_verify_botan = process_usrbintime_output('output/ds_rss/rss_ecdsa_verify_botan')
    RSS_sm2_verify_botan = process_usrbintime_output('output/ds_rss/rss_sm2_verify_botan')
    RSS_rsa_verify_botan = process_usrbintime_output('output/ds_rss/rss_rsa_verify_botan')
    create_dat_file_for_ds('graphs/ds/ds_rss_botan.dat',\
                            RSS_ecdsa_keygen_botan, RSS_ecdsa_sign_botan, RSS_ecdsa_verify_botan,\
                            RSS_sm2_keygen_botan, RSS_sm2_sign_botan, RSS_sm2_verify_botan,\
                            RSS_rsa_keygen_botan, RSS_rsa_sign_botan, RSS_rsa_verify_botan)

    print('\t\t\tMean\tMedian\tStd. Dev\t\tMin\tMax')
    #Keygen GmSSL
    ds_print_table_row('Botan', 'KeyGen', 'ECDSA', 'RSS', RSS_ecdsa_keygen_botan)
    ds_print_table_row('Botan', 'KeyGen', 'SM2', 'RSS', RSS_sm2_keygen_botan)
    ds_print_table_row('Botan', 'KeyGen', 'RSA', 'RSS', RSS_rsa_keygen_botan)
    #Sign GmSSL
    ds_print_table_row('Botan', 'Signing', 'ECDSA', 'RSS', RSS_ecdsa_sign_botan)
    ds_print_table_row('Botan', 'Signing', 'SM2', 'RSS', RSS_sm2_sign_botan)
    ds_print_table_row('Botan', 'Signing', 'RSA', 'RSS', RSS_rsa_sign_botan)
    #Verify GmSSL
    ds_print_table_row('Botan', 'Verify', 'ECDSA', 'RSS', RSS_ecdsa_verify_botan)
    ds_print_table_row('Botan', 'Verify', 'SM2', 'RSS', RSS_sm2_verify_botan)
    ds_print_table_row('Botan', 'Verify', 'RSA', 'RSS', RSS_rsa_verify_botan)
    print('\n')

elif (sys.argv[1] == 'block'):
    ###### OpenSSL Encryption ######
    RSS_aes_ni = process_proc_status_output("output/block_rss/openssl/openssl_aes_ni_rss", )
    RSS_aes = process_proc_status_output("output/block_rss/openssl/openssl_aes_rss")
    RSS_sm4 = process_proc_status_output("output/block_rss/openssl/openssl_sm4_rss")

    ###### OpenSSL Decryption ######
    dec_RSS_aes_ni = process_proc_status_output("output/block_rss/openssl/openssl_aes_ni_rss_decrypt")
    dec_RSS_aes = process_proc_status_output("output/block_rss/openssl/openssl_aes_rss_decrypt")
    dec_RSS_sm4 = process_proc_status_output("output/block_rss/openssl/openssl_sm4_rss_decrypt")

    create_dat_file_for_block("graphs/block/RSS/openssl_rss.dat",\
                              RSS_aes_ni, RSS_aes, RSS_sm4,\
                              dec_RSS_aes_ni, dec_RSS_aes, dec_RSS_sm4)

    ###### Botan Encryption ######
    botan_RSS_aes_ni = process_proc_status_output("output/block_rss/botan/botan_aes_ni_rss_encrypt", )
    botan_RSS_aes = process_proc_status_output("output/block_rss/botan/botan_aes_rss_encrypt")
    botan_RSS_sm4 = process_proc_status_output("output/block_rss/botan/botan_sm4_rss_encrypt")

    ###### Botan Decryption ######
    botan_dec_RSS_aes_ni = process_proc_status_output("output/block_rss/botan/botan_aes_ni_rss_decrypt")
    botan_dec_RSS_aes = process_proc_status_output("output/block_rss/botan/botan_aes_rss_decrypt")
    botan_dec_RSS_sm4 = process_proc_status_output("output/block_rss/botan/botan_sm4_rss_decrypt")

    create_dat_file_for_block("graphs/block/RSS/botan_rss.dat",\
                              botan_RSS_aes_ni, botan_RSS_aes, botan_RSS_sm4,\
                              botan_dec_RSS_aes_ni, botan_dec_RSS_aes, botan_dec_RSS_sm4)

else:
    print("No valid argument input")
