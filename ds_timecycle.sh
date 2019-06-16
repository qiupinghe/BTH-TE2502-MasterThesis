#!/bin/bash

repeat=0
lib=''
type=''

print_usage() {
  printf "Usage: ./ds_timecycle.sh -l <openssl/botan> -r 10 -t <key/sign/verify>"
}

while getopts 'l:r:t:' flag; do
  case "${flag}" in
    l) lib="${OPTARG}" ;;
    r) repeat="${OPTARG}" ;;
    t) type="${OPTARG}" ;;
    *) print_usage
       exit 1 ;;
  esac
done

# -z checks whether the string is null
if  [ -z "$lib" ] || [ -z "$type" ]
then
  echo "One or more flags are missing."
  print_usage
  exit 1
fi

if [ "$lib" != "botan" ] && [ "$lib" != "gmssl" ]
then
  echo "Not a valid library."
  print_usage
  exit 1
fi

if [ "$type" != "key" ] && [ "$type" != "sign" ] && [ "$type" != "verify" ]
then
  echo "Not a valid type. Choose 'key', 'sign', or 'verify'."
  print_usage
  exit 1
fi

if [ $repeat == 0 ]
then
  echo "Repeat is not set."
  print_usage
  exit 1
fi

if [ "$lib" == "gmssl" ]; then
  if [ "$type" == "key" ]; then
    printf "************************************************\n"
    printf "Generating ECDSA, RSA, and SM2 key pairs $repeat times using $lib.\n"
    printf "************************************************\n"
    for (( i=1; i<=$repeat; i++ ))
    do
      echo  -n "Round: $i , Date: "
      date
      #RSA
      sudo chrt -f 99 nice -n -20 perf stat -o output/ds_perf/rsa_keygen_perf_o --append -e cpu-clock,cycles \
      bash -c "for i in {1..10}; do gmssl genrsa -out private.key 3072 &>/dev/null && gmssl rsa -in private.key -pubout -out public.key &>/dev/null; done"
      #SM2
      sudo chrt -f 99 nice -n -20 perf stat -o output/ds_perf/sm2_keygen_perf_o --append -e cpu-clock,cycles \
      bash -c "for i in {1..1000}; do gmssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:sm2p256v1 -out private.key && gmssl pkey -pubout -in private.key -out public.key; done"
      #ECDSA
      sudo chrt -f 99 nice -n -20 perf stat -o output/ds_perf/ecdsa_keygen_perf_o --append -e cpu-clock,cycles \
      bash -c "for i in {1..1000}; do gmssl ecparam -genkey -name prime256v1 -out private.key && gmssl ec -in private.key -pubout -out public.key &>/dev/null; done"
      echo "------------------------"
    done
  elif [ "$type" == "sign" ]; then
    printf "************************************************\n"
    printf "Signing with ECDSA, RSA, and SM2 $repeat times using $lib.\n"
    printf "************************************************\n"
    for (( i=1; i<=$repeat; i++ ))
    do
      echo  -n "Round: $i , Date: "
      date
      #RSA
      sudo chrt -f 99 nice -n -20 perf stat -o output/ds_perf/rsa_sign_perf_o --append -e cpu-clock,cycles \
      bash -c "for i in {1..1000}; do gmssl pkeyutl -sign -in gmssl_setup/rsa/file -inkey gmssl_setup/rsa/private.key -out signature.sig; done"
      #SM2
      sudo chrt -f 99 nice -n -20 perf stat -o output/ds_perf/sm2_sign_perf_o --append -e cpu-clock,cycles \
      bash -c "for i in {1..1000}; do gmssl pkeyutl -sign -pkeyopt ec_scheme:sm2 -inkey gmssl_setup/sm2/private.key -in gmssl_setup/sm2/file -out signature.sig; done"
      #ECDSA
      sudo chrt -f 99 nice -n -20 perf stat -o output/ds_perf/ecdsa_sign_perf_o --append -e cpu-clock,cycles \
      bash -c "for i in {1..1000}; do gmssl pkeyutl -sign -in gmssl_setup/ecdsa/file -inkey gmssl_setup/ecdsa/private.key -out signature.sig; done"
      echo "------------------------"
    done
  elif [ "$type" == "verify" ]; then
    printf "************************************************\n"
    printf "Verifying with ECDSA, RSA, and SM2 $repeat times using $lib.\n"
    printf "************************************************\n"
    for (( i=1; i<=$repeat; i++ ))
    do
      echo  -n "Round: $i , Date: "
      date
      #RSA
      sudo chrt -f 99 nice -n -20 perf stat -o output/ds_perf/rsa_verify_perf_o --append -e cpu-clock,cycles \
      bash -c "for i in {1..1000}; do gmssl pkeyutl -verifyrecover -pubin -in gmssl_setup/rsa/signature.sig -inkey gmssl_setup/rsa/public.key &>/dev/null; done "
      #SM2
      sudo chrt -f 99 nice -n -20 perf stat -o output/ds_perf/sm2_verify_perf_o --append -e cpu-clock,cycles \
      bash -c "for i in {1..1000}; do gmssl pkeyutl -verify -pubin -pkeyopt ec_scheme:sm2 -inkey gmssl_setup/sm2/public.key -in gmssl_setup/sm2/file -sigfile gmssl_setup/sm2/signature.sig &>/dev/null; done"
      #ECDSA
      sudo chrt -f 99 nice -n -20 perf stat -o output/ds_perf/ecdsa_verify_perf_o --append -e cpu-clock,cycles \
      bash -c "for i in {1..1000}; do gmssl pkeyutl -verify -pubin  -inkey gmssl_setup/ecdsa/public.key -in gmssl_setup/ecdsa/file -sigfile gmssl_setup/ecdsa/signature.sig &>/dev/null; done"
      echo "------------------------"
    done
  fi
fi

if [ "$lib" == "botan" ]; then
  if [ "$type" == "key" ]; then
    printf "************************************************\n"
    printf "Generating ECDSA, RSA, and SM2 key pairs $repeat times using $lib.\n"
    printf "************************************************\n"
    for (( i=1; i<=$repeat; i++ ))
    do
      echo  -n "Round: $i , Date: "
      date
      sudo chrt -f 99 nice -n -20 perf stat -o output/ds_perf/rsa_keygen_perf --append -e \
      cpu-clock,cycles ./botan/rsa_keygen 10
      sudo chrt -f 99 nice -n -20 perf stat -o output/ds_perf/sm2_keygen_perf --append -e \
      cpu-clock,cycles ./botan/sm2_keygen 10000
      sudo chrt -f 99 nice -n -20 perf stat -o output/ds_perf/ecdsa_keygen_perf --append -e \
      cpu-clock,cycles ./botan/ecdsa_keygen 10000
      echo "------------------------"
    done
  elif [ "$type" == "sign" ]; then
    printf "************************************************\n"
    printf "Signing with ECDSA, RSA, and SM2 $repeat times using $lib.\n"
    printf "************************************************\n"
    for (( i=1; i<=$repeat; i++ ))
    do
      echo  -n "Round: $i , Date: "
      date
      sudo chrt -f 99 nice -n -20 perf stat -o output/ds_perf/rsa_sign_perf --append -e \
      cpu-clock,cycles ./botan/rsa_sign "botan/Generate_testfile/rsa/private.key" 1000
      sudo chrt -f 99 nice -n -20 perf stat -o output/ds_perf/sm2_sign_perf --append -e \
      cpu-clock,cycles ./botan/sm2_sign "botan/Generate_testfile/sm2/private.key" 10000
      sudo chrt -f 99 nice -n -20 perf stat -o output/ds_perf/ecdsa_sign_perf --append -e \
      cpu-clock,cycles ./botan/ecdsa_sign "botan/Generate_testfile/ecdsa/private.key" 10000
      echo "------------------------"
    done
  elif [ "$type" == "verify" ]; then
    printf "************************************************\n"
    printf "Verifying with ECDSA, RSA, and SM2 $repeat times using $lib.\n"
    printf "************************************************\n"
    for (( i=1; i<=$repeat; i++ ))
    do
      echo  -n "Round: $i , Date: "
      date
      sudo chrt -f 99 nice -n -20 perf stat -o output/ds_perf/rsa_verify_perf --append -e \
      cpu-clock,cycles ./botan/rsa_verify "botan/Generate_testfile/rsa/public.key" "botan/Generate_testfile/rsa/signature.sig" 10000
      sudo chrt -f 99 nice -n -20 perf stat -o output/ds_perf/sm2_verify_perf --append -e \
      cpu-clock,cycles ./botan/sm2_verify "botan/Generate_testfile/sm2/public.key" "botan/Generate_testfile/sm2/signature.sig" 10000
      sudo chrt -f 99 nice -n -20 perf stat -o output/ds_perf/ecdsa_verify_perf --append -e \
      cpu-clock,cycles ./botan/ecdsa_verify "botan/Generate_testfile/ecdsa/public.key" "botan/Generate_testfile/ecdsa/signature.sig" 10000
      echo "------------------------"
    done
  fi
fi
