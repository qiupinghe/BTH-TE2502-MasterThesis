#!/bin/bash

repeat=0
input=''
lib=''

print_usage() {
  printf "Usage: ./hash_timecycle -l openssl/botan -r 10 -i inputfile \n"
}

while getopts 'l:r:i:o:' flag; do
  case "${flag}" in
    l) lib="${OPTARG}" ;;
    r) repeat="${OPTARG}" ;;
    i) input="${OPTARG}" ;;
    *) print_usage
       exit 1 ;;
  esac
done

# -z checks whether the string is null
if  [ -z "$lib" ] || [ -z "$input" ]
then
  echo "One or more flags are missing."
  print_usage
  exit 1
fi

if [ "$lib" != "botan" ] && [ "$lib" != "openssl" ]
then
  echo "Not a valid library."
  print_usage
  exit 1
fi

if [ $repeat == 0 ]
then
  echo "Repeat is not set."
  print_usage
  exit 1
fi

printf "************************************************\n"
printf "Hashing file $input $repeat times with SHA256 and SM3 using $lib.\n"
printf "************************************************\n"
if [ "$lib" == "openssl" ]
then
  for (( i=1; i<=$repeat; i++ ))
  do
    echo "Round: $i"
    sudo chrt -f 99 nice -n -20 perf stat -o output/hash/sha256_perf_o --append -e \
    cpu-clock,cycles openssl dgst -sha256 $input
    sudo chrt -f 99 nice -n -20 perf stat -o output/hash/sm3_perf_o --append -e \
    cpu-clock,cycles openssl dgst -sm3 $input
    echo "------------------------"
  done
fi

if [ "$lib" == "botan" ]
then
  for (( i=1; i<=$repeat; i++ ))
  do
    echo "Round: $i"
    sudo chrt -f 99 nice -n -20 perf stat -o output/hash/sha256_perf --append -e \
    cpu-clock,cycles ./botan/sha256 $input
    sudo chrt -f 99 nice -n -20 perf stat -o output/hash/sm3_perf --append -e \
    cpu-clock,cycles ./botan/sm3 $input
    echo "------------------------"
  done
fi
