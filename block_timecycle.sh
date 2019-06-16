#!/bin/bash

type=''
mode=''
repeat=0
input=''
output=''
decrypt=''
lib=''
print_text=''

print_usage() {
  printf "Usage: ./block_timecycle -l <lib> -t <e/d> -m ecb -r 10 -i inputfile -o outputfile\n"
}

while getopts 'l:t:m:r:i:o:' flag; do
  case "${flag}" in
    l) lib="${OPTARG}" ;;
    t) type="${OPTARG}" ;;
    m) mode="${OPTARG}" ;;
    r) repeat="${OPTARG}" ;;
    i) input="${OPTARG}" ;;
    o) output="${OPTARG}" ;;
    *) print_usage
       exit 1 ;;
  esac
done

# -z checks whether the string is null
if [ -z "$type" ] || [ -z "$mode" ] || [ -z "$output" ] || [ -z $repeat ]
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

if [ $type == "d" ]; then
  print_text="Decrypting"
else
  print_text="Encrypting"
fi

printf "***********************************************************************\n"
printf "$print_text $input $repeat times with AES-128-NI, AES-128 and SM4 using $lib.\n"
printf "***********************************************************************\n"

if [ "$lib" == "openssl" ]
then
  for i in $(seq 1 $repeat)
  do
    echo "Round: $i"
    # Check if type is encrypt or decrypt
    if [ $type = "d" ]
    then
      decrypt='-d'
      sudo chrt -f 99 nice -n -20 perf stat -o output/block_perf/openssl/aes_ni_${mode}_decrypt --append -e cpu-clock,cycles \
      bash -c "openssl enc -aes-128-$mode $decrypt -in trash/aes-ni-${mode}_enc -out $output -pass pass:pineapple -pbkdf2 -nosalt"

      sudo chrt -f 99 nice -n -20 perf stat -o output/block_perf/openssl/aes_${mode}_decrypt --append -e cpu-clock,cycles \
      bash -c "OPENSSL_ia32cap='~0x200000200000000' openssl enc -aes-128-$mode $decrypt -in trash/aes-${mode}_enc -out $output -pass pass:pineapple -pbkdf2 -nosalt"

      sudo chrt -f 99 nice -n -20 perf stat -o output/block_perf/openssl/sm4_${mode}_decrypt --append -e cpu-clock,cycles \
      bash -c "openssl enc -sm4-$mode $decrypt -in trash/sm4-${mode}_enc -out $output -pass pass:pineapple -pbkdf2 -nosalt"
    else
      sudo chrt -f 99 nice -n -20 perf stat -o output/block_perf/openssl/aes_ni_$mode --append -e cpu-clock,cycles \
      bash -c "openssl enc -aes-128-$mode -in $input -out trash/aes-ni-${mode}_enc -pass pass:pineapple -pbkdf2 -nosalt"

      sudo chrt -f 99 nice -n -20 perf stat -o output/block_perf/openssl/aes_$mode --append -e cpu-clock,cycles \
      bash -c "OPENSSL_ia32cap='~0x200000200000000' openssl enc -aes-128-${mode} -in $input -out trash/aes-${mode}_enc -pass pass:pineapple -pbkdf2 -nosalt"

      sudo chrt -f 99 nice -n -20 perf stat -o output/block_perf/openssl/sm4_$mode --append -e cpu-clock,cycles \
      bash -c "openssl enc -sm4-$mode -in $input -out trash/sm4-${mode}_enc -pass pass:pineapple -pbkdf2 -nosalt"
    fi
  done
fi

if [ "$lib" == "botan" ]
then
  for i in $(seq 1 $repeat)
  do
    echo "Round: $i"
    if [ $type = "d" ]
    then
        if [ "$mode" == "ecb" ]
        then
        sudo chrt -f 99 nice -n -20 perf stat -o output/block_perf/botan/botan_aes_ni_${mode}_decrypt --append -e cpu-clock,cycles ./botan/aes_${mode}_dec.o ${mode}_enc.bin
        sudo chrt -f 99 nice -n -20 perf stat -o output/block_perf/botan/botan_sm4_${mode}_decrypt --append -e cpu-clock,cycles ./botan/sm4_${mode}_dec.o sm4_${mode}_enc.bin
        else
        sudo chrt -f 99 nice -n -20 perf stat -o output/block_perf/botan/botan_aes_ni_${mode}_decrypt --append -e cpu-clock,cycles ./botan/aes_${mode}_dec.o botan/Generate_testfile/${mode}_iv ${mode}_enc.bin
        sudo chrt -f 99 nice -n -20 perf stat -o output/block_perf/botan/botan_sm4_${mode}_decrypt --append -e cpu-clock,cycles ./botan/sm4_${mode}_dec.o botan/Generate_testfile/sm4_${mode}_iv sm4_${mode}_enc.bin
        fi
      fi

    if [ $type = "e" ]
    then
      if [ "$mode" == "ecb" ]
      then
        sudo chrt -f 99 nice -n -20 perf stat -o output/block_perf/botan/botan_aes_ni_$mode --append -e cpu-clock,cycles ./botan/aes_${mode}_enc.o $input
        sudo chrt -f 99 nice -n -20 perf stat -o output/block_perf/botan/botan_sm4_$mode --append -e cpu-clock,cycles ./botan/sm4_${mode}_enc.o $input
      else
      sudo chrt -f 99 nice -n -20 perf stat -o output/block_perf/botan/botan_aes_ni_$mode --append -e cpu-clock,cycles ./botan/aes_${mode}_enc.o botan/Generate_testfile/${mode}_iv $input
      sudo chrt -f 99 nice -n -20 perf stat -o output/block_perf/botan/botan_sm4_$mode --append -e cpu-clock,cycles ./botan/sm4_${mode}_enc.o botan/Generate_testfile/sm4_${mode}_iv $input
      fi
    fi
  done
fi
