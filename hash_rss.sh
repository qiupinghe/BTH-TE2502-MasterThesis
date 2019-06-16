#!/bin/bash

repeat=0
interval=0
input=''
lib=''

print_usage() {
  printf "Usage: ./hash_rss -l openssl/botan -r 10 -i inputfile \
  -j 0.5\n"
}

while getopts 'l:r:i:j:' flag; do
  case "${flag}" in
    l) lib="${OPTARG}" ;;
    r) repeat="${OPTARG}" ;;
    i) input="${OPTARG}" ;;
    j) interval="${OPTARG}" ;;
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

if [ $repeat == 0 ] || [ $interval == 0 ]
then
  echo "Repeat and/or interval is not set."
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
    echo "Round: $i" >> output/hash/sha256_rss_o
    sudo chrt -f 99 nice -n -20 openssl dgst -sha256 $input &
    sleep 0.2
    sudo_pid="$(ps --ppid $! -o pid=)"
    pid="$(ps --ppid $sudo_pid -o pid=)"
    pid="$(echo $pid | xargs)"
    while ps -p $pid > 3
    do
      cat "/proc/$pid/status" | grep 'VmRSS\|VmHWM' >> output/hash/sha256_rss_o
      sleep $interval
    done
    wait $!

    echo "Round: $i" >> output/hash/sm3_rss_o
    sudo chrt -f 99 nice -n -20 openssl dgst -sm3 $input &
    sleep 0.2
    sudo_pid="$(ps --ppid $! -o pid=)"
    pid="$(ps --ppid $sudo_pid -o pid=)"
    pid="$(echo $pid | xargs)"
    while ps -p $pid > 3
    do
      cat "/proc/$pid/status" | grep 'VmRSS\|VmHWM' >> output/hash/sm3_rss_o
      sleep $interval
    done
    wait $!
    echo "------------------------"
  done
fi

if [ "$lib" == "botan" ]
then
  for (( i=1; i<=$repeat; i++ ))
  do
    echo "Round: $i"
    echo "Round: $i" >> output/hash/sha256_rss
    sudo chrt -f 99 nice -n -20 ./botan/sha256 $input &
    sleep 0.2
    sudo_pid="$(ps --ppid $! -o pid=)"
    pid="$(ps --ppid $sudo_pid -o pid=)"
    pid="$(echo $pid | xargs)"
    while ps -p $pid > 3
    do
      cat "/proc/$pid/status" | grep 'VmRSS\|VmHWM' >> output/hash/sha256_rss
      sleep $interval
    done
    wait $!

    echo "Round: $i" >> output/hash/sm3_rss
    sudo chrt -f 99 nice -n -20 ./botan/sm3 $input &
    sleep 0.2
    sudo_pid="$(ps --ppid $! -o pid=)"
    pid="$(ps --ppid $sudo_pid -o pid=)"
    pid="$(echo $pid | xargs)"
    while ps -p $pid > 3
    do
      cat "/proc/$pid/status" | grep 'VmRSS\|VmHWM' >> output/hash/sm3_rss
      sleep $interval
    done
    wait $!
    echo "------------------------"
  done
fi
