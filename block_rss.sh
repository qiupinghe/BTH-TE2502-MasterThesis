#!/bin/bash

repeat=0
interval=0
input=''
output=''
lib=''
type=''
print_text=''

print_usage() {
  printf "Usage: ./block_rss -l <openssl/botan> -t <e/d> -r 10 -i inputfile -o outputfile -j 0.5\n"
}

while getopts 'l:t:r:i:o:j:' flag; do
  case "${flag}" in
    l) lib="${OPTARG}" ;;
    t) type="${OPTARG}" ;;
    r) repeat="${OPTARG}" ;;
    i) input="${OPTARG}" ;;
    o) output="${OPTARG}" ;;
    j) interval="${OPTARG}" ;;
    *) print_usage
       exit 1 ;;
  esac
done

# -z checks whether the string is null
if  [ -z "$lib" ] | [ -z "$type" ] || [ -z "$input" ] || [ -z "$output" ] || [ "$interval" == "0" ] || [ "$repeat" == "0" ]
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

if [ "$lib" == "openssl" ]; then
  for (( i=1; i<=$repeat; i++ ))
  do
      echo "Round: $i"
      #### DECRYPTION START
      if [ "$type" = "d" ]; then
        # AES-NI
        echo "Round: $i" >> output/block_rss/openssl/openssl_aes_ni_rss_decrypt
        sudo chrt -f 99 nice -n -20 bash -c "openssl enc -aes-128-ecb -d -in rss_openssl_aes_ni -out $output -pass pass:pineapple -pbkdf2 -nosalt" &
        sleep 0.2
        sudo_pid="$(ps --ppid $! -o pid=)"
        pid="$(ps --ppid $sudo_pid -o pid=)"
        pid="$(echo $pid | xargs)"

        while ps -p $pid > 3
        do
          cat "/proc/$pid/status" | grep 'VmRSS\|VmHWM' >> output/block_rss/openssl/openssl_aes_ni_rss_decrypt
          sleep $interval
        done
        wait $!

        # AES
        echo "Round: $i" >> output/block_rss/openssl/openssl_aes_rss_decrypt
        sudo chrt -f 99 nice -n -20 bash -c "OPENSSL_ia32cap='~0x200000200000000' openssl enc -aes-128-ecb -d -in rss_openssl_aes -out $output -pass pass:pineapple -pbkdf2 -nosalt" &
        sleep 0.2
        sudo_pid="$(ps --ppid $! -o pid=)"
        pid="$(ps --ppid $sudo_pid -o pid=)"
        pid="$(echo $pid | xargs)"

        while ps -p $pid > 3
        do
          cat "/proc/$pid/status" | grep 'VmRSS\|VmHWM' >> output/block_rss/openssl/openssl_aes_rss_decrypt
          sleep $interval
        done
        wait $!

        # SM4
        echo "Round: $i" >> output/block_rss/openssl/openssl_sm4_rss_decrypt
        sudo chrt -f 99 nice -n -20 bash -c "openssl enc -sm4-ecb -d -in rss_openssl_sm4 -out $output -pass pass:pineapple -pbkdf2 -nosalt" &
        sleep 0.2
        sudo_pid="$(ps --ppid $! -o pid=)"
        pid="$(ps --ppid $sudo_pid -o pid=)"
        pid="$(echo $pid | xargs)"
        while ps -p $pid > 3
        do
          cat "/proc/$pid/status" | grep 'VmRSS\|VmHWM' >> output/block_rss/openssl/openssl_sm4_rss_decrypt
          sleep $interval
        done
        wait $!
      #### DECRYPTION END
      # ------------------------------------------------------------------------------
      #### ENCRYPTION START
      else
        # AES-NI
        echo "Round: $i" >> output/block_rss/openssl/openssl_aes_ni_rss
        sudo chrt -f 99 nice -n -20 bash -c "openssl enc -aes-128-ecb -in $input -out rss_openssl_aes_ni -pass pass:pineapple -pbkdf2 -nosalt" &
        sleep 0.2
        sudo_pid="$(ps --ppid $! -o pid=)"
        pid="$(ps --ppid $sudo_pid -o pid=)"
        pid="$(echo $pid | xargs)"

        while ps -p $pid > 3
        do
          cat "/proc/$pid/status" | grep 'VmRSS\|VmHWM' >> output/block_rss/openssl/openssl_aes_ni_rss
          sleep $interval
        done
        wait $!

        # AES
        echo "Round: $i" >> output/block_rss/openssl/openssl_aes_rss
        sudo chrt -f 99 nice -n -20 bash -c "OPENSSL_ia32cap='~0x200000200000000' openssl enc -aes-128-ecb -in $input -out rss_openssl_aes -pass pass:pineapple -pbkdf2 -nosalt" &
        sleep 0.2
        sudo_pid="$(ps --ppid $! -o pid=)"
        pid="$(ps --ppid $sudo_pid -o pid=)"
        pid="$(echo $pid | xargs)"

        while ps -p $pid > 3
        do
          cat "/proc/$pid/status" | grep 'VmRSS\|VmHWM' >> output/block_rss/openssl/openssl_aes_rss
          sleep $interval
        done
        wait $!

        # SM4
        echo "Round: $i" >> output/block_rss/openssl/openssl_sm4_rss
        sudo chrt -f 99 nice -n -20 bash -c "openssl enc -sm4-ecb -in $input -out rss_openssl_sm4 -pass pass:pineapple -pbkdf2 -nosalt" &
        sleep 0.2
        sudo_pid="$(ps --ppid $! -o pid=)"
        pid="$(ps --ppid $sudo_pid -o pid=)"
        pid="$(echo $pid | xargs)"
        while ps -p $pid > 3
        do
          cat "/proc/$pid/status" | grep 'VmRSS\|VmHWM' >> output/block_rss/openssl/openssl_sm4_rss
          sleep $interval
        done
        wait $!
      #### ENCRYPTION END
      fi
  done
fi


if [ "$lib" == "botan" ]; then
  for (( i=1; i<=$repeat; i++ ))
  do
    #### DECRYPTION START
    echo "Round: $i"
    if [ "$type" = "d" ]; then
      # AES
      echo "Round: $i" >> output/block_rss/botan/botan_aes_ni_rss_decrypt
      sudo chrt -f 99 nice -n -20 ./botan/aes_ecb_dec.o ecb_enc.bin &
      sleep 0.5

      sudo_pid="$(ps --ppid $! -o pid=)"
      pid="$(ps --ppid $sudo_pid -o pid=)"
      #echo "PID: " $pid
      pid="$(echo $pid | xargs)"
      while ps -p $pid > 3
      do
        cat "/proc/$pid/status" | grep 'VmRSS\|VmHWM' >> output/block_rss/botan/botan_aes_ni_rss_decrypt
        sleep $interval
      done
      wait $!

      # SM4
      echo "Round: $i" >> output/block_rss/botan/botan_sm4_rss_decrypt
      sudo chrt -f 99 nice -n -20 ./botan/sm4_ecb_dec.o sm4_ecb_enc.bin &
      sleep 0.5

      sudo_pid="$(ps --ppid $! -o pid=)"
      pid="$(ps --ppid $sudo_pid -o pid=)"
      #echo "PID: " $pid
      pid="$(echo $pid | xargs)"
      while ps -p $pid > 3
      do
        cat "/proc/$pid/status" | grep 'VmRSS\|VmHWM' >> output/block_rss/botan/botan_sm4_rss_decrypt
        sleep $interval
      done
      wait $!
      #### DECRYPTION END

      #### ENCRYPTION START
    else
      # AES
      echo "Round: $i" >> output/block_rss/botan/botan_aes_ni_rss_encrypt
      sudo chrt -f 99 nice -n -20 ./botan/aes_ecb_enc.o $input &
      sleep 0.5

      sudo_pid="$(ps --ppid $! -o pid=)"
      pid="$(ps --ppid $sudo_pid -o pid=)"
      pid="$(echo $pid | xargs)"
      while ps -p $pid > 3
      do
        cat "/proc/$pid/status" | grep 'VmRSS\|VmHWM' >> output/block_rss/botan/botan_aes_ni_rss_encrypt
        sleep $interval
      done
      wait $!

      # SM4
      echo "Round: $i" >> output/block_rss/botan/botan_sm4_rss_encrypt
      sudo chrt -f 99 nice -n -20 ./botan/sm4_ecb_enc.o $input &
      sleep 0.5

      sudo_pid="$(ps --ppid $! -o pid=)"
      pid="$(ps --ppid $sudo_pid -o pid=)"
      pid="$(echo $pid | xargs)"
      while ps -p $pid > 3
      do
        cat "/proc/$pid/status" | grep 'VmRSS\|VmHWM' >> output/block_rss/botan/botan_sm4_rss_encrypt
        sleep $interval
      done
      wait $!

      #### ENCRYPTION END
    fi
  done
fi
