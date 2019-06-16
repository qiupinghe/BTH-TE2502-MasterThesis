#!/bin/bash

repeat=0
lib=''
type=''

print_usage() {
  printf "Usage: ./ds_rss.sh -l <openssl/botan> -t <key/sign/verify> -r 10 \n"
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

if [ $repeat == 0 ]
then
  echo "Repeat is not set."
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
      sudo /usr/bin/time -o output/ds_rss/rss_rsa_key_gmssl --append -f %M \
      gmssl genrsa -out private.key 3072 &>/dev/null
      sudo /usr/bin/time -o output/ds_rss/rss_rsa_key_gmssl --append -f %M \
      gmssl rsa -in private.key -pubout -out public.key &>/dev/null
      #SM2
      sudo /usr/bin/time -o output/ds_rss/rss_sm2_key_gmssl --append -f %M \
      gmssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:sm2p256v1 -out private.key
      sudo /usr/bin/time -o output/ds_rss/rss_sm2_key_gmssl --append -f %M \
      gmssl pkey -pubout -in private.key -out public.key
      #ECDSA
      sudo /usr/bin/time -o output/ds_rss/rss_ecdsa_key_gmssl --append -f %M \
      gmssl ecparam -genkey -name prime256v1 -out private.key &>/dev/null
      sudo /usr/bin/time -o output/ds_rss/rss_ecdsa_key_gmssl --append -f %M \
      gmssl ec -in private.key -pubout -out public.key &>/dev/null
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
      sudo /usr/bin/time -o output/ds_rss/rss_rsa_sign_gmssl --append -f %M \
      gmssl pkeyutl -sign -in gmssl_setup/rsa/file -inkey gmssl_setup/rsa/private.key \
      -out signature.sig
      #SM2
      sudo /usr/bin/time -o output/ds_rss/rss_sm2_sign_gmssl --append -f %M \
      gmssl pkeyutl -sign -pkeyopt ec_scheme:sm2 -inkey gmssl_setup/sm2/private.key \
      -in gmssl_setup/sm2/file -out signature.sig
      #ECDSA
      sudo /usr/bin/time -o output/ds_rss/rss_ecdsa_sign_gmssl --append -f %M \
      gmssl pkeyutl -sign -in gmssl_setup/ecdsa/file -inkey gmssl_setup/ecdsa/private.key \
      -out signature.sig
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
      sudo /usr/bin/time -o output/ds_rss/rss_rsa_verify_gmssl --append -f %M \
      gmssl pkeyutl -verifyrecover -pubin -in gmssl_setup/rsa/signature.sig \
      -inkey gmssl_setup/rsa/public.key &>/dev/null
      #SM2
      sudo /usr/bin/time -o output/ds_rss/rss_sm2_verify_gmssl --append -f %M \
      gmssl pkeyutl -verify -pubin -pkeyopt ec_scheme:sm2 -inkey gmssl_setup/sm2/public.key \
      -in gmssl_setup/sm2/file -sigfile gmssl_setup/sm2/signature.sig &>/dev/null
      #ECDSA
      sudo /usr/bin/time -o output/ds_rss/rss_ecdsa_verify_gmssl --append -f %M \
      gmssl pkeyutl -verify -pubin  -inkey gmssl_setup/ecdsa/public.key -in \
      gmssl_setup/ecdsa/file -sigfile gmssl_setup/ecdsa/signature.sig &>/dev/null
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
      #RSA
      sudo /usr/bin/time -o output/ds_rss/rss_rsa_key_botan --append -f %M ./botan/rsa_keygen 1
      #SM2
      sudo /usr/bin/time -o output/ds_rss/rss_sm2_key_botan --append -f %M ./botan/sm2_keygen 1
      #ECDSA
      sudo /usr/bin/time -o output/ds_rss/rss_ecdsa_key_botan --append -f %M ./botan/ecdsa_keygen 1
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
      sudo /usr/bin/time -o output/ds_rss/rss_rsa_sign_botan --append -f %M \
      ./botan/rsa_sign "botan/Generate_testfile/rsa/private.key" 1
      #SM2
      sudo /usr/bin/time -o output/ds_rss/rss_sm2_sign_botan --append -f %M \
      ./botan/sm2_sign "botan/Generate_testfile/sm2/private.key" 1
      #ECDSA
      sudo /usr/bin/time -o output/ds_rss/rss_ecdsa_sign_botan --append -f %M \
      ./botan/ecdsa_sign "botan/Generate_testfile/ecdsa/private.key" 1
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
      sudo /usr/bin/time -o output/ds_rss/rss_rsa_verify_botan --append -f %M \
      ./botan/rsa_verify "botan/Generate_testfile/rsa/public.key" "botan/Generate_testfile/rsa/signature.sig" 1
      #SM2
      sudo /usr/bin/time -o output/ds_rss/rss_sm2_verify_botan --append -f %M \
      ./botan/sm2_verify "botan/Generate_testfile/sm2/public.key" "botan/Generate_testfile/sm2/signature.sig" 1
      #ECDSA
      sudo /usr/bin/time -o output/ds_rss/rss_ecdsa_verify_botan --append -f %M \
      ./botan/ecdsa_verify "botan/Generate_testfile/ecdsa/public.key" "botan/Generate_testfile/ecdsa/signature.sig" 1
      echo "------------------------"
    done
  fi
fi
