#!/bin/bash

#Generate RSA keys
gmssl genrsa -out private.key 3072
gmssl rsa -in private.key -pubout -out public.key

#Create signature file
gmssl pkeyutl -sign -in file -inkey private.key -out signature.sig

#Verify signature file
gmssl pkeyutl -verifyrecover -pubin -in signature.sig -inkey public.key
