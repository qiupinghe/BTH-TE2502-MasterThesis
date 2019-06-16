#!/bin/bash

#Generate SM2 keys
gmssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:sm2p256v1 -out private.key
gmssl pkey -pubout -in private.key -out public.key

#Create signature file
gmssl pkeyutl -sign -pkeyopt ec_scheme:sm2 -inkey private.key -in file -out signature.sig

#Verify signature file
gmssl pkeyutl -verify -pubin -pkeyopt ec_scheme:sm2 -inkey public.key -in file -sigfile signature.sig
