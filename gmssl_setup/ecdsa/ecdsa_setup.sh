#!/bin/bash

#Generate ECDSA keys
gmssl ecparam -genkey -name prime256v1 -out private.key
gmssl ec -in private.key -pubout -out public.key

#Create signature file
gmssl pkeyutl -sign -in file -inkey private.key -out signature.sig

#Verify signature file
gmssl pkeyutl -verify -pubin -inkey public.key -in file -sigfile signature.sig
