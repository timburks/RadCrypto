#!/bin/sh
#
# run this to recreate the test.key and test.crt
#
openssl genrsa -out test.key 1024
openssl req -new -key test.key -out test.csr
openssl x509 -req -days 365 -in test.csr -signkey test.key -out test.crt

