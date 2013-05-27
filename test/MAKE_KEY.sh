#!/bin/sh
#
# run this to recreate the test.key and test.crt
#
openssl genrsa -out test2.key 1024
openssl req -new -key test2.key -out test2.csr
openssl x509 -req -days 365 -in test2.csr -signkey test2.key -out test2.crt

