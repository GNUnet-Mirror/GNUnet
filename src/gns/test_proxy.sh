#!/bin/bash
# This file is in the public domain.
TEST_DOMAIN="www.test"

# Delete old files before starting test
rm -rf /tmp/gnunet/test-gnunet-gns-testing/
gnunet-arm -s -c test_gns_proxy.conf
gnunet-gns-proxy-setup-ca -c test_gns_proxy.conf

openssl genrsa -des3 -passout pass:xxxx -out server.pass.key 2048
openssl rsa -passin pass:xxxx -in server.pass.key -out local.key
rm server.pass.key
openssl req -new -key local.key -out server.csr \
  -subj "/C=DE/O=GNUnet/OU=GNS/CN=test.local"
openssl x509 -req -days 1 -in server.csr -signkey local.key -out local.crt
openssl x509 -in local.crt -out local.der -outform DER
HEXCERT=`xxd -p local.der | tr -d '\n'`
#echo "This is the certificate the server does not use: $HEXCERT"
OLDBOXVALUE="6 8443 52 3 0 0 $HEXCERT"


openssl req -new -key local.key -out server.csr \
  -subj "/C=DE/O=GNUnet/OU=GNS/CN=test.local"
openssl x509 -req -days 1 -in server.csr -signkey local.key -out local.crt
openssl x509 -in local.crt -out local.der -outform DER
HEXCERT=`xxd -p local.der | tr -d '\n'`
#echo "This is the certificate the server does use: $HEXCERT"
BOXVALUE="6 8443 52 3 0 0 $HEXCERT"

cat local.crt > /tmp/server_cacert.pem
cat local.key >> /tmp/server_cacert.pem

gnunet-identity -C test -c test_gns_proxy.conf
gnunet-namestore -p -z test -a -n www -t A -V 127.0.0.1 -e never -c test_gns_proxy.conf
gnunet-namestore -p -z test -a -n www -t LEHO -V "test.local" -e never -c test_gns_proxy.conf
gnunet-namestore -p -z test -a -n www -t BOX -V "$OLDBOXVALUE" -e never -c test_gns_proxy.conf
gnunet-namestore -p -z test -a -n www -t BOX -V "$BOXVALUE" -e never -c test_gns_proxy.conf

gnunet-arm -i gns-proxy -c test_gns_proxy.conf

#gnurl --socks5-hostname 127.0.0.1:7777 https://www.test -v --cacert /tmp/proxy_cacert.pem
./test_gns_proxy -A /tmp/proxy_cacert.pem -S /tmp/server_cacert.pem -p 8443 -c test_gns_proxy.conf

RES=$?

rm /tmp/proxy_cacert.pem
rm /tmp/server_cacert.pem

gnunet-arm -e test_gns_proxy.conf

if test $RES != 0
then
  echo "Failed"
  exit 1
fi
