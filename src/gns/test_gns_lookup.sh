#!/bin/bash

TEST_IP="127.0.0.1"

gnunet-arm -s -c test_gns_lookup.conf

gnunet-identity -C testego -c test_gns_lookup.conf

gnunet-namestore -z testego -a -n www -t A -V $TEST_IP -e never -c test_gns_lookup.conf

RES_IP=$(gnunet-gns --raw -z testego -u www.gnu -t A -c test_gns_lookup.conf)

gnunet-namestore -z testego -d -n www -t A -V $TEST_IP -e never -c test_gns_lookup.conf

gnunet-arm -e -c test_gns_lookup.conf

if [ "$RES_IP" == "$TEST_IP" ]
then
  echo "OK"
  exit 0
else
  echo "Result $RES_IP NOTOK"
  exit 1
fi

