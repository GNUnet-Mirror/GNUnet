#!/bin/bash

TEST_IP="127.0.0.1"
DELEGATED_PKEY=$(gnunet-ecc -p egos/delegatedego)

gnunet-arm -s -c test_gns_lookup.conf

#gnunet-identity -C testego -c test_gns_lookup.conf

gnunet-namestore -p -z testego -a -n b -t PKEY -V $DELEGATED_PKEY -e never -c test_gns_lookup.conf
gnunet-namestore -p -z delegatedego -a -n www -t A -V $TEST_IP -e never -c test_gns_lookup.conf
RES_IP=$(gnunet-gns --raw -z testego -u www.b.gnu -t A -c test_gns_lookup.conf)

gnunet-namestore -z testego -d -n b -t PKEY -V $DELEGATED_PKEY  -e never -c test_gns_lookup.conf
gnunet-namestore -z delegatedego -d -n www -t A -V $TEST_IP  -e never -c test_gns_lookup.conf

gnunet-arm -e -c test_gns_lookup.conf

if [ "$RES_IP" == "$TEST_IP" ]
then
  exit 0
else
  exit 1
fi

