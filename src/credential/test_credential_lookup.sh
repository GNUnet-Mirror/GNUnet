#!/bin/bash
trap "gnunet-arm -e -c test_credential_lookup.conf" SIGINT

LOCATION=$(which gnunet-config)
if [ -z $LOCATION ]
then
  LOCATION="gnunet-config"
fi
$LOCATION --version 1> /dev/null
if test $? != 0
then
	echo "GNUnet command line tools cannot be found, check environmental variables PATH and GNUNET_PREFIX"
	exit 77
fi

rm -rf `gnunet-config -c test_credential_lookup.conf -s PATHS -o GNUNET_HOME -f`
which timeout &> /dev/null && DO_TIMEOUT="timeout 30"
TEST_CREDENTIAL="keySub keyIss credName"
gnunet-arm -s -c test_credential_lookup.conf
gnunet-identity -C testsubject -c test_credential_lookup.conf

#TODO1 Plugin serialization functions see REVERSE in gns/plugin_gnsrecord_gns.c
gnunet-namestore -p -z testsubject -a -n newcred -t CRED -V $TEST_CREDENTIAL -e never -c test_credential_lookup.conf

#TODO2 Add -z swich like in gnunet-gns
RES_IP=`$DO_TIMEOUT gnunet-credential -z testsubject -s testsubject -u credName -c test_credential_lookup.conf`
gnunet-namestore -z testsubject -d -n newcred -t CRED -e never -c test_credential_lookup.conf
gnunet-identity -D testsubject -c test_credential_lookup.conf
gnunet-arm -e -c test_credential_lookup.conf

#TODO3 proper test
exit 0

#if [ "$RES_IP" == "$TEST_CRED" ]
#then
#  exit 0
#else
#  echo "FAIL: Failed to resolve to proper IP, got $RES_IP."
#  exit 1
#fi
