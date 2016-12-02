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

#  (1) PKEY1.user -> PKEY2.resu.user
#  (2) PKEY2.resu -> PKEY3
#  (3) PKEY3.user -> PKEY4


which timeout &> /dev/null && DO_TIMEOUT="timeout 30"
TEST_ISSUER="PKEY1"
TEST_ATTR="user"
TEST_SUB_ATTR="resu"
TEST_DELEGATION_SUBJECT="PKEY2"
TEST_DELEGATION_ATTR="$TEST_SUB_ATTR.$TEST_ATTR"
TEST_SUBDELEGATION_SUBJECT="PKEY3"
TEST_SUBJECT="PKEY4"
TEST_CREDENTIAL="c1"
gnunet-arm -s -c test_credential_lookup.conf
gnunet-identity -C testone -c test_credential_lookup.conf
gnunet-identity -C testtwo -c test_credential_lookup.conf
gnunet-identity -C testthree -c test_credential_lookup.conf
gnunet-identity -C testfour -c test_credential_lookup.conf

#TODO1 Get credential and store it with subject (3)
CRED=`$DO_TIMEOUT gnunet-credential --issue --issuer=$TEST_SUBDELEGATION_SUBJECT --attribute=$TEST_SUB_ATTR --expiration 1m -c test_credential_lookup.conf`
gnunet-namestore -p -z testfour -a -n $TEST_CREDENTIAL -t CRED -V $CRED -e 5m -c test_credential_lookup.conf

# (1)
gnunet-namestore -p -z testone -a -n $TEST_ATTR -t ATTR -V "$TEST_DELEGATION_SUBJECT $TEST_DELEGATION_ATTR"

# (2)
gnunet-namestore -p -z testtwo -a -n $TEST_SUB_ATTR -t ATTR -V "$TEST_SUBDELEGATION_SUBJECT"


#TODO2 Add -z swich like in gnunet-gns
RES_IP=`$DO_TIMEOUT gnunet-credential --verify --issuer=$TEST_ISSUER --attribute="$TEST_DELEGATION_ATTR" --subject=$TEST_SUBJECT --credential=$TEST_CREDENTIAL -c test_credential_lookup.conf`

#TODO cleanup properly
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
