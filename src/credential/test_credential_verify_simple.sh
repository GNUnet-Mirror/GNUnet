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

#  (3) Isser.user -> Subject


which timeout &> /dev/null && DO_TIMEOUT="timeout 30"
gnunet-arm -s -c test_credential_lookup.conf
gnunet-identity -C testissuer -c test_credential_lookup.conf
gnunet-identity -C testsubject -c test_credential_lookup.conf

TEST_ATTR="user"
SUBJECT_KEY=$(gnunet-identity -d -c test_credential_lookup.conf | grep testsubject | awk '{print $3}')
ISSUER_KEY=$(gnunet-identity -d -c test_credential_lookup.conf | grep testissuer | awk '{print $3}')
CRED=`$DO_TIMEOUT gnunet-credential --issue --ego=testissuer --subject=$SUBJECT_KEY --attribute=$TEST_ATTR --ttl=5m -c test_credential_lookup.conf`

TEST_CREDENTIAL="t1"
gnunet-namestore -p -z testsubject -a -n $TEST_CREDENTIAL -t CRED -V "$CRED" -e 5m -c test_credential_lookup.conf

#TODO2 Add -z swich like in gnunet-gns
#RES_CRED=`$DO_TIMEOUT gnunet-credential --verify --issuer=$ISSUER_KEY --attribute="$TEST_ATTR" --subject=$SUBJECT_KEY --credential=$TEST_CREDENTIAL -c test_credential_lookup.conf`
RES_CRED=`gnunet-credential --verify --issuer=$ISSUER_KEY --attribute=$TEST_ATTR --subject=$SUBJECT_KEY --credential=$TEST_CREDENTIAL -c test_credential_lookup.conf`

#TODO cleanup properly
gnunet-namestore -z testsubject -d -n $TEST_CREDENTIAL -t CRED -e never -c test_credential_lookup.conf
gnunet-identity -D testsubject -c test_credential_lookup.conf
gnunet-arm -e -c test_credential_lookup.conf

#TODO3 proper test
if [ "$RES_CRED" == "Successful." ]
then
  exit 0
else
  echo "FAIL: Failed to verify credential."
  exit 1
fi
