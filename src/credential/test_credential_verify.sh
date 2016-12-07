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

#  (1) Authority.test -> Intermediate.org.user
#  (2) Intermediate.org -> Issuer
#  (3) Issuer.user -> Subject


which timeout &> /dev/null && DO_TIMEOUT="timeout 30"
gnunet-arm -s -c test_credential_lookup.conf
gnunet-identity -C testissuer -c test_credential_lookup.conf
gnunet-identity -C testsubject -c test_credential_lookup.conf
gnunet-identity -C testintermediate -c test_credential_lookup.conf
gnunet-identity -C testauthority -c test_credential_lookup.conf

TEST_ATTR="user"
INTERMEDIATE_KEY=$(gnunet-identity -d -c test_credential_lookup.conf | grep testintermediate | awk '{print $3}')
SUBJECT_KEY=$(gnunet-identity -d -c test_credential_lookup.conf | grep testsubject | awk '{print $3}')
ISSUER_KEY=$(gnunet-identity -d -c test_credential_lookup.conf | grep testissuer | awk '{print $3}')
AUTHORITY_KEY=$(gnunet-identity -d -c test_credential_lookup.conf | grep testauthority | awk '{print $3}')
CRED=`$DO_TIMEOUT gnunet-credential --issue --ego=testissuer --subject=$SUBJECT_KEY --attribute=$TEST_ATTR --ttl=5m -c test_credential_lookup.conf`

TEST_CREDENTIAL="t1"
gnunet-namestore -p -z testsubject -a -n $TEST_CREDENTIAL -t CRED -V "$CRED" -e 5m -c test_credential_lookup.conf

INTERMEDIATE_ATTR="org"
gnunet-namestore -p -z testintermediate -a -n $INTERMEDIATE_ATTR -t ATTR -V "$ISSUER_KEY" -e 5m -c test_credential_lookup.conf

AUTHORITY_ATTR="test"
gnunet-namestore -p -z testauthority -a -n $AUTHORITY_ATTR -t ATTR -V "$INTERMEDIATE_KEY $INTERMEDIATE_ATTR.$TEST_ATTR" -e 5m -c test_credential_lookup.conf

#TODO2 Add -z swich like in gnunet-gns
RES_CRED=`gnunet-credential --verify --issuer=$AUTHORITY_KEY --attribute=$AUTHORITY_ATTR --subject=$SUBJECT_KEY --credential=$TEST_CREDENTIAL -c test_credential_lookup.conf`

#TODO cleanup properly
gnunet-namestore -z testsubject -d -n $TEST_CREDENTIAL -t CRED -e never -c test_credential_lookup.conf
gnunet-arm -e -c test_credential_lookup.conf

if [ "$RES_CRED" == "Successful." ]
then
  exit 0
else
  echo "FAIL: Failed to verify credential $RES_IP."
  exit 1
fi
