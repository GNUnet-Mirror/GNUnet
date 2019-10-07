#!/usr/bin/env bash
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


which timeout > /dev/null 2>&1 && DO_TIMEOUT="timeout 30"

TEST_ATTR="test"
gnunet-arm -s -c test_credential_lookup.conf
gnunet-identity -C testissuer -c test_credential_lookup.conf
gnunet-identity -C testsubject -c test_credential_lookup.conf
SUBJECT_KEY=$(gnunet-identity -d -c test_credential_lookup.conf | grep testsubject | awk '{print $3}')
ISSUER_KEY=$(gnunet-identity -d -c test_credential_lookup.conf | grep testissuer | awk '{print $3}')

# Get credential and store it with subject (3)
SIGNED=`$DO_TIMEOUT gnunet-credential --signSubjectSide --ego=testissuer --attribute=$TEST_ATTR --subject=$SUBJECT_KEY --ttl="2019-12-12 10:00:00" -c test_credential_lookup.conf`

STATUS=$?

if test $? != 0
then
  echo "Error issuing..."
  exit 1
fi
#Try import
$DO_TIMEOUT gnunet-credential --createSubjectSide --ego=testsubject --import="$SIGNED" --private -c test_credential_lookup.conf
RES=$?
gnunet-arm -e -c test_credential_lookup.conf
exit $RES
