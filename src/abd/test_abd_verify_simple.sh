#!/usr/bin/env bash
trap "gnunet-arm -e -c test_abd_lookup.conf" SIGINT

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

rm -rf `gnunet-config -c test_abd_lookup.conf -s PATHS -o GNUNET_HOME -f`

#  (1) Issuer.user -> Subject


which timeout > /dev/null 2>&1 && DO_TIMEOUT="timeout 30"
gnunet-arm -s -c test_abd_lookup.conf
gnunet-identity -C testissuer -c test_abd_lookup.conf
gnunet-identity -C testsubject -c test_abd_lookup.conf

TEST_ATTR="user"
SUBJECT_KEY=$(gnunet-identity -d -c test_abd_lookup.conf | grep testsubject | awk '{print $3}')
ISSUER_KEY=$(gnunet-identity -d -c test_abd_lookup.conf | grep testissuer | awk '{print $3}')

gnunet-identity -d

# Create delegate (1)
SIGNED=`$DO_TIMEOUT gnunet-abd --signSubjectSide --ego=testissuer --attribute=$TEST_ATTR --subject=$SUBJECT_KEY --ttl="2019-12-12 10:00:00" -c test_abd_lookup.conf`
gnunet-abd --createSubjectSide --ego=testsubject --import="$SIGNED" --private
gnunet-namestore -D -z testsubject

# Starting to resolve
echo "+++ Starting to Resolve +++"

DELS=`$DO_TIMEOUT gnunet-abd --collect --issuer=$ISSUER_KEY --attribute=$TEST_ATTR --ego=testsubject -c test_abd_lookup.conf | paste -d, -s - -`
echo $DELS
gnunet-abd --verify --issuer=$ISSUER_KEY --attribute=$TEST_ATTR --subject=$SUBJECT_KEY --delegate="$DELS" -c test_abd_lookup.conf

RES=$?

# Cleanup properly
gnunet-namestore -z testsubject -d -n "@" -t DEL -c test_abd_lookup.conf
gnunet-arm -e -c test_abd_lookup.conf

if [ "$RES" == 0 ]
then
  exit 0
else
  echo "FAIL: Failed to verify credential."
  exit 1
fi