#!/bin/bash
trap "gnunet-arm -e -c test_idp.conf" SIGINT

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

rm -rf `gnunet-config -c test_idp.conf -s PATHS -o GNUNET_HOME -f`

#  (1) PKEY1.user -> PKEY2.resu.user
#  (2) PKEY2.resu -> PKEY3
#  (3) PKEY3.user -> PKEY4


which timeout &> /dev/null && DO_TIMEOUT="timeout 30"

TEST_ATTR="test"
gnunet-arm -s -c test_idp.conf
#gnunet-arm -i rest -c test_idp.conf
gnunet-identity -C testego -c test_idp.conf
gnunet-identity -C rpego -c test_idp.conf
SUBJECT_KEY=$(gnunet-identity -d -c test_idp.conf | grep rpego | awk '{print $3}')
TEST_KEY=$(gnunet-identity -d -c test_idp.conf | grep testego | awk '{print $3}')
gnunet-idp -e testego -a email -V john@doe.gnu -c test_idp.conf
gnunet-idp -e testego -a name -V John -c test_idp.conf
TICKET=$(gnunet-idp -e testego -i "email,name" -r $SUBJECT_KEY -c test_idp.conf | awk '{print $1}')
gnunet-idp -e rpego -C $TICKET -c test_idp.conf > /dev/null 2>&1

if test $? != 0
then
  "Failed."
  exit 1
fi
#curl http://localhost:7776/idp/tickets/testego
gnunet-arm -e -c test_idp.conf
