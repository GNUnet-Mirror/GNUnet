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

#  (1) Service.user -> GNU.project.member
#  (2) GNU.project -> GNUnet
#  (3) GNUnet.member -> GNUnet.developer
#  (4) GNUnet.member -> GNUnet.user
#  (5) GNUnet.developer -> Alice


which timeout > /dev/null 2>&1 && DO_TIMEOUT="timeout 30"
gnunet-arm -s -c test_credential_lookup.conf
gnunet-identity -C service -c test_credential_lookup.conf
gnunet-identity -C alice -c test_credential_lookup.conf
gnunet-identity -C gnu -c test_credential_lookup.conf
gnunet-identity -C gnunet -c test_credential_lookup.conf

GNU_KEY=$(gnunet-identity -d -c test_credential_lookup.conf | grep gnu | grep -v gnunet | awk '{print $3}')
ALICE_KEY=$(gnunet-identity -d -c test_credential_lookup.conf | grep alice | awk '{print $3}')
GNUNET_KEY=$(gnunet-identity -d -c test_credential_lookup.conf | grep gnunet | awk '{print $3}')
SERVICE_KEY=$(gnunet-identity -d -c test_credential_lookup.conf | grep service | awk '{print $3}')

USER_ATTR="user"
GNU_PROJECT_ATTR="project"
MEMBER_ATTR="member"
DEVELOPER_ATTR="developer"
DEV_ATTR="developer"
TEST_CREDENTIAL="mygnunetcreds"

gnunet-identity -d

# (1) A service assigns the attribute "user" to all entities that have been assigned "member" by entities that werde assigned "project" from GNU
gnunet-credential --createIssuerSide --ego=service --attribute="$USER_ATTR" --subject="$GNU_KEY $GNU_PROJECT_ATTR.$MEMBER_ATTR" --ttl="2019-12-12 10:00:00" -c test_credential_lookup.conf
gnunet-namestore -D -z service

# (2) GNU recognized GNUnet as a GNU project and delegates the "project" attribute
gnunet-credential --createIssuerSide --ego=gnu --attribute="$GNU_PROJECT_ATTR" --subject="$GNUNET_KEY" --ttl="2019-12-12 10:00:00" -c test_credential_lookup.conf
gnunet-namestore -D -z gnu

# (3+4) GNUnet assigns the attribute "member" to all entities gnunet has also assigned "developer" or "user"
gnunet-credential --createIssuerSide --ego=gnunet --attribute="$MEMBER_ATTR" --subject="$GNUNET_KEY $DEVELOPER_ATTR" --ttl="2019-12-12 10:00:00" -c test_credential_lookup.conf
gnunet-credential --createIssuerSide --ego=gnunet --attribute="$MEMBER_ATTR" --subject="$GNUNET_KEY $USER_ATTR" --ttl="2019-12-12 10:00:00" -c test_credential_lookup.conf
gnunet-namestore -D -z gnunet

# (5) GNUnet signes the delegate and Alice stores it
SIGNED=`$DO_TIMEOUT gnunet-credential --signSubjectSide --ego=gnunet --attribute=$DEV_ATTR --subject=$ALICE_KEY --ttl="2019-12-12 10:00:00"`
gnunet-credential --createSubjectSide --ego=alice --import="$SIGNED" --private
gnunet-namestore -D -z alice

# Starting to resolve
echo "+++ Starting to Resolve +++"

DELS=`$DO_TIMEOUT gnunet-credential --collect --issuer=$SERVICE_KEY --attribute=$USER_ATTR --ego=alice --backward -c test_credential_lookup.conf | paste -d, -s - -`
echo $DELS
echo gnunet-credential --verify --issuer=$SERVICE_KEY --attribute=$USER_ATTR --subject=$ALICE_KEY --delegate=\'$DELS\' --backward -c test_credential_lookup.conf
gnunet-credential --verify --issuer=$SERVICE_KEY --attribute=$USER_ATTR --subject=$ALICE_KEY --delegate="$DELS" --backward -c test_credential_lookup.conf

RES=$?

# Cleanup properly
gnunet-namestore -z alice -d -n "@" -t DEL -c test_credential_lookup.conf
gnunet-namestore -z gnu -d -n $GNU_PROJECT_ATTR -t ATTR -c test_credential_lookup.conf
gnunet-namestore -z gnunet -d -n $MEMBER_ATTR -t ATTR -c test_credential_lookup.conf
gnunet-namestore -z service -d -n $USER_ATTR -t ATTR -c test_credential_lookup.conf
gnunet-arm -e -c test_credential_lookup.conf

if [ "$RES" == 0 ]
then
  exit 0
else
  echo "FAIL: Failed to verify credential."
  exit 1
fi
