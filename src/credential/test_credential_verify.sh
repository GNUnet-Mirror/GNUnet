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

#  (1) Service.user -> GNU.project.member
#  (2) GNU.project -> GNUnet
#  (3) GNUnet.member -> GNUnet.developer
#  (4) GNUnet.member -> GNUnet.user
#  (5) GNUnet.developer -> Alice


which timeout &> /dev/null && DO_TIMEOUT="timeout 30"
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

# (1) A service assigns the attribute "user" to all entities that have been assigned "member" by entities that werde assigned "project" from GNU
gnunet-namestore -p -z service -a -n $USER_ATTR -t ATTR -V "$GNU_KEY $GNU_PROJECT_ATTR.$MEMBER_ATTR" -e 5m -c test_credential_lookup.conf

# (2) GNU recognized GNUnet as a GNU project and delegates the "project" attribute
gnunet-namestore -p -z gnu -a -n $GNU_PROJECT_ATTR -t ATTR -V "$GNUNET_KEY" -e 5m -c test_credential_lookup.conf

# (3+4) GNUnet assigns the attribute "member" to all entities gnunet has also assigned "developer" or "user"
gnunet-namestore -p -z gnunet -a -n $MEMBER_ATTR -t ATTR -V "$GNUNET_KEY $DEVELOPER_ATTR" -e 5m -c test_credential_lookup.conf
gnunet-namestore -p -z gnunet -a -n $MEMBER_ATTR -t ATTR -V "$GNUNET_KEY $USER_ATTR" -e 5m -c test_credential_lookup.conf

# (5) GNUnet issues Alice the credential "developer"
CRED=`$DO_TIMEOUT gnunet-credential --issue --ego=gnunet --subject=$ALICE_KEY --attribute=$DEV_ATTR --ttl=5m -c test_credential_lookup.conf`

# Alice stores the credential under "mygnunetcreds"
gnunet-namestore -p -z alice -a -n $TEST_CREDENTIAL -t CRED -V "$CRED" -e 5m -c test_credential_lookup.conf

CREDS=`$DO_TIMEOUT gnunet-credential --collect --issuer=$SERVICE_KEY --attribute=$USER_ATTR --ego=alice -c test_credential_lookup.conf | paste -d, -s`

echo gnunet-credential --verify --issuer=$SERVICE_KEY --attribute=$USER_ATTR --subject=$ALICE_KEY --credential=\'$CREDS\' -c test_credential_lookup.conf
#TODO2 Add -z swich like in gnunet-gns
gnunet-credential --verify --issuer=$SERVICE_KEY --attribute=$USER_ATTR --subject=$ALICE_KEY --credential="$CREDS" -c test_credential_lookup.conf


#TODO cleanup properly
gnunet-namestore -z alice -d -n $TEST_CREDENTIAL -t CRED -e never -c test_credential_lookup.conf
gnunet-namestore -z gnu -d -n $GNU_PROJECT_ATTR -t ATTR -c test_credential_lookup.conf
gnunet-namestore -z gnunet -d -n $MEMBER_ATTR -t ATTR -c test_credential_lookup.conf
gnunet-namestore -z service -d -n $USER_ATTR -t ATTR -c test_credential_lookup.conf
gnunet-arm -e -c test_credential_lookup.conf

if [ "$RES_CRED" != "Failed." ]
then
  echo -e "${RES_CRED}"
  exit 0
else
  echo "FAIL: Failed to verify credential $RES_CRED."
  exit 1
fi
