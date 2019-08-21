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




which timeout > /dev/null 2>&1 && DO_TIMEOUT="timeout 10"
gnunet-arm -s -c test_credential_lookup.conf

gnunet-identity -C a -c test_credential_lookup.conf
gnunet-identity -C b -c test_credential_lookup.conf
gnunet-identity -C c -c test_credential_lookup.conf
gnunet-identity -C d -c test_credential_lookup.conf
gnunet-identity -C e -c test_credential_lookup.conf
gnunet-identity -C f -c test_credential_lookup.conf
gnunet-identity -C g -c test_credential_lookup.conf
gnunet-identity -C h -c test_credential_lookup.conf
AKEY=$(gnunet-identity -d -c test_credential_lookup.conf | grep a | awk '{print $3}')
BKEY=$(gnunet-identity -d -c test_credential_lookup.conf | grep b | awk '{print $3}')
CKEY=$(gnunet-identity -d -c test_credential_lookup.conf | grep c | awk '{print $3}')
DKEY=$(gnunet-identity -d -c test_credential_lookup.conf | grep d | awk '{print $3}')
EKEY=$(gnunet-identity -d -c test_credential_lookup.conf | grep e | awk '{print $3}')
FKEY=$(gnunet-identity -d -c test_credential_lookup.conf | grep f | awk '{print $3}')
GKEY=$(gnunet-identity -d -c test_credential_lookup.conf | grep g | awk '{print $3}')
HKEY=$(gnunet-identity -d -c test_credential_lookup.conf | grep h | awk '{print $3}')

#   (1) (A.a) <- B.b
#   (2) (B.b) <- C.c AND G.g
#   (3) C.c <- (D.D)
#   (4) D.d <- (E.e)
#   (5) E.e <- (F) priv
#   (6) G.g <- (F) priv

# BIDIRECTIONAL
gnunet-credential --createIssuerSide --ego=a --attribute="a" --subject="$BKEY b" --ttl=5m -c test_credential_lookup.conf
gnunet-namestore -D -z a
gnunet-credential --createIssuerSide --ego=b --attribute="b" --subject="$CKEY c, $GKEY g" --ttl=5m -c test_credential_lookup.conf
gnunet-namestore -D -z b

SIGNED=`$DO_TIMEOUT gnunet-credential --signSubjectSide --ego=c --attribute="c" --subject="$DKEY d" --ttl="2019-12-12 10:00:00"`
gnunet-credential --createSubjectSide --ego=d --import "$SIGNED"
gnunet-namestore -D -z d
SIGNED=`$DO_TIMEOUT gnunet-credential --signSubjectSide --ego=d --attribute="d" --subject="$EKEY e" --ttl="2019-12-12 10:00:00"`
gnunet-credential --createSubjectSide --ego=e --import "$SIGNED"
gnunet-namestore -D -z e
SIGNED=`$DO_TIMEOUT gnunet-credential --signSubjectSide --ego=e --attribute="e" --subject="$FKEY" --ttl="2019-12-12 10:00:00"`
gnunet-credential --createSubjectSide --ego=f --import "$SIGNED" --private
gnunet-namestore -D -z f
SIGNED=`$DO_TIMEOUT gnunet-credential --signSubjectSide --ego=g --attribute="g" --subject="$FKEY" --ttl="2019-12-12 10:00:00"`
gnunet-credential --createSubjectSide --ego=f --import "$SIGNED" --private
gnunet-namestore -D -z h

# Starting to resolve
echo "+++ Starting to Resolve +++"

DELS=`$DO_TIMEOUT gnunet-credential --collect --issuer=$AKEY --attribute="a" --ego=f -c test_credential_lookup.conf | paste -d, -s - -`
echo $DELS
echo gnunet-credential --verify --issuer=$AKEY --attribute="a" --subject=$FKEY --delegate=\'$DELS\' -c test_credential_lookup.conf
RES_DELS=`gnunet-credential --verify --issuer=$AKEY --attribute="a" --subject=$FKEY --delegate="$DELS" -c test_credential_lookup.conf`

# Cleanup properly
gnunet-namestore -z a -d -n "a" -t ATTR -c test_credential_lookup.conf
gnunet-namestore -z b -d -n "b" -t ATTR -c test_credential_lookup.conf
gnunet-namestore -z d -d -n "@" -t DEL -c test_credential_lookup.conf
gnunet-namestore -z e -d -n "@" -t DEL -c test_credential_lookup.conf
gnunet-namestore -z f -d -n "@" -t DEL -c test_credential_lookup.conf

gnunet-arm -e -c test_credential_lookup.conf

if [ "$RES_DELS" != "Failed." ]
then
  # TODO: replace echo -e bashism
  echo -e "${RES_DELS}"
  exit 0
else
  echo "FAIL: Failed to verify credential $RES_DELS."
  exit 1
fi

