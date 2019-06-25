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

#   (1) EPub.discount <- EOrg.preferred
#   (2) EOrg.preferred <- StateU.student
#   (3) StateU.student <- RegistrarB.student
#   (4) RegistrarB.student <- Alice


which timeout > /dev/null 2>&1 && DO_TIMEOUT="timeout 30"
gnunet-arm -s -c test_credential_lookup.conf
gnunet-identity -C epub -c test_credential_lookup.conf
gnunet-identity -C eorg -c test_credential_lookup.conf
gnunet-identity -C stateu -c test_credential_lookup.conf
gnunet-identity -C registrarb -c test_credential_lookup.conf
gnunet-identity -C alice -c test_credential_lookup.conf

EPUB_KEY=$(gnunet-identity -d -c test_credential_lookup.conf | grep epub | awk '{print $3}')
EORG_KEY=$(gnunet-identity -d -c test_credential_lookup.conf | grep eorg | awk '{print $3}')
STATEU_KEY=$(gnunet-identity -d -c test_credential_lookup.conf | grep stateu | awk '{print $3}')
REGISTRARB_KEY=$(gnunet-identity -d -c test_credential_lookup.conf | grep registrarb | awk '{print $3}')
ALICE_KEY=$(gnunet-identity -d -c test_credential_lookup.conf | grep alice | awk '{print $3}')


DISC_ATTR="discount"
PREF_ATTR="preferred"
STATE_STUD_ATTR="student"
REG_STUD_ATTR="student"
END_ATTR="end"

TEST_CREDENTIAL="mygnunetcreds"
# Test for forward search (0) StateU.student -> EOrg.end
# gnunet-namestore -p -z eorg -a -n "@" -t DEL -V "$STATEU_KEY $STATE_STUD_ATTR <- $EORG_KEY $END_ATTR" -e 60m -c test_credential_lookup.conf
# gnunet-namestore -D -z eorg

# Alternative Format that is being implemented at the moment:
# Issuerside: 
#   gnunet-credential --create --ego=A --attribute="a" --subject="B.b" --where="is"
   gnunet-credential --createIssuerSide --ego=epub --attribute="aasds" --subject="$EORG_KEY basd" --ttl=60m
   SIGNED=`$DO_TIMEOUT gnunet-credential --signSubjectSide --ego=epub --attribute="asd" --subject="$EORG_KEY basd" --ttl=60m`
   echo $SIGNED
   gnunet-credential --createSubjectSide --extension "$SIGNED"
# Subjectside:
#   X = gnunet-credential --create -e E -a "a" -s "B.b" -w ss
#   gnunet-credential --add -e E -x X

# (1) EPub assigns the attribute "discount" to all entities that have been assigned "preferred" by EOrg
gnunet-namestore -p -z epub -a -n $DISC_ATTR -t ATTR -V "$EORG_KEY $PREF_ATTR" -e 5m -c test_credential_lookup.conf
gnunet-namestore -D -z epub

# (2) EOrg assigns the attribute "preferred" to all entities that have been assigned "student" by StateU
gnunet-namestore -p -z eorg -a -n $PREF_ATTR -t ATTR -V "$STATEU_KEY $STATE_STUD_ATTR" -e 5m -c test_credential_lookup.conf

# (3) StateU assigns the attribute "student" to all entities that have been asssigned "student" by RegistrarB
gnunet-namestore -p -z stateu -a -n $STATE_STUD_ATTR -t ATTR -V "$REGISTRARB_KEY $REG_STUD_ATTR" -e 5m -c test_credential_lookup.conf

# (4) RegistrarB issues Alice the credential "student"
CRED=`$DO_TIMEOUT gnunet-credential --issue --ego=registrarb --subject=$ALICE_KEY --attribute=$REG_STUD_ATTR --ttl=5m -c test_credential_lookup.conf`

# Alice stores the credential under "mygnunetcreds"
gnunet-namestore -p -z alice -a -n $TEST_CREDENTIAL -t CRED -V "$CRED" -e 5m -c test_credential_lookup.conf

# Starting to resolve
echo "+++++Starting Collect"

CREDS=`$DO_TIMEOUT gnunet-credential --collect --issuer=$EPUB_KEY --attribute=$DISC_ATTR --ego=alice -c test_credential_lookup.conf | paste -d, -s`
echo $CREDS
echo gnunet-credential --verify --issuer=$EPUB_KEY --attribute=$DISC_ATTR --subject=$ALICE_KEY --credential=\'$CREDS\' -c test_credential_lookup.conf

RES_CRED=`gnunet-credential --verify --issuer=$EPUB_KEY --attribute=$DISC_ATTR --subject=$ALICE_KEY --credential="$CREDS" -c test_credential_lookup.conf`


# Cleanup properly
gnunet-namestore -z alice -d -n $TEST_CREDENTIAL -t CRED -e never -c test_credential_lookup.conf
gnunet-namestore -z epub -d -n $DISC_ATTR -t ATTR -c test_credential_lookup.conf
gnunet-namestore -z eorg -d -n $PREF_ATTR -t ATTR -c test_credential_lookup.conf
gnunet-namestore -z stateu -d -n $STATE_STUD_ATTR -t ATTR -c test_credential_lookup.conf
gnunet-arm -e -c test_credential_lookup.conf

if [ "$RES_CRED" != "Failed." ]
then
  # TODO: replace echo -e bashism
  echo -e "${RES_CRED}"
  exit 0
else
  echo "FAIL: Failed to verify credential $RES_CRED."
  exit 1
fi

