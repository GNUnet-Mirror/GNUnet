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


which timeout > /dev/null 2>&1 && DO_TIMEOUT="timeout 10"
gnunet-arm -s -c test_credential_lookup.conf

gnunet-identity -C a -c test_credential_lookup.conf
gnunet-identity -C d -c test_credential_lookup.conf
gnunet-identity -C e -c test_credential_lookup.conf
gnunet-identity -C f -c test_credential_lookup.conf
gnunet-identity -C g -c test_credential_lookup.conf
AKEY=$(gnunet-identity -d -c test_credential_lookup.conf | grep a | awk '{print $3}')
DKEY=$(gnunet-identity -d -c test_credential_lookup.conf | grep d | awk '{print $3}')
EKEY=$(gnunet-identity -d -c test_credential_lookup.conf | grep e | awk '{print $3}')
FKEY=$(gnunet-identity -d -c test_credential_lookup.conf | grep f | awk '{print $3}')
GKEY=$(gnunet-identity -d -c test_credential_lookup.conf | grep g | awk '{print $3}')

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

# FORWARD, subject side stored
SIGNED=`$DO_TIMEOUT gnunet-credential --signSubjectSide --ego=a --attribute="a" --subject="$AKEY b.c" --ttl="2019-12-12 10:00:00"`
gnunet-credential --createSubjectSide --ego=a --import "$SIGNED"
gnunet-namestore -D -z a

SIGNED=`$DO_TIMEOUT gnunet-credential --signSubjectSide --ego=a --attribute="b" --subject="$DKEY d" --ttl="2019-12-12 10:00:00"`
gnunet-credential --createSubjectSide --ego=d --import "$SIGNED"
gnunet-namestore -D -z d

SIGNED=`$DO_TIMEOUT gnunet-credential --signSubjectSide --ego=d --attribute="d" --subject="$EKEY" --ttl="2019-12-12 10:00:00"`
gnunet-credential --createSubjectSide --ego=e --import "$SIGNED"
gnunet-namestore -D -z e

SIGNED=`$DO_TIMEOUT gnunet-credential --signSubjectSide --ego=e --attribute="c" --subject="$FKEY c" --ttl="2019-12-12 10:00:00"`
gnunet-credential --createSubjectSide --ego=f --import "$SIGNED"
SIGNED=`$DO_TIMEOUT gnunet-credential --signSubjectSide --ego=e --attribute="k" --subject="$FKEY c.k" --ttl="2019-12-12 10:00:00"`
gnunet-credential --createSubjectSide --ego=f --import "$SIGNED"
gnunet-namestore -D -z f

SIGNED=`$DO_TIMEOUT gnunet-credential --signSubjectSide --ego=f --attribute="c" --subject="$GKEY" --ttl="2019-12-12 10:00:00"`
gnunet-credential --createSubjectSide --ego=g --import "$SIGNED"
SIGNED=`$DO_TIMEOUT gnunet-credential --signSubjectSide --ego=a --attribute="c" --subject="$GKEY" --ttl="2019-12-12 10:00:00"`
gnunet-credential --createSubjectSide --ego=g --import "$SIGNED"
gnunet-namestore -D -z g


# BACKWARD, issuer side stored
# (1) EPub assigns the attribute "discount" to all entities that have been assigned "preferred" by EOrg
gnunet-credential --createIssuerSide --ego=epub --attribute=$DISC_ATTR --subject="$EORG_KEY $PREF_ATTR" --ttl=5m -c test_credential_lookup.conf

# (2) EOrg assigns the attribute "preferred" to all entities that have been assigned "student" by StateU
gnunet-credential --createIssuerSide --ego=eorg --attribute=$PREF_ATTR --subject="$STATEU_KEY $STATE_STUD_ATTR" --ttl=5m -c test_credential_lookup.conf

# (3) StateU assigns the attribute "student" to all entities that have been asssigned "student" by RegistrarB
gnunet-credential --createIssuerSide --ego=stateu --attribute=$STATE_STUD_ATTR --subject="$REGISTRARB_KEY $REG_STUD_ATTR" --ttl=5m -c test_credential_lookup.conf

# (4) RegistrarB issues Alice the credential "student"
SIGNED=`$DO_TIMEOUT gnunet-credential --signSubjectSide --ego=registrarb --attribute="$REG_STUD_ATTR" --subject="$ALICE_KEY" --ttl="2019-12-12 10:00:00"`
gnunet-credential --createSubjectSide --ego=alice --import "$SIGNED"

# Starting to resolve
echo "+++ Starting to Resolve +++"

#CREDS=`$DO_TIMEOUT gnunet-credential --collect --issuer=$AKEY --attribute="a" --ego=g -c test_credential_lookup.conf | paste -d, -s`
#echo $CREDS
#echo gnunet-credential --verify --issuer=$AKEY --attribute="a" --subject=$GKEY --credential=\'$CREDS\' -c test_credential_lookup.conf
#RES_CRED=`gnunet-credential --verify --issuer=$AKEY --attribute="a" --subject=$GKEY --credential="$CREDS" -c test_credential_lookup.conf`

CREDS=`$DO_TIMEOUT gnunet-credential --collect --issuer=$EPUB_KEY --attribute=$DISC_ATTR --ego=alice -c test_credential_lookup.conf | paste -d, -s`
echo $CREDS
echo gnunet-credential --verify --issuer=$EPUB_KEY --attribute=$DISC_ATTR --subject=$ALICE_KEY --credential=\'$CREDS\' -c test_credential_lookup.conf
RES_CRED=`gnunet-credential --verify --issuer=$EPUB_KEY --attribute=$DISC_ATTR --subject=$ALICE_KEY --credential="$CREDS" -c test_credential_lookup.conf`


# Cleanup properly
gnunet-namestore -z epub -d -n $DISC_ATTR -t ATTR -c test_credential_lookup.conf
gnunet-namestore -z eorg -d -n $PREF_ATTR -t ATTR -c test_credential_lookup.conf
gnunet-namestore -z stateu -d -n $STATE_STUD_ATTR -t ATTR -c test_credential_lookup.conf
#gnunet-namestore -z a -d -n $STATE_STUD_ATTR -t ATTR -c test_credential_lookup.conf
#gnunet-namestore -z d -d -n $STATE_STUD_ATTR -t ATTR -c test_credential_lookup.conf
#gnunet-namestore -z e -d -n $STATE_STUD_ATTR -t ATTR -c test_credential_lookup.conf
#gnunet-namestore -z f -d -n $STATE_STUD_ATTR -t ATTR -c test_credential_lookup.conf
#gnunet-namestore -z g -d -n $STATE_STUD_ATTR -t ATTR -c test_credential_lookup.conf

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

