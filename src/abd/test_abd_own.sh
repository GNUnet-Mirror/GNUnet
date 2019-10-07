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



which timeout > /dev/null 2>&1 && DO_TIMEOUT="timeout 10"
gnunet-arm -s -c test_abd_lookup.conf

gnunet-identity -C a -c test_abd_lookup.conf
gnunet-identity -C d -c test_abd_lookup.conf
gnunet-identity -C e -c test_abd_lookup.conf
gnunet-identity -C f -c test_abd_lookup.conf
gnunet-identity -C g -c test_abd_lookup.conf
AKEY=$(gnunet-identity -d -c test_abd_lookup.conf | grep a | awk '{print $3}')
DKEY=$(gnunet-identity -d -c test_abd_lookup.conf | grep d | awk '{print $3}')
EKEY=$(gnunet-identity -d -c test_abd_lookup.conf | grep e | awk '{print $3}')
FKEY=$(gnunet-identity -d -c test_abd_lookup.conf | grep f | awk '{print $3}')
GKEY=$(gnunet-identity -d -c test_abd_lookup.conf | grep g | awk '{print $3}')

############################################################################################
#   (1) EPub.discount <- EOrg.preferred
#   (2) EOrg.preferred <- StateU.student
#   (3) StateU.student <- RegistrarB.student
#   (4) RegistrarB.student <- Alice

gnunet-identity -C epub -c test_abd_lookup.conf
gnunet-identity -C eorg -c test_abd_lookup.conf
gnunet-identity -C stateu -c test_abd_lookup.conf
gnunet-identity -C registrarb -c test_abd_lookup.conf
gnunet-identity -C alice -c test_abd_lookup.conf

EPUB_KEY=$(gnunet-identity -d -c test_abd_lookup.conf | grep epub | awk '{print $3}')
EORG_KEY=$(gnunet-identity -d -c test_abd_lookup.conf | grep eorg | awk '{print $3}')
STATEU_KEY=$(gnunet-identity -d -c test_abd_lookup.conf | grep stateu | awk '{print $3}')
REGISTRARB_KEY=$(gnunet-identity -d -c test_abd_lookup.conf | grep registrarb | awk '{print $3}')
ALICE_KEY=$(gnunet-identity -d -c test_abd_lookup.conf | grep alice | awk '{print $3}')


DISC_ATTR="discount"
PREF_ATTR="preferred"
STATE_STUD_ATTR="student"
REG_STUD_ATTR="student"
END_ATTR="end"

gnunet-identity -d

# FORWARD, subject side stored (different constallations)
SIGNED=`$DO_TIMEOUT gnunet-abd --signSubjectSide --ego=a --attribute="a" --subject="$AKEY b.c" --ttl="2019-12-12 10:00:00"`
gnunet-abd --createSubjectSide --ego=a --import="$SIGNED"
gnunet-namestore -D -z a

SIGNED=`$DO_TIMEOUT gnunet-abd --signSubjectSide --ego=a --attribute="b" --subject="$DKEY d" --ttl="2019-12-12 10:00:00"`
gnunet-abd --createSubjectSide --ego=d --import="$SIGNED"
gnunet-namestore -D -z d

SIGNED=`$DO_TIMEOUT gnunet-abd --signSubjectSide --ego=d --attribute="d" --subject="$EKEY" --ttl="2019-12-12 10:00:00"`
gnunet-abd --createSubjectSide --ego=e --import="$SIGNED"
gnunet-namestore -D -z e

SIGNED=`$DO_TIMEOUT gnunet-abd --signSubjectSide --ego=e --attribute="c" --subject="$FKEY c" --ttl="2019-12-12 10:00:00"`
gnunet-abd --createSubjectSide --ego=f --import="$SIGNED"
SIGNED=`$DO_TIMEOUT gnunet-abd --signSubjectSide --ego=e --attribute="k" --subject="$FKEY c.k" --ttl="2019-12-12 10:00:00"`
gnunet-abd --createSubjectSide --ego=f --import="$SIGNED"
gnunet-namestore -D -z f

SIGNED=`$DO_TIMEOUT gnunet-abd --signSubjectSide --ego=f --attribute="c" --subject="$GKEY" --ttl="2019-12-12 10:00:00"`
gnunet-abd --createSubjectSide --ego=g --import="$SIGNED" --private
SIGNED=`$DO_TIMEOUT gnunet-abd --signSubjectSide --ego=a --attribute="c" --subject="$GKEY" --ttl="2019-12-12 10:00:00"`
gnunet-abd --createSubjectSide --ego=g --import="$SIGNED" --private
SIGNED=`$DO_TIMEOUT gnunet-abd --signSubjectSide --ego=d --attribute="h.o" --subject="$GKEY" --ttl="2019-12-12 10:00:00"`
gnunet-abd --createSubjectSide --ego=g --import="$SIGNED"
gnunet-namestore -D -z g


# BACKWARD, issuer side stored
# (1) EPub assigns the attribute "discount" to all entities that have been assigned "preferred" by EOrg
gnunet-abd --createIssuerSide --ego=epub --attribute=$DISC_ATTR --subject="$EORG_KEY $PREF_ATTR" --ttl=5m -c test_abd_lookup.conf

# (2) EOrg assigns the attribute "preferred" to all entities that have been assigned "student" by StateU
gnunet-abd --createIssuerSide --ego=eorg --attribute=$PREF_ATTR --subject="$STATEU_KEY $STATE_STUD_ATTR" --ttl=5m -c test_abd_lookup.conf

# (3) StateU assigns the attribute "student" to all entities that have been asssigned "student" by RegistrarB
gnunet-abd --createIssuerSide --ego=stateu --attribute=$STATE_STUD_ATTR --subject="$REGISTRARB_KEY $REG_STUD_ATTR" --ttl=5m -c test_abd_lookup.conf

# (4) RegistrarB issues Alice the credential "student"
SIGNED=`$DO_TIMEOUT gnunet-abd --signSubjectSide --ego=registrarb --attribute="$REG_STUD_ATTR" --subject="$ALICE_KEY" --ttl="2019-12-12 10:00:00"`
gnunet-abd --createSubjectSide --ego=alice --import="$SIGNED" --private

# Starting to resolve
echo "+++ Starting to Resolve +++"

# FORWARD
#DELS=`$DO_TIMEOUT gnunet-abd --collect --issuer=$AKEY --attribute="a" --ego=g --forward -c test_abd_lookup.conf | paste -d, -s - -`
#echo $DELS
#echo gnunet-abd --verify --issuer=$AKEY --attribute="a" --subject=$GKEY --delegate=\'$DELS\' --forward -c test_abd_lookup.conf
#RES_DELS=`gnunet-abd --verify --issuer=$AKEY --attribute="a" --subject=$GKEY --delegate="$DELS" --forward -c test_abd_lookup.conf`

# BACKWARD
DELS=`$DO_TIMEOUT gnunet-abd --collect --issuer=$EPUB_KEY --attribute=$DISC_ATTR --ego=alice --backward -c test_abd_lookup.conf | paste -d, -s - -`
echo $DELS
echo gnunet-abd --verify --issuer=$EPUB_KEY --attribute=$DISC_ATTR --subject=$ALICE_KEY --delegate=\'$DELS\' --backward -c test_abd_lookup.conf
gnunet-abd --verify --issuer=$EPUB_KEY --attribute=$DISC_ATTR --subject=$ALICE_KEY --delegate="$DELS" --backward -c test_abd_lookup.conf

RES=$?

# Cleanup properly
gnunet-namestore -z epub -d -n $DISC_ATTR -t ATTR -c test_abd_lookup.conf
gnunet-namestore -z eorg -d -n $PREF_ATTR -t ATTR -c test_abd_lookup.conf
gnunet-namestore -z stateu -d -n $STATE_STUD_ATTR -t ATTR -c test_abd_lookup.conf
#gnunet-namestore -z a -d -n "@" -t DEL -c test_abd_lookup.conf
#gnunet-namestore -z d -d -n "@" -t DEL -c test_abd_lookup.conf
#gnunet-namestore -z e -d -n "@" -t DEL -c test_abd_lookup.conf
#gnunet-namestore -z f -d -n "@" -t DEL -c test_abd_lookup.conf
#gnunet-namestore -z g -d -n "@" -t DEL -c test_abd_lookup.conf


gnunet-arm -e -c test_abd_lookup.conf

if [ "$RES" == 0 ]
then
  exit 0
else
  echo "FAIL: Failed to verify credential."
  exit 1
fi

