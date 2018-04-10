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
gnunet-arm -s -c test_idp.conf 2&>1 > /dev/null
gnunet-identity -C alice -c test_idp.conf
gnunet-identity -C bob -c test_idp.conf
gnunet-identity -C eve -c test_idp.conf
ALICE_KEY=$(gnunet-identity -d -c test_idp.conf | grep alice | awk '{print $3}')
BOB_KEY=$(gnunet-identity -d -c test_idp.conf | grep bob | awk '{print $3}')
EVE_KEY=$(gnunet-identity -d -c test_idp.conf | grep eve | awk '{print $3}')

gnunet-idp -e alice -E 15s -a email -V john@doe.gnu -c test_idp.conf 
gnunet-idp -e alice -E 15s -a name -V John -c test_idp.conf
TICKET_BOB=$(gnunet-idp -e alice -i "email,name" -r $BOB_KEY -c test_idp.conf | awk '{print $1}')
#gnunet-idp -e bob -C $TICKET_BOB -c test_idp.conf
TICKET_EVE=$(gnunet-idp -e alice -i "email" -r $EVE_KEY -c test_idp.conf | awk '{print $1}')

#echo "Consuming $TICKET"
#gnunet-idp -e eve -C $TICKET_EVE -c test_idp.conf
gnunet-idp -e alice -R $TICKET_EVE -c test_idp.conf

#sleep 6

gnunet-idp -e eve -C $TICKET_EVE -c test_idp.conf 2&>1 >/dev/null
if test $? == 0
then 
  echo "Eve can still resolve attributes..."
  gnunet-arm -e -c test_idp.conf
  exit 1
fi

gnunet-arm -e -c test_idp.conf
gnunet-arm -s -c test_idp.conf 2&>1 > /dev/null

gnunet-idp -e bob -C $TICKET_BOB -c test_idp.conf 2&>1 >/dev/null
if test $? != 0
then
  echo "Bob cannot resolve attributes..."
  gnunet-arm -e -c test_idp.conf
  exit 1
fi

gnunet-arm -e -c test_idp.conf
