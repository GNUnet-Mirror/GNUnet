#!/bin/sh
# This file is in the public domain.
trap "gnunet-arm -e -c test_gns_lookup.conf" INT
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

rm -rf `gnunet-config -c test_gns_lookup.conf -f -s paths -o GNUNET_TEST_HOME`

gns_link="http://localhost:7776/gns"
wrong_link="http://localhost:7776/gnsandmore"

curl_get () {
    #$1 is link
    #$2 is grep
    XURL=`which gnurl || which curl`
    if [ "" = "$XURL" ]
    then
        echo "HTTP client (curl/gnurl) not found, exiting"
        exit 77
    fi
    sleep 0.5
    cache="$(${XURL} -v "$1" 2>&1 | grep "$2")"
    #echo "$cache"
    if [ "" = "$cache" ]
    then
        gnunet-identity -D "$TEST_TLD" -c test_gns_lookup.conf > /dev/null 2>&1
        gnunet-arm -e -c test_gns_lookup.conf
        echo "Download of $1 using $XURL failed"
        exit 1
    fi
}
TEST_TLD="testtld"

gnunet-arm -s -c test_gns_lookup.conf
curl_get "$gns_link/www.$TEST_TLD" "error"

gnunet-identity -C "$TEST_TLD"  -c test_gns_lookup.conf
sleep 0.5
curl_get "$gns_link/www.$TEST_TLD" "\[\]"

gnunet-namestore -z "$TEST_TLD" -p -a -n www -e 1d -V 1.1.1.1 -t A -c test_gns_lookup.conf

curl_get "$gns_link/www.$TEST_TLD" "1.1.1.1"

gnunet-namestore -z "$TEST_TLD" -p -a -n www -e 1d -V 1::1 -t AAAA -c test_gns_lookup.conf

curl_get "$gns_link/www.$TEST_TLD" "1::1.*1.1.1.1"

gnunet-namestore -z "$TEST_TLD" -p -a -n www -e 1d -V 1.1.1.2 -t A -c test_gns_lookup.conf

curl_get "$gns_link/www.$TEST_TLD" "1.1.1.2.*1::1.*1.1.1.1"
curl_get "$gns_link/www.$TEST_TLD?record_type=A" "1.1.1.2.*1.1.1.1"
curl_get "$gns_link/www.$TEST_TLD?record_type=AAAA" "1::1"
curl_get "$gns_link/www.$TEST_TLD?record_type=WRONG_TYPE" "1.1.1.2.*1::1.*1.1.1.1"

gnunet-namestore -z "$TEST_TLD" -p -a -n www1 -e 1d -V 1.1.1.1 -t A -c test_gns_lookup.conf
curl_get "$gns_link/www1.$TEST_TLD" "1.1.1.1"

gnunet-namestore -z "$TEST_TLD" -d -n www1 -c test_gns_lookup.conf
gnunet-namestore -z "$TEST_TLD" -d -n www -c test_gns_lookup.conf

gnunet-identity -D "$TEST_TLD" -c test_gns_lookup.conf > /dev/null 2>&1

curl_get "$gns_link/www1.$TEST_TLD" "error"
gnunet-arm -e -c test_gns_lookup.conf
exit 0
