#!/bin/bash

# Check for required packages
if ! [ -x "$(command -v gnunet-namestore)" ]; then
    echo 'bind/named is not installed' >&2
    exit 1
fi

# Check if gnunet is running
gnunet-arm -I 2&>1 /dev/null
ret=$?
if [ 0 -ne $ret ]; then
    echo 'gnunet services are not running'
    exit 1
fi

## GNUNET part
# Check if identity exists and delets and readds it to get rid of entries in zone
gnunet-identity -d | grep randomtestingid 2>&1 /dev/null
ret=$?

if [ 0 -ne $ret ]; then
    gnunet-identity -D randomtestingid
    gnunet-identity -C randomtestingid
fi

function minimize_ttl {
    ttl=10000000
    arr=$1
    # parse each element and update ttl to smallest one
    for i in "${arr[@]}"
    do
        currttl=$(echo -n "$i" | cut -d' ' -f1)
        if [ "$currttl"  -lt "$ttl" ]
        then
            ttl=$currttl
        fi

    done
    echo "$ttl"
}

function get_record_type {
    arr=$1
    typ=$(echo -n "${arr[0]}" | cut -d' ' -f2)
    echo "$typ"
}

function get_value {
    arr=$1
    val=$(echo -n "${arr[0]}" | cut -d' ' -f4-)
    echo "$val"
}

function testing {
    label=$1
    records=$2
    recordstring=""
    typ=$(get_record_type "${records[@]}")
    for i in "${records[@]}"
    do
        recordstring+="-R $i"
    done
    #echo "$recordstring"
    gnunet-namestore -z randomtestingid -n "$label" "$recordstring" 2>&1  /dev/null
    if [ 0 -ne $ret ]; then
        echo "failed to add record $label: $recordstring"
    fi
    gnunet-gns -t "$typ" -u foo2.randomtestingid 2>&1 /dev/null
    if [ 0 -ne $ret ]; then
        echo "record $label could not be found"
    fi
}

# TEST CASES
# 1
echo "Testing adding of single A record with -R"
declare -a arr=('1200 A n 127.0.0.1')
testing test1 "${arr[@]}"
# 2
echo "Testing adding of multiple A records with -R"
declare -a arr=('1200 A n 127.0.0.1' '2400 A n 127.0.0.2')
testing test2 "${arr[@]}"
# 3
echo "Testing adding of multiple different records with -R"
declare -a arr=('1200 A n 127.0.0.1' '2400 AAAA n 2002::')
testing test3 "${arr[@]}"
# 4
echo "Testing adding of single GNS2DNS record with -R"
declare -a arr=('86400 GNS2DNS n gnu.org@127.0.0.1')
testing test4 "${arr[@]}"
# 5
echo "Testing adding of single GNS2DNS shadow record with -R"
declare -a arr=('86409 GNS2DNS s gnu.org@127.0.0.250')
testing test5 "${arr[@]}"
# 6
echo "Testing adding of multiple GNS2DNS record with -R"
declare -a arr=('1 GNS2DNS n gnunet.org@127.0.0.1' '3600 GNS2DNS s gnunet.org@127.0.0.2')
testing test6 "${arr[@]}"
val=$(gnunet-gns -t GNS2DNS -u test6.randomtestingid)
if [[ $val == *"127.0.0.1"* ]]; then
    echo "shadow!"
fi
echo "Sleeping to let record expire"
sleep 5
val=$(gnunet-gns -t GNS2DNS -u test6.randomtestingid)
if [[ $val == *"127.0.0.2"* ]]; then
    echo "no shadow!"
fi
# 7
echo "Testing adding MX record with -R"
declare -a arr=('3600 MX n 10,mail')
testing test7 "${arr[@]}"
# 8
echo "Testing adding TXT record with -R"
declare -a arr=('3600 TXT n Pretty_Unicorns')
testing test8 "${arr[@]}"
# 8
echo "Testing adding TXT record with -R"
declare -a arr=('3600 SRV n _autodiscover_old._tcp.bfh.ch.')
testing test8 "${arr[@]}"

# CLEANUP
gnunet-identity -D randomtestingid
