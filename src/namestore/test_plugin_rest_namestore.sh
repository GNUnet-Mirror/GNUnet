#!/bin/sh
trap "gnunet-arm -e -c test_gns_lookup.conf" SIGINT

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

rm -rf `gnunet-config -c test_namestore_api.conf -f -s paths -o GNUNET_TEST_HOME`

namestore_link="http://localhost:7776/namestore"
wrong_link="http://localhost:7776/namestoreandmore"


curl_get () {
  #$1 is link
  #$2 is grep
  resp=$(curl -v "$1" 2>&1)
  cache="$(echo $resp | grep "$2")"
  #echo $cache
  if [ "" = "$cache" ]
  then
    echo "Error in get response: $resp, expected $2"
    gnunet-arm -e -c test_namestore_api.conf
    exit 1
  fi
}

curl_post () {
  #$1 is link
  #$2 is data
  #$3 is grep
  resp=$(curl -v -X "POST" "$1" --data "$2" 2>&1)
  cache="$(echo $resp | grep "$3")"
  #echo $cache
  if [ "" = "$cache" ]
  then
    echo "Error in post response: $resp ($2), expected $3"
    gnunet-arm -e -c test_namestore_api.conf
    exit 1
  fi
}

curl_delete () {
  #$1 is link
  #$2 is grep
  resp=$(curl -v -X "DELETE" "$1" 2>&1)
  cache="$(echo $resp | grep "$2")"
  #echo $cache
  if [ "" = "$cache" ]
  then
    echo "Error in delete response: $resp, expected $2"
    gnunet-arm -e -c test_namestore_api.conf
    exit 1
  fi
}

# curl_put () {
#     #$1 is link
#     #$2 is data
#     #$3 is grep
#     cache="$(curl -v -X "PUT" "$1" --data "$2" 2>&1 | grep "$3")"
#     #echo $cache
#     if [ "" == "$cache" ]
#     then
#         exit 1
#     fi
# }

#Test subsystem default identity

TEST_ID="test"
gnunet-arm -s -c test_namestore_api.conf
gnunet-arm -i rest -c test_namestore_api.conf
#Test GET
gnunet-identity -C $TEST_ID -c test_namestore_api.conf
test="$(gnunet-namestore -D -z $TEST_ID -c test_namestore_api.conf)"
name=$TEST_ID
public="$(gnunet-identity -d -c test_namestore_api.conf | grep $TEST_ID | awk 'NR==1{print $3}')"
gnunet-namestore -z $name -p -a -n "test_entry" -e "1d" -V "HVX38H2CB7WJM0WCPWT9CFX6GASMYJVR65RN75SJSSKAYVYXHMRG" -t "PKEY" -c test_namestore_api.conf
curl_get "${namestore_link}" "HTTP/1.1 200 OK"
curl_get "${namestore_link}/$name" "HTTP/1.1 200 OK"
curl_get "${namestore_link}/$public" "error"
gnunet-namestore -z $name -d -n "test_entry" -c test_namestore_api.conf

#Test POST with NAME
curl_post "${namestore_link}/$name" '{"data": [{"value":"HVX38H2CB7WJM0WCPWT9CFX6GASMYJVR65RN75SJSSKAYVYXHMRG", "record_type":"PKEY", "expiration_time":"1d","flag":0}],"record_name":"test_entry"}' "HTTP/1.1 204 No Content"
gnunet-namestore -z $name -d -n "test_entry" -c test_namestore_api.conf > /dev/null 2>&1

# invalid values
curl_post "${namestore_link}/$name" '{"data": [{"value":"HVX38H2CB7WJM0WCPWT9CFX6GASMYJVR65RN75SJSSKAYVYXHMRGxxx", "record_type":"PKEY", "expiration_time":"1d","flag":0}],"record_name":"test_entry"}' "error"
gnunet-namestore -z $name -d -n "test_entry" -c test_namestore_api.conf > /dev/null 2>&1


curl_post "${namestore_link}/$name" '{"data": [{"value":"", "record_type":"PKEY", "expiration_time":"1d","flag":0,"record_name"}]:"test_entry"}' "error"
gnunet-namestore -z $name -d -n "test_entry" -c test_namestore_api.conf > /dev/null 2>&1

curl_post "${namestore_link}/$name" '{"data": [{"record_type":"PKEY", "expiration_time":"1d","flag":0}],"record_name":"test_entry"}' "error"
gnunet-namestore -z $name -d -n "test_entry" -c test_namestore_api.conf > /dev/null 2>&1

#expirations
curl_post "${namestore_link}/$name" '{"data": [{"value":"HVX38H2CB7WJM0WCPWT9CFX6GASMYJVR65RN75SJSSKAYVYXHMRG", "record_type":"PKEY", "expiration_time":"0d","flag":0}],"record_name":"test_entry"}' "HTTP/1.1 204"
gnunet-namestore -z $name -d -n "test_entry" -c test_namestore_api.conf > /dev/null 2>&1

curl_post "${namestore_link}/$name" '{"data": [{"value":"HVX38H2CB7WJM0WCPWT9CFX6GASMYJVR65RN75SJSSKAYVYXHMRG", "record_type":"PKEY", "expiration_time":"10000d","flag":0}],"record_name":"test_entry"}' "HTTP/1.1 204"
gnunet-namestore -z $name -d -n "test_entry" -c test_namestore_api.conf > /dev/null 2>&1

curl_post "${namestore_link}/$name" '{"data": [{"value":"HVX38H2CB7WJM0WCPWT9CFX6GASMYJVR65RN75SJSSKAYVYXHMRG", "record_type":"PKEY", "expiration_time":"now","flag":0}],"record_name":"test_entry"}' "error"
gnunet-namestore -z $name -d -n "test_entry" -c test_namestore_api.conf > /dev/null 2>&1

curl_post "${namestore_link}/$name" '{"data": [{"value":"HVX38H2CB7WJM0WCPWT9CFX6GASMYJVR65RN75SJSSKAYVYXHMRG", "record_type":"PKEY", "expiration_time_missing":"1d","flag":0}],"record_name":"test_entry"}' "error"
gnunet-namestore -z $name -d -n "test_entry" -c test_namestore_api.conf > /dev/null 2>&1

#record_name
curl_post "${namestore_link}/$name" '{"data": [{"value":"HVX38H2CB7WJM0WCPWT9CFX6GASMYJVR65RN75SJSSKAYVYXHMRG", "record_type":"PKEY", "expiration_time":"1d","flag":0}],"record_name":""}' "error"
gnunet-namestore -z $name -d -n "test_entry"  -c test_namestore_api.conf > /dev/null 2>&1
curl_post "${namestore_link}/$name" '{"data": [{"value":"HVX38H2CB7WJM0WCPWT9CFX6GASMYJVR65RN75SJSSKAYVYXHMRG", "record_type":"PKEY", "expiration_time":"1d","flag":0}],"record_name_missing":"test_entry"}' "error"
gnunet-namestore -z $name -d -n "test_entry"  -c test_namestore_api.conf > /dev/null 2>&1

#Test DELETE
gnunet-namestore -z $name -p -a -n "test_entry" -e "1d" -V "HVX38H2CB7WJM0WCPWT9CFX6GASMYJVR65RN75SJSSKAYVYXHMRG" -t "PKEY"  -c test_namestore_api.conf
curl_delete "${namestore_link}/$name?record_name=test_entry" "HTTP/1.1 204" 
curl_delete "${namestore_link}/$name?record_name=test_entry" "error" 
gnunet-namestore -z $name -p -a -n "test_entry" -e "1d" -V "HVX38H2CB7WJM0WCPWT9CFX6GASMYJVR65RN75SJSSKAYVYXHMRG" -t "PKEY"  -c test_namestore_api.conf
curl_delete "${namestore_link}/$public?record_name=test_entry" "error" 

gnunet-arm -e  -c test_namestore_api.conf
exit 0;

