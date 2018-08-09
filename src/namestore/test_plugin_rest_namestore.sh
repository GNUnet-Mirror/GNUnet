#!/usr/bin/bash

#First, start gnunet-arm and the rest-service.
#Exit 0 means success, exit 1 means failed test

namestore_link="http://localhost:7776/namestore"
wrong_link="http://localhost:7776/namestoreandmore"


curl_get () {
    #$1 is link
    #$2 is grep
    cache="$(curl -v "$1" 2>&1 | grep "$2")"
    #echo $cache
    if [ "" == "$cache" ]
    then
        exit 1
    fi
}

curl_post () {
    #$1 is link
    #$2 is data
    #$3 is grep
    cache="$(curl -v -X "POST" "$1" --data "$2" 2>&1 | grep "$3")"
    #echo $cache
    if [ "" == "$cache" ]
    then
        exit 1
    fi
}

curl_delete () {
    #$1 is link
    #$2 is grep
    cache="$(curl -v -X "DELETE" "$1" 2>&1 | grep "$2")"
    #echo $cache
    if [ "" == "$cache" ]
    then
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

#Test GET
gnunet-identity -D "test_plugin_rest_namestore"
gnunet-identity -C "test_plugin_rest_namestore"
test="$(gnunet-namestore -D -z "test_plugin_rest_namestore")"
name="test_plugin_rest_namestore"
public="$(gnunet-identity -d | grep "test_plugin_rest_namestore" | awk 'NR==1{print $3}')"
if [ "" == "$test" ]
then
    #if no entries for test_plugin_rest_namestore
    curl_get "${namestore_link}?name=$name" "error"
    curl_get "${namestore_link}?name=" "error"
    curl_get "${namestore_link}?name=$public" "error"
    
    curl_get "${namestore_link}?pubkey=$public" "error"
    curl_get "${namestore_link}?pubkey=$name" "error"
    curl_get "${namestore_link}?pubkey=" "error"
else
    #if entries exists (that should not be possible)
    curl_get "${namestore_link}" "HTTP/1.1 200 OK"
    curl_get "${namestore_link}?name=$name" "HTTP/1.1 200 OK"
    curl_get "${namestore_link}?name=" "error"
    curl_get "${namestore_link}?name=$public" "error"
    
    curl_get "${namestore_link}?pubkey=$public" "HTTP/1.1 200 OK"
    curl_get "${namestore_link}?pubkey=$name" "error"
    curl_get "${namestore_link}?pubkey=" "error"
fi
gnunet-namestore -z $name -p -a -n "test_entry" -e "1d" -V "HVX38H2CB7WJM0WCPWT9CFX6GASMYJVR65RN75SJSSKAYVYXHMRG" -t "PKEY"
curl_get "${namestore_link}" "HTTP/1.1 200 OK"
curl_get "${namestore_link}?name=$name" "HTTP/1.1 200 OK"
curl_get "${namestore_link}?name=" "error"
curl_get "${namestore_link}?name=$public" "error"
curl_get "${namestore_link}?pubkey=$public" "HTTP/1.1 200 OK"
curl_get "${namestore_link}?pubkey=$name" "error"
curl_get "${namestore_link}?pubkey=" "error"
gnunet-namestore -z $name -d -n "test_entry"

#Test POST with NAME
curl_post "${namestore_link}?name=$name" '{"value":"HVX38H2CB7WJM0WCPWT9CFX6GASMYJVR65RN75SJSSKAYVYXHMRG", "type":"PKEY", "expiration_time":"1d","flag":0,"label":"test_entry"}' "HTTP/1.1 204 No Content"
gnunet-namestore -z $name -d -n "test_entry" > /dev/null 2>&1
#value
curl_post "${namestore_link}?name=$name" '{"value":"HVX38H2CB7WJM0WCPWT9CFX6GASMYJVR65RN75SJSSKAYVYXHMRGxxx", "type":"PKEY", "expiration_time":"1d","flag":0,"label":"test_entry"}' "error"
gnunet-namestore -z $name -d -n "test_entry" > /dev/null 2>&1
curl_post "${namestore_link}?name=$name" '{"value":"", "type":"PKEY", "expiration_time":"1d","flag":0,"label":"test_entry"}' "error"
gnunet-namestore -z $name -d -n "test_entry" > /dev/null 2>&1
curl_post "${namestore_link}?name=$name" '{"value_missing":"HVX38H2CB7WJM0WCPWT9CFX6GASMYJVR65RN75SJSSKAYVYXHMRGxxx", "type":"PKEY", "expiration_time":"1d","flag":0,"label":"test_entry"}' "error"
gnunet-namestore -z $name -d -n "test_entry" > /dev/null 2>&1
#time
curl_post "${namestore_link}?name=$name" '{"value":"HVX38H2CB7WJM0WCPWT9CFX6GASMYJVR65RN75SJSSKAYVYXHMRG", "type":"PKEY", "expiration_time":"0d","flag":0,"label":"test_entry"}' "HTTP/1.1 204"
gnunet-namestore -z $name -d -n "test_entry" > /dev/null 2>&1
curl_post "${namestore_link}?name=$name" '{"value":"HVX38H2CB7WJM0WCPWT9CFX6GASMYJVR65RN75SJSSKAYVYXHMRG", "type":"PKEY", "expiration_time":"10000d","flag":0,"label":"test_entry"}' "HTTP/1.1 204"
gnunet-namestore -z $name -d -n "test_entry" > /dev/null 2>&1
curl_post "${namestore_link}?name=$name" '{"value":"HVX38H2CB7WJM0WCPWT9CFX6GASMYJVR65RN75SJSSKAYVYXHMRG", "type":"PKEY", "expiration_time":"now","flag":0,"label":"test_entry"}' "error"
gnunet-namestore -z $name -d -n "test_entry" > /dev/null 2>&1
curl_post "${namestore_link}?name=$name" '{"value":"HVX38H2CB7WJM0WCPWT9CFX6GASMYJVR65RN75SJSSKAYVYXHMRG", "type":"PKEY", "expiration_time":"","flag":0,"label":"test_entry"}' "error"
gnunet-namestore -z $name -d -n "test_entry" > /dev/null 2>&1
curl_post "${namestore_link}?name=$name" '{"value":"HVX38H2CB7WJM0WCPWT9CFX6GASMYJVR65RN75SJSSKAYVYXHMRG", "type":"PKEY", "expiration_time_missing":"1d","flag":0,"label":"test_entry"}' "error"
gnunet-namestore -z $name -d -n "test_entry" > /dev/null 2>&1
#flag
curl_post "${namestore_link}?name=$name" '{"value":"HVX38H2CB7WJM0WCPWT9CFX6GASMYJVR65RN75SJSSKAYVYXHMRG", "type":"PKEY", "expiration_time":"1d","flag":0,"label":"test_entry"}' "HTTP/1.1 204 No Content"
gnunet-namestore -z $name -d -n "test_entry" > /dev/null 2>&1
curl_post "${namestore_link}?name=$name" '{"value":"HVX38H2CB7WJM0WCPWT9CFX6GASMYJVR65RN75SJSSKAYVYXHMRG", "type":"PKEY", "expiration_time":"1d","flag":2,"label":"test_entry"}' "HTTP/1.1 204 No Content"
gnunet-namestore -z $name -d -n "test_entry" > /dev/null 2>&1
curl_post "${namestore_link}?name=$name" '{"value":"HVX38H2CB7WJM0WCPWT9CFX6GASMYJVR65RN75SJSSKAYVYXHMRG", "type":"PKEY", "expiration_time":"1d","flag":8,"label":"test_entry"}' "HTTP/1.1 204 No Content"
gnunet-namestore -z $name -d -n "test_entry" > /dev/null 2>&1
curl_post "${namestore_link}?name=$name" '{"value":"HVX38H2CB7WJM0WCPWT9CFX6GASMYJVR65RN75SJSSKAYVYXHMRG", "type":"PKEY", "expiration_time":"1d","flag":16,"label":"test_entry"}' "HTTP/1.1 204 No Content"
gnunet-namestore -z $name -d -n "test_entry" > /dev/null 2>&1
curl_post "${namestore_link}?name=$name" '{"value":"HVX38H2CB7WJM0WCPWT9CFX6GASMYJVR65RN75SJSSKAYVYXHMRG", "type":"PKEY", "expiration_time":"1d","flag":-1,"label":"test_entry"}' "error"
gnunet-namestore -z $name -d -n "test_entry" > /dev/null 2>&1
curl_post "${namestore_link}?name=$name" '{"value":"HVX38H2CB7WJM0WCPWT9CFX6GASMYJVR65RN75SJSSKAYVYXHMRG", "type":"PKEY", "expiration_time":"1d","flag":"Test","label":"test_entry"}' "error"
gnunet-namestore -z $name -d -n "test_entry" > /dev/null 2>&1
curl_post "${namestore_link}?name=$name" '{"value":"HVX38H2CB7WJM0WCPWT9CFX6GASMYJVR65RN75SJSSKAYVYXHMRG", "type":"PKEY", "expiration_time":"1d","flag":,"label":"test_entry"}' "error"
gnunet-namestore -z $name -d -n "test_entry" > /dev/null 2>&1
curl_post "${namestore_link}?name=$name" '{"value":"HVX38H2CB7WJM0WCPWT9CFX6GASMYJVR65RN75SJSSKAYVYXHMRG", "type":"PKEY", "expiration_time":"1d","flag_missing":0,"label":"test_entry"}' "error"
gnunet-namestore -z $name -d -n "test_entry" > /dev/null 2>&1
#label
curl_post "${namestore_link}?name=$name" '{"value":"HVX38H2CB7WJM0WCPWT9CFX6GASMYJVR65RN75SJSSKAYVYXHMRG", "type":"PKEY", "expiration_time":"1d","flag":0,"label":"test_entry"}' "HTTP/1.1 204 No Content"
curl_post "${namestore_link}?name=$name" '{"value":"HVX38H2CB7WJM0WCPWT9CFX6GASMYJVR65RN75SJSSKAYVYXHMRG", "type":"PKEY", "expiration_time":"1d","flag":0,"label":"test_entry"}' "HTTP/1.1 409"
gnunet-namestore -z $name -d -n "test_entry" > /dev/null 2>&1
curl_post "${namestore_link}?name=$name" '{"value":"HVX38H2CB7WJM0WCPWT9CFX6GASMYJVR65RN75SJSSKAYVYXHMRG", "type":"PKEY", "expiration_time":"1d","flag":0,"label":""}' "error"
gnunet-namestore -z $name -d -n "test_entry" > /dev/null 2>&1
curl_post "${namestore_link}?name=$name" '{"value":"HVX38H2CB7WJM0WCPWT9CFX6GASMYJVR65RN75SJSSKAYVYXHMRG", "type":"PKEY", "expiration_time":"1d","flag":0,"label_missing":"test_entry"}' "error"
gnunet-namestore -z $name -d -n "test_entry" > /dev/null 2>&1

#Test POST with PUBKEY
curl_post "${namestore_link}?pubkey=$public" '{"value":"HVX38H2CB7WJM0WCPWT9CFX6GASMYJVR65RN75SJSSKAYVYXHMRG", "type":"PKEY", "expiration_time":"1d","flag":0,"label":"test_entry"}' "HTTP/1.1 204 No Content"
gnunet-namestore -z $name -d -n "test_entry" > /dev/null 2>&1
#value
curl_post "${namestore_link}?pubkey=$public" '{"value":"HVX38H2CB7WJM0WCPWT9CFX6GASMYJVR65RN75SJSSKAYVYXHMRGxxx", "type":"PKEY", "expiration_time":"1d","flag":0,"label":"test_entry"}' "error"
gnunet-namestore -z $name -d -n "test_entry" > /dev/null 2>&1
curl_post "${namestore_link}?pubkey=$public" '{"value":"", "type":"PKEY", "expiration_time":"1d","flag":0,"label":"test_entry"}' "error"
gnunet-namestore -z $name -d -n "test_entry" > /dev/null 2>&1
curl_post "${namestore_link}?pubkey=$public" '{"value_missing":"HVX38H2CB7WJM0WCPWT9CFX6GASMYJVR65RN75SJSSKAYVYXHMRGxxx", "type":"PKEY", "expiration_time":"1d","flag":0,"label":"test_entry"}' "error"
gnunet-namestore -z $name -d -n "test_entry" > /dev/null 2>&1
#time
curl_post "${namestore_link}?pubkey=$public" '{"value":"HVX38H2CB7WJM0WCPWT9CFX6GASMYJVR65RN75SJSSKAYVYXHMRG", "type":"PKEY", "expiration_time":"0d","flag":0,"label":"test_entry"}' "HTTP/1.1 204"
gnunet-namestore -z $name -d -n "test_entry" > /dev/null 2>&1
curl_post "${namestore_link}?pubkey=$public" '{"value":"HVX38H2CB7WJM0WCPWT9CFX6GASMYJVR65RN75SJSSKAYVYXHMRG", "type":"PKEY", "expiration_time":"10000d","flag":0,"label":"test_entry"}' "HTTP/1.1 204"
gnunet-namestore -z $name -d -n "test_entry" > /dev/null 2>&1
curl_post "${namestore_link}?pubkey=$public" '{"value":"HVX38H2CB7WJM0WCPWT9CFX6GASMYJVR65RN75SJSSKAYVYXHMRG", "type":"PKEY", "expiration_time":"now","flag":0,"label":"test_entry"}' "error"
gnunet-namestore -z $name -d -n "test_entry" > /dev/null 2>&1
curl_post "${namestore_link}?pubkey=$public" '{"value":"HVX38H2CB7WJM0WCPWT9CFX6GASMYJVR65RN75SJSSKAYVYXHMRG", "type":"PKEY", "expiration_time":"","flag":0,"label":"test_entry"}' "error"
gnunet-namestore -z $name -d -n "test_entry" > /dev/null 2>&1
curl_post "${namestore_link}?pubkey=$public" '{"value":"HVX38H2CB7WJM0WCPWT9CFX6GASMYJVR65RN75SJSSKAYVYXHMRG", "type":"PKEY", "expiration_time_missing":"1d","flag":0,"label":"test_entry"}' "error"
gnunet-namestore -z $name -d -n "test_entry" > /dev/null 2>&1
#flag
curl_post "${namestore_link}?pubkey=$public" '{"value":"HVX38H2CB7WJM0WCPWT9CFX6GASMYJVR65RN75SJSSKAYVYXHMRG", "type":"PKEY", "expiration_time":"1d","flag":0,"label":"test_entry"}' "HTTP/1.1 204 No Content"
gnunet-namestore -z $name -d -n "test_entry" > /dev/null 2>&1
curl_post "${namestore_link}?pubkey=$public" '{"value":"HVX38H2CB7WJM0WCPWT9CFX6GASMYJVR65RN75SJSSKAYVYXHMRG", "type":"PKEY", "expiration_time":"1d","flag":2,"label":"test_entry"}' "HTTP/1.1 204 No Content"
gnunet-namestore -z $name -d -n "test_entry" > /dev/null 2>&1
curl_post "${namestore_link}?pubkey=$public" '{"value":"HVX38H2CB7WJM0WCPWT9CFX6GASMYJVR65RN75SJSSKAYVYXHMRG", "type":"PKEY", "expiration_time":"1d","flag":8,"label":"test_entry"}' "HTTP/1.1 204 No Content"
gnunet-namestore -z $name -d -n "test_entry" > /dev/null 2>&1
curl_post "${namestore_link}?pubkey=$public" '{"value":"HVX38H2CB7WJM0WCPWT9CFX6GASMYJVR65RN75SJSSKAYVYXHMRG", "type":"PKEY", "expiration_time":"1d","flag":16,"label":"test_entry"}' "HTTP/1.1 204 No Content"
gnunet-namestore -z $name -d -n "test_entry" > /dev/null 2>&1
curl_post "${namestore_link}?pubkey=$public" '{"value":"HVX38H2CB7WJM0WCPWT9CFX6GASMYJVR65RN75SJSSKAYVYXHMRG", "type":"PKEY", "expiration_time":"1d","flag":-1,"label":"test_entry"}' "error"
gnunet-namestore -z $name -d -n "test_entry" > /dev/null 2>&1
curl_post "${namestore_link}?pubkey=$public" '{"value":"HVX38H2CB7WJM0WCPWT9CFX6GASMYJVR65RN75SJSSKAYVYXHMRG", "type":"PKEY", "expiration_time":"1d","flag":"Test","label":"test_entry"}' "error"
gnunet-namestore -z $name -d -n "test_entry" > /dev/null 2>&1
curl_post "${namestore_link}?pubkey=$public" '{"value":"HVX38H2CB7WJM0WCPWT9CFX6GASMYJVR65RN75SJSSKAYVYXHMRG", "type":"PKEY", "expiration_time":"1d","flag":,"label":"test_entry"}' "error"
gnunet-namestore -z $name -d -n "test_entry" > /dev/null 2>&1
curl_post "${namestore_link}?pubkey=$public" '{"value":"HVX38H2CB7WJM0WCPWT9CFX6GASMYJVR65RN75SJSSKAYVYXHMRG", "type":"PKEY", "expiration_time":"1d","flag_missing":0,"label":"test_entry"}' "error"
gnunet-namestore -z $name -d -n "test_entry" > /dev/null 2>&1
#label
curl_post "${namestore_link}?pubkey=$public" '{"value":"HVX38H2CB7WJM0WCPWT9CFX6GASMYJVR65RN75SJSSKAYVYXHMRG", "type":"PKEY", "expiration_time":"1d","flag":0,"label":"test_entry"}' "HTTP/1.1 204 No Content"
curl_post "${namestore_link}?pubkey=$public" '{"value":"HVX38H2CB7WJM0WCPWT9CFX6GASMYJVR65RN75SJSSKAYVYXHMRG", "type":"PKEY", "expiration_time":"1d","flag":0,"label":"test_entry"}' "HTTP/1.1 409"
gnunet-namestore -z $name -d -n "test_entry" > /dev/null 2>&1
curl_post "${namestore_link}?pubkey=$public" '{"value":"HVX38H2CB7WJM0WCPWT9CFX6GASMYJVR65RN75SJSSKAYVYXHMRG", "type":"PKEY", "expiration_time":"1d","flag":0,"label":""}' "error"
gnunet-namestore -z $name -d -n "test_entry" > /dev/null 2>&1
curl_post "${namestore_link}?pubkey=$public" '{"value":"HVX38H2CB7WJM0WCPWT9CFX6GASMYJVR65RN75SJSSKAYVYXHMRG", "type":"PKEY", "expiration_time":"1d","flag":0,"label_missing":"test_entry"}' "error"
gnunet-namestore -z $name -d -n "test_entry" > /dev/null 2>&1

#wrong zone
curl_post "${namestore_link}?name=$public" '{"value":"HVX38H2CB7WJM0WCPWT9CFX6GASMYJVR65RN75SJSSKAYVYXHMRG", "type":"PKEY", "expiration_time":"1d","flag":0,"label":"test_entry"}' "error"
gnunet-namestore -z $name -d -n "test_entry" > /dev/null 2>&1
curl_post "${namestore_link}?pubkey=$name" '{"value":"HVX38H2CB7WJM0WCPWT9CFX6GASMYJVR65RN75SJSSKAYVYXHMRG", "type":"PKEY", "expiration_time":"1d","flag":0,"label":"test_entry"}' "error"
gnunet-namestore -z $name -d -n "test_entry" > /dev/null 2>&1

#Test DELETE
gnunet-namestore -z $name -p -a -n "test_entry" -e "1d" -V "HVX38H2CB7WJM0WCPWT9CFX6GASMYJVR65RN75SJSSKAYVYXHMRG" -t "PKEY"
curl_delete "${namestore_link}?label=test_entry&name=$name" "HTTP/1.1 204" 
gnunet-namestore -z $name -p -a -n "test_entry" -e "1d" -V "HVX38H2CB7WJM0WCPWT9CFX6GASMYJVR65RN75SJSSKAYVYXHMRG" -t "PKEY"
curl_delete "${namestore_link}?label=test_entry&pubkey=$public" "HTTP/1.1 204" 
gnunet-namestore -z $name -p -a -n "test_entry" -e "1d" -V "HVX38H2CB7WJM0WCPWT9CFX6GASMYJVR65RN75SJSSKAYVYXHMRG" -t "PKEY"
curl_delete "${namestore_link}?label=test_entry&pubkey=$name" "HTTP/1.1 404" 


#Test default identity
#not possible without defining 

exit 0;

