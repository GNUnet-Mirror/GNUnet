#!/usr/bin/bash

#First, start gnunet-arm and the rest-service.
#Exit 0 means success, exit 1 means failed test

gns_link="http://localhost:7776/gns"
wrong_link="http://localhost:7776/gnsandmore"

curl_get () {
    #$1 is link
    #$2 is grep
    cache="$(curl -v "$1" 2>&1 | grep "$2")"
    echo $cache
    if [ "" == "$cache" ]
    then
        exit 1
    fi
}

gnunet-identity -D "test_plugin_rest_gns" > /dev/null 2>&1

curl_get "$gns_link?name=www.test_plugin_rest_gns" "error"

gnunet-identity -C "test_plugin_rest_gns"

curl_get "$gns_link?name=www.test_plugin_rest_gns" "\[\]"

gnunet-namestore -z "test_plugin_rest_gns" -p -a -n www -e 1d -V 1.1.1.1 -t A

curl_get "$gns_link?name=www.test_plugin_rest_gns" "1.1.1.1"

gnunet-namestore -z "test_plugin_rest_gns" -p -a -n www -e 1d -V 1::1 -t AAAA

curl_get "$gns_link?name=www.test_plugin_rest_gns" "1::1.*1.1.1.1"

gnunet-namestore -z "test_plugin_rest_gns" -p -a -n www -e 1d -V 1.1.1.2 -t A

curl_get "$gns_link?name=www.test_plugin_rest_gns" "1.1.1.2.*1::1.*1.1.1.1"
curl_get "$gns_link?name=www.test_plugin_rest_gns&record_type=A" "1.1.1.2.*1.1.1.1"
curl_get "$gns_link?name=www.test_plugin_rest_gns&record_type=AAAA" "1::1"
curl_get "$gns_link?name=www.test_plugin_rest_gns&record_type=WRONG_TYPE" "1.1.1.2.*1::1.*1.1.1.1"

gnunet-namestore -z "test_plugin_rest_gns" -p -a -n www1 -e 1d -V 1.1.1.1 -t A
curl_get "$gns_link?name=www1.test_plugin_rest_gns" "1.1.1.1"

gnunet-identity -D "test_plugin_rest_gns"

curl_get "$gns_link?name=www1.test_plugin_rest_gns" "error"

exit 0
