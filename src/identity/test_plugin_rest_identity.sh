#!/usr/bin/bash

#First, start gnunet-arm and the rest-service.
#Exit 0 means success, exit 1 means failed test

#No test for subsystem available

identity_link="http://localhost:7776/identity"
wrong_link="http://localhost:7776/identityandmore"


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

curl_put () {
    #$1 is link
    #$2 is data
    #$3 is grep
    cache="$(curl -v -X "PUT" "$1" --data "$2" 2>&1 | grep "$3")"
    #echo $cache
    if [ "" == "$cache" ]
    then
        exit 1
    fi
}

#Test GET
test="$(gnunet-identity -d)"
#if no identity exists
if [ "" == "$test" ]
then
    curl_get "$identity_link" "error"
    gnunet-identity -C "test_plugin_rest_identity"
    name="$(gnunet-identity -d | awk 'NR==1{print $1}')"
    public="$(gnunet-identity -d | awk 'NR==1{print $3}')"
    
    curl_get "${identity_link}?name=$name" "$public"
    curl_get "${identity_link}?name=" "error"
    curl_get "${identity_link}?name=$public" "error"
    
    curl_get "${identity_link}?pubkey=$public" "$name"
    curl_get "${identity_link}?pubkey=$name" "error"
    curl_get "${identity_link}?pubkey=" "error"
    
    gnunet-identity -D "test_plugin_rest_identity"
else
    name="$(gnunet-identity -d | awk 'NR==1{print $1}')"
    public="$(gnunet-identity -d | awk 'NR==1{print $3}')"
    
    curl_get "${identity_link}?name=$name" "$public"
    curl_get "${identity_link}?name=" "error"
    curl_get "${identity_link}?name=$public" "error"
    
    curl_get "${identity_link}?pubkey=$public" "$name"
    curl_get "${identity_link}?pubkey=$name" "error"
    curl_get "${identity_link}?pubkey=" "error"
fi

#Test POST
gnunet-identity -D "test_plugin_rest_identity" > /dev/null 2>&1
gnunet-identity -D "test_plugin_rest_identity1" > /dev/null 2>&1

curl_post "${identity_link}" '{"name":"test_plugin_rest_identity"}' "HTTP/1.1 201 Created"
curl_post "${identity_link}" '{"name":"test_plugin_rest_identity"}' "HTTP/1.1 409"
curl_post "${identity_link}" '{"name":"Test_plugin_rest_identity"}' "HTTP/1.1 409"
curl_post "${identity_link}" '{}' "error"
curl_post "${identity_link}" '' "error"
curl_post "${identity_link}" '{"name":""}' "error"
curl_post "${identity_link}" '{"name":123}' "error"
curl_post "${identity_link}" '{"name":[]}' "error"
curl_post "${identity_link}" '{"name1":"test_plugin_rest_identity"}' "error"
curl_post "${identity_link}" '{"other":""}' "error"
curl_post "${identity_link}" '{"name":"test_plugin_rest_identity1", "other":"test_plugin_rest_identity2"}' "error"

#Test PUT
name="$(gnunet-identity -d | grep "test_plugin_rest_identity" | awk 'NR==1{print $1}')"
public="$(gnunet-identity -d | grep "test_plugin_rest_identity" | awk 'NR==1{print $3}')"

curl_put "${identity_link}" '{"newname":"test_plugin_rest_identity1","pubkey":"'$public'"}' "HTTP/1.1 204"
curl_put "${identity_link}" '{"newname":"test_plugin_rest_identity1","pubkey":"'$public'"}' "HTTP/1.1 409"
curl_put "${identity_link}" '{"newname":"test_plugin_rest_identity1","pubkey":"'$public'xx"}' "HTTP/1.1 404"
curl_put "${identity_link}" '{"newname":"test_plugin_rest_identity1","pubkey":""}' "HTTP/1.1 404"
curl_put "${identity_link}" '{"newname":"test_plugin_rest_identity1","pubke":""}' "HTTP/1.1 404"
curl_put "${identity_link}" '{"newname":"test_plugin_rest_identity1","pubke":"","other":"sdfdsf"}' "HTTP/1.1 404"
curl_put "${identity_link}" '{"newname":"test_plugin_rest_identity1","pubke":"","name":"sdfdsf"}' "HTTP/1.1 404"
curl_put "${identity_link}" '{"newname":"test_plugin_rest_identity","pubke":"","name":"test_plugin_rest_identity1"}' "HTTP/1.1 204"
curl_put "${identity_link}" '{"newnam":"test_plugin_rest_identity","pubkey":"'$public'"}' "error"
curl_put "${identity_link}" '{"newname":"test_plugin_rest_identity1","name":"test_plugin_rest_identity"}' "HTTP/1.1 204"
curl_put "${identity_link}" '{"newname":"TEST_plugin_rest_identity1","name":"test_plugin_rest_identity1"}' "HTTP/1.1 409"
curl_put "${identity_link}" '{"newname":"test_plugin_rest_identity1","name":"test_plugin_rest_identity1"}' "HTTP/1.1 409"
curl_put "${identity_link}" '{"newname":"test_plugin_rest_identity","name":"test_plugin_rest_identityxxx"}' "HTTP/1.1 404"
curl_put "${identity_link}" '{"newname":"test_plugin_rest_identity","name":"test_plugin_rest_identity1"}' "HTTP/1.1 204"
curl_put "${identity_link}" '{"newnam":"test_plugin_rest_identityfail","name":"test_plugin_rest_identity"}' "error"


#Test subsystem
curl_put "${identity_link}" '{"subsystem":"namestore","name":"test_plugin_rest_identity"}' "HTTP/1.1 204"
curl_put "${identity_link}" '{"subsystem":"namestore","name":"test_plugin_rest_identity"}' "HTTP/1.1 204"
curl_get "${identity_link}?subsystem=namestore" "test_plugin_rest_identity"
curl_post "${identity_link}" '{"name":"test_plugin_rest_identity1"}' "HTTP/1.1 201 Created"
public="$(gnunet-identity -d | grep "test_plugin_rest_identity" | awk 'NR==1{print $3}')"
curl_put "${identity_link}" '{"subsystem":"namestore","pubkey":"'"$public"'"}' "HTTP/1.1 204"
curl_get "${identity_link}?subsystem=namestore" "test_plugin_rest_identity1"
curl_get "${identity_link}?subsystem=test_plugin_rest_identity_no_subsystem" "error"
curl_put "${identity_link}" '{"subsystem":"test_plugin_rest_identity_no_subsystem","name":"test_plugin_rest_identity1"}' "HTTP/1.1 204"
curl_get "${identity_link}?subsystem=test_plugin_rest_identity_no_subsystem" "test_plugin_rest_identity1"

curl_put "${identity_link}" '{"subsyste":"test_plugin_rest_identity_no_subsystem","name":"test_plugin_rest_identity1"}' "error"
curl_put "${identity_link}" '{"subsystem":"test_plugin_rest_identity_no_subsystem","name":"Test_plugin_rest_identity1"}' "HTTP/1.1 204"

#Test DELETE
curl_delete "${identity_link}?name=test_plugin_rest_identity" "HTTP/1.1 204"
curl_get "${identity_link}?name=test_plugin_rest_identity" "error"
curl_delete "${identity_link}?name=TEST_plugin_rest_identity1" "HTTP/1.1 404"
curl_delete "${identity_link}?name=test_plugin_rest_identity1" "HTTP/1.1 204"
curl_get "${identity_link}?name=test_plugin_rest_identity1" "error"
curl_delete "${identity_link}?name=test_plugin_rest_identity_not_found" "HTTP/1.1 404"
curl_post "${identity_link}" '{"name":"test_plugin_rest_identity1"}' "HTTP/1.1 201 Created"
public="$(gnunet-identity -d | grep "test_plugin_rest_identity1" | awk 'NR==1{print $3}')"
curl_delete "${identity_link}?pubkey=$public" "HTTP/1.1 204"
curl_delete "${identity_link}?pubke=$public" "error"
curl_delete "${identity_link}?pubkey=$public&other=232" "HTTP/1.1 404"

#Test wrong_link
curl_get "$wrong_link" "HTTP/1.1 404"
curl_post "$wrong_link" '{"name":"test_plugin_rest_identity"}' "HTTP/1.1 404"
curl_put "$wrong_link" '{"newname":"test_plugin_rest_identity1","name":"test_plugin_rest_identity"}' "HTTP/1.1 404"
curl_delete "$wrong_link?name=test_plugin_rest_identity1" "HTTP/1.1 404"

exit 0;
