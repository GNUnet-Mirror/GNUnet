#!/usr/bin/bash

#First, start gnunet-arm and the rest-service. Make sure, no identity exists
#Exit 0 means success, exit 1 means failed test

#No test for subsystem available

link_to_api="http://localhost:7776/identity"
wrong_link="http://localhost:7776/idenmmmy"
wrong_link2="http://localhost:7776/identityandmore"

#Test GET (multiple identities) for error when no identity exists
#The next test case can be ignored if you have already added identities
cache="$(curl --silent "$link_to_api" | grep "error")"
if [ "" == "$cache" ]
then
    exit 1
fi

#Test POST success code, error response code and error json
#The next test case can be ignored if you have already added an identity with the name Test
cache="$(curl -v -X "POST" "$link_to_api" --data "{\"name\":\"Test\"}" 2>&1 | grep "HTTP/1.1 201")"
if [ "" == "$cache" ]
then
    exit 1
fi

cache="$(curl -v -X "POST" "$link_to_api" --data "{\"name\":\"Test\"}" 2>&1 | grep "HTTP/1.1 409")"
if [ "" == "$cache" ]
then
    exit 1
fi

cache="$(curl -v -X "POST" "$link_to_api" 2>&1 | grep "error")"
if [ "" == "$cache" ]
then
    exit 1
fi

cache="$(curl -v -X "POST" "$link_to_api" --data "wrong" 2>&1 | grep "error")"
if [ "" == "$cache" ]
then
    exit 1
fi

cache="$(curl -v -X "POST" "$link_to_api" --data "[{}]" 2>&1 | grep "error")"
if [ "" == "$cache" ]
then
    exit 1
fi

cache="$(curl -v -X "POST" "$link_to_api" --data "{\"name\":\"Test\",\"other\":\"Test\"}" 2>&1 | grep "error")"
if [ "" == "$cache" ]
then
    exit 1
fi

cache="$(curl -v -X "POST" "$link_to_api" --data "{\"nam\":\"Test\"}" 2>&1 | grep "error")"
if [ "" == "$cache" ]
then
    exit 1
fi

cache="$(curl -v -X "POST" "$link_to_api" --data "{\"name\":123}" 2>&1 | grep "error")"
if [ "" == "$cache" ]
then
    exit 1
fi

cache="$(curl -v -X "POST" "$link_to_api" --data "{\"name\":""}" 2>&1 | grep "error")"
if [ "" == "$cache" ]
then
    exit 1
fi


#Test GET (multiple identities) for success and error json
cache="$(curl --silent "$link_to_api" | grep "error")"
if [ "" != "$cache" ]
then
    exit 1
fi


id="$(gnunet-identity -d | grep "Test - " | sed  "s/Test - //g")"
#Test GET (one identity) for success and error json
cache="$(curl --silent "${link_to_api}?name=Test" | grep "error")"
if [ "" != "$cache" ]
then
    exit 1
fi
#Test GET (one identity) for success and error json
cache="$(curl --silent "${link_to_api}?pubkey=$id" | grep "error")"
if [ "" != "$cache" ]
then
    exit 1
fi


#Test DELETE success code, error response code and error json
#echo "Next tests for DELETE will probably fail when POST fails"
cache="$(curl -v -X "DELETE" "${link_to_api}?pubkey=$id" 2>&1 | grep "HTTP/1.1 404")"
if [ "" != "$cache" ]
then
    exit 1
fi

curl --silent -X "POST" "$link_to_api" --data "{\"name\":\"Test\"}"
id="$(gnunet-identity -d | grep "Test - " | sed  "s/Test - //g")"

cache="$(curl -v -X "DELETE" "${link_to_api}?pubkey=df1" 2>&1 | grep "HTTP/1.1 404")"
if [ "" == "$cache" ]
then
    exit 1
fi

cache="$(curl -v -X "DELETE" "${link_to_api}?pubke=$id" 2>&1 | grep "error")"
if [ "" == "$cache" ]
then
    exit 1
fi

#Test PUT success code, error response codes and error json
cache="$(curl -v -X "PUT" "${link_to_api}" --data "{\"newname\":\"NewTest\",\"pubkey\":\"${id}\"}" 2>&1 | grep "HTTP/1.1 204")"
if [ "" == "$cache" ]
then
    exit 1
fi

cache="$(curl -v -X "PUT" "${link_to_api}" --data "{\"newname\":\"NewNewTest\",\"pubkey\":\"${id}1\"}" 2>&1 | grep "HTTP/1.1 404")"
if [ "" == "$cache" ]
then
    exit 1
fi

# feature: you can rename your identity with its own name.
# cache="$(curl -v -X "PUT" "$link_to_api" --data "{\"newname\":\"NewTest\",\"pubkey\":\"${id}\"}" 2>&1 | grep "error")"
# if [ "" == "$cache" ]
# then
#     exit 1
# fi


cache="$(curl -v -X "PUT" "$link_to_api" 2>&1 | grep "error")"
if [ "" == "$cache" ]
then
    exit 1
fi

cache="$(curl -v -X "PUT" "$link_to_api" --data "wrong" 2>&1 | grep "error")"
if [ "" == "$cache" ]
then
    exit 1
fi

cache="$(curl -v -X "PUT" "$link_to_api" --data "[{}]" 2>&1 | grep "error")"
if [ "" == "$cache" ]
then
    exit 1
fi

cache="$(curl -v -X "PUT" "$link_to_api" --data "{\"newname\":\"Test\",\"other\":\"Test\",\"pubkey\":\"${id}\"}" 2>&1 | grep "error")"
if [ "" == "$cache" ]
then
    exit 1
fi

cache="$(curl -v -X "PUT" "$link_to_api" --data "{\"newnam\":\"Test\",\"pubkey\":\"${id}\"}" 2>&1 | grep "error")"
if [ "" == "$cache" ]
then
    exit 1
fi

cache="$(curl -v -X "PUT" "$link_to_api" --data "{\"newname\":\"Test\",\"pubke\":\"${id}\"}" 2>&1 | grep "error")"
if [ "" == "$cache" ]
then
    exit 1
fi

cache="$(curl -v -X "PUT" "$link_to_api" --data "{\"newname\":123,\"pubkey\":\"${id}\"}" 2>&1 | grep "error")"
if [ "" == "$cache" ]
then
    exit 1
fi

cache="$(curl -v -X "PUT" "$link_to_api" --data "{\"newname\":"",\"pubkey\":\"${id}\"}" 2>&1 | grep "error")"
if [ "" == "$cache" ]
then
    exit 1
fi
#TODO Missing subsystem test

#Missing OPTIONS success - nothing can really go wrong here

#Test wrong url
cache="$(curl -v "$wrong_link" 2>&1 | grep "HTTP/1.1 404")"
if [ "" == "$cache" ]
then
    exit 1
fi

cache="$(curl -X "PUT" -v "$wrong_link" --data "{\"newname\":\"Testing\",\"pubkey\":\"${id}\"}" 2>&1 | grep "HTTP/1.1 404")"
if [ "" == "$cache" ]
then
    exit 1
fi

cache="$(curl -X "POST" -v "$wrong_link?pubkey=$id" --data "{\"name\":\"Test\"}" 2>&1 | grep "HTTP/1.1 404")"
if [ "" == "$cache" ]
then
    exit 1
fi

cache="$(curl -X "DELETE" -v "${wrong_link}?pubkey=$id" 2>&1 | grep "HTTP/1.1 404")"
if [ "" == "$cache" ]
then
    exit 1
fi

gnunet-identity -D NewTest

exit 0
