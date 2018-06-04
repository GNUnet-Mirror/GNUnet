#!/usr/bin/bash

#First, start gnunet-arm and the rest-service. Make sure, no identity exists

link_to_api="http://localhost:7776/identity"
wrong_link="http://localhost:7776/idenmmmy"

#Test GET (multiple identities) for error when no identity exists

echo "No test for subsystem available"
echo "The next test case can be ignored if you have already added identities"
cache="$(curl --silent "$link_to_api" | grep "error")"
if [ "" == "$cache" ]
then
    echo -n -e "[\033[0;31m FAILURE\033[0m ] Success for GET request when missing identity\n"
else
    echo -n -e "[\033[0;32m SUCCESS\033[0m ] Error for GET request when missing identity\n"
fi

#Test POST success code, error response code and error json
echo "The next test case can be ignored if you have already added an identity with the name Test"
cache="$(curl -v -X "POST" "$link_to_api" --data "{\"name\":\"Test\"}" 2>&1 | grep "HTTP/1.1 201")"
if [ "" == "$cache" ]
then
    echo -n -e "[\033[0;31m FAILURE\033[0m ] Error for good POST request\n"
else
    echo -n -e "[\033[0;32m SUCCESS\033[0m ] Success for good POST request\n"
fi

cache="$(curl -v -X "POST" "$link_to_api" --data "{\"name\":\"Test\"}" 2>&1 | grep "HTTP/1.1 409")"
if [ "" == "$cache" ]
then
    echo -n -e "[\033[0;31m FAILURE\033[0m ] Success for duplicate name POST request\n"
else
    echo -n -e "[\033[0;32m SUCCESS\033[0m ] Error for duplicate name POST request\n"
fi

cache="$(curl -v -X "POST" "$link_to_api" 2>&1 | grep "error")"
if [ "" == "$cache" ]
then
    echo -n -e "[\033[0;31m FAILURE\033[0m ] Success for no data POST request\n"
else
    echo -n -e "[\033[0;32m SUCCESS\033[0m ] Error for no data POST request\n"
fi

cache="$(curl -v -X "POST" "$link_to_api" --data "wrong" 2>&1 | grep "error")"
if [ "" == "$cache" ]
then
    echo -n -e "[\033[0;31m FAILURE\033[0m ] Success for wrong data POST request\n"
else
    echo -n -e "[\033[0;32m SUCCESS\033[0m ] Error for wrong data POST request\n"
fi

cache="$(curl -v -X "POST" "$link_to_api" --data "[{}]" 2>&1 | grep "error")"
if [ "" == "$cache" ]
then
    echo -n -e "[\033[0;31m FAILURE\033[0m ] Success for json array input POST request\n"
else
    echo -n -e "[\033[0;32m SUCCESS\033[0m ] Error for json array input POST request\n"
fi

cache="$(curl -v -X "POST" "$link_to_api" --data "{\"name\":\"Test\",\"other\":\"Test\"}" 2>&1 | grep "error")"
if [ "" == "$cache" ]
then
    echo -n -e "[\033[0;31m FAILURE\033[0m ] Success for multi element json POST request\n"
else
    echo -n -e "[\033[0;32m SUCCESS\033[0m ] Error for multi element json POST request\n"
fi

cache="$(curl -v -X "POST" "$link_to_api" --data "{\"nam\":\"Test\"}" 2>&1 | grep "error")"
if [ "" == "$cache" ]
then
    echo -n -e "[\033[0;31m FAILURE\033[0m ] Success for wrong json POST request\n"
else
    echo -n -e "[\033[0;32m SUCCESS\033[0m ] Error for wrong json POST request\n"
fi

cache="$(curl -v -X "POST" "$link_to_api" --data "{\"name\":123}" 2>&1 | grep "error")"
if [ "" == "$cache" ]
then
    echo -n -e "[\033[0;31m FAILURE\033[0m ] Success for wrong json type POST request\n"
else
    echo -n -e "[\033[0;32m SUCCESS\033[0m ] Error for wrong json type POST request\n"
fi

cache="$(curl -v -X "POST" "$link_to_api" --data "{\"name\":""}" 2>&1 | grep "error")"
if [ "" == "$cache" ]
then
    echo -n -e "[\033[0;31m FAILURE\033[0m ] Success for no name POST request\n"
else
    echo -n -e "[\033[0;32m SUCCESS\033[0m ] Error for no name POST request\n"
fi


#Test GET (multiple identities) for success and error json
cache="$(curl --silent "$link_to_api" | grep "error")"
if [ "" == "$cache" ]
then
    echo -n -e "[\033[0;32m SUCCESS\033[0m ] Success for good GET request (multiple identities)\n"
else
    echo -n -e "[\033[0;31m FAILURE\033[0m ] Error for good GET request (multiple identities)\n"
fi


id="$(gnunet-identity -d | grep "Test - " | sed  "s/Test - //g")"
#Test GET (one identity) for success and error json
cache="$(curl --silent "${link_to_api}/$id" | grep "error")"
if [ "" == "$cache" ]
then
    echo -n -e "[\033[0;32m SUCCESS\033[0m ] Success for good GET request (one identity)\n"
else
    echo -n -e "[\033[0;31m FAILURE\033[0m ] Error for good GET request (one identity)\n"
fi


#Test DELETE success code, error response code and error json
echo "Next tests for DELETE will probably fail when POST fails"
cache="$(curl -v -X "DELETE" "${link_to_api}/$id" 2>&1 | grep "HTTP/1.1 404")"
if [ "" == "$cache" ]
then
    echo -n -e "[\033[0;32m SUCCESS\033[0m ] Success for good DELETE request\n"
else
    echo -n -e "[\033[0;31m FAILURE\033[0m ] Error for good DELETE request\n"
fi

curl --silent -X "POST" "$link_to_api" --data "{\"name\":\"Test\"}"
id="$(gnunet-identity -d | grep "Test - " | sed  "s/Test - //g")"

cache="$(curl -v -X "DELETE" "${link_to_api}/df1" 2>&1 | grep "HTTP/1.1 404")"
if [ "" == "$cache" ]
then
    echo -n -e "[\033[0;31m FAILURE\033[0m ] Success for wrong DELETE request\n"
else
    echo -n -e "[\033[0;32m SUCCESS\033[0m ] Error for wrong DELETE request\n"
fi

#Test PUT success code, error response codes and error json
cache="$(curl -v -X "PUT" "${link_to_api}/$id" --data "{\"newname\":\"NewTest\"}" 2>&1 | grep "HTTP/1.1 204")"
if [ "" == "$cache" ]
then
    echo -n -e "[\033[0;31m FAILURE\033[0m ] Error for good PUT request\n"
else
    echo -n -e "[\033[0;32m SUCCESS\033[0m ] Success for good PUT request\n"
fi

cache="$(curl -v -X "PUT" "${link_to_api}/${id}1" --data "{\"newname\":\"NewNewTest\"}" 2>&1 | grep "HTTP/1.1 404")"
if [ "" == "$cache" ]
then
    echo -n -e "[\033[0;31m FAILURE\033[0m ] Success for wrong identity PUT request\n"
else
    echo -n -e "[\033[0;32m SUCCESS\033[0m ] Error for wrong identity PUT request\n"
fi

cache="$(curl -v -X "PUT" "$link_to_api/$id" --data "{\"newname\":\"NewTest\"}" 2>&1 | grep "error")"
if [ "" == "$cache" ]
then
    echo -n -e "[\033[0;31m FAILURE\033[0m ] Success for duplicate name PUT request\n"
else
    echo -n -e "[\033[0;32m SUCCESS\033[0m ] Error for duplicate name PUT request\n"
fi

cache="$(curl -v -X "PUT" "$link_to_api/$id" 2>&1 | grep "error")"
if [ "" == "$cache" ]
then
    echo -n -e "[\033[0;31m FAILURE\033[0m ] Success for no data PUT request\n"
else
    echo -n -e "[\033[0;32m SUCCESS\033[0m ] Error for no data PUT request\n"
fi

cache="$(curl -v -X "PUT" "$link_to_api/$id" --data "wrong" 2>&1 | grep "error")"
if [ "" == "$cache" ]
then
    echo -n -e "[\033[0;31m FAILURE\033[0m ] Success for wrong data PUT request\n"
else
    echo -n -e "[\033[0;32m SUCCESS\033[0m ] Error for wrong data PUT request\n"
fi

cache="$(curl -v -X "PUT" "$link_to_api/$id" --data "[{}]" 2>&1 | grep "error")"
if [ "" == "$cache" ]
then
    echo -n -e "[\033[0;31m FAILURE\033[0m ] Success for json array input PUT request\n"
else
    echo -n -e "[\033[0;32m SUCCESS\033[0m ] Error for json array input PUT request\n"
fi

cache="$(curl -v -X "PUT" "$link_to_api/$id" --data "{\"newname\":\"Test\",\"other\":\"Test\"}" 2>&1 | grep "error")"
if [ "" == "$cache" ]
then
    echo -n -e "[\033[0;31m FAILURE\033[0m ] Success for multi element json PUT request\n"
else
    echo -n -e "[\033[0;32m SUCCESS\033[0m ] Error for multi element json PUT request\n"
fi

cache="$(curl -v -X "PUT" "$link_to_api/$id" --data "{\"newnam\":\"Test\"}" 2>&1 | grep "error")"
if [ "" == "$cache" ]
then
    echo -n -e "[\033[0;31m FAILURE\033[0m ] Success for wrong json PUT request\n"
else
    echo -n -e "[\033[0;32m SUCCESS\033[0m ] Error for wrong json PUT request\n"
fi

cache="$(curl -v -X "PUT" "$link_to_api/$id" --data "{\"newname\":123}" 2>&1 | grep "error")"
if [ "" == "$cache" ]
then
    echo -n -e "[\033[0;31m FAILURE\033[0m ] Success for wrong json type PUT request\n"
else
    echo -n -e "[\033[0;32m SUCCESS\033[0m ] Error for wrong json type PUT request\n"
fi

cache="$(curl -v -X "PUT" "$link_to_api/$id" --data "{\"newname\":""}" 2>&1 | grep "error")"
if [ "" == "$cache" ]
then
    echo -n -e "[\033[0;31m FAILURE\033[0m ] Success for no name PUT request\n"
else
    echo -n -e "[\033[0;32m SUCCESS\033[0m ] Error for no name PUT request\n"
fi
#TODO Missing subsystem test

#Missing OPTIONS success - nothing can really go wrong here

#Test wrong url
cache="$(curl -v "$wrong_link" 2>&1 | grep "HTTP/1.1 404")"
if [ "" == "$cache" ]
then
    echo -n -e "[\033[0;31m FAILURE\033[0m ] Success for wrong url GET request \n"
else
    echo -n -e "[\033[0;32m SUCCESS\033[0m ] Error for wrong url GET request \n"
fi

cache="$(curl -X "PUT" -v "$wrong_link/$id" --data "{\"newname\":\"Testing\"}" 2>&1 | grep "HTTP/1.1 404")"
if [ "" == "$cache" ]
then
    echo -n -e "[\033[0;31m FAILURE\033[0m ] Success for wrong url GET request \n"
else
    echo -n -e "[\033[0;32m SUCCESS\033[0m ] Error for wrong url GET request \n"
fi

cache="$(curl -X "POST" -v "$wrong_link/$id" --data "{\"name\":\"Test\"}" 2>&1 | grep "HTTP/1.1 404")"
if [ "" == "$cache" ]
then
    echo -n -e "[\033[0;31m FAILURE\033[0m ] Success for wrong url POST request \n"
else
    echo -n -e "[\033[0;32m SUCCESS\033[0m ] Error for wrong url POST request \n"
fi

cache="$(curl -X "DELETE" -v "${wrong_link}/$id" 2>&1 | grep "HTTP/1.1 404")"
if [ "" == "$cache" ]
then
    echo -n -e "[\033[0;31m FAILURE\033[0m ] Success for wrong url DELETE request \n"
else
    echo -n -e "[\033[0;32m SUCCESS\033[0m ] Error for wrong url DELETE request \n"
fi
