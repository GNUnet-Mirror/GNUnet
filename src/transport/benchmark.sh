#/bin/sh

for i in {1..0}
do
 echo RUN $i
 ./test_transport_api_reliability_http
done

for i in {1..100}
do
 echo RUN $i
 ./test_transport_api_reliability_https
done
 
 