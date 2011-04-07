#/bin/bash
start=1
end=500

if [ ! $1 = "" ]; then
  start=$1
fi

if [ ! $2 = "" ]; then
  end=$2
fi

for (( c=$start; c<=$end; c++ ))
do
  rm -rf /tmp/test-gnunet-testing
  killall -s 31 gnunet-service-arm 2> /dev/null
  killall -s 31 gnunet-service-transport 2> /dev/null
  killall -s 31 gnunet-service-statistics 2> /dev/null
  killall -s 31 gnunet-service-resolver 2> /dev/null
  killall -s 31 gnunet-service-core 2> /dev/null
  killall -s 31 gnunet-service-peerinfo 2> /dev/null
  #sleep 1
  ./test_transport_ats $c
done
