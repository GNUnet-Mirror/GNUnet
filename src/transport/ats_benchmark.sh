#/bin/bash
start=1
end=500

rm bench_1addr.ats
rm bench_2addr.ats
rm bench_4addr.ats

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
  echo "$c peers, 4 addr/peer"
  ./test_transport_ats -c test_transport_ats_4addr.conf -m -p $c 2>> bench_4addr.ats
  rm -rf /tmp/test-gnunet-testing
  killall -s 31 gnunet-service-arm 2> /dev/null
  killall -s 31 gnunet-service-transport 2> /dev/null
  killall -s 31 gnunet-service-statistics 2> /dev/null
  killall -s 31 gnunet-service-resolver 2> /dev/null
  killall -s 31 gnunet-service-core 2> /dev/null
  killall -s 31 gnunet-service-peerinfo 2> /dev/null
  echo "$c peers, 2 addr/peer"
  ./test_transport_ats -c test_transport_ats_2addr.conf -m -p $c 2>> bench_2addr.ats
  rm -rf /tmp/test-gnunet-testing
  killall -s 31 gnunet-service-arm 2> /dev/null
  killall -s 31 gnunet-service-transport 2> /dev/null
  killall -s 31 gnunet-service-statistics 2> /dev/null
  killall -s 31 gnunet-service-resolver 2> /dev/null
  killall -s 31 gnunet-service-core 2> /dev/null
  killall -s 31 gnunet-service-peerinfo 2> /dev/null
  echo "$c peers, 1 addr/peer"
  ./test_transport_ats -c test_transport_ats_1addr.conf -m -p $c 2>> bench_1addr.ats
  rm -rf /tmp/test-gnunet-testing
  killall -s 31 gnunet-service-arm 2> /dev/null
  killall -s 31 gnunet-service-transport 2> /dev/null
  killall -s 31 gnunet-service-statistics 2> /dev/null
  killall -s 31 gnunet-service-resolver 2> /dev/null
  killall -s 31 gnunet-service-core 2> /dev/null
  killall -s 31 gnunet-service-peerinfo 2> /dev/null
done
