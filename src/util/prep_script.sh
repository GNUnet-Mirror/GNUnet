#!/bin/sh
killall gnunet-service-arm &> /dev/null
killall gnunet-service-peerinfo &> /dev/null
killall gnunet-service-resolver &> /dev/null
killall gnunet-service-transport &> /dev/null
killall gnunet-service-core &> /dev/null
exit 0
