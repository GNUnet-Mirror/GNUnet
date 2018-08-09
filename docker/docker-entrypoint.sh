#!/bin/bash -e

echo "${LOCAL_PORT_RANGE:-49152 65535}" > /proc/sys/net/ipv4/ip_local_port_range
sed -i 's/$GNUNET_PORT/'${GNUNET_PORT:-2086}'/g' /etc/gnunet.conf

if [[ $# -eq 0 ]]; then
  exec gnunet-arm \
    --config=/etc/gnunet.conf \
    --start \
    --monitor
elif [[ -z $1 ]] || [[ ${1:0:1} == '-' ]]; then
  exec gnunet-arm "$@"
else
  exec "$@"
fi
