#!/bin/sh
# $1 - bindir
# $2 - gnunetdns group
# $3 - sudo binary (optional)
$3 chown root $1/gnunet-helper-dns
$3 chgrp $2 $1/gnunet-helper-dns
$3 chmod 4750 $1/gnunet-helper-dns
$3 chown gnunet:$2 $1/gnunet-service-dns
$3 chmod 2750 $1/gnunet-service-dns

