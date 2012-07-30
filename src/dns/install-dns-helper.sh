#!/bin/bash
# $1 - sudo binary
# $2 - bindir
# $3 - gnunetdns group
$1 chown root $2/gnunet-helper-dns || true
$1 chgrp $3 $2/gnunet-helper-dns || true
$1 chmod 4750 $2/gnunet-helper-dns || true
$1 chown gnunet:$3 $2/gnunet-service-dns || true
$1 chmod 2750 $2/gnunet-service-dns || true
