#!/bin/bash
# $1 - sudo binary
# $2 - bindir
# $3 - nattest
$1 chown root:root $2/gnunet-helper-nat-server $2/gnunet-helper-nat-client $3 || true
$1 chmod u+s $2/gnunet-helper-nat-server $2/gnunet-helper-nat-client $3 || true
