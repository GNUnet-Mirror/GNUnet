#!/bin/bash
# $1 - bindir
# $2 - sudo binary (optional)
$2 chown root:root $1/gnunet-helper-vpn || true
$2 chmod u+s $1/gnunet-helper-vpn || true
