#!/bin/sh

make version.texi
make version2.texi
./gendocs.sh --email gnunet-developers@gnu.org gnunet "GNUnet reference handbook"
./gendocs.sh --email gnunet-developers@gnu.org gnunet-c-tutorial "GNUnet C Tutorial"
