#!/bin/sh

make version.texi
make version2.texi
./gendocs.sh --email gnunet-developers@gnu.org gnunet-c-tutorial "GNUnet C Tutorial" -o "manual/gnunet-c-tutorial"
#cd manual
#mkdir gnunet-c-tutorial
#mv * gnunet-c-tutorial/
#cd ..
./gendocs.sh --email gnunet-developers@gnu.org gnunet "GNUnet reference handbook" -o "manual/gnunet"
#cd manual
#mkdir handbook
#mkdir ../tmp-gnunet
#mv gnunet ../tmp-gnunet
#mv * handbook/
#mv ../tmp-gnunet gnunet
printf "Success"
