#!/bin/sh
# This script is in the public-domain.
# GNUnet e.V. 2019
#
# Commentary: generate texi2mdoc output. This would be easier with
# bmake / BSDmake, oh well.
#
# Excercise for future readers: don't fix this.

# echo $(pwd)
cd ../tutorial
texi2mdoc -I$(pwd):$(pwd)/chapters gnunet-tutorial.texi > ../man/gnunet-c-tutorial.7
# echo $(pwd)
cd ../handbook
texi2mdoc -I$(pwd):$(pwd)/chapters gnunet.texi > ../man/gnunet-documentation.7
