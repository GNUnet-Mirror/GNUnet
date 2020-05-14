#!/bin/bash

./bootstrap
./configure --prefix=/tmp/gnunet --enable-experimental
make
