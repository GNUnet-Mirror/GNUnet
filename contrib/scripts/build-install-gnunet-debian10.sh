#!/bin/sh
set -exo
set -u pipefail

if [ "$USER" = "root" ]; then
  export SUDO_CMD=""
else
  SUDO_CMD="sudo"
fi

$SUDO_CMD apt update

$SUDO_CMD apt install -y git libtool autoconf \
autopoint libmicrohttpd-dev build-essential libgcrypt-dev \
libidn11-dev zlib1g-dev libunistring-dev libglpk-dev miniupnpc \
libextractor-dev libjansson-dev libcurl4-gnutls-dev gnutls-bin \
libsqlite3-dev openssl libnss3-tools libopus-dev libpulse-dev libogg-dev

mkdir ~/gnunet_installation || true

cd ~/gnunet_installation

git clone --depth 1 https://gnunet.org/git/gnunet.git || true

cd ~/gnunet_installation/gnunet

./bootstrap

export GNUNET_PREFIX=/usr
export CFLAGS="-g -Wall -O0"

./configure --prefix=$GNUNET_PREFIX --enable-logging=verbose --disable-documentation

$SUDO_CMD addgroup gnunet || true

$SUDO_CMD usermod -aG gnunet $USER || true

make -j$(nproc || echo -n 1)

$SUDO_CMD make install
