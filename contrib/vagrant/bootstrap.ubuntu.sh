#/bin/bash
# Source https://gnunet.org/dependencies and README

apt-get update

# Install required tools
apt-get -y install git build-essential gnupg curl openssl gnutls-bin miniupnpc

# Autotools required for compiling
apt-get -y install autoconf automake libtool autopoint

# Tools for debugging
apt-get -y install gdb valgrind

# Direct dependencies obtained from README
apt-get -y install libmicrohttpd-dev
apt-get -y install libextractor-dev
apt-get -y install libunistring-dev
apt-get -y install libidn11-dev
apt-get -y install libgcrypt20-dev
apt-get -y install libgnutls30-dev
apt-get -y install libltdl-dev
apt-get -y install libcurl3
apt-get -y install sqlite3 libsqlite3-dev
apt-get -y install zlib1g-dev
# apt-get -y install texlive-full # Skipped > 1GB
# optional for gnunet-conversation
# apt-get -y install libpulse-dev libopus-dev libogg-dev gstreamer1.0
# optional for gnunet-qr
apt-get -y install python-zbar
# optional for experimental code
apt-get -y install libglpk-dev
#
apt-get -y install libbluetooth-dev libjansson-dev

# Compilation process
addgroup gnunetdns
adduser --system --home "/var/lib/gnunet" --group gnunet --shell /bin/sh
# cd /gnunet
# . bootstrap
# export GNUNET_PREFIX=/usr/local/lib # or other directory of your choice
# ./configure --prefix=$GNUNET_PREFIX/.. --with-extractor=$LE_PREFIX
# make
# make install
# make check
# echo "/usr/local/lib/gnunet" > /etc/ld.so.conf.d/libgnunet.conf
# ldconfig
# sudo -u gnunet gnunet-arm -s
