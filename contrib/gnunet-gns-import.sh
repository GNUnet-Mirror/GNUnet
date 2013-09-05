#!/bin/sh
# This shell-script will import some GNS authorities into your GNS
# namestore.
#
# By default, we create three GNS zones:
gnunet-identity -C master-zone 
gnunet-identity -C short-zone
gnunet-identity -C private-zone

# Additionally, we create the FS SKS zone
gnunet-identity -C sks-zone

# Integrate those with the respective subsystems.
gnunet-identity -e short-zone -s gns-short
gnunet-identity -e master-zone -s gns-master
gnunet-identity -e private-zone -s gns-private
gnunet-identity -e sks-zone -s fs-sks

# Get the public keys as strings (so we can create PKEY records)
MASTER=`gnunet-identity -d | grep master-zone | awk '{print $3}`
SHORT=`gnunet-identity -d | grep short-zone | awk '{print $3}`
PRIVATE=`gnunet-identity -d | grep private-zone | awk '{print $3}`

# Link short and private zones into master zone
gnunet-namestore -z master-zone -a -e never -n private -p -t PKEY -V $PRIVATE 
gnunet-namestore -z master-zone -a -e never -n short -p -t PKEY -V $SHORT 

# Link GNUnet's FCFS zone into master zone
gnunet-namestore -z master-zone -a -e never -n fcfs -p -t PKEY -V 72QC35CO20UJN1E91KPJFNT9TG4CLKAPB4VK9S3Q758S9MLBRKOG

