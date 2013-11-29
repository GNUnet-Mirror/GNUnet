#!/bin/sh
# This shell-script will import some GNS authorities into your GNS
# namestore.

LOCATION=$(which gnunet-config)
if [ -z $LOCATION ]
then
	echo "GNUnet command line tools not found, check environmental variables PATH and GNUNET_PREFIX" 
	exit 1
fi

gnunet-arm -I 1> /dev/null 2>/dev/null
if [ ! $? -eq 0 ]
then
	echo "GNUnet is not running, please start GNUnet before running import" 
	exit 1
fi

options=''

while getopts "c:" opt; do
  case $opt in
    c)
      options+="-c $OPTARG"
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      exit 1
      ;;
    :)
      echo "Option -$OPTARG requires an argument." >&2
      exit 1
      ;;
  esac
done

# By default, we create three GNS zones:
gnunet-identity -C master-zone $options
gnunet-identity -C short-zone $options
gnunet-identity -C private-zone $options

# Additionally, we create the FS SKS zone
gnunet-identity -C sks-zone $options

# Integrate those with the respective subsystems.
gnunet-identity -e short-zone -s gns-short $options
gnunet-identity -e master-zone -s gns-master $options
gnunet-identity -e master-zone -s gns-proxy $options
gnunet-identity -e private-zone -s gns-private $options
gnunet-identity -e sks-zone -s fs-sks $options

# Get the public keys as strings (so we can create PKEY records)
MASTER=`gnunet-identity -d $options | grep master-zone | awk '{print $3}'`
SHORT=`gnunet-identity -d $options | grep short-zone | awk '{print $3}'`
PRIVATE=`gnunet-identity -d $options | grep private-zone | awk '{print $3}'`

# Link short and private zones into master zone
gnunet-namestore -z master-zone -a -e never -n private -p -t PKEY -V $PRIVATE $options
gnunet-namestore -z master-zone -a -e never -n short -p -t PKEY -V $SHORT $options

# Link GNUnet's FCFS zone into master zone under label "pin"
gnunet-namestore -z master-zone -a -e never -n pin -p -t PKEY -V 72QC35CO20UJN1E91KPJFNT9TG4CLKAPB4VK9S3Q758S9MLBRKOG $options

