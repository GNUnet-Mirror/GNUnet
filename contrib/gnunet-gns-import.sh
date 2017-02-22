#!/bin/sh
# This shell-script will import some GNS authorities into your GNS
# namestore.

LOCATION=$(which gnunet-config)
if [ -z $LOCATION ]
then
  LOCATION="gnunet-config"
fi
$LOCATION --version 1> /dev/null
if test $? != 0
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
      options="$options -c $OPTARG"
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

# By default, we create two GNS zones:
gnunet-identity -C master-zone $options
gnunet-identity -C private-zone $options

# Additionally, we create the FS SKS zone
gnunet-identity -C sks-zone $options

#### Integrate those with the respective subsystems ####

# Zone for shortening by gns-proxy,
# (remove this entry to disable shortening)
gnunet-identity -e short-zone -s gns-short $options

# Default zone for 'gnunet-gns' lookups
gnunet-identity -e master-zone -s gns-master $options

# Default zone for 'gnunet-namestore' operations
gnunet-identity -e master-zone -s namestore $options

# Use master-zone for GNS proxy lookups
gnunet-identity -e master-zone -s gns-proxy $options

# Use master-zone for intercepted DNS queries
# (remove this entry to disable DNS interception by GNS service)
gnunet-identity -e master-zone -s gns-intercept $options

# 'gns-private' is not yet used (!)
gnunet-identity -e private-zone -s gns-private $options

# 'fs-sks' default ego for gnunet-fs-gtk namespace operations
gnunet-identity -e sks-zone -s fs-sks $options

# Get the public keys as strings (so we can create PKEY records)
MASTER=`gnunet-identity -d $options | grep master-zone | awk '{print $3}'`
SHORT=`gnunet-identity -d $options | grep short-zone | awk '{print $3}'`
PRIVATE=`gnunet-identity -d $options | grep private-zone | awk '{print $3}'`
PIN=DWJASSPE33MRN8T6Q0PENRNBTQY0E6ZYGTRCDP5DGPBF2CRJMJEG

# Link short and private zones into master zone
if (gnunet-namestore -z master-zone -D -n private -t PKEY | grep "PKEY: $PRIVATE" 1>/dev/null)
then
  echo "Private zone link exists, skipping"
else
  gnunet-namestore -z master-zone -a -e never -n private -p -t PKEY -V $PRIVATE $options
fi
if (gnunet-namestore -z master-zone -D -n short -t PKEY | grep "PKEY: $SHORT" 1>/dev/null)
then
  echo "Shorten zone link exists, skipping"
else
  gnunet-namestore -z master-zone -a -e never -n short -p -t PKEY -V $SHORT $options
fi

# Link GNUnet's FCFS zone into master zone under label "pin"
if (gnunet-namestore -z master-zone -D -n pin -t PKEY | grep "PKEY: $PIN" 1>/dev/null)
then
  echo "Pin zone link exists, skipping"
else
  gnunet-namestore -z master-zone -a -e never -n pin -p -t PKEY -V $PIN $options
fi
