#!/bin/bash

###################################################################################
# Script to clean a previous run of testbed which has crashed. This scripts kills #
# the peers and cleans the temporary files created for those peers		  #
# 										  #
# Author: Sree Harsha Totakura							  #
###################################################################################

for host in `cut -d : -f 1 < infiniband_cluster.hosts`
do
    echo "ssh --> $host"
    ssh $host 'pkill gnunet; rm -rf /tmp/gnunet-pipe*; rm -rf /tmp/testbed*'
done
