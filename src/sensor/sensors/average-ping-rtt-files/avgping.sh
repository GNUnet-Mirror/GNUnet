#!/bin/sh

ping -c 10 gnunet.org | awk -F/ '/^rtt/ { print $5 }'
