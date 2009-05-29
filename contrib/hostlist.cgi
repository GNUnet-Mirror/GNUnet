#!/bin/sh
# This is a CGI script to generate the host list on-demand.
# by Michael Wensley, with minor improvements by Christian Grothoff
echo -ne "Content-Type: application/octet-stream\r\n\r\n"
cat /var/lib/gnunet/data/hosts/*.{2,3,4,5,6,8,12,17,23,25}
