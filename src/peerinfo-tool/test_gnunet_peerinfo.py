#!/usr/bin/python 
#    This file is part of GNUnet.
#    (C) 2010 Christian Grothoff (and other contributing authors)
#
#    GNUnet is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published
#    by the Free Software Foundation; either version 2, or (at your
#    option) any later version.
#
#    GNUnet is distributed in the hope that it will be useful, but
#    WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#    General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with GNUnet; see the file COPYING.  If not, write to the
#    Free Software Foundation, Inc., 59 Temple Place - Suite 330,
#    Boston, MA 02111-1307, USA.
#
# Testcase for gnunet-peerinfo
import pexpect
import os
import signal
import re

pinfo = pexpect.spawn ('gnunet-peerinfo -c test_gnunet_peerinfo_data.conf')
pinfo.expect  ('Timeout trying to interact with PEERINFO service\r')
pinfo.expect (pexpect.EOF);
os.system ('rm -rf /tmp/gnunet-test-peerinfo/')
os.system ('gnunet-arm -sq -c test_gnunet_peerinfo_data.conf')

try:
  pinfo = pexpect.spawn ('gnunet-peerinfo -c test_gnunet_peerinfo_data.conf -s')
  pinfo.expect (re.compile ("I am peer `.*\'.\r"));
  pinfo.expect (pexpect.EOF);

  pinfo = pexpect.spawn ('gnunet-peerinfo -c test_gnunet_peerinfo_data.conf -qs')
  pinfo.expect (re.compile (".......................................................................................................\r"));
  pinfo.expect (pexpect.EOF);

  pinfo = pexpect.spawn ('gnunet-peerinfo -c test_gnunet_peerinfo_data.conf invalid')
  pinfo.expect (re.compile ("Invalid command line argument `invalid\'\r"));
  pinfo.expect (pexpect.EOF);


  os.system ('gnunet-arm -q -i transport -c test_gnunet_peerinfo_data.conf')

  pinfo = pexpect.spawn ('gnunet-peerinfo -c test_gnunet_peerinfo_data.conf')
  pinfo.expect (re.compile ("Peer `.*\' with trust  *0\r"));
  pinfo.expect (re.compile (" *localhost:24357\r"));
  pinfo.expect (pexpect.EOF);

  pinfo = pexpect.spawn ('gnunet-peerinfo -c test_gnunet_peerinfo_data.conf -n')
  pinfo.expect (re.compile ("Peer `.*\' with trust  *0\r"));
  pinfo.expect (re.compile (" *127.0.0.1:24357\r"));
  pinfo.expect (pexpect.EOF);

  pinfo = pexpect.spawn ('gnunet-peerinfo -c test_gnunet_peerinfo_data.conf -qs')
  pid = pinfo.read (-1)
  pid = pid.strip ()

  pinfo = pexpect.spawn ('gnunet-peerinfo -c test_gnunet_peerinfo_data.conf 4 ' + pid)
  pinfo.expect (re.compile ("Peer `" + pid + "\' with trust  *4\r"));
  pinfo.expect (pexpect.EOF);  

  pinfo = pexpect.spawn ('gnunet-peerinfo -c test_gnunet_peerinfo_data.conf -- -4 ' + pid)
  pinfo.expect (re.compile ("Peer `" + pid + "\' with trust  *0\r"));
  pinfo.expect (pexpect.EOF);  

finally:
  os.system ('gnunet-arm -c test_gnunet_peerinfo_data.conf -eq')
  os.system ('rm -rf /tmp/gnunet-test-peerinfo/')
