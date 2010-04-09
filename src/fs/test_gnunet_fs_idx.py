#!/usr/bin/env python 
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
# Testcase for file-sharing command-line tools (indexing and unindexing)
import pexpect
import os
import signal
import re

os.system ('rm -rf /tmp/gnunet-test-fs-py-idx/')
os.system ('gnunet-arm -sq -c test_gnunet_fs_idx_data.conf')
try:
  pub = pexpect.spawn ('gnunet-publish -c test_gnunet_fs_idx_data.conf -m "description:The GNU Public License" -k gpl ../../COPYING')
  pub.expect ('Publishing `../../COPYING\' done.\r')
  pub.expect ("URI is `gnunet://fs/chk/PC0M19QMQC0BPSHR6BGA228PP6INER1D610MGEMOMEM87222FN8HVUO7PQGO0O9HD2GVLHF2N5IDHEQUNK6LKE428FPO96SKQEA486O.PG7K85JGQ6N599MD5HEP3CHEVFPKQD9JB6NPSLVA3T1SKDS66CFI499VS6MGQ88B0QUAVT1282TCRD4GGFVUKDLGI8F0SPIANA3J2LG.35147'.\r")
  pub.expect (pexpect.EOF)

  down = pexpect.spawn ('gnunet-download -c test_gnunet_fs_idx_data.conf -o \"COPYING\" gnunet://fs/chk/PC0M19QMQC0BPSHR6BGA228PP6INER1D610MGEMOMEM87222FN8HVUO7PQGO0O9HD2GVLHF2N5IDHEQUNK6LKE428FPO96SKQEA486O.PG7K85JGQ6N599MD5HEP3CHEVFPKQD9JB6NPSLVA3T1SKDS66CFI499VS6MGQ88B0QUAVT1282TCRD4GGFVUKDLGI8F0SPIANA3J2LG.35147')
  down.expect (re.compile ("Downloading `COPYING\' done \(.*\).\r"));
  down.expect (pexpect.EOF);
  os.system ('rm COPYING');

  unindex = pexpect.spawn ('gnunet-unindex -c test_gnunet_fs_idx_data.conf ../../COPYING')
  unindex.expect ('Unindexing done.\r')
  unindex.expect (pexpect.EOF)

finally:
  os.system ('gnunet-arm -c test_gnunet_fs_idx_data.conf -eq')
  os.system ('rm -rf /tmp/gnunet-test-fs-py-idx/')
