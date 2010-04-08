#!python
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
# Testcase for file-sharing command-line tools (namespaces)
import pexpect
import os
import signal
import re

os.system ('rm -rf /tmp/gnunet-test-fs-py-ns/')
os.system ('gnunet-arm -sq -c test_gnunet_fs_ns_data.conf')
try:
  pseu = pexpect.spawn ('gnunet-pseudonym -c test_gnunet_fs_ns_data.conf -C licenses -k gplad -m "description:Free Software Licenses" -r myroot')
  pseu.expect (pexpect.EOF)
  pseu = pexpect.spawn ('gnunet-pseudonym -c test_gnunet_fs_ns_data.conf -o')
  pseu.expect (re.compile("licenses \(.*\)\r"))
  pseu.expect (pexpect.EOF)

  pub = pexpect.spawn ('gnunet-publish -c test_gnunet_fs_ns_data.conf -k licenses -P licenses -u gnunet://fs/chk/PC0M19QMQC0BPSHR6BGA228PP6INER1D610MGEMOMEM87222FN8HVUO7PQGO0O9HD2GVLHF2N5IDHEQUNK6LKE428FPO96SKQEA486O.PG7K85JGQ6N599MD5HEP3CHEVFPKQD9JB6NPSLVA3T1SKDS66CFI499VS6MGQ88B0QUAVT1282TCRD4GGFVUKDLGI8F0SPIANA3J2LG.35147 -t gpl -N gpl3')
  pub.expect (pexpect.EOF)

  search = pexpect.spawn ('gnunet-search -V -c test_gnunet_fs_ns_data.conf gplad')
  search.expect (re.compile ("gnunet-download gnunet://fs/sks/.*/myroot\r"))
  search.expect (re.compile (" *description: Free Software Licenses\r"))
  search.kill (signal.SIGTERM)
  search.expect (pexpect.EOF)

  pseu = pexpect.spawn ('gnunet-pseudonym -c test_gnunet_fs_ns_data.conf')
  pseu.expect (re.compile ("Free Software Licenses.*:\r"))
  pseu.expect (pexpect.EOF)

finally:
  os.system ('gnunet-arm -c test_gnunet_fs_ns_data.conf -eq')
  os.system ('rm -rf /tmp/gnunet-test-fs-py-ns/')
