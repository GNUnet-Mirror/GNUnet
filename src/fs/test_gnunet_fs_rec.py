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
# Testcase for file-sharing command-line tools (recursive publishing & download)
import pexpect
import os
import signal
import re

os.system ('rm -rf /tmp/gnunet-test-fs-py/')
os.system ('gnunet-arm -sq -c test_gnunet_fs_data.conf')
os.system ('tar xfz test_gnunet_fs_rec_data.tgz')
try:
  pub = pexpect.spawn ('gnunet-publish -c test_gnunet_fs_data.conf -d -k testdir dir/')
  pub.expect ('Publishing `dir/\' done.\r')
  pub.expect ("URI is `gnunet://fs/chk/P5BPKNHH7CECDQA1A917G5EB67PPVG99NVO5QMJ8AJP2C02NM8O1ALNGOJPLLO0RMST0FNM0ATJV95PDAGATHDGH7AGIK2N3O0OOC70.OSG2JS3JDSI0AV8LMOL9MKPJ70DNG2RBL2CBTUCHK563VEM7L00RN8I2K0VPB459JRVBFOIKJG72LIQPDP9RFCVEVI37BUD76RJ3KK0.20169\'.")
  pub.expect (pexpect.EOF)

  down = pexpect.spawn ('gnunet-download -c test_gnunet_fs_data.conf -R -o rdir.gnd gnunet://fs/chk/P5BPKNHH7CECDQA1A917G5EB67PPVG99NVO5QMJ8AJP2C02NM8O1ALNGOJPLLO0RMST0FNM0ATJV95PDAGATHDGH7AGIK2N3O0OOC70.OSG2JS3JDSI0AV8LMOL9MKPJ70DNG2RBL2CBTUCHK563VEM7L00RN8I2K0VPB459JRVBFOIKJG72LIQPDP9RFCVEVI37BUD76RJ3KK0.20169\'.')

  down.expect (re.compile ("Downloading `rdir.gnd\' done \(.*\).\r"));
  down.expect (pexpect.EOF);

  dir = pexpect.spawn ('gnunet-directory rdir/a.gnd')
  dir.expect (re.compile (" *embedded filename: a"));
  dir.expect (re.compile (" *embedded filename: COPYING"));
  dir.expect (pexpect.EOF)

  os.system ('rm -r rdir/b.gnd rdir/a.gnd')
  if (0 != os.system ("diff -r dir rdir")):
    raise Exception ("Unexpected difference between source directory and downloaded result")
  
finally:
  os.system ('gnunet-arm -c test_gnunet_fs_data.conf -eq')
  os.system ('rm -r dir rdir rdir.gnd')
