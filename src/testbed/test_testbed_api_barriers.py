#!/usr/bin/env python
# This file is part of GNUnet.
# (C) 2008--2013 Christian Grothoff (and other contributing authors)
#
# GNUnet is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published
# by the Free Software Foundation; either version 2, or (at your
# option) any later version.
#
# GNUnet is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with GNUnet; see the file COPYING.  If not, write to the
# Free Software Foundation, Inc., 59 Temple Place - Suite 330,
# Boston, MA 02111-1307, USA.


# file:     testbed/test_testbed_api_barriers.py
# brief:    execution script for testing testbed barriers API.
# author:   Sree Harsha Totakura


import subprocess
import os
import sys
from buildvars import libexecdir

if os.name == 'nt':
  service = 'gnunet-service-test-barriers.exe'
  test_testbed_api_barriers = './test_testbed_api_barriers.exe'
else:
  service = 'gnunet-service-test-barriers'
  test_testbed_api_barriers = './test_testbed_api_barriers'

# copy gnunet-service-test-barriers service to gnunet's libexec dir
ret = subprocess.call (['libtool', '--mode=install', 'install',
                        service, libexecdir],
                       shell=False, executable='libtool')
if ret is not 0:
    print "could not install test daemon"
    sys.exit (ret);

# start the testcase binary
ret = subprocess.call (test_testbed_api_barriers, shell=False)

# remove the installed gnunet-service-test-barriers copy
os.unlink (os.path.join (libexecdir, service))

sys.exit (ret)
