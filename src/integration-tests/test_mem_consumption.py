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
# 
#
# This test starts 3 peers and expects bootstrap and a connected clique
#
# Conditions for successful exit:
# Both peers have 1 connected peer in transport, core, topology, fs 

import sys
import os
import subprocess
import re
import shutil
import time
from gnunet_testing import Peer
from gnunet_testing import Test
from gnunet_testing import Check
from gnunet_testing import Condition
from gnunet_testing import * 
 
if os.name == "nt":
  tmp = os.getenv ("TEMP")
else:
  tmp = "/tmp"

#definitions

testname = "test_integration_clique"
verbose = True
check_timeout = 180


def cleanup ():
    shutil.rmtree (os.path.join (tmp, "c_bootstrap_server"), True)
    shutil.rmtree (os.path.join (tmp, "c_no_nat_client"), True)
    shutil.rmtree (os.path.join (tmp, "c_no_nat_client_2"), True)


        
def check_disconnect ():
  check = Check (test)
  check.add (StatisticsCondition (client, 'transport', '# peers connected',1))
  check.add (StatisticsCondition (client, 'core', '# neighbour entries allocated',1))  
  check.add (StatisticsCondition (client, 'core', '# peers connected',1))
  check.add (StatisticsCondition (client, 'topology', '# peers connected',1))
  check.add (StatisticsCondition (client, 'fs', '# peers connected',1))
  
  check.add (StatisticsCondition (server, 'transport', '# peers connected',1))
  check.add (StatisticsCondition (server, 'core', '# neighbour entries allocated',1))  
  check.add (StatisticsCondition (server, 'core', '# peers connected',1))
  check.add (StatisticsCondition (server, 'topology', '# peers connected',1))
  check.add (StatisticsCondition (server, 'fs', '# peers connected',1))
  
  check.run_blocking (check_timeout, None, None)



def check_connect ():
  check = Check (test)
  check.add (StatisticsCondition (client, 'transport', '# peers connected',2))
  check.add (StatisticsCondition (client, 'core', '# neighbour entries allocated',2))  
  check.add (StatisticsCondition (client, 'core', '# peers connected',2))
  check.add (StatisticsCondition (client, 'topology', '# peers connected',2))
  check.add (StatisticsCondition (client, 'fs', '# peers connected',2))

  check.add (StatisticsCondition (client2, 'transport', '# peers connected',2))
  check.add (StatisticsCondition (client2, 'core', '# neighbour entries allocated',2))  
  check.add (StatisticsCondition (client2, 'core', '# peers connected',2))
  check.add (StatisticsCondition (client2, 'topology', '# peers connected',2))
  check.add (StatisticsCondition (client2, 'fs', '# peers connected',2))
  
  check.add (StatisticsCondition (server, 'transport', '# peers connected',2))
  check.add (StatisticsCondition (server, 'core', '# neighbour entries allocated',2))  
  check.add (StatisticsCondition (server, 'core', '# peers connected',2))
  check.add (StatisticsCondition (server, 'topology', '# peers connected',2))
  check.add (StatisticsCondition (server, 'fs', '# peers connected',2))  
  
  check.run_blocking (check_timeout, None, None)

# 
# Test execution
# 
def run ():
    global success
    global test
    global server
    global client
    global client2	
    restarts = 0
    iterations = 4
    success = False
    
    test = Test ('test_memory_consumption', verbose)
    server = Peer(test, './confs/c_bootstrap_server_w_massif.conf');
    server.start();
    client = Peer(test, './confs/c_no_nat_client.conf');
    client.start();
    
    while (restarts < iterations):
       print 'Iteration #' + str (restarts) + ' of ' + str (restarts)
       restarts += 1
       client2 = Peer(test, './confs/c_no_nat_client_2.conf');
       client2.start();	
       if ((client.started == True) and (client2.started == True) and (server.started == True)):
           test.p ('Peers started, waiting for clique connection')
           check_connect ()
           test.p ('All peers connected, stopping client2')   
           client2.stop ()
           check_disconnect ()
           test.p ('Peer disconnected')

    print str (iterations) + " Iteration executed" 
    server.stop ()    
    client.stop ()    
    cleanup ()
    
try:
    run ()
except (KeyboardInterrupt, SystemExit):    
    print 'Test interrupted'
    server.stop ()
    client.stop ()
    client2.stop ()
    cleanup ()
if (success == False):
	sys.exit(1)   
else:
	sys.exit(0)    
	    

