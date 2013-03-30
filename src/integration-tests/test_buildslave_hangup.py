#!/bin/python
import sys
import time 

print ("This test hangs up for 1300 seconds to see how buildslave will go about killing it")
time.sleep (1300)
sys.exit (0)
