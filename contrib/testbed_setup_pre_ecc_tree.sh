#!/bin/sh

svn up -r26032 
svn up -r26167 src/nse/ src/regex/
svn up -r26079 src/include/gnunet_helper_lib.h src/util/helper.c
svn up -r26219 src/include/gnunet_protocols.h
svn up src/include/gnunet_testbed_service.h src/testbed/
svn up contrib
svn up configure.ac
