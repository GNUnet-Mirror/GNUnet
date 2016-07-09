/*
     This file is part of GNUnet.
     Copyright (C) 2016 GNUnet e.V.

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 3, or (at your
     option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     General Public License for more details.

     You should have received a copy of the GNU General Public License
     along with GNUnet; see the file COPYING.  If not, write to the
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/
/**
 * @file transport-testing-main.c
 * @brief convenience main function for tests
 * @author Christian Grothoff
 */
#include "transport-testing.h"


/**
 * Setup testcase.  Calls @a check with the data the test needs.
 *
 * @param argv0 binary name (argv[0])
 * @param filename source file name (__FILE__)
 * @param num_peers number of peers to start
 * @param check main function to run
 * @param check_cls closure for @a check
 * @return #GNUNET_OK on success
 */
int
GNUNET_TRANSPORT_TESTING_main_ (const char *argv0,
                                const char *filename,
                                unsigned int num_peers,
                                GNUNET_TRANSPORT_TESTING_CheckCallback check,
                                void *check_cls)
{
  return GNUNET_SYSERR;
}

/* end of transport-testing-main.c */
