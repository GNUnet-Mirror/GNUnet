/*
      This file is part of GNUnet
      (C) 2008--2012 Christian Grothoff (and other contributing authors)

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
      Free Software Foundation, Inc., 59 Temple Place - Suite 330,
      Boston, MA 02111-1307, USA.
 */

/**
 * @file testbed/testbed_api_test.c
 * @brief high-level test function
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_testbed_service.h"




/**
 * Convenience method for running a "simple" test on the local system
 * with a single call from 'main'.  Underlay and overlay topology are
 * configured using the "UNDERLAY" and "OVERLAY" options in the
 * "[testbed]" section of the configuration (with possible options
 * given in "UNDERLAY_XXX" and/or "OVERLAY_XXX").
 *
 * The test is to be terminated using a call to
 * "GNUNET_SCHEDULER_shutdown".  If starting the test fails,
 * the program is stopped without 'master' ever being run.
 *
 * NOTE: this function should be called from 'main', NOT from
 * within a GNUNET_SCHEDULER-loop.  This function will initialze
 * the scheduler loop, the testbed and then pass control to
 * 'master'.
 *
 * @param testname name of the testcase (to configure logging, etc.)
 * @param cfg_filename configuration filename to use
 *              (for testbed, controller and peers)
 * @param num_peers number of peers to start
 * @param test_master task to run once the test is ready
 * @param test_master_cls closure for 'task'.
 */
void
GNUNET_TESTBED_test_run (const char *testname,
			 const char *cfg_filename,
			 unsigned int num_peers,
			 GNUNET_TESTBED_TestMaster test_master,
			 void *test_master_cls)
{
  GNUNET_break (0);
}



/* end of testbed_api_test.c */
