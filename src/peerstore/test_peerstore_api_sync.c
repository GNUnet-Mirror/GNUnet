/*
     This file is part of GNUnet.
     Copyright (C) 2015 GNUnet e.V.

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
 * @file peerstore/test_peerstore_api_sync.c
 * @brief testcase for peerstore sync-on-disconnect feature. Stores
 *        a value just before disconnecting, and then checks that
 *        this value is actually stored.
 * @author Omar Tarabai
 * @author Christian Grothoff (minor fix, comments)
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_lib.h"
#include "gnunet_peerstore_service.h"

/**
 * Overall result, 0 for success.
 */
static int ok = 404;

/**
 * Configuration we use.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * handle to talk to the peerstore.
 */
static struct GNUNET_PEERSTORE_Handle *h;

/**
 * Subsystem we store the value for.
 */
static const char *subsystem = "test_peerstore_api_sync";

/**
 * Fake PID under which we store the value.
 */
static struct GNUNET_PeerIdentity pid;

/**
 * Test key we're storing the test value under.
 */
static const char *key = "test_peerstore_api_store_key";

/**
 * Test value we are storing.
 */
static const char *val = "test_peerstore_api_store_val";


/**
 * Function that should be called with the result of the
 * lookup, and finally once with NULL to signal the end
 * of the iteration.
 *
 * Upon the first call, we set "ok" to success. On the
 * second call (end of iteration) we terminate the test.
 *
 * @param cls NULL
 * @param record the information stored in the peerstore
 * @param emsg any error message
 * @return #GNUNET_YES (all good, continue)
 */
static int
iterate_cb (void *cls, 
	    const struct GNUNET_PEERSTORE_Record *record,
            const char *emsg)
{
  const char *rec_val;

  GNUNET_break (NULL == emsg);
  if (NULL == record)
  {
    GNUNET_PEERSTORE_disconnect (h, 
				 GNUNET_NO);
    GNUNET_SCHEDULER_shutdown ();
    return GNUNET_YES;
  }
  rec_val = record->value;
  GNUNET_break (0 == strcmp (rec_val, val));
  ok = 0;
  return GNUNET_YES;
}


/**
 * Run the 2nd stage of the test where we fetch the
 * data that should have been stored.
 *
 * @param cls NULL
 * @param tc unused
 */
static void
test_cont (void *cls,
	   const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  h = GNUNET_PEERSTORE_connect (cfg);
  GNUNET_PEERSTORE_iterate (h, 
			    subsystem, 
			    &pid, key,
                            GNUNET_TIME_UNIT_FOREVER_REL, 
			    &iterate_cb, NULL);
}


/**
 * Actually run the test.
 */
static void
test1 ()
{
  h = GNUNET_PEERSTORE_connect (cfg);
  GNUNET_PEERSTORE_store (h, 
			  subsystem,
			  &pid, 
			  key, 
			  val, strlen (val) + 1,
                          GNUNET_TIME_UNIT_FOREVER_ABS,
                          GNUNET_PEERSTORE_STOREOPTION_REPLACE, 
			  NULL, NULL);
  GNUNET_PEERSTORE_disconnect (h, 
			       GNUNET_YES);
  h = NULL;
  /* We need to wait a little bit to give the disconnect
     a chance to actually finish the operation; otherwise,
     the test may fail non-deterministically if the new
     connection is faster than the cleanup routine of the
     old one. */
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
				&test_cont,
				NULL);
}


/**
 * Initialize globals and launch the test.
 *
 * @param cls NULL
 * @param c configuration to use
 * @param peer handle to our peer (unused)
 */
static void
run (void *cls, 
     const struct GNUNET_CONFIGURATION_Handle *c,
     struct GNUNET_TESTING_Peer *peer)
{
  cfg = c;
  GNUNET_assert (NULL != h);
  memset (&pid, 1, sizeof (pid));
  test1 ();
}


int
main (int argc, char *argv[])
{
  if (0 !=
      GNUNET_TESTING_service_run ("test-gnunet-peerstore-sync", 
				  "peerstore",
                                  "test_peerstore_api_data.conf",
				  &run, NULL))
    return 1;
  if (0 != ok)
    fprintf (stderr,
	     "Test failed: %d\n",
	     ok);
  return ok;
}

/* end of test_peerstore_api_sync.c */
