/*
     This file is part of GNUnet.
     Copyright (C) 2013 Christian Grothoff (and other contributing authors)

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
 * @file identity/test_identity.c
 * @brief testcase for identity service
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_identity_service.h"
#include "gnunet_testing_lib.h"


#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10)


/**
 * Return value from 'main'.
 */
static int res;

/**
 * Handle to identity service.
 */
static struct GNUNET_IDENTITY_Handle *h;

/**
 * Handle to identity operation.
 */
static struct GNUNET_IDENTITY_Operation *op;

/**
 * Handle for task for timeout termination.
 */
static struct GNUNET_SCHEDULER_Task * endbadly_task;


/**
 * Clean up all resources used.
 */
static void
cleanup ()
{
  if (NULL != op)
  {
    GNUNET_IDENTITY_cancel (op);
    op = NULL;
  }
  if (NULL != h)
  {
    GNUNET_IDENTITY_disconnect (h);
    h = NULL;
  }
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Termiante the testcase (failure).
 *
 * @param cls NULL
 * @param tc scheduler context
 */
static void
endbadly (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  cleanup ();
  res = 1;
}


/**
 * Termiante the testcase (success).
 *
 * @param cls NULL
 * @param tc scheduler context
 */
static void
end_normally (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  cleanup ();
  res = 0;
}


/**
 * Finish the testcase (successfully).
 */
static void
end ()
{
  if (endbadly_task != NULL)
  {
    GNUNET_SCHEDULER_cancel (endbadly_task);
    endbadly_task = NULL;
  }
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_MILLISECONDS,
				&end_normally, NULL);
}


/**
 * Continuation called from successful delete operation.
 *
 * @param cls NULL
 * @param emsg (should also be NULL)
 */
static void
delete_cont (void *cls,
	     const char *emsg)
{
  op = NULL;
  GNUNET_assert (NULL == emsg);
  end ();
}


/**
 * Continuation called from expected-to-fail rename operation.
 *
 * @param cls NULL
 * @param emsg (should also be NULL)
 */
static void
get_cb (void *cls,
	struct GNUNET_IDENTITY_Ego *ego,
	void **ctx,
	const char *identifier)
{
  GNUNET_assert (NULL != ego);
  GNUNET_assert (NULL != identifier);
  GNUNET_assert (0 == strcmp (identifier, "test-id"));
  op = GNUNET_IDENTITY_delete (h,
			       "test-id",
			       &delete_cont,
			       NULL);
}


/**
 * Main function of the test, run from scheduler.
 *
 * @param cls NULL
 * @param cfg configuration we use (also to connect to identity service)
 * @param peer handle to access more of the peer (not used)
 */
static void
run_get (void *cls,
	 const struct GNUNET_CONFIGURATION_Handle *cfg,
	 struct GNUNET_TESTING_Peer *peer)
{
  endbadly_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT,
						&endbadly, NULL);
  h = GNUNET_IDENTITY_connect (cfg, NULL, NULL);
  GNUNET_assert (NULL != h);
  op = GNUNET_IDENTITY_get (h,
			    "test-service",
			    &get_cb,
			    NULL);
}


/**
 * Continuation called from successful rename operation.
 *
 * @param cls NULL
 * @param emsg (should also be NULL)
 */
static void
success_set_cont (void *cls,
		  const char *emsg)
{
  op = NULL;
  GNUNET_assert (NULL == emsg);
  end ();
}


/**
 * Called with events about egos.
 *
 * @param cls NULL
 * @param ego ego handle
 * @param ego_ctx context for application to store data for this ego
 *                 (during the lifetime of this process, initially NULL)
 * @param identifier identifier assigned by the user for this ego,
 *                   NULL if the user just deleted the ego and it
 *                   must thus no longer be used
 */
static void
notification_cb (void *cls,
		 struct GNUNET_IDENTITY_Ego *ego,
		 void **ctx,
		 const char *identifier)
{
  if (NULL == ego)
    return; /* skip first call */
  if (NULL == identifier)
    return; /* deletion / shutdown */
  op = GNUNET_IDENTITY_set (h,
			    "test-service",
			    ego,
			    &success_set_cont,
			    NULL);
}


/**
 * Called with events about created ego.
 *
 * @param cls NULL
 * @param emsg error message
 */
static void
create_cb (void *cls,
	   const char *emsg)
{
  GNUNET_assert (NULL == emsg);
  op = NULL;
}


/**
 * Main function of the test, run from scheduler.
 *
 * @param cls NULL
 * @param cfg configuration we use (also to connect to identity service)
 * @param peer handle to access more of the peer (not used)
 */
static void
run_set (void *cls,
	 const struct GNUNET_CONFIGURATION_Handle *cfg,
	 struct GNUNET_TESTING_Peer *peer)
{
  endbadly_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT,
						&endbadly, NULL);
  h = GNUNET_IDENTITY_connect (cfg, &notification_cb, NULL);
  GNUNET_assert (NULL != h);
  op = GNUNET_IDENTITY_create (h,
			       "test-id",
			       &create_cb,
			       NULL);

}


int
main (int argc, char *argv[])
{
  GNUNET_DISK_directory_remove ("/tmp/test-identity-service");
  res = 1;
  if (0 !=
      GNUNET_TESTING_service_run ("test-identity-defaults",
				  "identity",
				  "test_identity.conf",
				  &run_set,
				  NULL))
    return 1;
  if (0 !=
      GNUNET_TESTING_service_run ("test-identity-defaults",
				  "identity",
				  "test_identity.conf",
				  &run_get,
				  NULL))
    return 1;
  GNUNET_DISK_directory_remove ("/tmp/test-identity-service");
  return res;
}


/* end of test_identity.c */
