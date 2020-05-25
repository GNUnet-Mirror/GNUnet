/*
     This file is part of GNUnet.
     Copyright (C) 2013, 2016 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
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
static struct GNUNET_SCHEDULER_Task *endbadly_task;

#define CHECK(cond)     \
  do                    \
  {                     \
    if (! (cond))       \
    {                   \
      GNUNET_break (0); \
      end ();           \
      return;           \
    }                   \
  } while (0)


/**
 * Clean up all resources used.
 */
static void
cleanup (void *cls)
{
  (void) cls;
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
}


/**
 * Termiante the testcase (failure).
 *
 * @param cls NULL
 */
static void
endbadly (void *cls)
{
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Finish the testcase (successfully).
 */
static void
end ()
{
  if (NULL != endbadly_task)
  {
    GNUNET_SCHEDULER_cancel (endbadly_task);
    endbadly_task = NULL;
  }
  GNUNET_SCHEDULER_shutdown ();
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
  static struct GNUNET_IDENTITY_Ego *my_ego;
  static int round;

  switch (round)
  {
  case 0:   /* end of initial iteration */
    CHECK (NULL == ego);
    CHECK (NULL == identifier);
    break;

  case 1:   /* create */
    CHECK (NULL != ego);
    CHECK (NULL != identifier);
    CHECK (0 == strcmp (identifier, "test-id"));
    my_ego = ego;
    *ctx = &round;
    break;

  case 2:   /* rename */
    CHECK (my_ego == ego);
    CHECK (NULL != identifier);
    CHECK (0 == strcmp (identifier, "test"));
    CHECK (*ctx == &round);
    break;

  case 3:   /* reconnect-down */
    CHECK (my_ego == ego);
    CHECK (NULL == identifier);
    CHECK (*ctx == &round);
    *ctx = NULL;
    break;

  case 4:   /* reconnect-up */
    CHECK (NULL != identifier);
    CHECK (0 == strcmp (identifier, "test"));
    my_ego = ego;
    *ctx = &round;
    break;

  case 5:   /* end of iteration after reconnect */
    CHECK (NULL == ego);
    CHECK (NULL == identifier);
    break;

  case 6:   /* delete */
    CHECK (my_ego == ego);
    CHECK (*ctx == &round);
    *ctx = NULL;
    break;

  default:
    CHECK (0);
  }
  round++;
}


/**
 * Continuation called from successful delete operation.
 *
 * @param cls NULL
 * @param emsg (should also be NULL)
 */
static void
delete_cont (void *cls, const char *emsg)
{
  op = NULL;
  CHECK (NULL == emsg);
  res = 0;
  end ();
}


/**
 * Continue by deleting the "test" identity.
 *
 * @param cls NULL
 */
static void
finally_delete (void *cls)
{
  op = GNUNET_IDENTITY_delete (h, "test", &delete_cont, NULL);
}


/**
 * Continuation called from expected-to-fail rename operation.
 *
 * @param cls NULL
 * @param emsg (should also be NULL)
 */
static void
fail_rename_cont (void *cls, const char *emsg)
{
  CHECK (NULL != emsg);
  op = NULL;
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
                                &finally_delete,
                                NULL);
}


/**
 * Continuation called from successful rename operation.
 *
 * @param cls NULL
 * @param emsg (should also be NULL)
 */
static void
success_rename_cont (void *cls, const char *emsg)
{
  CHECK (NULL == emsg);
  op = GNUNET_IDENTITY_rename (h, "test-id", "test", &fail_rename_cont, NULL);
}


/**
 * Called with events about created ego.
 *
 * @param cls NULL
 * @param pk private key of the ego, or NULL on error
 * @param emsg error message
 */
static void
create_cb (void *cls,
           const struct GNUNET_CRYPTO_EcdsaPrivateKey *pk,
           const char *emsg)
{
  CHECK (NULL != pk);
  CHECK (NULL == emsg);
  op =
    GNUNET_IDENTITY_rename (h, "test-id", "test", &success_rename_cont, NULL);
}


/**
 * Main function of the test, run from scheduler.
 *
 * @param cls NULL
 * @param cfg configuration we use (also to connect to identity service)
 * @param peer handle to access more of the peer (not used)
 */
static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_TESTING_Peer *peer)
{
  endbadly_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT, &endbadly, NULL);
  GNUNET_SCHEDULER_add_shutdown (&cleanup, NULL);
  h = GNUNET_IDENTITY_connect (cfg, &notification_cb, NULL);
  CHECK (NULL != h);
  op = GNUNET_IDENTITY_create (h, "test-id", NULL, &create_cb, NULL);
}


int
main (int argc, char *argv[])
{
  GNUNET_DISK_directory_remove ("/tmp/gnunet/test-identity-service");
  res = 1;
  if (0 != GNUNET_TESTING_service_run ("test-identity",
                                       "identity",
                                       "test_identity.conf",
                                       &run,
                                       NULL))
    return 1;
  GNUNET_DISK_directory_remove ("/tmp/gnunet/test-identity-service");
  return res;
}


/* end of test_identity.c */
