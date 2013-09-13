/*
     This file is part of GNUnet.
     (C) 2013 Christian Grothoff (and other contributing authors)

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
 * @file psycstore/test_psycstore.c
 * @brief Testcase for the PSYCstore service
 * @author Gabor X Toth
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_util_lib.h"
#include "gnunet_psycstore_service.h"
#include "gnunet_testing_lib.h"


#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10)


/**
 * Return value from 'main'.
 */
static int res;

/**
 * Handle to PSYCstore service.
 */
static struct GNUNET_PSYCSTORE_Handle *h;

/**
 * Handle to PSYCstore operation.
 */
static struct GNUNET_PSYCSTORE_OperationHandle *op;

/**
 * Handle for task for timeout termination.
 */ 
static GNUNET_SCHEDULER_TaskIdentifier endbadly_task;

static struct GNUNET_CRYPTO_EccPrivateKey *channel_key;
static struct GNUNET_CRYPTO_EccPrivateKey *slave_key;

static struct GNUNET_CRYPTO_EccPublicSignKey channel_pub_key;
static struct GNUNET_CRYPTO_EccPublicSignKey slave_pub_key;

/**
 * Clean up all resources used.
 */
static void
cleanup ()
{
  if (NULL != op)
  {
    GNUNET_PSYCSTORE_operation_cancel (op);
    op = NULL;
  }
  if (NULL != h)
  {
    GNUNET_PSYCSTORE_disconnect (h);
    h = NULL;
  }
  if (NULL != channel_key)
  {
    GNUNET_free (channel_key);
    channel_key = NULL;
  }
  if (NULL != slave_key)
  {
    GNUNET_free (slave_key);
    slave_key = NULL;
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
  if (endbadly_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (endbadly_task);
    endbadly_task = GNUNET_SCHEDULER_NO_TASK;
  }
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_MILLISECONDS,
				&end_normally, NULL);
}

void
membership_store_result (void *cls, int result, const char *err_msg)
{

}

/**
 * Main function of the test, run from scheduler.
 *
 * @param cls NULL
 * @param cfg configuration we use (also to connect to PSYCstore service)
 * @param peer handle to access more of the peer (not used)
 */
static void
run (void *cls, 
     const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_TESTING_Peer *peer)
{
  endbadly_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT, 
						&endbadly, NULL); 
  h = GNUNET_PSYCSTORE_connect (cfg);
  GNUNET_assert (NULL != h);

  channel_key = GNUNET_CRYPTO_ecc_key_create ();
  slave_key = GNUNET_CRYPTO_ecc_key_create ();

  GNUNET_CRYPTO_ecc_key_get_public_for_signature (channel_key, &channel_pub_key);
  GNUNET_CRYPTO_ecc_key_get_public_for_signature (slave_key, &slave_pub_key);

  op = GNUNET_PSYCSTORE_membership_store (h, &channel_pub_key, &slave_pub_key,
                                          GNUNET_YES, 2, 2, 1,
                                          &membership_store_result, NULL);

  end ();
}


int
main (int argc, char *argv[])
{
  res = 1;
  if (0 != 
      GNUNET_TESTING_service_run ("test-psycstore",
				  "psycstore",
				  "test_psycstore.conf",
				  &run,
				  NULL))
    return 1;
  return res;
}


/* end of test_psycstore.c */
