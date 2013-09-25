/*
 * This file is part of GNUnet
 * (C) 2013 Christian Grothoff (and other contributing authors)
 *
 * GNUnet is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 3, or (at your
 * option) any later version.
 *
 * GNUnet is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNUnet; see the file COPYING.  If not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

/**
 * @file psycstore/test_psycstore.c
 * @brief Test for the PSYCstore service.
 * @author Gabor X Toth
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_lib.h"
#include "gnunet_psyc_service.h"

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10)

#define DEBUG_SERVICE 1


/**
 * Return value from 'main'.
 */
static int res;

static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Handle for task for timeout termination.
 */
static GNUNET_SCHEDULER_TaskIdentifier end_badly_task;

static struct GNUNET_PSYC_Master *mst;
static struct GNUNET_PSYC_Slave *slv;
static struct GNUNET_PSYC_Channel *ch;

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
  if (master != NULL)
  {
    GNUNET_PSYC_master_stop (master);
    master = NULL;
  }
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Terminate the testcase (failure).
 *
 * @param cls NULL
 * @param tc scheduler context
 */
static void
end_badly (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  res = 1;
  cleanup ();
}


/**
 * Terminate the testcase (success).
 *
 * @param cls NULL
 * @param tc scheduler context
 */
static void
end_normally (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  res = 0;
  cleanup ();
}


/**
 * Finish the testcase (successfully).
 */
static void
end ()
{
  if (end_badly_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (end_badly_task);
    end_badly_task = GNUNET_SCHEDULER_NO_TASK;
  }
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_MILLISECONDS,
				&end_normally, NULL);
}


static int
method (void *cls, const struct GNUNET_CRYPTO_EccPublicSignKey *slave_key,
        uint64_t message_id, const char *method_name,
        size_t modifier_count, const struct GNUNET_ENV_Modifier *modifiers,
        uint64_t data_offset, const void *data, size_t data_size,
        enum GNUNET_PSYC_MessageFlags flags)
{
  return GNUNET_OK;
}


static int
join (void *cls, const struct GNUNET_CRYPTO_EccPublicSignKey *slave_key,
      const char *method_name,
      size_t variable_count, const struct GNUNET_ENV_Modifier *variables,
      const void *data, size_t data_size, struct GNUNET_PSYC_JoinHandle *jh)
{
  return GNUNET_OK;
}


void
master_started (void *cls, uint64_t max_message_id)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Master started: %lu\n", max_message_id);
}


void
slave_joined (void *cls, uint64_t max_message_id)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Slave joined: %lu\n", max_message_id);
}


/**
 * Main function of the test, run from scheduler.
 *
 * @param cls NULL
 * @param cfg configuration we use (also to connect to PSYCstore service)
 * @param peer handle to access more of the peer (not used)
 */
static void
#if DEBUG_SERVICE
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *c)
#else
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *c,
     struct GNUNET_TESTING_Peer *peer)
#endif
{
  cfg = c;
  end_badly_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT, &end_badly, NULL);

  channel_key = GNUNET_CRYPTO_ecc_key_create ();
  slave_key = GNUNET_CRYPTO_ecc_key_create ();

  GNUNET_CRYPTO_ecc_key_get_public_for_signature (channel_key, &channel_pub_key);
  GNUNET_CRYPTO_ecc_key_get_public_for_signature (slave_key, &slave_pub_key);

  mst = GNUNET_PSYC_master_start (cfg, channel_key,
                                  GNUNET_PSYC_CHANNEL_PRIVATE,
                                  &method, &join, &master_started, NULL);

  slv = GNUNET_PSYC_slave_join (cfg, &channel_pub_key, slave_key,
                                &method, &join, &slave_joined, NULL);
}


int
main (int argc, char *argv[])
{
  res = 1;
#if DEBUG_SERVICE
  const struct GNUNET_GETOPT_CommandLineOption opts[] = {
    GNUNET_GETOPT_OPTION_END
  };
  if (GNUNET_OK != GNUNET_PROGRAM_run (argc, argv, "test-psyc",
                                       "test-psyc [options]",
                                       opts, &run, NULL))
    return 1;
#else
  if (0 != GNUNET_TESTING_service_run ("test-psyc", "psyc",
                                       "test_psyc.conf", &run, NULL))
    return 1;
#endif
  return res;
}

/* end of test_psyc.c */
