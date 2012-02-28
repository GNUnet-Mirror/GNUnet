/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

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
 * @file namestore/test_namestore_api_zone_iteration.c
 * @brief testcase for namestore_api.c zone iteration functionality
 */
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_namestore_service.h"

#define VERBOSE GNUNET_NO

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10)

static struct GNUNET_NAMESTORE_Handle * nsh;

static GNUNET_SCHEDULER_TaskIdentifier endbadly_task;
static GNUNET_SCHEDULER_TaskIdentifier stopiteration_task;
static struct GNUNET_OS_Process *arm;

static struct GNUNET_CRYPTO_RsaPrivateKey * privkey;
static struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded pubkey;
static GNUNET_HashCode zone;

static struct GNUNET_NAMESTORE_ZoneIterator *zi;
static int res;

static void
start_arm (const char *cfgname)
{
  arm = GNUNET_OS_start_process (GNUNET_YES, NULL, NULL, "gnunet-service-arm",
                               "gnunet-service-arm", "-c", cfgname,
#if VERBOSE_PEERS
                               "-L", "DEBUG",
#else
                               "-L", "ERROR",
#endif
                               NULL);
}

static void
stop_arm ()
{
  if (NULL != arm)
  {
    if (0 != GNUNET_OS_process_kill (arm, SIGTERM))
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "kill");
    GNUNET_OS_process_wait (arm);
    GNUNET_OS_process_close (arm);
    arm = NULL;
  }
}

/**
 * Re-establish the connection to the service.
 *
 * @param cls handle to use to re-connect.
 * @param tc scheduler context
 */
static void
endbadly (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (stopiteration_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (stopiteration_task);
    stopiteration_task = GNUNET_SCHEDULER_NO_TASK;
  }

  if (nsh != NULL)
    GNUNET_NAMESTORE_disconnect (nsh, GNUNET_YES);
  nsh = NULL;

  if (privkey != NULL)
    GNUNET_CRYPTO_rsa_key_free (privkey);
  privkey = NULL;

  if (NULL != arm)
    stop_arm();

  res = 1;
}


static void
end (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (stopiteration_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (stopiteration_task);
    stopiteration_task = GNUNET_SCHEDULER_NO_TASK;
  }

  if (endbadly_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (endbadly_task);
    endbadly_task = GNUNET_SCHEDULER_NO_TASK;
  }


  if (privkey != NULL)
    GNUNET_CRYPTO_rsa_key_free (privkey);
  privkey = NULL;

  if (nsh != NULL)
    GNUNET_NAMESTORE_disconnect (nsh, GNUNET_YES);
  nsh = NULL;


  if (NULL != arm)
    stop_arm();

  res = 0;
}

static void
stop_iteration (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  stopiteration_task = GNUNET_SCHEDULER_NO_TASK;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Stopping iteration for zone `%s'\n", GNUNET_h2s (&zone));
  GNUNET_NAMESTORE_zone_iteration_stop (zi);

  GNUNET_SCHEDULER_add_now (&end, NULL);
}

void zone_proc (void *cls,
                const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *zone_key,
                struct GNUNET_TIME_Absolute expire,
                const char *name,
                unsigned int rd_count,
                const struct GNUNET_NAMESTORE_RecordData *rd,
                const struct GNUNET_CRYPTO_RsaSignature *signature)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Callback for zone `%s'\n", GNUNET_h2s (&zone));

  stopiteration_task = GNUNET_SCHEDULER_add_now (&stop_iteration, NULL);
}

static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  endbadly_task = GNUNET_SCHEDULER_add_delayed(TIMEOUT,&endbadly, NULL);

  privkey = GNUNET_CRYPTO_rsa_key_create_from_file("hostkey");
  GNUNET_assert (privkey != NULL);
  GNUNET_CRYPTO_rsa_key_get_public(privkey, &pubkey);

  GNUNET_CRYPTO_hash_create_random (GNUNET_CRYPTO_QUALITY_WEAK, &zone);

  start_arm (cfgfile);
  GNUNET_assert (arm != NULL);

  nsh = GNUNET_NAMESTORE_connect (cfg);
  GNUNET_break (NULL != nsh);

  zi = GNUNET_NAMESTORE_zone_iteration_start(nsh,
                                        &zone,
                                        GNUNET_NAMESTORE_RF_NONE,
                                        GNUNET_NAMESTORE_RF_NONE,
                                        zone_proc,
                                        &zone);
  if (zi == NULL)
  {
    GNUNET_break (0);
    GNUNET_SCHEDULER_cancel (endbadly_task);
    endbadly_task = GNUNET_SCHEDULER_add_now (&endbadly, NULL);
  }
}

static int
check ()
{
  static char *const argv[] = { "test_namestore_api_zone_iteration",
    "-c",
    "test_namestore_api.conf",
#if VERBOSE
    "-L", "DEBUG",
#endif
    NULL
  };
  static struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  res = 1;
  GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1, argv, "test_namestore_api_zone_iteration",
                      "nohelp", options, &run, &res);
  return res;
}

int
main (int argc, char *argv[])
{
  int ret;

  ret = check ();

  return ret;
}

/* end of test_namestore_api_zone_iteration.c */
