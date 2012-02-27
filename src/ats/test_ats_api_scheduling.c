/*
     This file is part of GNUnet.
     (C) 2010,2011 Christian Grothoff (and other contributing authors)

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
 * @file ats/test_ats_api_scheduling.c
 * @brief test automatic transport selection scheduling API
 * @author Christian Grothoff
 * @author Matthias Wachs
 *
 * TODO:
 * - write test case
 * - extend API to get performance data
 * - implement simplistic strategy based on say 'lowest latency' or strict ordering
 * - extend API to get peer preferences, implement proportional bandwidth assignment
 * - re-implement API against a real ATS service (!)
 */
#include "platform.h"
#include "gnunet_ats_service.h"
#include "ats.h"

#define VERBOSE GNUNET_NO

#define VERBOSE_ARM GNUNET_NO

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10)

static GNUNET_SCHEDULER_TaskIdentifier die_task;

static struct GNUNET_ATS_SchedulingHandle *ats;

struct GNUNET_OS_Process *arm_proc;



static int ret;

struct Address
{
  char *plugin;
  size_t plugin_len;

  void *addr;
  size_t addr_len;

  struct GNUNET_ATS_Information *ats;
  int ats_count;

  void *session;
};

struct PeerContext
{
  struct GNUNET_PeerIdentity id;

  struct Address *addr;
};

struct Address addr[2];
struct PeerContext p[2];
struct GNUNET_ATS_Information atsi[2];

static void
stop_arm ()
{
  if (0 != GNUNET_OS_process_kill (arm_proc, SIGTERM))
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "kill");
  GNUNET_OS_process_wait (arm_proc);
  GNUNET_OS_process_close (arm_proc);
  arm_proc = NULL;
}


static void
end_badly (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  die_task = GNUNET_SCHEDULER_NO_TASK;
  if (ats != NULL)
    GNUNET_ATS_scheduling_done (ats);

  ret = GNUNET_SYSERR;

  stop_arm ();
}


static void
end ()
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Shutting down\n");
  if (die_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (die_task);
    die_task = GNUNET_SCHEDULER_NO_TASK;
  }

  GNUNET_ATS_scheduling_done (ats);

  ret = 0;

  stop_arm ();
}


static void
address_suggest_cb (void *cls, const struct GNUNET_HELLO_Address *address,
                    struct Session *session,
                    struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out,
                    struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in,
                    const struct GNUNET_ATS_Information *ats,
                    uint32_t ats_count)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "ATS suggests address `%s'\n",
              GNUNET_i2s (&address->peer));

  GNUNET_assert (0 ==
                 memcmp (&address->peer, &p[0].id,
                         sizeof (struct GNUNET_PeerIdentity)));
  GNUNET_assert (0 == strcmp (address->transport_name, addr[0].plugin));
  GNUNET_assert (address->address_length == addr[0].addr_len);
  GNUNET_assert (0 ==
                 memcmp (address->address, addr[0].plugin,
                         address->address_length));
  GNUNET_assert (addr[0].session == session);


  /* TODO ats merge
   * GNUNET_assert (ats_count == 2);
   * GNUNET_assert (atsi[0].type == htons (1));
   * GNUNET_assert (atsi[0].type == htons (2));
   * GNUNET_assert (atsi[1].type == htons (2));
   * GNUNET_assert (atsi[1].type == htons (2));
   */

  ret = 0;

  GNUNET_SCHEDULER_add_now (&end, NULL);
}

void
start_arm (const char *cfgname)
{
  arm_proc =
    GNUNET_OS_start_process (GNUNET_YES, NULL, NULL, "gnunet-service-arm",
                               "gnunet-service-arm",
#if VERBOSE_ARM
                               "-L", "DEBUG",
#endif
                               "-c", cfgname, NULL);
}

static void
check (void *cls, char *const *args, const char *cfgfile,
       const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_HELLO_Address address0;

  ret = GNUNET_SYSERR;

  die_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT, &end_badly, NULL);
  start_arm (cfgfile);

  ats = GNUNET_ATS_scheduling_init (cfg, &address_suggest_cb, NULL);

  if (ats == NULL)
  {
    ret = GNUNET_SYSERR;
    end ();
    return;
  }

  /* set up peer */
  GNUNET_CRYPTO_hash_create_random (GNUNET_CRYPTO_QUALITY_WEAK,
                                    &p[0].id.hashPubKey);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Created peer `%s'\n",
              GNUNET_i2s (&p[0].id));

  GNUNET_CRYPTO_hash_create_random (GNUNET_CRYPTO_QUALITY_WEAK,
                                    &p[1].id.hashPubKey);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Created peer `%s'\n",
              GNUNET_i2s (&p[1].id));

  addr[0].plugin = "test";
  addr[0].session = NULL;
  addr[0].addr = GNUNET_strdup ("test");
  addr[0].addr_len = 4;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Testing address creation\n");

  address0.peer = p[0].id;
  address0.transport_name = addr[0].plugin;
  address0.address = addr[0].addr;
  address0.address_length = addr[0].addr_len;
  GNUNET_ATS_address_update (ats, &address0, addr[0].session, NULL, 0);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Testing ATS info creation\n");

  atsi[0].type = htonl (GNUNET_ATS_UTILIZATION_UP);
  atsi[0].value = htonl (1024);

  GNUNET_ATS_address_update (ats, &address0, addr[0].session, atsi, 1);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Testing ATS info update\n");

  atsi[0].type = htonl (GNUNET_ATS_UTILIZATION_UP);
  atsi[0].value = htonl (2048);

  atsi[1].type = htonl (GNUNET_ATS_UTILIZATION_DOWN);
  atsi[1].value = htonl (1024);

  GNUNET_ATS_address_update (ats, &address0, addr[0].session, atsi, 2);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Testing manual address deletion \n");
  address0.peer = p[1].id;      // FIXME: why? typo in old code?
  GNUNET_ATS_address_update (ats, &address0, addr[0].session, NULL, 0);
  GNUNET_ATS_address_destroyed (ats, &address0, addr[0].session);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Requesting peer `%s'\n",
              GNUNET_i2s (&p[0].id));
  GNUNET_ATS_suggest_address (ats, &p[0].id);
}

int
main (int argc, char *argv[])
{
  static char *const argv2[] = { "test_ats_api_scheduling",
    "-c",
    "test_ats_api.conf",
#if VERBOSE
    "-L", "DEBUG",
#else
    "-L", "WARNING",
#endif
    NULL
  };

  static struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  GNUNET_PROGRAM_run ((sizeof (argv2) / sizeof (char *)) - 1, argv2,
                      "test_ats_api_scheduling", "nohelp", options, &check,
                      NULL);


  return ret;
}

/* end of file test_ats_api_scheduling.c */
