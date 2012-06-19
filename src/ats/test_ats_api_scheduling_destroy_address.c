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
 * @file ats/test_ats_api_scheduling_destroy_address.c
 * @brief test destroying addresses in automatic transport selection scheduling API
 * @author Christian Grothoff
 * @author Matthias Wachs
 *
 */
#include "platform.h"
#include "gnunet_ats_service.h"
#include "ats.h"

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10)

static GNUNET_SCHEDULER_TaskIdentifier die_task;

static struct GNUNET_ATS_SchedulingHandle *ats;

struct GNUNET_OS_Process *arm_proc;



static int ret;
static int stage;

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

struct Address test_addr;
struct PeerContext p;
struct GNUNET_ATS_Information atsi;
struct GNUNET_HELLO_Address hello_address;

static void
stop_arm ()
{
  if (0 != GNUNET_OS_process_kill (arm_proc, SIGTERM))
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "kill");
  GNUNET_OS_process_wait (arm_proc);
  GNUNET_OS_process_destroy (arm_proc);
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

  if (2 == stage)
    ret = 0;
  else
  {
    GNUNET_break (0);
    ret = 1;
  }

  stop_arm ();
}


static void
address_suggest_cb (void *cls, const struct GNUNET_HELLO_Address *address,
                    struct Session *session,
                    struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out,
                    struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in,
                    const struct GNUNET_ATS_Information *atsi,
                    uint32_t ats_count)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Stage %u: ATS suggests address `%s' session %p\n",
              stage, GNUNET_i2s (&address->peer), session);
  GNUNET_ATS_reset_backoff(ats, &address->peer);

  GNUNET_assert (0 ==
                 memcmp (&address->peer, &p.id,
                         sizeof (struct GNUNET_PeerIdentity)));
  GNUNET_assert (0 == strcmp (address->transport_name, test_addr.plugin));
  GNUNET_assert (address->address_length == test_addr.addr_len);
  GNUNET_assert (0 ==
                 memcmp (address->address, test_addr.plugin,
                         address->address_length));
  GNUNET_assert (test_addr.session == session);

  if (0 == stage)
  {
    /* Delete session */
    GNUNET_ATS_address_destroyed (ats, &hello_address, test_addr.session);
    test_addr.session = NULL;
    GNUNET_ATS_suggest_address (ats, &p.id);
  }
  if (1 == stage)
  {
    /* Delete address */
    GNUNET_ATS_address_destroyed (ats, &hello_address, test_addr.session);
    test_addr.session = NULL;
    GNUNET_ATS_suggest_address (ats, &p.id);
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS, &end, NULL);
  }
  stage++;
}

void
start_arm (const char *cfgname)
{
  arm_proc =
    GNUNET_OS_start_process (GNUNET_YES, NULL, NULL, "gnunet-service-arm",
                               "gnunet-service-arm",
                               "-c", cfgname, NULL);
}

static void
check (void *cls, char *const *args, const char *cfgfile,
       const struct GNUNET_CONFIGURATION_Handle *cfg)
{
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
                                    &p.id.hashPubKey);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Created peer `%s'\n",
              GNUNET_i2s (&p.id));

  test_addr.plugin = "test";
  test_addr.session = &test_addr;
  test_addr.addr = GNUNET_strdup ("test");
  test_addr.addr_len = 4;

  /* Adding address with session */
  hello_address.peer = p.id;
  hello_address.transport_name = test_addr.plugin;
  hello_address.address = test_addr.addr;
  hello_address.address_length = test_addr.addr_len;
  GNUNET_ATS_address_add (ats, &hello_address, test_addr.session, NULL, 0);

  GNUNET_ATS_suggest_address (ats, &p.id);
}

int
main (int argc, char *argv[])
{
  static char *const argv2[] = { "test_ats_api_scheduling_destroy_address",
    "-c",
    "test_ats_api.conf",
    "-L", "WARNING",
    NULL
  };

  static struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  GNUNET_PROGRAM_run ((sizeof (argv2) / sizeof (char *)) - 1, argv2,
                      "test_ats_api_scheduling_destroy_address", "nohelp", options, &check,
                      NULL);


  return ret;
}

/* end of file test_ats_api_scheduling_destroy_address.c */
