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
 * @file ats/test_ats_api_reset_backoff.c
 * @brief test case for block reset api
 * @author Christian Grothoff
 * @author Matthias Wachs
 */
#include "platform.h"
#include "gnunet_ats_service.h"
#include "ats.h"

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10)
#define ATS_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS, 90)

static GNUNET_SCHEDULER_TaskIdentifier die_task;

static GNUNET_SCHEDULER_TaskIdentifier suggest_timeout_task;

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

struct GNUNET_HELLO_Address hello_addr;
struct Address address;
struct PeerContext peer;
struct GNUNET_ATS_Information atsi[2];

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

  if (suggest_timeout_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (suggest_timeout_task);
    suggest_timeout_task = GNUNET_SCHEDULER_NO_TASK;
  }

  if (ats != NULL)
  {
    GNUNET_ATS_scheduling_done (ats);
    ats = NULL;
  }

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

  if (suggest_timeout_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (suggest_timeout_task);
    suggest_timeout_task = GNUNET_SCHEDULER_NO_TASK;
  }

  GNUNET_ATS_scheduling_done (ats);

  ret = 0;

  stop_arm ();
}


static void
suggest_timeout (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  suggest_timeout_task = GNUNET_SCHEDULER_NO_TASK;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Requesting address for peer timed out\n");

  if (die_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (die_task);
    die_task = GNUNET_SCHEDULER_NO_TASK;
  }

  die_task = GNUNET_SCHEDULER_add_now (&end_badly, NULL);
}

static void
address_suggest_cb (void *cls, const struct GNUNET_HELLO_Address *a,
                    struct Session *session,
                    struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out,
                    struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in,
                    const struct GNUNET_ATS_Information *atsi,
                    uint32_t ats_count)
{
  static int suggestions;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "ATS suggests address `%s'\n",
              GNUNET_i2s (&a->peer));

  if (0 != memcmp (&a->peer, &peer.id,
                         sizeof (struct GNUNET_PeerIdentity)))
  {
   GNUNET_break (0);
   if (die_task != GNUNET_SCHEDULER_NO_TASK)
   {
     GNUNET_SCHEDULER_cancel (die_task);
     die_task = GNUNET_SCHEDULER_NO_TASK;
   }
   GNUNET_SCHEDULER_add_now (&end_badly, NULL);
   return;
  }

  if (0 != strcmp (a->transport_name, address.plugin))
  {
   GNUNET_break (0);
   if (die_task != GNUNET_SCHEDULER_NO_TASK)
   {
     GNUNET_SCHEDULER_cancel (die_task);
     die_task = GNUNET_SCHEDULER_NO_TASK;
   }
   GNUNET_SCHEDULER_add_now (&end_badly, NULL);
   return;
  }

  if (a->address_length != address.addr_len)
  {
   GNUNET_break (0);
   if (die_task != GNUNET_SCHEDULER_NO_TASK)
   {
     GNUNET_SCHEDULER_cancel (die_task);
     die_task = GNUNET_SCHEDULER_NO_TASK;
   }
   GNUNET_SCHEDULER_add_now (&end_badly, NULL);
   return;
  }

  if (0 != memcmp (a->address, address.addr,
      a->address_length))
  {
   GNUNET_break (0);
   if (die_task != GNUNET_SCHEDULER_NO_TASK)
   {
     GNUNET_SCHEDULER_cancel (die_task);
     die_task = GNUNET_SCHEDULER_NO_TASK;
   }
   GNUNET_SCHEDULER_add_now (&end_badly, NULL);
   return;
  }

  if (session != address.session)
  {
   GNUNET_break (0);
   if (die_task != GNUNET_SCHEDULER_NO_TASK)
   {
     GNUNET_SCHEDULER_cancel (die_task);
     die_task = GNUNET_SCHEDULER_NO_TASK;
   }
   GNUNET_SCHEDULER_add_now (&end_badly, NULL);
   return;
  }

  suggestions ++;

  if (2 == suggestions)
  {
    GNUNET_SCHEDULER_add_now(&end, NULL);
    return;
  }

  if (suggest_timeout_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (suggest_timeout_task);
    suggest_timeout_task = GNUNET_SCHEDULER_NO_TASK;
  }
  suggest_timeout_task = GNUNET_SCHEDULER_add_delayed(ATS_TIMEOUT, &suggest_timeout, NULL);
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
                                    &peer.id.hashPubKey);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Created peer `%s'\n", GNUNET_i2s (&peer.id));

  address.plugin = "test";
  address.session = NULL;
  address.addr = GNUNET_strdup ("test");
  address.addr_len = 4;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Adding address\n");

  hello_addr.peer = peer.id;
  hello_addr.transport_name = address.plugin;
  hello_addr.address = address.addr;
  hello_addr.address_length = address.addr_len;
  GNUNET_ATS_address_update (ats, &hello_addr, address.session, NULL, 0);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Requesting address for peer `%s'\n",
              GNUNET_i2s (&peer.id));
  /* Increase block timout far beyond ATS_TIMEOUT */
  GNUNET_ATS_suggest_address (ats, &peer.id);

  GNUNET_ATS_reset_backoff(ats, &peer.id);
  GNUNET_ATS_suggest_address (ats, &peer.id);
}

int
main (int argc, char *argv[])
{
  static char *const argv2[] = { "test_ats_api_scheduling",
    "-c",
    "test_ats_api.conf",
    "-L", "WARNING",
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
/* end of file test_ats_api_reset_backoff.c */
