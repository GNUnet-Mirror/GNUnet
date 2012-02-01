/*
     This file is part of GNUnet.
     (C) 2009, 2010, 2011 Christian Grothoff (and other contributing authors)

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
 * @file transport/transport_api_blacklisting.c
 * @brief test for the blacklisting API
 * @author Matthias Wachs
 *
 */
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_hello_lib.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_os_lib.h"
#include "gnunet_program_lib.h"
#include "gnunet_scheduler_lib.h"
#include "gnunet_transport_service.h"
#include "transport.h"
#include "transport-testing.h"

#define VERBOSE GNUNET_EXTRA_LOGGING
#define VERBOSE_ARM GNUNET_EXTRA_LOGGING

#define START_ARM GNUNET_YES

/**
 * How long until we give up on transmitting the message?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 120)

/**
 * How long until we give up on transmitting the message?
 */
#define TIMEOUT_TRANSMIT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 60)

#define MTYPE 12345

static int ok;

struct GNUNET_TRANSPORT_Blacklist * blacklist;

static GNUNET_SCHEDULER_TaskIdentifier die_task;

#if VERBOSE
#define OKPP do { ok++; FPRINTF (stderr, "Now at stage %u at %s:%u\n", ok, __FILE__, __LINE__); } while (0)
#else
#define OKPP do { ok++; } while (0)
#endif


static void
end ()
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Stopping\n");

  if (die_task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (die_task);

  ok = 0;
}

static void
end_badly (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  die_task = GNUNET_SCHEDULER_NO_TASK;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Fail!\n");

  ok = GNUNET_SYSERR;
}


int blacklist_cb (void *cls,
                 const struct
                 GNUNET_PeerIdentity * pid)
{
  return GNUNET_YES;
}

static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  die_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT, &end_badly, NULL);

  blacklist = GNUNET_TRANSPORT_blacklist (cfg,
                              &blacklist_cb,
                              NULL);

  GNUNET_assert (blacklist != NULL);

  GNUNET_TRANSPORT_blacklist_cancel (blacklist);

  end ();
}


static int
check ()
{
  static char *const argv[] = { "test-transport-api-blacklisting",
    "-c",
    "test_transport_api_data.conf",
#if VERBOSE
    "-L", "DEBUG",
#endif
    NULL
  };
  static struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

#if WRITECONFIG
  setTransportOptions ("test_transport_api_data.conf");
#endif

  ok = 1;
  GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1, argv, "test-transport-api-blacklisting",
                      "nohelp", options, &run, &ok);

  return ok;
}

int
main (int argc, char *argv[])
{
  int ret;

  GNUNET_log_setup ("test-transport-api-blacklisting",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);

  ret = check ();

  return ret;
}

/* end of transport_api_blacklisting.c */
