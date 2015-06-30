/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2010 Christian Grothoff (and other contributing authors)

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
 * @file transport/test_transport_testing_startstop.c
 * @brief test case for transport testing library:
 * start the peer, get the HELLO message and stop the peer
 *
 */
#include "platform.h"
#include "gnunet_transport_service.h"
#include "transport-testing.h"

/**
 * How long until we give up on transmitting the message?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 30)

struct GNUNET_SCHEDULER_Task * timeout_task;

static struct PeerContext *p;

struct GNUNET_TRANSPORT_TESTING_handle *tth;

static int ret = 0;

static void
end ()
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Stopping peers\n");

  if (timeout_task != NULL)
    GNUNET_SCHEDULER_cancel (timeout_task);

  GNUNET_TRANSPORT_TESTING_stop_peer (tth, p);
  GNUNET_TRANSPORT_TESTING_done (tth);
}

static void
end_badly ()
{
  timeout_task = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Fail! Stopping peers\n");

  if (NULL != p)
    GNUNET_TRANSPORT_TESTING_stop_peer (tth, p);

  if (NULL != tth)
    GNUNET_TRANSPORT_TESTING_done (tth);

  ret = GNUNET_SYSERR;
}


static void
start_cb (struct PeerContext *p, void *cls)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Peer %u (`%s') successfully started\n",
              p->no,
              GNUNET_i2s (&p->id));

  ret = 0;
  GNUNET_SCHEDULER_add_now (&end, NULL);
}


static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  ret = 1;
  tth = GNUNET_TRANSPORT_TESTING_init ();
  GNUNET_assert (NULL != tth);

  timeout_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_MINUTES, &end_badly, NULL);

  p = GNUNET_TRANSPORT_TESTING_start_peer(tth, cfgfile, 1,
                                          NULL, /* receive cb */
                                          NULL, /* connect cb */
                                          NULL, /* disconnect cb */
                                          start_cb, /* startup cb */
                                          NULL); /* closure */
  if (NULL == p)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Failed to start peer\n");
    if (timeout_task != NULL)
      GNUNET_SCHEDULER_cancel (timeout_task);
    timeout_task = GNUNET_SCHEDULER_add_now (&end_badly, NULL);
  }
}

int
main (int argc, char *argv[])
{
  GNUNET_log_setup ("test_transport_testing_startstop",
                    "WARNING",
                    NULL);

  char *const argv_1[] = { "test_transport_testing",
    "-c",
    "test_transport_api_data.conf",
    NULL
  };

  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  GNUNET_PROGRAM_run ((sizeof (argv_1) / sizeof (char *)) - 1, argv_1,
                      "test_transport_testing_startstop", "nohelp", options, &run, &ret);

  return ret;
}

/* end of test_transport_testing_startstop.c */
