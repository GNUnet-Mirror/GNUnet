/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2010, 2016 GNUnet e.V.

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
 * @file transport/test_transport_testing_restart.c
 * @brief test case for transport testing library:
 * start the peer, get the HELLO message, restart and stop the peer
 */
#include "platform.h"
#include "gnunet_transport_service.h"
#include "transport-testing.h"

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 30)


static struct GNUNET_SCHEDULER_Task *timeout_task;

static struct GNUNET_TRANSPORT_TESTING_PeerContext *p;

static struct GNUNET_TRANSPORT_TESTING_Handle *tth;

static int ret;


static void
end ()
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Stopping peers\n");
  if (NULL != timeout_task)
    GNUNET_SCHEDULER_cancel (timeout_task);
  if (NULL != p)
    GNUNET_TRANSPORT_TESTING_stop_peer (p);
  if (NULL != tth)
    GNUNET_TRANSPORT_TESTING_done (tth);
}


static void
end_badly ()
{
  timeout_task = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "Timeout!\n");
  end ();
  ret = GNUNET_SYSERR;
}


static void
restart_cb (struct GNUNET_TRANSPORT_TESTING_PeerContext *p,
            void *cls)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Peer %u (`%s') successfully restarted\n",
              p->no,
              GNUNET_i2s (&p->id));
  ret = 0;
  end ();
}


static void
restart_task ()
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Peer %u (`%s') restarting\n",
              p->no,
              GNUNET_i2s (&p->id));
  GNUNET_TRANSPORT_TESTING_restart_peer (p,
                                         &restart_cb,
                                         p);
}


static void
start_cb (struct GNUNET_TRANSPORT_TESTING_PeerContext *p,
          void *cls)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Peer %u (`%s') successfully started\n",
              p->no,
              GNUNET_i2s (&p->id));
  GNUNET_SCHEDULER_add_now (&restart_task,
                            NULL);
}


static void
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  ret = 1;
  tth = GNUNET_TRANSPORT_TESTING_init ();
  GNUNET_assert (NULL != tth);

  timeout_task
    = GNUNET_SCHEDULER_add_delayed (TIMEOUT,
                                    &end_badly,
                                    NULL);
  p = GNUNET_TRANSPORT_TESTING_start_peer(tth,
                                          cfgfile,
                                          1,
                                          NULL, /* receive cb */
                                          NULL, /* connect cb */
                                          NULL, /* disconnect cb */
                                          start_cb, /* startup cb */
                                          NULL); /* closure */
  if (NULL == p)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to start peer\n");
    end ();
    ret = 1;
  }
}


int
main (int argc,
      char *argv[])
{
  char *const argv_1[] = { "test_transport_testing_restart",
    "-c",
    "test_transport_api_data.conf",
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  GNUNET_log_setup ("test_transport_testing_restart",
                    "WARNING",
                    NULL);
  GNUNET_PROGRAM_run ((sizeof (argv_1) / sizeof (char *)) - 1,
                      argv_1,
                      "test_transport_testing_restart",
                      "nohelp",
                      options,
                      &run,
                      NULL);
  return ret;
}

/* end of test_transport_testing_restart.c */
