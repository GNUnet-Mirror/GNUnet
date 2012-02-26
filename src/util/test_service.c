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
 * @file util/test_service.c
 * @brief tests for service.c
 */
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_client_lib.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_program_lib.h"
#include "gnunet_service_lib.h"
#include "gnunet_scheduler_lib.h"
#include "gnunet_time_lib.h"


#define VERBOSE GNUNET_NO

#define PORT 12435

#define MY_TYPE 256

static struct GNUNET_SERVICE_Context *sctx;

static int ok = 1;


static size_t
build_msg (void *cls, size_t size, void *buf)
{
  struct GNUNET_CLIENT_Connection *client = cls;
  struct GNUNET_MessageHeader *msg = buf;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Client connected, transmitting\n");
  GNUNET_assert (size >= sizeof (struct GNUNET_MessageHeader));
  msg->type = htons (MY_TYPE);
  msg->size = htons (sizeof (struct GNUNET_MessageHeader));
  GNUNET_CLIENT_disconnect (client, GNUNET_NO);
  return sizeof (struct GNUNET_MessageHeader);
}


static void
ready (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  const struct GNUNET_CONFIGURATION_Handle *cfg = cls;
  struct GNUNET_CLIENT_Connection *client;

  GNUNET_assert (0 != (tc->reason & GNUNET_SCHEDULER_REASON_PREREQ_DONE));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Service confirmed running\n");
  client = GNUNET_CLIENT_connect ("test_service", cfg);
  GNUNET_assert (client != NULL);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Client connecting, waiting to transmit\n");
  GNUNET_CLIENT_notify_transmit_ready (client,
                                       sizeof (struct GNUNET_MessageHeader),
                                       GNUNET_TIME_UNIT_SECONDS, GNUNET_NO,
                                       &build_msg, client);
}


static void
do_stop (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_SERVICE_stop (sctx);
}


static void
recv_cb (void *cls, struct GNUNET_SERVER_Client *client,
         const struct GNUNET_MessageHeader *message)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Receiving client message...\n");
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
  if (sctx != NULL)
    GNUNET_SCHEDULER_add_now (&do_stop, NULL);
  else
    GNUNET_SCHEDULER_shutdown ();
  ok = 0;
}


static struct GNUNET_SERVER_MessageHandler myhandlers[] = {
  {&recv_cb, NULL, MY_TYPE, sizeof (struct GNUNET_MessageHeader)},
  {NULL, NULL, 0, 0}
};


static void
runner (void *cls, struct GNUNET_SERVER_Handle *server,
        const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Service initializing\n");
  GNUNET_SERVER_add_handlers (server, myhandlers);
  GNUNET_CLIENT_service_test ("test_service", cfg, GNUNET_TIME_UNIT_SECONDS,
                              &ready, (void *) cfg);
}


/**
 * Main method, starts scheduler with task1,
 * checks that "ok" is correct at the end.
 */
static int
check ()
{
  ok = 1;
  char *const argv[] = {
    "test_service",
    "-c",
    "test_service_data.conf",
    "-L",
#if VERBOSE
    "DEBUG",
#else
    "WARNING",
#endif
    NULL
  };
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Starting service\n");
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_SERVICE_run (5, argv, "test_service",
                                     GNUNET_SERVICE_OPTION_NONE, &runner, &ok));
  GNUNET_assert (0 == ok);
  return ok;
}

static void
ready6 (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  const struct GNUNET_CONFIGURATION_Handle *cfg = cls;
  struct GNUNET_CLIENT_Connection *client;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "V6 ready\n");
  GNUNET_assert (0 != (tc->reason & GNUNET_SCHEDULER_REASON_PREREQ_DONE));
  client = GNUNET_CLIENT_connect ("test_service6", cfg);
  GNUNET_assert (client != NULL);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "V6 client connected\n");
  GNUNET_CLIENT_notify_transmit_ready (client,
                                       sizeof (struct GNUNET_MessageHeader),
                                       GNUNET_TIME_UNIT_SECONDS, GNUNET_NO,
                                       &build_msg, client);
}

static void
runner6 (void *cls, struct GNUNET_SERVER_Handle *server,
         const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Initializing v6 service\n");
  GNUNET_SERVER_add_handlers (server, myhandlers);
  GNUNET_CLIENT_service_test ("test_service6", cfg, GNUNET_TIME_UNIT_SECONDS,
                              &ready6, (void *) cfg);
}

/**
 * Main method, starts scheduler with task1,
 * checks that "ok" is correct at the end.
 */
static int
check6 ()
{
  char *const argv[] = {
    "test_service6",
    "-c",
    "test_service_data.conf",
    "-L",
#if VERBOSE
    "DEBUG",
#else
    "WARNING",
#endif
    NULL
  };
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Starting v6 service\n");
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_SERVICE_run (5, argv, "test_service6",
                                     GNUNET_SERVICE_OPTION_NONE, &runner6,
                                     &ok));
  GNUNET_assert (0 == ok);
  return ok;
}



static void
start_stop_main (void *cls, char *const *args, const char *cfgfile,
                 const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  int *ret = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Starting service using start method\n");
  sctx = GNUNET_SERVICE_start ("test_service", cfg);
  GNUNET_assert (NULL != sctx);
  runner (cls, GNUNET_SERVICE_get_server (sctx), cfg);
  *ret = 0;
}


static int
check_start_stop ()
{
  char *const argv[] = {
    "test-service-program",
    "-c",
    "test_service_data.conf",
    "-L",
#if VERBOSE
    "DEBUG",
#else
    "WARNING",
#endif
    NULL
  };
  const struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  int ret = 1;

  GNUNET_assert (GNUNET_OK ==
                 GNUNET_PROGRAM_run (5, argv, "test-service-program", "no help",
                                     options, &start_stop_main, &ret));

  GNUNET_break (0 == ret);
  return ret;
}


int
main (int argc, char *argv[])
{
  int ret = 0;
  struct GNUNET_NETWORK_Handle *s = NULL;

  GNUNET_log_setup ("test-service",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);
  ret += check ();
  ret += check ();

  // FIXME
#ifndef MINGW
  s = GNUNET_NETWORK_socket_create (PF_INET6, SOCK_STREAM, 0);
#endif
  if (NULL == s)
  {
    if ((errno == ENOBUFS) || (errno == ENOMEM) || (errno == ENFILE) ||
        (errno == EACCES))
    {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "socket");
      return 1;
    }
    FPRINTF (stderr,
             "IPv6 support seems to not be available (%s), not testing it!\n",
             strerror (errno));
  }
  else
  {
    GNUNET_break (GNUNET_OK == GNUNET_NETWORK_socket_close (s));
    ret += check6 ();
  }
  ret += check_start_stop ();

  return ret;
}

/* end of test_service.c */
