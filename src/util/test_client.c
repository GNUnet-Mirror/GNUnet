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
 * @file util/test_client.c
 * @brief tests for client.c
 */
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_client_lib.h"
#include "gnunet_configuration_lib.h"
#include "gnunet_scheduler_lib.h"
#include "gnunet_server_lib.h"
#include "gnunet_time_lib.h"

#define VERBOSE GNUNET_NO

#define PORT 14325

#define MYNAME "test_client"

static struct GNUNET_CLIENT_Connection *client;

static struct GNUNET_SERVER_Handle *server;

static struct GNUNET_CONFIGURATION_Handle *cfg;

#define MY_TYPE 130

struct CopyContext
{
  struct GNUNET_SERVER_Client *client;
  struct GNUNET_MessageHeader *cpy;
};

static size_t
copy_msg (void *cls, size_t size, void *buf)
{
  struct CopyContext *ctx = cls;
  struct GNUNET_MessageHeader *cpy = ctx->cpy;

  GNUNET_assert (sizeof (struct GNUNET_MessageHeader) == ntohs (cpy->size));
  GNUNET_assert (size >= ntohs (cpy->size));
  memcpy (buf, cpy, ntohs (cpy->size));
  GNUNET_SERVER_receive_done (ctx->client, GNUNET_OK);
  GNUNET_free (cpy);
  GNUNET_free (ctx);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Message bounced back to client\n");
  return sizeof (struct GNUNET_MessageHeader);
}


/**
 * Callback that just bounces the message back to the sender.
 */
static void
echo_cb (void *cls, struct GNUNET_SERVER_Client *client,
         const struct GNUNET_MessageHeader *message)
{
  struct CopyContext *cc;
  struct GNUNET_MessageHeader *cpy;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Receiving message from client, bouncing back\n");
  GNUNET_assert (sizeof (struct GNUNET_MessageHeader) == ntohs (message->size));
  cc = GNUNET_malloc (sizeof (struct CopyContext));
  cc->client = client;
  cpy = GNUNET_malloc (ntohs (message->size));
  memcpy (cpy, message, ntohs (message->size));
  cc->cpy = cpy;
  GNUNET_assert (NULL !=
                 GNUNET_SERVER_notify_transmit_ready (client,
                                                      ntohs (message->size),
                                                      GNUNET_TIME_UNIT_SECONDS,
                                                      &copy_msg, cc));
}


static struct GNUNET_SERVER_MessageHandler handlers[] = {
  {&echo_cb, NULL, MY_TYPE, sizeof (struct GNUNET_MessageHeader)},
  {NULL, NULL, 0, 0}
};


static void
recv_bounce (void *cls, const struct GNUNET_MessageHeader *got)
{
  int *ok = cls;
  struct GNUNET_MessageHeader msg;

  GNUNET_assert (got != NULL);  /* timeout */
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Receiving bounce, checking content\n");
  msg.type = htons (MY_TYPE);
  msg.size = htons (sizeof (struct GNUNET_MessageHeader));
  GNUNET_assert (0 == memcmp (got, &msg, sizeof (struct GNUNET_MessageHeader)));
  GNUNET_CLIENT_disconnect (client);
  client = NULL;
  GNUNET_SERVER_destroy (server);
  server = NULL;
  *ok = 0;
}


static size_t
make_msg (void *cls, size_t size, void *buf)
{
  struct GNUNET_MessageHeader *msg = buf;

  GNUNET_assert (size >= sizeof (struct GNUNET_MessageHeader));
  msg->type = htons (MY_TYPE);
  msg->size = htons (sizeof (struct GNUNET_MessageHeader));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Creating message for transmission\n");
  return sizeof (struct GNUNET_MessageHeader);
}


static void
task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct sockaddr_in sa;
  struct sockaddr *sap[2];
  socklen_t slens[2];

  /* test that ill-configured client fails instantly */
  GNUNET_assert (NULL == GNUNET_CLIENT_connect ("invalid-service", cfg));

  /* test IPC between client and server */
  sap[0] = (struct sockaddr *) &sa;
  slens[0] = sizeof (sa);
  sap[1] = NULL;
  slens[1] = 0;
  memset (&sa, 0, sizeof (sa));
#if HAVE_SOCKADDR_IN_SIN_LEN
  sa.sin_len = sizeof (sa);
#endif
  sa.sin_family = AF_INET;
  sa.sin_port = htons (PORT);
  server =
      GNUNET_SERVER_create (NULL, NULL, sap, slens,
                            GNUNET_TIME_relative_multiply
                            (GNUNET_TIME_UNIT_MILLISECONDS, 10000), GNUNET_NO);
  GNUNET_assert (server != NULL);
  handlers[0].callback_cls = cls;
  handlers[1].callback_cls = cls;
  GNUNET_SERVER_add_handlers (server, handlers);
  client = GNUNET_CLIENT_connect (MYNAME, cfg);
  GNUNET_assert (client != NULL);
  GNUNET_assert (NULL !=
                 GNUNET_CLIENT_notify_transmit_ready (client,
                                                      sizeof (struct
                                                              GNUNET_MessageHeader),
                                                      GNUNET_TIME_UNIT_SECONDS,
                                                      GNUNET_NO, &make_msg,
                                                      NULL));
  GNUNET_CLIENT_receive (client, &recv_bounce, cls,
                         GNUNET_TIME_relative_multiply
                         (GNUNET_TIME_UNIT_MILLISECONDS, 10000));
}


/**
 * Main method, starts scheduler with task1,
 * checks that "ok" is correct at the end.
 */
static int
check ()
{
  int ok;

  cfg = GNUNET_CONFIGURATION_create ();
  GNUNET_CONFIGURATION_set_value_number (cfg, MYNAME, "PORT", PORT);
  GNUNET_CONFIGURATION_set_value_string (cfg, MYNAME, "HOSTNAME", "localhost");
  GNUNET_CONFIGURATION_set_value_string (cfg, "resolver", "HOSTNAME",
                                         "localhost");
  ok = 1;
  GNUNET_SCHEDULER_run (&task, &ok);
  GNUNET_CONFIGURATION_destroy (cfg);
  return ok;
}

int
main (int argc, char *argv[])
{
  int ret = 0;

  GNUNET_log_setup ("test_client",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);
  ret += check ();

  return ret;
}

/* end of test_client.c */
