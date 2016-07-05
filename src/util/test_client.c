/*
     This file is part of GNUnet.
     Copyright (C) 2009 GNUnet e.V.

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
 * @file util/test_client.c
 * @brief tests for client.c
 */
#include "platform.h"
#include "gnunet_util_lib.h"


#define PORT 14325

#define MYNAME "test_client"

static struct GNUNET_MQ_Handle *mq;

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
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Message bounced back to client\n");
  return sizeof (struct GNUNET_MessageHeader);
}


/**
 * Callback that just bounces the message back to the sender.
 */
static void
echo_cb (void *cls,
         struct GNUNET_SERVER_Client *client,
         const struct GNUNET_MessageHeader *message)
{
  struct CopyContext *cc;
  struct GNUNET_MessageHeader *cpy;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Receiving message from client, bouncing back\n");
  GNUNET_assert (sizeof (struct GNUNET_MessageHeader) == ntohs (message->size));
  cc = GNUNET_new (struct CopyContext);
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
handle_bounce (void *cls,
               const struct GNUNET_MessageHeader *got)
{
  int *ok = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Receiving bounce, checking content\n");
  GNUNET_assert (NULL != got);
  GNUNET_MQ_destroy (mq);
  mq = NULL;
  GNUNET_SERVER_destroy (server);
  server = NULL;
  *ok = 0;
}


/**
 * Generic error handler, called with the appropriate error code and
 * the same closure specified at the creation of the message queue.
 * Not every message queue implementation supports an error handler.
 *
 * @param cls closure with the `struct GNUNET_STATISTICS_Handle *`
 * @param error error code
 */
static void
mq_error_handler (void *cls,
                  enum GNUNET_MQ_Error error)
{
  GNUNET_assert (0); /* should never happen */
}


static void
task (void *cls)
{
  struct sockaddr_in sa;
  struct sockaddr *sap[2];
  socklen_t slens[2];
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_MessageHeader *msg;
  GNUNET_MQ_hd_fixed_size (bounce,
                           MY_TYPE,
                           struct GNUNET_MessageHeader);
  struct GNUNET_MQ_MessageHandler chandlers[] = {
    make_bounce_handler (cls),
    GNUNET_MQ_handler_end ()
  };

  /* test that ill-configured client fails instantly */
  GNUNET_assert (NULL == GNUNET_CLIENT_connecT (cfg,
                                                "invalid-service",
                                                NULL,
                                                &mq_error_handler,
                                                NULL));

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
                            (GNUNET_TIME_UNIT_SECONDS, 10), GNUNET_NO);
  GNUNET_assert (server != NULL);
  handlers[0].callback_cls = cls;
  handlers[1].callback_cls = cls;
  GNUNET_SERVER_add_handlers (server, handlers);
  mq = GNUNET_CLIENT_connecT (cfg,
                              MYNAME,
                              chandlers,
                              &mq_error_handler,
                              NULL);
  GNUNET_assert (NULL != mq);
  env = GNUNET_MQ_msg (msg,
                       MY_TYPE);
  GNUNET_MQ_send (mq,
                  env);
}


int
main (int argc, char *argv[])
{
  int ok;

  GNUNET_log_setup ("test_client",
                    "WARNING",
                    NULL);
  cfg = GNUNET_CONFIGURATION_create ();
  GNUNET_CONFIGURATION_set_value_number (cfg, MYNAME, "PORT", PORT);
  GNUNET_CONFIGURATION_set_value_string (cfg, MYNAME, "HOSTNAME", "localhost");
  ok = 1;
  GNUNET_SCHEDULER_run (&task, &ok);
  GNUNET_CONFIGURATION_destroy (cfg);
  return ok;
}

/* end of test_client.c */
