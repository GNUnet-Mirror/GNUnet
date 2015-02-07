/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2010, 2014 Christian Grothoff (and other contributing authors)

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
 * @file util/test_server.c
 * @brief tests for server.c
 */
#include "platform.h"
#include "gnunet_util_lib.h"

/**
 * TCP port to use for the server.
 */
#define PORT 12435

/**
 * Timeout to use for operations.
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 2)

/**
 * Test message type.
 */
#define MY_TYPE 128

/**
 * Test message type.
 */
#define MY_TYPE2 129

/**
 * Handle for the server.
 */
static struct GNUNET_SERVER_Handle *server;

/**
 * Handle for the client.
 */
static struct GNUNET_CLIENT_Connection *cc;

/**
 * Handle of the server for the client.
 */
static struct GNUNET_SERVER_Client *argclient;

/**
 * Our configuration.
 */
static struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Number indiciating in which phase of the test we are.
 */
static int ok;


/**
 * Final task invoked to clean up.
 *
 * @param cls NULL
 * @param tc scheduler context
 */
static void
finish_up (void *cls,
           const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_assert (7 == ok);
  ok = 0;
  GNUNET_SERVER_destroy (server);
  GNUNET_CLIENT_disconnect (cc);
  GNUNET_CONFIGURATION_destroy (cfg);
}


/**
 * The server has received the second message, initiate clean up.
 *
 * @param cls NULL
 * @param client client we got the message from
 * @param message the message
 */
static void
recv_fin_cb (void *cls,
             struct GNUNET_SERVER_Client *client,
             const struct GNUNET_MessageHeader *message)
{
  GNUNET_assert (6 == ok);
  ok = 7;
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
  GNUNET_SCHEDULER_add_now (&finish_up, NULL);
}


/**
 * The client connected to the server and is now allowed
 * to send a second message.  We send one.
 *
 * @param cls NULL
 * @param size number of bytes that can be transmitted
 * @param buf where to copy the message
 * @return number of bytes copied to @a buf
 */
static size_t
transmit_second_message (void *cls,
                         size_t size,
                         void *buf)
{
  struct GNUNET_MessageHeader msg;

  GNUNET_assert (5 == ok);
  ok = 6;
  GNUNET_assert (size >= sizeof (struct GNUNET_MessageHeader));
  msg.type = htons (MY_TYPE2);
  msg.size = htons (sizeof (struct GNUNET_MessageHeader));
  memcpy (buf, &msg, sizeof (struct GNUNET_MessageHeader));
  return sizeof (struct GNUNET_MessageHeader);
}


/**
 * We have received the reply from the server, check that we are at
 * the right stage and queue the next message to the server.  Cleans
 * up #argclient.
 *
 * @param cls NULL
 * @param msg message we got from the server
 */
static void
first_reply_handler (void *cls,
                     const struct GNUNET_MessageHeader *msg)
{
  GNUNET_assert (4 == ok);
  ok = 5;
  GNUNET_assert (NULL !=
                 GNUNET_CLIENT_notify_transmit_ready (cc,
                                                      sizeof (struct GNUNET_MessageHeader),
                                                      TIMEOUT,
                                                      GNUNET_YES,
                                                      &transmit_second_message,
                                                      NULL));
}


/**
 * Send a reply of type #MY_TYPE from the server to the client.
 * Checks that we are in the right phase and transmits the
 * reply.  Cleans up #argclient state.
 *
 * @param cls NULL
 * @param size number of bytes we are allowed to send
 * @param buf where to copy the reply
 * @return number of bytes written to @a buf
 */
static size_t
reply_msg (void *cls,
           size_t size,
           void *buf)
{
  struct GNUNET_MessageHeader msg;

  GNUNET_assert (3 == ok);
  ok = 4;
  GNUNET_assert (size >= sizeof (struct GNUNET_MessageHeader));
  msg.type = htons (MY_TYPE);
  msg.size = htons (sizeof (struct GNUNET_MessageHeader));
  memcpy (buf, &msg, sizeof (struct GNUNET_MessageHeader));
  GNUNET_assert (NULL != argclient);
  GNUNET_SERVER_receive_done (argclient, GNUNET_OK);
  GNUNET_SERVER_client_drop (argclient);
  argclient = NULL;
  return sizeof (struct GNUNET_MessageHeader);
}


/**
 * Function called whenever the server receives a message of
 * type #MY_TYPE.  Checks that we are at the stage where
 * we expect the first message, then sends a reply.  Stores
 * the handle to the client in #argclient.
 *
 * @param cls NULL
 * @param client client that sent the message
 * @param message the message we received
 */
static void
recv_cb (void *cls,
         struct GNUNET_SERVER_Client *client,
         const struct GNUNET_MessageHeader *message)
{
  GNUNET_assert (2 == ok);
  ok = 3;
  argclient = client;
  GNUNET_SERVER_client_keep (argclient);
  GNUNET_assert (sizeof (struct GNUNET_MessageHeader) == ntohs (message->size));
  GNUNET_assert (MY_TYPE == ntohs (message->type));
  GNUNET_assert (NULL !=
                 GNUNET_SERVER_notify_transmit_ready (client,
                                                      ntohs (message->size),
                                                      TIMEOUT, &reply_msg,
                                                      NULL));
}


/**
 * The client connected to the server and is now allowed
 * to send a first message.  We transmit a simple message,
 * ask for a second transmission and get ready to receive
 * a response.
 *
 * @param cls NULL
 * @param size number of bytes that can be transmitted
 * @param buf where to copy the message
 * @return number of bytes copied to @a buf
 */
static size_t
transmit_initial_message (void *cls,
                          size_t size,
                          void *buf)
{
  struct GNUNET_MessageHeader msg;

  GNUNET_assert (1 == ok);
  ok = 2;
  GNUNET_assert (size >= sizeof (struct GNUNET_MessageHeader));
  msg.type = htons (MY_TYPE);
  msg.size = htons (sizeof (struct GNUNET_MessageHeader));
  memcpy (buf, &msg, sizeof (struct GNUNET_MessageHeader));
  GNUNET_CLIENT_receive (cc, &first_reply_handler, NULL, TIMEOUT);
  return sizeof (struct GNUNET_MessageHeader);
}


/**
 * Message handlers for the server.
 */
static struct GNUNET_SERVER_MessageHandler handlers[] = {
  {&recv_cb, NULL, MY_TYPE, sizeof (struct GNUNET_MessageHeader)},
  {&recv_fin_cb, NULL, MY_TYPE2, sizeof (struct GNUNET_MessageHeader)},
  {NULL, NULL, 0, 0}
};


/**
 * First task run by the scheduler.  Initializes the server and
 * a client and asks for a transmission from the client to the
 * server.
 *
 * @param cls NULL
 * @param tc scheduler context
 */
static void
task (void *cls,
      const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct sockaddr_in sa;
  struct sockaddr *sap[2];
  socklen_t slens[2];

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
  server = GNUNET_SERVER_create (NULL, NULL,
                                 sap, slens,
                                 TIMEOUT, GNUNET_NO);
  GNUNET_assert (server != NULL);
  GNUNET_SERVER_add_handlers (server, handlers);
  cfg = GNUNET_CONFIGURATION_create ();
  GNUNET_CONFIGURATION_set_value_number (cfg,
                                         "test-server",
                                         "PORT",
                                         PORT);
  GNUNET_CONFIGURATION_set_value_string (cfg,
                                         "test-server",
                                         "HOSTNAME",
                                         "localhost");
  GNUNET_CONFIGURATION_set_value_string (cfg,
                                         "resolver",
                                         "HOSTNAME",
                                         "localhost");
  cc = GNUNET_CLIENT_connect ("test-server", cfg);
  GNUNET_assert (cc != NULL);
  GNUNET_assert (NULL !=
                 GNUNET_CLIENT_notify_transmit_ready (cc,
                                                      sizeof (struct
                                                              GNUNET_MessageHeader),
                                                      TIMEOUT, GNUNET_YES,
                                                      &transmit_initial_message,
                                                      NULL));
}


/**
 * Runs the test.
 *
 * @param argc length of @a argv
 * @param argv command line arguments (ignored)
 * @return 0 on success, otherwise phase of failure
 */
int
main (int argc, char *argv[])
{
  GNUNET_log_setup ("test_server",
                    "WARNING",
                    NULL);
  ok = 1;
  GNUNET_SCHEDULER_run (&task, &ok);
  return ok;
}

/* end of test_server.c */
