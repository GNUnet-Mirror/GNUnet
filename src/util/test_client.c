/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2016 GNUnet e.V.

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
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"

static int global_ret;

static struct GNUNET_MQ_Handle *client_mq;

#define MY_TYPE 130


/**
 * Callback that just bounces the message back to the sender.
 */
static void
handle_echo (void *cls,
	     const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_SERVICE_Client *c = cls;
  struct GNUNET_MQ_Handle *mq = GNUNET_SERVICE_client_get_mq (c);
  struct GNUNET_MQ_Envelope *env;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Receiving message from client, bouncing back\n");
  env = GNUNET_MQ_msg_copy (message);
  GNUNET_MQ_send (mq,
		  env);
  GNUNET_SERVICE_client_continue (c);
}


static void
handle_bounce (void *cls,
               const struct GNUNET_MessageHeader *got)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Receiving bounce, checking content\n");
  GNUNET_assert (NULL != got);
  global_ret = 2;
  GNUNET_MQ_destroy (client_mq);
  client_mq = NULL;
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
task (void *cls,
      const struct GNUNET_CONFIGURATION_Handle *cfg,
      struct GNUNET_SERVICE_Handle *sh)
{
  struct GNUNET_MQ_MessageHandler chandlers[] = {
    GNUNET_MQ_hd_fixed_size (bounce,
                             MY_TYPE,
                             struct GNUNET_MessageHeader,
                             cls),
    GNUNET_MQ_handler_end ()
  };
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_MessageHeader *msg;

  /* test that ill-configured client fails instantly */
  GNUNET_assert (NULL ==
		 GNUNET_CLIENT_connect (cfg,
					"invalid-service",
					NULL,
					&mq_error_handler,
					NULL));
  client_mq = GNUNET_CLIENT_connect (cfg,
				     "test_client",
				     chandlers,
				     &mq_error_handler,
				     NULL);
  GNUNET_assert (NULL != client_mq);
  env = GNUNET_MQ_msg (msg,
                       MY_TYPE);
  GNUNET_MQ_send (client_mq,
                  env);
}


/**
 * Function called when the client connects to the service.
 *
 * @param cls the name of the service
 * @param c connecting client
 * @param mq message queue to talk to the client
 * @return @a c
 */
static void *
connect_cb (void *cls,
	    struct GNUNET_SERVICE_Client *c,
	    struct GNUNET_MQ_Handle *mq)
{
  return c;
}


/**
 * Function called when the client disconnects.
 *
 * @param cls our service name
 * @param c disconnecting client
 * @param internal_cls must match @a c
 */ 
static void
disconnect_cb (void *cls,
	       struct GNUNET_SERVICE_Client *c,
	       void *internal_cls)
{
  if (2 == global_ret)
  {
    GNUNET_SCHEDULER_shutdown ();
    global_ret = 0;
  }
}


int
main (int argc,
      char *argv[])
{
  struct GNUNET_MQ_MessageHandler shandlers[] = {
    GNUNET_MQ_hd_fixed_size (echo,
                             MY_TYPE,
                             struct GNUNET_MessageHeader,
                             NULL),
    GNUNET_MQ_handler_end ()
  };
  char * test_argv[] = {
    (char *) "test_client",
    "-c",
    "test_client_data.conf",
    NULL
  };

  GNUNET_log_setup ("test_client",
                    "WARNING",
                    NULL);
  if (0 != strstr (argv[0],
		   "unix"))
    test_argv[2] = "test_client_unix.conf";
  global_ret = 1;
  if (0 !=
      GNUNET_SERVICE_run_ (3,
			   test_argv,
			   "test_client",
			   GNUNET_SERVICE_OPTION_NONE,
			   &task,
			   &connect_cb,
			   &disconnect_cb,
			   NULL,
			   shandlers))
    global_ret = 3;
  return global_ret;
}

/* end of test_client.c */
