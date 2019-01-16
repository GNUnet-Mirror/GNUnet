/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2013, 2016 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.
    
     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
*/
/**
 * @file util/test_service.c
 * @brief tests for service.c
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"

/**
 * Message type we use for testing.
 */
#define MY_TYPE 256

#define TIMEOUT GNUNET_TIME_UNIT_SECONDS

static int global_ret = 1;

static struct GNUNET_MQ_Handle *mq;

/**
 * Timeout task.
 */
static struct GNUNET_SCHEDULER_Task *tt;


static void
handle_recv (void *cls,
	     const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_SERVICE_Client *client = cls;
  
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Received client message...\n");
  GNUNET_SERVICE_client_continue (client);
  global_ret = 2;
  if (NULL != mq)
  {
    GNUNET_MQ_destroy (mq);
    mq = NULL;
  }
}


/**
 * Function called when the client connects to the service.
 *
 * @param cls the name of the service
 * @param c connecting client
 * @param mq message queue to talk to the client
 * @return @a c so we have the client handle in the future
 */
static void *
connect_cb (void *cls,
	    struct GNUNET_SERVICE_Client *c,
	    struct GNUNET_MQ_Handle *mq)
{
  /* FIXME: in the future, do something with mq
     to test sending messages to the client! */
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
  GNUNET_assert (c == internal_cls);
  if (2 == global_ret)
  {
    GNUNET_SCHEDULER_shutdown ();
    global_ret = 0;
    if (NULL != tt)
    {
      GNUNET_SCHEDULER_cancel (tt);
      tt = NULL;
    }
  }
}


static void
timeout_task (void *cls)
{
  tt = NULL;
  if (NULL != mq)
  {
    GNUNET_MQ_destroy (mq);
    mq = NULL;
  }
  global_ret = 33;
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Initialization function of the service.  Starts
 * a client to connect to the service.
 *
 * @param cls the name of the service (const char *)
 * @param cfg the configuration we use
 * @param sh handle to the service
 */
static void
service_init (void *cls,
	      const struct GNUNET_CONFIGURATION_Handle *cfg,
	      struct GNUNET_SERVICE_Handle *sh)
{
  const char *service_name = cls;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_MessageHeader *msg;

  GNUNET_assert (NULL == tt);
  tt = GNUNET_SCHEDULER_add_delayed (TIMEOUT,
				     &timeout_task,
				     NULL);
  mq = GNUNET_CLIENT_connect (cfg,
                              service_name,
                              NULL,
                              NULL,
                              NULL);
  GNUNET_assert (NULL != mq);
  env = GNUNET_MQ_msg (msg,
                       MY_TYPE);
  GNUNET_MQ_send (mq,
                  env);
}


/**
 * Main method, starts the service and initiates
 * the running of the test.
 *
 * @param sname name of the service to run
 */
static int
check (const char *sname)
{
  struct GNUNET_MQ_MessageHandler myhandlers[] = {
    GNUNET_MQ_hd_fixed_size (recv,
			     MY_TYPE,
			     struct GNUNET_MessageHeader,
			     NULL),
    GNUNET_MQ_handler_end ()
  };
  char *const argv[] = {
    (char *) sname,
    "-c",
    "test_service_data.conf",
    NULL
  };
  
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Starting `%s' service\n",
	      sname);
  global_ret = 1;
  GNUNET_assert (0 ==
                 GNUNET_SERVICE_run_ (3,
				      argv,
				      sname,
				      GNUNET_SERVICE_OPTION_NONE,
				      &service_init,
				      &connect_cb,
				      &disconnect_cb,
				      (void *) sname,
				      myhandlers));
  return global_ret;
}


int
main (int argc,
      char *argv[])
{
  int ret = 0;
  struct GNUNET_NETWORK_Handle *s = NULL;

  GNUNET_log_setup ("test-service",
                    "WARNING",
                    NULL);
  ret += check ("test_service");
  ret += check ("test_service");
#ifndef MINGW
  s = GNUNET_NETWORK_socket_create (PF_INET6,
				    SOCK_STREAM,
				    0);
#endif
  if (NULL == s)
  {
    if ( (errno == ENOBUFS) ||
	 (errno == ENOMEM) ||
	 (errno == ENFILE) ||
	 (errno == EACCES) )
    {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR,
			   "socket");
      return 1;
    }
    FPRINTF (stderr,
             "IPv6 support seems to not be available (%s), not testing it!\n",
             strerror (errno));
  }
  else
  {
    GNUNET_break (GNUNET_OK ==
		  GNUNET_NETWORK_socket_close (s));
    ret += check ("test_service6");
  }
  return ret;
}

/* end of test_service.c */
