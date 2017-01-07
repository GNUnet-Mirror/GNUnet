/*
  This file is part of GNUnet.
  Copyright (C) 2016, 2017 GNUnet e.V.

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
 * @file nat-auto/gnunet-service-nat-auto.c
 * @brief NAT autoconfiguration service
 * @author Christian Grothoff
 *
 * TODO:
 * - merge client handle and autoconfig context
 * - implement "more" autoconfig:
 *   + re-work gnunet-nat-server & integrate!
 *   + integrate "legacy" code
 *   + test manually punched NAT (how?)
 */
#include "platform.h"
#include <math.h>
#include "gnunet_util_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_signatures.h"
#include "gnunet_nat_service.h"
#include "gnunet_statistics_service.h"
#include "gnunet_resolver_service.h"
#include "nat-auto.h"
#include <gcrypt.h>


/**
 * How long do we wait until we forcefully terminate autoconfiguration?
 */
#define AUTOCONFIG_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)


/**
 * Internal data structure we track for each of our clients.
 */
struct ClientHandle
{

  /**
   * Kept in a DLL.
   */
  struct ClientHandle *next;
  
  /**
   * Kept in a DLL.
   */
  struct ClientHandle *prev;

  /**
   * Underlying handle for this client with the service.
   */ 
  struct GNUNET_SERVICE_Client *client;

  /**
   * Message queue for communicating with the client.
   */
  struct GNUNET_MQ_Handle *mq;
};


/**
 * Context for autoconfiguration operations.
 */
struct AutoconfigContext
{
  /**
   * Kept in a DLL.
   */
  struct AutoconfigContext *prev;

  /**
   * Kept in a DLL.
   */
  struct AutoconfigContext *next;

  /**
   * Which client asked the question.
   */
  struct ClientHandle *ch;

  /**
   * Configuration we are creating.
   */ 
  struct GNUNET_CONFIGURATION_Handle *c;

  /**
   * Original configuration (for diffing).
   */ 
  struct GNUNET_CONFIGURATION_Handle *orig;

  /**
   * Timeout task to force termination.
   */
  struct GNUNET_SCHEDULER_Task *timeout_task;

  /**
   * #GNUNET_YES if upnpc should be used,
   * #GNUNET_NO if upnpc should not be used,
   * #GNUNET_SYSERR if we should simply not change the option.
   */
  int enable_upnpc;

  /**
   * Status code to return to the client.
   */
  enum GNUNET_NAT_StatusCode status_code;

  /**
   * NAT type to return to the client.
   */
  enum GNUNET_NAT_Type type;
};


/**
 * Head of client DLL.
 */
static struct ClientHandle *ch_head;
  
/**
 * Tail of client DLL.
 */
static struct ClientHandle *ch_tail;

/**
 * DLL of our autoconfiguration operations.
 */
static struct AutoconfigContext *ac_head;

/**
 * DLL of our autoconfiguration operations.
 */
static struct AutoconfigContext *ac_tail;

/**
 * Handle to our current configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Handle to the statistics service.
 */
static struct GNUNET_STATISTICS_Handle *stats;


/**
 * Check validity of #GNUNET_MESSAGE_TYPE_NAT_REQUEST_AUTO_CFG message
 * from client.
 *
 * @param cls client who sent the message
 * @param message the message received
 * @return #GNUNET_OK if message is well-formed
 */
static int
check_autoconfig_request (void *cls,
			  const struct GNUNET_NAT_AUTO_AutoconfigRequestMessage *message)
{
  return GNUNET_OK;  /* checked later */
}


/**
 * Stop all pending activities with respect to the @a ac
 *
 * @param ac autoconfiguration to terminate activities for
 */
static void
terminate_ac_activities (struct AutoconfigContext *ac)
{
  if (NULL != ac->timeout_task)
  {
    GNUNET_SCHEDULER_cancel (ac->timeout_task);
    ac->timeout_task = NULL;
  }
}


/**
 * Finish handling the autoconfiguration request and send
 * the response to the client.
 *
 * @param cls the `struct AutoconfigContext` to conclude
 */
static void
conclude_autoconfig_request (void *cls)
{
  struct AutoconfigContext *ac = cls;
  struct ClientHandle *ch = ac->ch;
  struct GNUNET_NAT_AUTO_AutoconfigResultMessage *arm;
  struct GNUNET_MQ_Envelope *env;
  size_t c_size;
  char *buf;
  struct GNUNET_CONFIGURATION_Handle *diff;
  
  ac->timeout_task = NULL;
  terminate_ac_activities (ac);

  /* Send back response */
  diff = GNUNET_CONFIGURATION_get_diff (ac->orig,
					ac->c);
  buf = GNUNET_CONFIGURATION_serialize (diff,
					&c_size);
  GNUNET_CONFIGURATION_destroy (diff);
  env = GNUNET_MQ_msg_extra (arm,
			     c_size,
			     GNUNET_MESSAGE_TYPE_NAT_AUTO_CFG_RESULT);
  arm->status_code = htonl ((uint32_t) ac->status_code);
  arm->type = htonl ((uint32_t) ac->type);
  GNUNET_memcpy (&arm[1],
		 buf,
		 c_size);
  GNUNET_free (buf);
  GNUNET_MQ_send (ch->mq,
		  env);

  /* clean up */
  GNUNET_CONFIGURATION_destroy (ac->orig);
  GNUNET_CONFIGURATION_destroy (ac->c);
  GNUNET_CONTAINER_DLL_remove (ac_head,
			       ac_tail,
			       ac);
  GNUNET_free (ac);
  GNUNET_SERVICE_client_continue (ch->client);
}


/**
 * Check if all autoconfiguration operations have concluded,
 * and if they have, send the result back to the client.
 *
 * @param ac autoconfiguation context to check
 */
static void
check_autoconfig_finished (struct AutoconfigContext *ac)
{
  GNUNET_SCHEDULER_cancel (ac->timeout_task);
  ac->timeout_task
    = GNUNET_SCHEDULER_add_now (&conclude_autoconfig_request,
				ac);
}


/**
 * Update ENABLE_UPNPC configuration option.
 *
 * @param ac autoconfiguration to update
 */
static void
update_enable_upnpc_option (struct AutoconfigContext *ac)
{
  switch (ac->enable_upnpc)
  {
  case GNUNET_YES:
    GNUNET_CONFIGURATION_set_value_string (ac->c,
					   "NAT",
					   "ENABLE_UPNP",
					   "YES");
    break;
  case GNUNET_NO:
    GNUNET_CONFIGURATION_set_value_string (ac->c,
					   "NAT",
					   "ENABLE_UPNP",
					   "NO");
    break;
  case GNUNET_SYSERR:
    /* We are unsure, do not change option */
    break;
  }
}


/**
 * Handler for #GNUNET_MESSAGE_TYPE_NAT_REQUEST_AUTO_CFG message from
 * client.
 *
 * @param cls client who sent the message
 * @param message the message received
 */
static void
handle_autoconfig_request (void *cls,
			   const struct GNUNET_NAT_AUTO_AutoconfigRequestMessage *message)
{
  struct ClientHandle *ch = cls;
  size_t left = ntohs (message->header.size) - sizeof (*message);
  struct AutoconfigContext *ac;

  ac = GNUNET_new (struct AutoconfigContext);
  ac->status_code = GNUNET_NAT_ERROR_SUCCESS;
  ac->ch = ch;
  ac->c = GNUNET_CONFIGURATION_create ();
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_deserialize (ac->c,
					(const char *) &message[1],
					left,
					GNUNET_NO))
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (ch->client);
    GNUNET_CONFIGURATION_destroy (ac->c);
    GNUNET_free (ac);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Received REQUEST_AUTO_CONFIG message from client\n");

  GNUNET_CONTAINER_DLL_insert (ac_head,
			       ac_tail,
			       ac);
  ac->orig
    = GNUNET_CONFIGURATION_dup (ac->c);
  ac->timeout_task
    = GNUNET_SCHEDULER_add_delayed (AUTOCONFIG_TIMEOUT,
				    &conclude_autoconfig_request,
				    ac);
  ac->enable_upnpc = GNUNET_SYSERR; /* undecided */
  
  /* Probe for upnpc */
  if (GNUNET_SYSERR ==
      GNUNET_OS_check_helper_binary ("upnpc",
				     GNUNET_NO,
				     NULL))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		_("UPnP client `upnpc` command not found, disabling UPnP\n"));
    ac->enable_upnpc = GNUNET_NO;
  }
  else
  {
    /* We might at some point be behind NAT, try upnpc */
    ac->enable_upnpc = GNUNET_YES;
  }
  update_enable_upnpc_option (ac);

  /* Finally, check if we are already done */  
  check_autoconfig_finished (ac);
}


/**
 * Task run during shutdown.
 *
 * @param cls unused
 */
static void
shutdown_task (void *cls)
{
  struct AutoconfigContext *ac;

  while (NULL != (ac = ac_head))
  {
    GNUNET_CONTAINER_DLL_remove (ac_head,
				 ac_tail,
				 ac);
    terminate_ac_activities (ac);
    GNUNET_free (ac);
  }
  if (NULL != stats)
  {
    GNUNET_STATISTICS_destroy (stats,
			       GNUNET_NO);
    stats = NULL;
  }
}


/**
 * Setup NAT service.
 *
 * @param cls closure
 * @param c configuration to use
 * @param service the initialized service
 */
static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *c,
     struct GNUNET_SERVICE_Handle *service)
{
  cfg = c;
  GNUNET_SCHEDULER_add_shutdown (&shutdown_task,
				 NULL);
  stats = GNUNET_STATISTICS_create ("nat-auto",
				    cfg);
}


/**
 * Callback called when a client connects to the service.
 *
 * @param cls closure for the service
 * @param c the new client that connected to the service
 * @param mq the message queue used to send messages to the client
 * @return a `struct ClientHandle`
 */
static void *
client_connect_cb (void *cls,
		   struct GNUNET_SERVICE_Client *c,
		   struct GNUNET_MQ_Handle *mq)
{
  struct ClientHandle *ch;

  ch = GNUNET_new (struct ClientHandle);
  ch->mq = mq;
  ch->client = c;
  GNUNET_CONTAINER_DLL_insert (ch_head,
			       ch_tail,
			       ch);
  return ch;
}


/**
 * Callback called when a client disconnected from the service
 *
 * @param cls closure for the service
 * @param c the client that disconnected
 * @param internal_cls a `struct ClientHandle *`
 */
static void
client_disconnect_cb (void *cls,
		      struct GNUNET_SERVICE_Client *c,
		      void *internal_cls)
{
  struct ClientHandle *ch = internal_cls;

  GNUNET_CONTAINER_DLL_remove (ch_head,
			       ch_tail,
			       ch);
  GNUNET_free (ch);
}


/**
 * Define "main" method using service macro.
 */
GNUNET_SERVICE_MAIN
("nat-auto",
 GNUNET_SERVICE_OPTION_NONE,
 &run,
 &client_connect_cb,
 &client_disconnect_cb,
 NULL,
 GNUNET_MQ_hd_var_size (autoconfig_request,
			GNUNET_MESSAGE_TYPE_NAT_AUTO_REQUEST_CFG,
			struct GNUNET_NAT_AUTO_AutoconfigRequestMessage,
			NULL),
 GNUNET_MQ_handler_end ());


#if defined(LINUX) && defined(__GLIBC__)
#include <malloc.h>

/**
 * MINIMIZE heap size (way below 128k) since this process doesn't need much.
 */
void __attribute__ ((constructor))
GNUNET_ARM_memory_init ()
{
  mallopt (M_TRIM_THRESHOLD, 4 * 1024);
  mallopt (M_TOP_PAD, 1 * 1024);
  malloc_trim (0);
}
#endif

/* end of gnunet-service-nat.c */
