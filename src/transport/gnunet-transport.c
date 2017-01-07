/*
 This file is part of GNUnet.
 Copyright (C) 2011-2014, 2016, 2017 GNUnet e.V.

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
 * @file src/transport/gnunet-transport.c
 * @brief Tool to help configure, measure and control the transport subsystem.
 * @author Christian Grothoff
 * @author Nathan Evans
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_resolver_service.h"
#include "gnunet_protocols.h"
#include "gnunet_transport_service.h"
#include "gnunet_transport_core_service.h"

/**
 * Timeout for a name resolution
 */
#define RESOLUTION_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 30)

/**
 * Timeout for an operation
 */
#define OP_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 30)


/**
 * Context to store name resolutions for valiation
 */
struct ValidationResolutionContext
{
  /**
   * Next in DLL
   */
  struct ValidationResolutionContext *next;

  /**
   * Previous in DLL
   */
  struct ValidationResolutionContext *prev;

  /**
   * Address to resolve
   */
  struct GNUNET_HELLO_Address *addrcp;

  /**
   * Time of last validation
   */
  struct GNUNET_TIME_Absolute last_validation;

  /**
   * Address is valid until
   */
  struct GNUNET_TIME_Absolute valid_until;

  /**
   * Time of next validation
   */
  struct GNUNET_TIME_Absolute next_validation;

  /**
   * Tranport conversion handle
   */
  struct GNUNET_TRANSPORT_AddressToStringContext *asc;

  /**
   * plugin name
   */
  char *transport;

  /**
   * was the entry printed
   */
  int printed;
};

/**
 * Struct to store information about peers in monitor mode
 */
struct MonitoredPeer
{
  /**
   * State of the peer
   */
  enum GNUNET_TRANSPORT_PeerState state;

  /**
   * Timeout
   */
  struct GNUNET_TIME_Absolute state_timeout;

  /**
   * The address to convert
   */
  struct GNUNET_HELLO_Address *address;
};

/**
 * Context to store name resolutions for valiation
 */
struct PeerResolutionContext
{
  /**
   * Next in DLL
   */
  struct PeerResolutionContext *next;

  /**
   * Prev in DLL
   */
  struct PeerResolutionContext *prev;

  /**
   * address to resolve
   */
  struct GNUNET_HELLO_Address *addrcp;

  /**
   * transport conversiion context
   */
  struct GNUNET_TRANSPORT_AddressToStringContext *asc;

  /**
   * peer state
   */
  enum GNUNET_TRANSPORT_PeerState state;

  /**
   * state timeout
   */
  struct GNUNET_TIME_Absolute state_timeout;

  /**
   * transport plugin
   */
  char *transport;

  /**
   * was the entry printed
   */
  int printed;
};


/**
 * Benchmarking block size in KB
 */
#define BLOCKSIZE 4

/**
 * Which peer should we connect to?
 */
static char *cpid;

/**
 * Handle to transport service.
 */
static struct GNUNET_TRANSPORT_CoreHandle *handle;

/**
 * Configuration handle
 */
static struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Blacklisting handle
 */
struct GNUNET_TRANSPORT_Blacklist *blacklist;

/**
 * Option -s.
 */
static int benchmark_send;

/**
 * Option -b.
 */
static int benchmark_receive;

/**
 * Option -l.
 */
static int benchmark_receive;

/**
 * Option -i.
 */
static int iterate_connections;

/**
 * Option -a.
 */
static int iterate_all;

/**
 * Option -c.
 */
static int monitor_connects;

/**
 * Option -m.
 */
static int monitor_connections;

/**
 * Option -P.
 */
static int monitor_plugins;

/**
 * Option -D.
 */
static int do_disconnect;

/**
 * Option -n.
 */
static int numeric;

/**
 * Global return value (0 success).
 */
static int ret;

/**
 * Current number of connections in monitor mode
 */
static int monitor_connect_counter;

/**
 * Number of bytes of traffic we received so far.
 */
static unsigned long long traffic_received;

/**
 * Number of bytes of traffic we sent so far.
 */
static unsigned long long traffic_sent;

/**
 * Starting time of transmitting/receiving data.
 */
static struct GNUNET_TIME_Absolute start_time;

/**
 * Map storing information about monitored peers
 */
static struct GNUNET_CONTAINER_MultiPeerMap *monitored_peers;

/**
 * Map storing information about monitored plugins's sessions.
 */
static struct GNUNET_CONTAINER_MultiPeerMap *monitored_plugins;

/**
 * Handle if we are monitoring peers at the transport level.
 */
static struct GNUNET_TRANSPORT_PeerMonitoringContext *pic;

/**
 * Handle if we are monitoring plugin session activity.
 */
static struct GNUNET_TRANSPORT_PluginMonitor *pm;

/**
 * Identity of the peer we transmit to / connect to.
 * (equivalent to 'cpid' string).
 */
static struct GNUNET_PeerIdentity pid;

/**
 * Task for operation timeout
 */
static struct GNUNET_SCHEDULER_Task *op_timeout;

/**
 * Selected level of verbosity.
 */
static int verbosity;

/**
 * Resolver process handle.
 */
struct GNUNET_OS_Process *resolver;

/**
 * Number of address resolutions pending
 */
static unsigned int address_resolutions;

/**
 * DLL: head of validation resolution entries
 */
static struct ValidationResolutionContext *vc_head;

/**
 * DLL: tail of validation resolution entries
 */
static struct ValidationResolutionContext *vc_tail;

/**
 * DLL: head of resolution entries
 */
static struct PeerResolutionContext *rc_head;

/**
 * DLL: head of resolution entries
 */
static struct PeerResolutionContext *rc_tail;


/**
 * Function called to release data stored in the #monitored_peers map.
 *
 * @param cls unused
 * @param key the peer identity
 * @param value a `struct MonitoredPeer` to release
 * @return #GNUNET_OK (continue to iterate)
 */
static int
destroy_it (void *cls,
            const struct GNUNET_PeerIdentity *key,
            void *value)
{
  struct MonitoredPeer *m = value;

  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multipeermap_remove (monitored_peers,
                                                       key,
                                                       value));
  GNUNET_free_non_null (m->address);
  GNUNET_free (value);
  return GNUNET_OK;
}


/**
 * Task run in monitor mode when the user presses CTRL-C to abort.
 * Stops monitoring activity.
 *
 * @param cls NULL
 */
static void
shutdown_task (void *cls)
{
  struct GNUNET_TIME_Relative duration;
  struct ValidationResolutionContext *cur;
  struct ValidationResolutionContext *next;
  struct PeerResolutionContext *rc;

  if (NULL != op_timeout)
  {
    GNUNET_SCHEDULER_cancel (op_timeout);
    op_timeout = NULL;
  }
  if (NULL != pic)
  {
    GNUNET_TRANSPORT_monitor_peers_cancel (pic);
    pic = NULL;
  }
  if (NULL != pm)
  {
    GNUNET_TRANSPORT_monitor_plugins_cancel (pm);
    pm = NULL;
  }

  next = vc_head;
  for (cur = next; NULL != cur; cur = next)
  {
    next = cur->next;

    GNUNET_TRANSPORT_address_to_string_cancel (cur->asc);
    GNUNET_CONTAINER_DLL_remove (vc_head,
				 vc_tail,
				 cur);
    GNUNET_free (cur->transport);
    GNUNET_HELLO_address_free (cur->addrcp);
    GNUNET_free (cur);
  }
  while (NULL != (rc = rc_head))
  {
    GNUNET_CONTAINER_DLL_remove (rc_head,
				 rc_tail,
				 rc);
    GNUNET_TRANSPORT_address_to_string_cancel (rc->asc);
    GNUNET_free (rc->transport);
    GNUNET_free (rc->addrcp);
    GNUNET_free (rc);
  }
  if (NULL != handle)
  {
    GNUNET_TRANSPORT_core_disconnect (handle);
    handle = NULL;
  }
  if (benchmark_send)
  {
    duration = GNUNET_TIME_absolute_get_duration (start_time);
    FPRINTF (stdout,
             _("Transmitted %llu bytes/s (%llu bytes in %s)\n"),
             1000LL * 1000LL * traffic_sent / (1 + duration.rel_value_us),
             traffic_sent,
             GNUNET_STRINGS_relative_time_to_string (duration,
						     GNUNET_YES));
  }
  if (benchmark_receive)
  {
    duration = GNUNET_TIME_absolute_get_duration (start_time);
    FPRINTF (stdout,
             _("Received %llu bytes/s (%llu bytes in %s)\n"),
             1000LL * 1000LL * traffic_received / (1 + duration.rel_value_us),
             traffic_received,
             GNUNET_STRINGS_relative_time_to_string (duration,
						     GNUNET_YES));
  }

  if (NULL != monitored_peers)
  {
    GNUNET_CONTAINER_multipeermap_iterate (monitored_peers,
					   &destroy_it,
					   NULL);
    GNUNET_CONTAINER_multipeermap_destroy (monitored_peers);
    monitored_peers = NULL;
  }
  if (NULL != monitored_plugins)
  {
    GNUNET_break (0 ==
                  GNUNET_CONTAINER_multipeermap_size (monitored_plugins));
    GNUNET_CONTAINER_multipeermap_destroy (monitored_plugins);
    monitored_plugins = NULL;
  }
  if (NULL != blacklist)
  {
    GNUNET_TRANSPORT_blacklist_cancel (blacklist);
    blacklist = NULL;
    ret = 0;
  }
}


/**
 * We are done, shut down.
 */
static void
operation_timeout (void *cls)
{
  struct PeerResolutionContext *cur;
  struct PeerResolutionContext *next;

  op_timeout = NULL;
  if ((benchmark_send) || (benchmark_receive))
  {
    FPRINTF (stdout,
             _("Failed to connect to `%s'\n"),
             GNUNET_i2s_full (&pid));
    GNUNET_SCHEDULER_shutdown ();
    ret = 1;
    return;
  }
  if (iterate_connections)
  {
    next = rc_head;
    while (NULL != (cur = next))
    {
      next = cur->next;
      FPRINTF (stdout,
               _("Failed to resolve address for peer `%s'\n"),
               GNUNET_i2s (&cur->addrcp->peer));

      GNUNET_CONTAINER_DLL_remove(rc_head, 
				  rc_tail,
				  cur);
      GNUNET_TRANSPORT_address_to_string_cancel (cur->asc);
      GNUNET_free (cur->transport);
      GNUNET_free (cur->addrcp);
      GNUNET_free (cur);

    }
    FPRINTF (stdout,
             "%s",
             _("Failed to list connections, timeout occured\n"));
    GNUNET_SCHEDULER_shutdown ();
    ret = 1;
    return;
  }
}


/**
 * Function called to notify a client about the socket
 * begin ready to queue more data.  Sends another message.
 *
 * @param cls closure with the message queue
 */
static void
do_send (void *cls)
{
  struct GNUNET_MQ_Handle *mq = cls;
  struct GNUNET_MessageHeader *m;
  struct GNUNET_MQ_Envelope *env;

  env = GNUNET_MQ_msg_extra (m,
			     BLOCKSIZE * 1024,
			      GNUNET_MESSAGE_TYPE_DUMMY);
  memset (&m[1],
	  52,
	  BLOCKSIZE * 1024 - sizeof(struct GNUNET_MessageHeader));
  traffic_sent += BLOCKSIZE * 1024;
  GNUNET_MQ_notify_sent (env,
			 &do_send,
			 mq);
  if (verbosity > 0)
    FPRINTF (stdout,
	     _("Transmitting %u bytes\n"),
	     (unsigned int) BLOCKSIZE * 1024);
  GNUNET_MQ_send (mq,
		  env);
}


/**
 * Function called to notify transport users that another
 * peer connected to us.
 *
 * @param cls closure
 * @param peer the peer that connected
 * @param mq message queue for sending to @a peer
 */
static void *
notify_connect (void *cls,
                const struct GNUNET_PeerIdentity *peer,
		struct GNUNET_MQ_Handle *mq)
{
  if (0 != memcmp (&pid,
		   peer,
		   sizeof(struct GNUNET_PeerIdentity)))
    return NULL;
  ret = 0;
  if (! benchmark_send)
    return NULL;
  if (NULL != op_timeout)
  {
    GNUNET_SCHEDULER_cancel (op_timeout);
    op_timeout = NULL;
  }
  if (verbosity > 0)
    FPRINTF (stdout,
	     _("Successfully connected to `%s', starting to send benchmark data in %u Kb blocks\n"),
	     GNUNET_i2s (peer),
	     BLOCKSIZE);
  start_time = GNUNET_TIME_absolute_get ();
  do_send (mq);
  return mq;
}


/**
 * Function called to notify transport users that another
 * peer disconnected from us.
 *
 * @param cls closure
 * @param peer the peer that disconnected
 * @param internal_cls what we returned from #notify_connect()
 */
static void
notify_disconnect (void *cls,
                   const struct GNUNET_PeerIdentity *peer,
		   void *internal_cls)
{
  if (0 != memcmp (&pid,
		   peer,
		   sizeof(struct GNUNET_PeerIdentity)))
    return;
  if (NULL == internal_cls)
    return; /* not about target peer */
  if (! benchmark_send)
    return; /* not transmitting */
  FPRINTF (stdout,
	   _("Disconnected from peer `%s' while benchmarking\n"),
	   GNUNET_i2s (&pid));
}


/**
 * Function called to notify transport users that another
 * peer connected to us.
 *
 * @param cls closure
 * @param peer the peer that connected
 * @param mq for sending messages to @a peer
 * @return NULL
 */
static void *
monitor_notify_connect (void *cls,
                        const struct GNUNET_PeerIdentity *peer,
			struct GNUNET_MQ_Handle *mq)
{
  struct GNUNET_TIME_Absolute now = GNUNET_TIME_absolute_get ();
  const char *now_str = GNUNET_STRINGS_absolute_time_to_string (now);

  monitor_connect_counter++;
  FPRINTF (stdout,
           _("%24s: %-17s %4s   (%u connections in total)\n"),
           now_str,
           _("Connected to"),
           GNUNET_i2s (peer),
           monitor_connect_counter);
  return NULL;
}


/**
 * Function called to notify transport users that another
 * peer disconnected from us.
 *
 * @param cls closure
 * @param peer the peer that disconnected
 * @param internal_cls what we returned from #monitor_notify_connect()
 */
static void
monitor_notify_disconnect (void *cls,
                           const struct GNUNET_PeerIdentity *peer,
			   void *internal_cls)
{
  struct GNUNET_TIME_Absolute now = GNUNET_TIME_absolute_get ();
  const char *now_str = GNUNET_STRINGS_absolute_time_to_string (now);

  GNUNET_assert(monitor_connect_counter > 0);
  monitor_connect_counter--;

  FPRINTF (stdout,
           _("%24s: %-17s %4s   (%u connections in total)\n"),
           now_str,
           _("Disconnected from"),
           GNUNET_i2s (peer),
           monitor_connect_counter);
}


/**
 * Function called by the transport for each received message.
 *
 * @param cls closure
 * @param message the message
 * @return #GNUNET_OK
 */
static int
check_dummy (void *cls,
	     const struct GNUNET_MessageHeader *message)
{
  return GNUNET_OK; /* all messages are fine */
}


/**
 * Function called by the transport for each received message.
 *
 * @param cls closure
 * @param message the message
 */
static void
handle_dummy (void *cls,
	      const struct GNUNET_MessageHeader *message)
{
  if (! benchmark_receive)
    return;
  if (verbosity > 0)
    FPRINTF (stdout,
	     _("Received %u bytes\n"),
	     (unsigned int) ntohs (message->size));
  if (0 == traffic_received)
    start_time = GNUNET_TIME_absolute_get ();
  traffic_received += ntohs (message->size);
}


/**
 * Convert address to a printable format.
 *
 * @param address the address
 * @param numeric #GNUNET_YES to convert to numeric format, #GNUNET_NO
 *                to try to use reverse DNS
 * @param state state the peer is in
 * @param state_timeout when will the peer's state expire
 */
static void
resolve_peer_address (const struct GNUNET_HELLO_Address *address,
                      int numeric,
                      enum GNUNET_TRANSPORT_PeerState state,
                      struct GNUNET_TIME_Absolute state_timeout);


static void
print_info (const struct GNUNET_PeerIdentity *id,
            const char *transport,
            const char *addr,
            enum GNUNET_TRANSPORT_PeerState state,
            struct GNUNET_TIME_Absolute state_timeout)
{

  if ( ((GNUNET_YES == iterate_connections) &&
	(GNUNET_YES == iterate_all)) ||
       (GNUNET_YES == monitor_connections))
  {
    FPRINTF (stdout,
             _("Peer `%s': %s %s in state `%s' until %s\n"),
             GNUNET_i2s (id),
             (NULL == transport) ? "<none>" : transport,
             (NULL == transport) ? "<none>" : addr,
             GNUNET_TRANSPORT_ps2s (state),
             GNUNET_STRINGS_absolute_time_to_string (state_timeout));
  }
  else if ( (GNUNET_YES == iterate_connections) &&
	    (GNUNET_TRANSPORT_is_connected(state)) ) 
  {
    /* Only connected peers, skip state */
    FPRINTF (stdout,
             _("Peer `%s': %s %s\n"),
             GNUNET_i2s (id),
             transport,
             addr);
  }
}


/**
 * Function called with a textual representation of an address.  This
 * function will be called several times with different possible
 * textual representations, and a last time with @a address being NULL
 * to signal the end of the iteration.  Note that @a address NULL
 * always is the last call, regardless of the value in @a res.
 *
 * @param cls closure
 * @param address NULL on end of iteration,
 *        otherwise 0-terminated printable UTF-8 string,
 *        in particular an empty string if @a res is #GNUNET_NO
 * @param res result of the address to string conversion:
 *        if #GNUNET_OK: conversion successful
 *        if #GNUNET_NO: address was invalid (or not supported)
 *        if #GNUNET_SYSERR: communication error (IPC error)
 */
static void
process_peer_string (void *cls,
                     const char *address,
                     int res)
{
  struct PeerResolutionContext *rc = cls;

  if (NULL != address)
  {
    if (GNUNET_SYSERR == res)
    {
      FPRINTF (stderr,
               "Failed to convert address for peer `%s' plugin `%s' length %u to string \n",
               GNUNET_i2s (&rc->addrcp->peer),
               rc->addrcp->transport_name,
               (unsigned int) rc->addrcp->address_length);
      print_info (&rc->addrcp->peer,
                  rc->transport,
                  NULL,
                  rc->state,
                  rc->state_timeout);
      rc->printed = GNUNET_YES;
      return;
    }
    if (GNUNET_OK == res)
    {
      print_info (&rc->addrcp->peer,
                  rc->transport,
                  address,
                  rc->state,
                  rc->state_timeout);
      rc->printed = GNUNET_YES;
      return; /* Wait for done call */
    }
    /* GNUNET_NO == res: ignore, was simply not supported */
    return;
  }
  /* NULL == address, last call, we are done */

  rc->asc = NULL;
  GNUNET_assert (address_resolutions > 0);
  address_resolutions--;
  if (GNUNET_NO == rc->printed)
  {
    if (numeric == GNUNET_NO)
    {
      /* Failed to resolve address, try numeric lookup
         (note: this should not be needed, as transport
         should fallback to numeric conversion if DNS takes
         too long) */
      resolve_peer_address (rc->addrcp,
                            GNUNET_YES,
                            rc->state,
                            rc->state_timeout);
    }
    else
    {
      print_info (&rc->addrcp->peer,
                  rc->transport,
                  NULL,
                  rc->state,
                  rc->state_timeout);
    }
  }
  GNUNET_free (rc->transport);
  GNUNET_free (rc->addrcp);
  GNUNET_CONTAINER_DLL_remove (rc_head,
			       rc_tail,
			       rc);
  GNUNET_free (rc);
  if ((0 == address_resolutions) && (iterate_connections))
  {
    if (NULL != op_timeout)
    {
      GNUNET_SCHEDULER_cancel (op_timeout);
      op_timeout = NULL;
    }
    ret = 0;
    GNUNET_SCHEDULER_shutdown ();
  }
}


/**
 * Convert address to a printable format and print it
 * together with the given state data.
 *
 * @param address the address
 * @param numeric #GNUNET_YES to convert to numeric format, #GNUNET_NO
 *                to try to use reverse DNS
 * @param state state the peer is in
 * @param state_timeout when will the peer's state expire
 */
static void
resolve_peer_address (const struct GNUNET_HELLO_Address *address,
                      int numeric,
                      enum GNUNET_TRANSPORT_PeerState state,
                      struct GNUNET_TIME_Absolute state_timeout)
{
  struct PeerResolutionContext *rc;

  rc = GNUNET_new (struct PeerResolutionContext);
  GNUNET_CONTAINER_DLL_insert (rc_head,
			       rc_tail,
			       rc);
  address_resolutions++;
  rc->transport = GNUNET_strdup (address->transport_name);
  rc->addrcp = GNUNET_HELLO_address_copy (address);
  rc->printed = GNUNET_NO;
  rc->state = state;
  rc->state_timeout = state_timeout;
  /* Resolve address to string */
  rc->asc = GNUNET_TRANSPORT_address_to_string (cfg,
                                                address,
                                                numeric,
                                                RESOLUTION_TIMEOUT,
                                                &process_peer_string,
						rc);
}


/**
 * Function called with information about a peers during a one shot iteration
 *
 * @param cls closure
 * @param peer identity of the peer, NULL for final callback when operation done
 * @param address binary address used to communicate with this peer,
 *  NULL on disconnect or when done
 * @param state current state this peer is in
 * @param state_timeout time out for the current state
 */
static void
process_peer_iteration_cb (void *cls,
                           const struct GNUNET_PeerIdentity *peer,
                           const struct GNUNET_HELLO_Address *address,
                           enum GNUNET_TRANSPORT_PeerState state,
                           struct GNUNET_TIME_Absolute state_timeout)
{
  if (NULL == peer)
  {
    /* done */
    pic = NULL;
    return;
  }

  if ( (GNUNET_NO == iterate_all) &&
       (GNUNET_NO == GNUNET_TRANSPORT_is_connected(state)))
      return; /* Display only connected peers */

  if (NULL != op_timeout)
    GNUNET_SCHEDULER_cancel (op_timeout);
  op_timeout = GNUNET_SCHEDULER_add_delayed (OP_TIMEOUT,
                                             &operation_timeout,
                                             NULL);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received address for peer `%s': %s\n",
              GNUNET_i2s (peer),
              address ? address->transport_name : "");

  if (NULL != address)
    resolve_peer_address (address,
			  numeric,
			  state,
			  state_timeout);
  else
    print_info (peer,
		NULL,
		NULL,
		state,
		state_timeout);
}


/**
 * Context for address resolution by #plugin_monitoring_cb().
 */
struct PluginMonitorAddress
{

  /**
   * Ongoing resolution request.
   */
  struct GNUNET_TRANSPORT_AddressToStringContext *asc;

  /**
   * Resolved address as string.
   */
  char *str;

  /**
   * Last event we got and did not yet print because
   * @e str was NULL (address not yet resolved).
   */
  struct GNUNET_TRANSPORT_SessionInfo si;
};


/**
 * Print information about a plugin monitoring event.
 *
 * @param addr out internal context
 * @param info the monitoring information
 */
static void
print_plugin_event_info (struct PluginMonitorAddress *addr,
			 const struct GNUNET_TRANSPORT_SessionInfo *info)
{
  const char *state;

  switch (info->state)
  {
  case GNUNET_TRANSPORT_SS_INIT:
    state = "INIT";
    break;
  case GNUNET_TRANSPORT_SS_HANDSHAKE:
    state = "HANDSHAKE";
    break;
  case GNUNET_TRANSPORT_SS_UP:
    state = "UP";
    break;
  case GNUNET_TRANSPORT_SS_UPDATE:
    state = "UPDATE";
    break;
  case GNUNET_TRANSPORT_SS_DONE:
    state = "DONE";
    break;
  default:
    state = "UNKNOWN";
    break;
  }
  fprintf (stdout,
           "%s: state %s timeout in %s @ %s%s\n",
           GNUNET_i2s (&info->address->peer),
           state,
           GNUNET_STRINGS_relative_time_to_string (GNUNET_TIME_absolute_get_remaining (info->session_timeout),
						   GNUNET_YES),
	   addr->str,
           (info->is_inbound == GNUNET_YES) ? " (INBOUND)" : "");
  fprintf (stdout,
           "%s: queue has %3u messages and %6u bytes\n",
           GNUNET_i2s (&info->address->peer),
           info->num_msg_pending,
           info->num_bytes_pending);
  if (0 != GNUNET_TIME_absolute_get_remaining (info->receive_delay).rel_value_us)
    fprintf (stdout,
	     "%s: receiving blocked until %s\n",
	     GNUNET_i2s (&info->address->peer),
	     GNUNET_STRINGS_absolute_time_to_string (info->receive_delay));
}


/**
 * Function called with a textual representation of an address.  This
 * function will be called several times with different possible
 * textual representations, and a last time with @a address being NULL
 * to signal the end of the iteration.  Note that @a address NULL
 * always is the last call, regardless of the value in @a res.
 *
 * @param cls closure
 * @param address NULL on end of iteration,
 *        otherwise 0-terminated printable UTF-8 string,
 *        in particular an empty string if @a res is #GNUNET_NO
 * @param res result of the address to string conversion:
 *        if #GNUNET_OK: conversion successful
 *        if #GNUNET_NO: address was invalid (or not supported)
 *        if #GNUNET_SYSERR: communication error (IPC error)
 */
static void
address_cb (void *cls,
            const char *address,
            int res)
{
  struct PluginMonitorAddress *addr = cls;

  if (NULL == address)
  {
    addr->asc = NULL;
    return;
  }
  if (NULL != addr->str)
    return;
  addr->str = GNUNET_strdup (address);
  print_plugin_event_info (addr,
			   &addr->si);
}


/**
 * Function called by the plugin with information about the
 * current sessions managed by the plugin (for monitoring).
 *
 * @param cls closure (NULL)
 * @param session session handle this information is about,
 *        NULL to indicate that we are "in sync" (initial
 *        iteration complete)
 * @param session_ctx storage location where the application
 *        can store data; will point to NULL on #GNUNET_TRANSPORT_SS_INIT,
 *        and must be reset to NULL on #GNUNET_TRANSPORT_SS_DONE
 * @param info information about the state of the session,
 *        NULL if @a session is also NULL and we are
 *        merely signalling that the initial iteration is over;
 *        NULL with @a session being non-NULL if the monitor
 *        was being cancelled while sessions were active
 */
static void
plugin_monitoring_cb (void *cls,
                      struct GNUNET_TRANSPORT_PluginSession *session,
                      void **session_ctx,
                      const struct GNUNET_TRANSPORT_SessionInfo *info)
{
  struct PluginMonitorAddress *addr;

  if ( (NULL == info) &&
       (NULL == session) )
    return; /* in sync with transport service */
  addr = *session_ctx;
  if (NULL == info)
  {
    if (NULL != addr)
    {
      if (NULL != addr->asc)
      {
        GNUNET_TRANSPORT_address_to_string_cancel (addr->asc);
        addr->asc = NULL;
      }
      GNUNET_free_non_null (addr->str);
      GNUNET_free (addr);
      *session_ctx = NULL;
    }
    return; /* shutdown */
  }
  if ( (NULL != cpid) &&
       (0 != memcmp (&info->address->peer,
                     cpid,
                     sizeof (struct GNUNET_PeerIdentity))) )
    return; /* filtered */
  if (NULL == addr)
  {
    addr = GNUNET_new (struct PluginMonitorAddress);
    addr->asc = GNUNET_TRANSPORT_address_to_string (cfg,
                                                    info->address,
                                                    numeric,
                                                    GNUNET_TIME_UNIT_FOREVER_REL,
                                                    &address_cb,
                                                    addr);
    *session_ctx = addr;
  }
  if (NULL == addr->str)
    addr->si = *info;
  else
    print_plugin_event_info (addr,
			     info);
  if (GNUNET_TRANSPORT_SS_DONE == info->state)
  {
    if (NULL != addr->asc)
    {
      GNUNET_TRANSPORT_address_to_string_cancel (addr->asc);
      addr->asc = NULL;
    }
    GNUNET_free_non_null (addr->str);
    GNUNET_free (addr);
    *session_ctx = NULL;
  }
}


/**
 * Function called with information about a peers
 *
 * @param cls closure, NULL
 * @param peer identity of the peer, NULL for final callback when operation done
 * @param address binary address used to communicate with this peer,
 *  NULL on disconnect or when done
 * @param state current state this peer is in
 * @param state_timeout time out for the current state
 */
static void
process_peer_monitoring_cb (void *cls,
                            const struct GNUNET_PeerIdentity *peer,
                            const struct GNUNET_HELLO_Address *address,
                            enum GNUNET_TRANSPORT_PeerState state,
                            struct GNUNET_TIME_Absolute state_timeout)
{
  struct MonitoredPeer *m;

  if (NULL == peer)
  {
    FPRINTF (stdout,
             "%s",
             _("Monitor disconnected from transport service. Reconnecting.\n"));
    return;
  }

  if (NULL != op_timeout)
    GNUNET_SCHEDULER_cancel (op_timeout);
  op_timeout = GNUNET_SCHEDULER_add_delayed (OP_TIMEOUT,
                                             &operation_timeout,
                                             NULL);

  if (NULL == (m = GNUNET_CONTAINER_multipeermap_get (monitored_peers,
						      peer)))
  {
    m = GNUNET_new (struct MonitoredPeer);
    GNUNET_CONTAINER_multipeermap_put (monitored_peers,
				       peer,
				       m,
				       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
  }
  else
  {
    if ( (m->state == state) &&
	 (m->state_timeout.abs_value_us == state_timeout.abs_value_us) &&
	 (NULL == address) &&
	 (NULL == m->address) )
    {
      return; /* No real change */
    }
    if ( (m->state == state) &&
	 (NULL != address) &&
	 (NULL != m->address) &&
	 (0 == GNUNET_HELLO_address_cmp(m->address, address)) )
      return; /* No real change */
  }

  if (NULL != m->address)
  {
    GNUNET_free (m->address);
    m->address = NULL;
  }
  if (NULL != address)
    m->address = GNUNET_HELLO_address_copy (address);
  m->state = state;
  m->state_timeout = state_timeout;

  if (NULL != address)
    resolve_peer_address (m->address,
                          numeric,
                          m->state,
                          m->state_timeout);
  else
    print_info (peer,
                NULL,
                NULL,
                m->state,
                m->state_timeout);
}


/**
 * Function called with the transport service checking if we
 * want to blacklist a peer. Return #GNUNET_SYSERR for the
 * peer that we should disconnect from.
 *
 * @param cls NULL
 * @param cpid peer to check blacklisting for
 * @return #GNUNET_OK if the connection is allowed, #GNUNET_SYSERR if not
 */
static int
blacklist_cb (void *cls,
              const struct GNUNET_PeerIdentity *cpid)
{
  if (0 == memcmp (cpid,
                   &pid,
                   sizeof (struct GNUNET_PeerIdentity)))
    return GNUNET_SYSERR;
  return GNUNET_OK;
}


/**
 * Main function that will be run by the scheduler.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param mycfg configuration
 */
static void
run (void *cls,
     char * const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *mycfg)
{
  int counter = 0;
  ret = 1;

  cfg = (struct GNUNET_CONFIGURATION_Handle *) mycfg;
  if ( (NULL != cpid) &&
       (GNUNET_OK !=
        GNUNET_CRYPTO_eddsa_public_key_from_string (cpid,
                                                    strlen (cpid),
                                                    &pid.public_key)))
  {
    FPRINTF (stderr,
             _("Failed to parse peer identity `%s'\n"),
             cpid);
    return;
  }

  counter = benchmark_send + benchmark_receive + iterate_connections
      + monitor_connections + monitor_connects + do_disconnect +
      monitor_plugins;

  if (1 < counter)
  {
    FPRINTF (stderr,
             _("Multiple operations given. Please choose only one operation: %s, %s, %s, %s, %s, %s %s\n"),
             "disconnect",
	     "benchmark send",
	     "benchmark receive",
	     "information",
             "monitor",
	     "events",
	     "plugins");
    return;
  }
  if (0 == counter)
  {
    FPRINTF (stderr,
	     _("No operation given. Please choose one operation: %s, %s, %s, %s, %s, %s, %s\n"),
             "disconnect",
	     "benchmark send",
	     "benchmark receive",
	     "information",
             "monitor",
	     "events",
	     "plugins");
    return;
  }

  if (do_disconnect) /* -D: Disconnect from peer */
  {
    if (NULL == cpid)
    {
      FPRINTF (stderr,
               _("Option `%s' makes no sense without option `%s'.\n"),
               "-D", "-p");
      ret = 1;
      return;
    }
    blacklist = GNUNET_TRANSPORT_blacklist (cfg,
                                            &blacklist_cb,
                                            NULL);
    if (NULL == blacklist)
    {
      FPRINTF (stderr,
               "%s",
               _("Failed to connect to transport service for disconnection\n"));
      ret = 1;
      return;
    }
    FPRINTF (stdout,
             "%s",
             _("Blacklisting request in place, stop with CTRL-C\n"));
  }
  else if (benchmark_send) /* -s: Benchmark sending */
  {
    if (NULL == cpid)
    {
      FPRINTF (stderr,
	       _("Option `%s' makes no sense without option `%s'.\n"),
	       "-s", "-p");
      ret = 1;
      return;
    }
    handle = GNUNET_TRANSPORT_core_connect (cfg,
					    NULL,
					    NULL,
					    NULL,
					    &notify_connect,
					    &notify_disconnect,
					    NULL);
    if (NULL == handle)
    {
      FPRINTF (stderr,
	       "%s",
	       _("Failed to connect to transport service\n"));
      ret = 1;
      return;
    }
    start_time = GNUNET_TIME_absolute_get ();
    op_timeout = GNUNET_SCHEDULER_add_delayed (OP_TIMEOUT,
                                               &operation_timeout,
                                               NULL);
  }
  else if (benchmark_receive) /* -b: Benchmark receiving */
  {
    struct GNUNET_MQ_MessageHandler handlers[] = {
      GNUNET_MQ_hd_var_size (dummy,
                             GNUNET_MESSAGE_TYPE_DUMMY,
                             struct GNUNET_MessageHeader,
                             NULL),
      GNUNET_MQ_handler_end ()
    };
    
    handle = GNUNET_TRANSPORT_core_connect (cfg,
					    NULL,
					    handlers,
					    NULL,
					    NULL,
					    NULL,
					    NULL);
    if (NULL == handle)
    {
      FPRINTF (stderr,
	       "%s",
	       _("Failed to connect to transport service\n"));
      ret = 1;
      return;
    }
    if (verbosity > 0)
      FPRINTF (stdout,
	       "%s",
	       _("Starting to receive benchmark data\n"));
    start_time = GNUNET_TIME_absolute_get ();

  }
  else if (iterate_connections) /* -i: List information about peers once */
  {
    pic = GNUNET_TRANSPORT_monitor_peers (cfg,
                                          (NULL == cpid) ? NULL : &pid,
                                          GNUNET_YES,
                                          &process_peer_iteration_cb,
                                          (void *) cfg);
    op_timeout = GNUNET_SCHEDULER_add_delayed (OP_TIMEOUT,
                                               &operation_timeout,
                                               NULL);
  }
  else if (monitor_connections) /* -m: List information about peers continuously */
  {
    monitored_peers = GNUNET_CONTAINER_multipeermap_create (10,
							    GNUNET_NO);
    pic = GNUNET_TRANSPORT_monitor_peers (cfg,
					  (NULL == cpid) ? NULL : &pid,
                                          GNUNET_NO,
                                          &process_peer_monitoring_cb,
                                          NULL);
  }
  else if (monitor_plugins) /* -P: List information about plugins continuously */
  {
    monitored_plugins = GNUNET_CONTAINER_multipeermap_create (10, GNUNET_NO);
    pm = GNUNET_TRANSPORT_monitor_plugins (cfg,
                                           &plugin_monitoring_cb,
                                           NULL);
  }
  else if (monitor_connects) /* -e : Monitor (dis)connect events continuously */
  {
    monitor_connect_counter = 0;
    handle = GNUNET_TRANSPORT_core_connect (cfg,
					    NULL,
					    NULL,
					    NULL,
					    &monitor_notify_connect,
					    &monitor_notify_disconnect,
					    NULL);
    if (NULL == handle)
    {
      FPRINTF (stderr,
               "%s",
               _("Failed to connect to transport service\n"));
      ret = 1;
      return;
    }
    ret = 0;
  }
  else
  {
    GNUNET_break(0);
    return;
  }

  GNUNET_SCHEDULER_add_shutdown (&shutdown_task,
				 NULL);
}


int
main (int argc,
      char * const *argv)
{
  int res;
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    { 'a', "all", NULL,
      gettext_noop ("print information for all peers (instead of only connected peers)"),
      0, &GNUNET_GETOPT_set_one, &iterate_all },
    { 'b', "benchmark", NULL,
      gettext_noop ("measure how fast we are receiving data from all peers (until CTRL-C)"),
      0, &GNUNET_GETOPT_set_one, &benchmark_receive },
    { 'D', "disconnect",
      NULL, gettext_noop ("disconnect from a peer"), 0,
      &GNUNET_GETOPT_set_one, &do_disconnect },
    { 'i', "information", NULL,
      gettext_noop ("provide information about all current connections (once)"),
      0, &GNUNET_GETOPT_set_one, &iterate_connections },
    { 'm', "monitor", NULL,
      gettext_noop ("provide information about all current connections (continuously)"),
      0, &GNUNET_GETOPT_set_one, &monitor_connections },
    { 'e', "events", NULL,
      gettext_noop ("provide information about all connects and disconnect events (continuously)"),
      0, &GNUNET_GETOPT_set_one, &monitor_connects },
    { 'n', "numeric",
      NULL, gettext_noop ("do not resolve hostnames"), 0,
      &GNUNET_GETOPT_set_one, &numeric },
    { 'p', "peer", "PEER",
      gettext_noop ("peer identity"), 1, &GNUNET_GETOPT_set_string,
      &cpid },
    { 'P', "plugins", NULL,
      gettext_noop ("monitor plugin sessions"), 0, &GNUNET_GETOPT_set_one,
      &monitor_plugins },
    { 's', "send", NULL, gettext_noop
      ("send data for benchmarking to the other peer (until CTRL-C)"), 0,
      &GNUNET_GETOPT_set_one, &benchmark_send },
    GNUNET_GETOPT_OPTION_VERBOSE (&verbosity),
    GNUNET_GETOPT_OPTION_END
  };

  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;

  res = GNUNET_PROGRAM_run (argc, argv,
                            "gnunet-transport",
                            gettext_noop ("Direct access to transport service."),
                            options,
                            &run, NULL);
  GNUNET_free ((void *) argv);
  if (GNUNET_OK == res)
    return ret;
  return 1;
}

/* end of gnunet-transport.c */
