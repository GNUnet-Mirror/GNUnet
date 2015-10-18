/*
 This file is part of GNUnet
 Copyright (C) 2010-2015 Christian Grothoff (and other contributing authors)

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
 * @file transport/plugin_transport_udp.c
 * @brief Implementation of the UDP transport protocol
 * @author Christian Grothoff
 * @author Nathan Evans
 * @author Matthias Wachs
 */
#include "platform.h"
#include "plugin_transport_udp.h"
#include "gnunet_hello_lib.h"
#include "gnunet_util_lib.h"
#include "gnunet_fragmentation_lib.h"
#include "gnunet_nat_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_resolver_service.h"
#include "gnunet_signatures.h"
#include "gnunet_constants.h"
#include "gnunet_statistics_service.h"
#include "gnunet_transport_service.h"
#include "gnunet_transport_plugin.h"
#include "transport.h"

#define LOG(kind,...) GNUNET_log_from (kind, "transport-udp", __VA_ARGS__)

/**
 * After how much inactivity should a UDP session time out?
 */
#define UDP_SESSION_TIME_OUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 60)

/**
 * Number of messages we can defragment in parallel.  We only really
 * defragment 1 message at a time, but if messages get re-ordered, we
 * may want to keep knowledge about the previous message to avoid
 * discarding the current message in favor of a single fragment of a
 * previous message.  3 should be good since we don't expect massive
 * message reorderings with UDP.
 */
#define UDP_MAX_MESSAGES_IN_DEFRAG 3

/**
 * We keep a defragmentation queue per sender address.  How many
 * sender addresses do we support at the same time? Memory consumption
 * is roughly a factor of 32k * #UDP_MAX_MESSAGES_IN_DEFRAG times this
 * value. (So 128 corresponds to 12 MB and should suffice for
 * connecting to roughly 128 peers via UDP).
 */
#define UDP_MAX_SENDER_ADDRESSES_WITH_DEFRAG 128


/**
 * UDP Message-Packet header (after defragmentation).
 */
struct UDPMessage
{
  /**
   * Message header.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Always zero for now.
   */
  uint32_t reserved;

  /**
   * What is the identity of the sender
   */
  struct GNUNET_PeerIdentity sender;

};


/**
 * Closure for #append_port().
 */
struct PrettyPrinterContext
{
  /**
   * DLL
   */
  struct PrettyPrinterContext *next;

  /**
   * DLL
   */
  struct PrettyPrinterContext *prev;

  /**
   * Our plugin.
   */
  struct Plugin *plugin;

  /**
   * Resolver handle
   */
  struct GNUNET_RESOLVER_RequestHandle *resolver_handle;

  /**
   * Function to call with the result.
   */
  GNUNET_TRANSPORT_AddressStringCallback asc;

  /**
   * Clsoure for @e asc.
   */
  void *asc_cls;

  /**
   * Timeout task
   */
  struct GNUNET_SCHEDULER_Task *timeout_task;

  /**
   * Is this an IPv6 address?
   */
  int ipv6;

  /**
   * Options
   */
  uint32_t options;

  /**
   * Port to add after the IP address.
   */
  uint16_t port;

};


/**
 * Session with another peer.
 */
struct GNUNET_ATS_Session
{
  /**
   * Which peer is this session for?
   */
  struct GNUNET_PeerIdentity target;

  /**
   * Plugin this session belongs to.
   */
  struct Plugin *plugin;

  /**
   * Context for dealing with fragments.
   */
  struct UDP_FragmentationContext *frag_ctx;

  /**
   * Desired delay for next sending we send to other peer
   */
  struct GNUNET_TIME_Relative flow_delay_for_other_peer;

  /**
   * Desired delay for transmissions we received from other peer.
   * This is for full messages, the value needs to be adjusted for
   * fragmented messages.
   */
  struct GNUNET_TIME_Relative flow_delay_from_other_peer;

  /**
   * Session timeout task
   */
  struct GNUNET_SCHEDULER_Task *timeout_task;

  /**
   * When does this session time out?
   */
  struct GNUNET_TIME_Absolute timeout;

  /**
   * What time did we last transmit?
   */
  struct GNUNET_TIME_Absolute last_transmit_time;

  /**
   * expected delay for ACKs
   */
  struct GNUNET_TIME_Relative last_expected_ack_delay;

  /**
   * desired delay between UDP messages
   */
  struct GNUNET_TIME_Relative last_expected_msg_delay;

  /**
   * Our own address.
   */
  struct GNUNET_HELLO_Address *address;

  /**
   * Number of bytes waiting for transmission to this peer.
   */
  unsigned long long bytes_in_queue;

  /**
   * Number of messages waiting for transmission to this peer.
   */
  unsigned int msgs_in_queue;

  /**
   * Reference counter to indicate that this session is
   * currently being used and must not be destroyed;
   * setting @e in_destroy will destroy it as soon as
   * possible.
   */
  unsigned int rc;

  /**
   * Network type of the address.
   */
  enum GNUNET_ATS_Network_Type scope;

  /**
   * Is this session about to be destroyed (sometimes we cannot
   * destroy a session immediately as below us on the stack
   * there might be code that still uses it; in this case,
   * @e rc is non-zero).
   */
  int in_destroy;
};



/**
 * Data structure to track defragmentation contexts based
 * on the source of the UDP traffic.
 */
struct DefragContext
{

  /**
   * Defragmentation context.
   */
  struct GNUNET_DEFRAGMENT_Context *defrag;

  /**
   * Reference to master plugin struct.
   */
  struct Plugin *plugin;

  /**
   * Node in the defrag heap.
   */
  struct GNUNET_CONTAINER_HeapNode *hnode;

  /**
   * Source address this receive context is for (allocated at the
   * end of the struct).
   */
  const union UdpAddress *udp_addr;

  /**
   * Who's message(s) are we defragmenting here?
   * Only initialized once we succeeded and
   * @e have_sender is set.
   */
  struct GNUNET_PeerIdentity sender;

  /**
   * Length of @e udp_addr.
   */
  size_t udp_addr_len;

  /**
   * Network type the address belongs to.
   */
  enum GNUNET_ATS_Network_Type network_type;

  /**
   * Has the @e sender field been initialized yet?
   */
  int have_sender;
};


/**
 * Context to send fragmented messages
 */
struct UDP_FragmentationContext
{
  /**
   * Next in linked list
   */
  struct UDP_FragmentationContext *next;

  /**
   * Previous in linked list
   */
  struct UDP_FragmentationContext *prev;

  /**
   * The plugin
   */
  struct Plugin *plugin;

  /**
   * Handle for fragmentation.
   */
  struct GNUNET_FRAGMENT_Context *frag;

  /**
   * The session this fragmentation context belongs to
   */
  struct GNUNET_ATS_Session *session;

  /**
   * Function to call upon completion of the transmission.
   */
  GNUNET_TRANSPORT_TransmitContinuation cont;

  /**
   * Closure for @e cont.
   */
  void *cont_cls;

  /**
   * Start time.
   */
  struct GNUNET_TIME_Absolute start_time;

  /**
   * Transmission time for the next fragment.  Incremented by
   * the @e flow_delay_from_other_peer for each fragment when
   * we setup the fragments.
   */
  struct GNUNET_TIME_Absolute next_frag_time;

  /**
   * Desired delay for transmissions we received from other peer.
   * Adjusted to be per fragment (UDP_MTU), even though on the
   * wire it was for "full messages".
   */
  struct GNUNET_TIME_Relative flow_delay_from_other_peer;

  /**
   * Message timeout
   */
  struct GNUNET_TIME_Absolute timeout;

  /**
   * Payload size of original unfragmented message
   */
  size_t payload_size;

  /**
   * Bytes used to send all fragments on wire including UDP overhead
   */
  size_t on_wire_size;

};


/**
 * Function called when a message is removed from the
 * transmission queue.
 *
 * @param cls closure
 * @param udpw message wrapper finished
 * @param result #GNUNET_OK on success (message was sent)
 *               #GNUNET_SYSERR if the target disconnected
 *               or we had a timeout or other trouble sending
 */
typedef void
(*QueueContinuation) (void *cls,
                      struct UDP_MessageWrapper *udpw,
                      int result);


/**
 * Information we track for each message in the queue.
 */
struct UDP_MessageWrapper
{
  /**
   * Session this message belongs to
   */
  struct GNUNET_ATS_Session *session;

  /**
   * DLL of messages, previous element
   */
  struct UDP_MessageWrapper *prev;

  /**
   * DLL of messages, next element
   */
  struct UDP_MessageWrapper *next;

  /**
   * Message with @e msg_size bytes including UDP-specific overhead.
   */
  char *msg_buf;

  /**
   * Function to call once the message wrapper is being removed
   * from the queue (with success or failure).
   */
  QueueContinuation qc;

  /**
   * Closure for @e qc.
   */
  void *qc_cls;

  /**
   * External continuation to call upon completion of the
   * transmission, NULL if this queue entry is not for a
   * message from the application.
   */
  GNUNET_TRANSPORT_TransmitContinuation cont;

  /**
   * Closure for @e cont.
   */
  void *cont_cls;

  /**
   * Fragmentation context.
   * frag_ctx == NULL if transport <= MTU
   * frag_ctx != NULL if transport > MTU
   */
  struct UDP_FragmentationContext *frag_ctx;

  /**
   * Message enqueue time.
   */
  struct GNUNET_TIME_Absolute start_time;

  /**
   * Desired transmission time for this message, based on the
   * flow limiting information we got from the other peer.
   */
  struct GNUNET_TIME_Absolute transmission_time;

  /**
   * Message timeout.
   */
  struct GNUNET_TIME_Absolute timeout;

  /**
   * Size of UDP message to send, including UDP-specific overhead.
   */
  size_t msg_size;

  /**
   * Payload size of original message.
   */
  size_t payload_size;

};


GNUNET_NETWORK_STRUCT_BEGIN

/**
 * UDP ACK Message-Packet header.
 */
struct UDP_ACK_Message
{
  /**
   * Message header.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Desired delay for flow control, in us (in NBO).
   * A value of UINT32_MAX indicates that the other
   * peer wants us to disconnect.
   */
  uint32_t delay GNUNET_PACKED;

  /**
   * What is the identity of the sender
   */
  struct GNUNET_PeerIdentity sender;

};

GNUNET_NETWORK_STRUCT_END


/* ************************* Monitoring *********** */


/**
 * If a session monitor is attached, notify it about the new
 * session state.
 *
 * @param plugin our plugin
 * @param session session that changed state
 * @param state new state of the session
 */
static void
notify_session_monitor (struct Plugin *plugin,
                        struct GNUNET_ATS_Session *session,
                        enum GNUNET_TRANSPORT_SessionState state)
{
  struct GNUNET_TRANSPORT_SessionInfo info;

  if (NULL == plugin->sic)
    return;
  if (GNUNET_YES == session->in_destroy)
    return; /* already destroyed, just RC>0 left-over actions */
  memset (&info,
          0,
          sizeof (info));
  info.state = state;
  info.is_inbound = GNUNET_SYSERR; /* hard to say */
  info.num_msg_pending = session->msgs_in_queue;
  info.num_bytes_pending = session->bytes_in_queue;
  /* info.receive_delay remains zero as this is not supported by UDP
     (cannot selectively not receive from 'some' peer while continuing
     to receive from others) */
  info.session_timeout = session->timeout;
  info.address = session->address;
  plugin->sic (plugin->sic_cls,
               session,
               &info);
}


/**
 * Return information about the given session to the monitor callback.
 *
 * @param cls the `struct Plugin` with the monitor callback (`sic`)
 * @param peer peer we send information about
 * @param value our `struct GNUNET_ATS_Session` to send information about
 * @return #GNUNET_OK (continue to iterate)
 */
static int
send_session_info_iter (void *cls,
                        const struct GNUNET_PeerIdentity *peer,
                        void *value)
{
  struct Plugin *plugin = cls;
  struct GNUNET_ATS_Session *session = value;

  notify_session_monitor (plugin,
                          session,
                          GNUNET_TRANSPORT_SS_INIT);
  notify_session_monitor (plugin,
                          session,
                          GNUNET_TRANSPORT_SS_UP);
  return GNUNET_OK;
}


/**
 * Begin monitoring sessions of a plugin.  There can only
 * be one active monitor per plugin (i.e. if there are
 * multiple monitors, the transport service needs to
 * multiplex the generated events over all of them).
 *
 * @param cls closure of the plugin
 * @param sic callback to invoke, NULL to disable monitor;
 *            plugin will being by iterating over all active
 *            sessions immediately and then enter monitor mode
 * @param sic_cls closure for @a sic
 */
static void
udp_plugin_setup_monitor (void *cls,
                          GNUNET_TRANSPORT_SessionInfoCallback sic,
                          void *sic_cls)
{
  struct Plugin *plugin = cls;

  plugin->sic = sic;
  plugin->sic_cls = sic_cls;
  if (NULL != sic)
  {
    GNUNET_CONTAINER_multipeermap_iterate (plugin->sessions,
                                           &send_session_info_iter,
                                           plugin);
    /* signal end of first iteration */
    sic (sic_cls,
         NULL,
         NULL);
  }
}


/* ****************** Little Helpers ****************** */


/**
 * Function to free last resources associated with a session.
 *
 * @param s session to free
 */
static void
free_session (struct GNUNET_ATS_Session *s)
{
  if (NULL != s->address)
  {
    GNUNET_HELLO_address_free (s->address);
    s->address = NULL;
  }
  if (NULL != s->frag_ctx)
  {
    GNUNET_FRAGMENT_context_destroy (s->frag_ctx->frag,
                                     NULL,
                                     NULL);
    GNUNET_free (s->frag_ctx);
    s->frag_ctx = NULL;
  }
  GNUNET_free (s);
}


/**
 * Function that is called to get the keepalive factor.
 * #GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT is divided by this number to
 * calculate the interval between keepalive packets.
 *
 * @param cls closure with the `struct Plugin`
 * @return keepalive factor
 */
static unsigned int
udp_query_keepalive_factor (void *cls)
{
  return 15;
}


/**
 * Function obtain the network type for a session
 *
 * @param cls closure (`struct Plugin *`)
 * @param session the session
 * @return the network type
 */
static enum GNUNET_ATS_Network_Type
udp_plugin_get_network (void *cls,
                        struct GNUNET_ATS_Session *session)
{
  return session->scope;
}


/**
 * Function obtain the network type for an address.
 *
 * @param cls closure (`struct Plugin *`)
 * @param address the address
 * @return the network type
 */
static enum GNUNET_ATS_Network_Type
udp_plugin_get_network_for_address (void *cls,
                                    const struct GNUNET_HELLO_Address *address)
{
  struct Plugin *plugin = cls;
  size_t addrlen;
  struct sockaddr_in a4;
  struct sockaddr_in6 a6;
  const struct IPv4UdpAddress *u4;
  const struct IPv6UdpAddress *u6;
  const void *sb;
  size_t sbs;

  addrlen = address->address_length;
  if (addrlen == sizeof(struct IPv6UdpAddress))
  {
    GNUNET_assert (NULL != address->address); /* make static analysis happy */
    u6 = address->address;
    memset (&a6, 0, sizeof(a6));
#if HAVE_SOCKADDR_IN_SIN_LEN
    a6.sin6_len = sizeof (a6);
#endif
    a6.sin6_family = AF_INET6;
    a6.sin6_port = u6->u6_port;
    memcpy (&a6.sin6_addr, &u6->ipv6_addr, sizeof(struct in6_addr));
    sb = &a6;
    sbs = sizeof(a6);
  }
  else if (addrlen == sizeof(struct IPv4UdpAddress))
  {
    GNUNET_assert (NULL != address->address); /* make static analysis happy */
    u4 = address->address;
    memset (&a4, 0, sizeof(a4));
#if HAVE_SOCKADDR_IN_SIN_LEN
    a4.sin_len = sizeof (a4);
#endif
    a4.sin_family = AF_INET;
    a4.sin_port = u4->u4_port;
    a4.sin_addr.s_addr = u4->ipv4_addr;
    sb = &a4;
    sbs = sizeof(a4);
  }
  else
  {
    GNUNET_break (0);
    return GNUNET_ATS_NET_UNSPECIFIED;
  }
  return plugin->env->get_address_type (plugin->env->cls,
                                        sb,
                                        sbs);
}


/* ******************* Event loop ******************** */

/**
 * We have been notified that our readset has something to read.  We don't
 * know which socket needs to be read, so we have to check each one
 * Then reschedule this function to be called again once more is available.
 *
 * @param cls the plugin handle
 * @param tc the scheduling context (for rescheduling this function again)
 */
static void
udp_plugin_select_v4 (void *cls,
                      const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * We have been notified that our readset has something to read.  We don't
 * know which socket needs to be read, so we have to check each one
 * Then reschedule this function to be called again once more is available.
 *
 * @param cls the plugin handle
 * @param tc the scheduling context (for rescheduling this function again)
 */
static void
udp_plugin_select_v6 (void *cls,
                      const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * (re)schedule IPv4-select tasks for this plugin.
 *
 * @param plugin plugin to reschedule
 */
static void
schedule_select_v4 (struct Plugin *plugin)
{
  struct GNUNET_TIME_Relative min_delay;
  struct GNUNET_TIME_Relative delay;
  struct UDP_MessageWrapper *udpw;
  struct UDP_MessageWrapper *min_udpw;

  if ( (GNUNET_YES == plugin->enable_ipv4) &&
       (NULL != plugin->sockv4) )
  {
    /* Find a message ready to send:
     * Flow delay from other peer is expired or not set (0) */
    min_delay = GNUNET_TIME_UNIT_FOREVER_REL;
    min_udpw = NULL;
    for (udpw = plugin->ipv4_queue_head; NULL != udpw; udpw = udpw->next)
    {
      delay = GNUNET_TIME_absolute_get_remaining (udpw->transmission_time);
      if (delay.rel_value_us < min_delay.rel_value_us)
      {
        min_delay = delay;
        min_udpw = udpw;
      }
    }
    if (NULL != plugin->select_task_v4)
      GNUNET_SCHEDULER_cancel (plugin->select_task_v4);
    if (NULL != min_udpw)
    {
      if (min_delay.rel_value_us > GNUNET_CONSTANTS_LATENCY_WARN.rel_value_us)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                    "Calculated flow delay for UDPv4 at %s for %s\n",
                    GNUNET_STRINGS_relative_time_to_string (min_delay,
                                                            GNUNET_YES),
                    GNUNET_i2s (&udpw->session->target));
      }
      else
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "Calculated flow delay for UDPv4 at %s for %s\n",
                    GNUNET_STRINGS_relative_time_to_string (min_delay,
                                                            GNUNET_YES),
                    GNUNET_i2s (&udpw->session->target));
      }
    }
    plugin->select_task_v4
      = GNUNET_SCHEDULER_add_read_net (min_delay,
                                       plugin->sockv4,
                                       &udp_plugin_select_v4,
                                       plugin);
  }
}


/**
 * (re)schedule IPv6-select tasks for this plugin.
 *
 * @param plugin plugin to reschedule
 */
static void
schedule_select_v6 (struct Plugin *plugin)
{
  struct GNUNET_TIME_Relative min_delay;
  struct GNUNET_TIME_Relative delay;
  struct UDP_MessageWrapper *udpw;
  struct UDP_MessageWrapper *min_udpw;

  if ( (GNUNET_YES == plugin->enable_ipv6) &&
       (NULL != plugin->sockv6) )
  {
    min_delay = GNUNET_TIME_UNIT_FOREVER_REL;
    min_udpw = NULL;
    for (udpw = plugin->ipv6_queue_head; NULL != udpw; udpw = udpw->next)
    {
      delay = GNUNET_TIME_absolute_get_remaining (udpw->transmission_time);
      if (delay.rel_value_us < min_delay.rel_value_us)
      {
        min_delay = delay;
        min_udpw = udpw;
      }
    }
    if (NULL != plugin->select_task_v6)
      GNUNET_SCHEDULER_cancel (plugin->select_task_v6);
    if (NULL != min_udpw)
    {
      if (min_delay.rel_value_us > GNUNET_CONSTANTS_LATENCY_WARN.rel_value_us)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                    "Calculated flow delay for UDPv6 at %s for %s\n",
                    GNUNET_STRINGS_relative_time_to_string (min_delay,
                                                            GNUNET_YES),
                    GNUNET_i2s (&udpw->session->target));
      }
      else
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "Calculated flow delay for UDPv6 at %s for %s\n",
                    GNUNET_STRINGS_relative_time_to_string (min_delay,
                                                            GNUNET_YES),
                    GNUNET_i2s (&udpw->session->target));
      }
    }
    plugin->select_task_v6
      = GNUNET_SCHEDULER_add_read_net (min_delay,
                                       plugin->sockv6,
                                       &udp_plugin_select_v6,
                                       plugin);
  }
}


/* ******************* Address to string and back ***************** */


/**
 * Function called for a quick conversion of the binary address to
 * a numeric address.  Note that the caller must not free the
 * address and that the next call to this function is allowed
 * to override the address again.
 *
 * @param cls closure
 * @param addr binary address (a `union UdpAddress`)
 * @param addrlen length of the @a addr
 * @return string representing the same address
 */
const char *
udp_address_to_string (void *cls,
                       const void *addr,
                       size_t addrlen)
{
  static char rbuf[INET6_ADDRSTRLEN + 10];
  char buf[INET6_ADDRSTRLEN];
  const void *sb;
  struct in_addr a4;
  struct in6_addr a6;
  const struct IPv4UdpAddress *t4;
  const struct IPv6UdpAddress *t6;
  int af;
  uint16_t port;
  uint32_t options;

  if (NULL == addr)
  {
    GNUNET_break_op (0);
    return NULL;
  }

  if (addrlen == sizeof(struct IPv6UdpAddress))
  {
    t6 = addr;
    af = AF_INET6;
    options = ntohl (t6->options);
    port = ntohs (t6->u6_port);
    a6 = t6->ipv6_addr;
    sb = &a6;
  }
  else if (addrlen == sizeof(struct IPv4UdpAddress))
  {
    t4 = addr;
    af = AF_INET;
    options = ntohl (t4->options);
    port = ntohs (t4->u4_port);
    a4.s_addr = t4->ipv4_addr;
    sb = &a4;
  }
  else
  {
    GNUNET_break_op (0);
    return NULL;
  }
  inet_ntop (af,
             sb,
             buf,
             INET6_ADDRSTRLEN);
  GNUNET_snprintf (rbuf,
                   sizeof(rbuf),
                   (af == AF_INET6)
                   ? "%s.%u.[%s]:%u"
                   : "%s.%u.%s:%u",
                   PLUGIN_NAME,
                   options,
                   buf,
                   port);
  return rbuf;
}


/**
 * Function called to convert a string address to a binary address.
 *
 * @param cls closure (`struct Plugin *`)
 * @param addr string address
 * @param addrlen length of the address
 * @param buf location to store the buffer
 * @param added location to store the number of bytes in the buffer.
 *        If the function returns #GNUNET_SYSERR, its contents are undefined.
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on failure
 */
static int
udp_string_to_address (void *cls,
                       const char *addr,
                       uint16_t addrlen,
                       void **buf,
                       size_t *added)
{
  struct sockaddr_storage socket_address;
  char *address;
  char *plugin;
  char *optionstr;
  uint32_t options;

  /* Format tcp.options.address:port */
  address = NULL;
  plugin = NULL;
  optionstr = NULL;

  if ((NULL == addr) || (0 == addrlen))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if ('\0' != addr[addrlen - 1])
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (strlen (addr) != addrlen - 1)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  plugin = GNUNET_strdup (addr);
  optionstr = strchr (plugin, '.');
  if (NULL == optionstr)
  {
    GNUNET_break (0);
    GNUNET_free (plugin);
    return GNUNET_SYSERR;
  }
  optionstr[0] = '\0';
  optionstr++;
  options = atol (optionstr);
  address = strchr (optionstr, '.');
  if (NULL == address)
  {
    GNUNET_break (0);
    GNUNET_free (plugin);
    return GNUNET_SYSERR;
  }
  address[0] = '\0';
  address++;

  if (GNUNET_OK !=
      GNUNET_STRINGS_to_address_ip (address,
                                    strlen (address),
                                    &socket_address))
  {
    GNUNET_break (0);
    GNUNET_free (plugin);
    return GNUNET_SYSERR;
  }
  GNUNET_free(plugin);

  switch (socket_address.ss_family)
  {
  case AF_INET:
    {
      struct IPv4UdpAddress *u4;
      const struct sockaddr_in *in4 = (const struct sockaddr_in *) &socket_address;

      u4 = GNUNET_new (struct IPv4UdpAddress);
      u4->options = htonl (options);
      u4->ipv4_addr = in4->sin_addr.s_addr;
      u4->u4_port = in4->sin_port;
      *buf = u4;
      *added = sizeof (struct IPv4UdpAddress);
      return GNUNET_OK;
    }
  case AF_INET6:
    {
      struct IPv6UdpAddress *u6;
      const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *) &socket_address;

      u6 = GNUNET_new (struct IPv6UdpAddress);
      u6->options = htonl (options);
      u6->ipv6_addr = in6->sin6_addr;
      u6->u6_port = in6->sin6_port;
      *buf = u6;
      *added = sizeof (struct IPv6UdpAddress);
      return GNUNET_OK;
    }
  default:
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
}


/**
 * Append our port and forward the result.
 *
 * @param cls a `struct PrettyPrinterContext *`
 * @param hostname result from DNS resolver
 */
static void
append_port (void *cls,
             const char *hostname)
{
  struct PrettyPrinterContext *ppc = cls;
  struct Plugin *plugin = ppc->plugin;
  char *ret;

  if (NULL == hostname)
  {
    /* Final call, done */
    GNUNET_CONTAINER_DLL_remove (plugin->ppc_dll_head,
                                 plugin->ppc_dll_tail,
                                 ppc);
    ppc->resolver_handle = NULL;
    ppc->asc (ppc->asc_cls,
              NULL,
              GNUNET_OK);
    GNUNET_free (ppc);
    return;
  }
  if (GNUNET_YES == ppc->ipv6)
    GNUNET_asprintf (&ret,
                     "%s.%u.[%s]:%d",
                     PLUGIN_NAME,
                     ppc->options,
                     hostname,
                     ppc->port);
  else
    GNUNET_asprintf (&ret,
                     "%s.%u.%s:%d",
                     PLUGIN_NAME,
                     ppc->options,
                     hostname,
                     ppc->port);
  ppc->asc (ppc->asc_cls,
            ret,
            GNUNET_OK);
  GNUNET_free (ret);
}


/**
 * Convert the transports address to a nice, human-readable format.
 *
 * @param cls closure with the `struct Plugin *`
 * @param type name of the transport that generated the address
 * @param addr one of the addresses of the host, NULL for the last address
 *        the specific address format depends on the transport;
 *        a `union UdpAddress`
 * @param addrlen length of the address
 * @param numeric should (IP) addresses be displayed in numeric form?
 * @param timeout after how long should we give up?
 * @param asc function to call on each string
 * @param asc_cls closure for @a asc
 */
static void
udp_plugin_address_pretty_printer (void *cls,
                                   const char *type,
                                   const void *addr,
                                   size_t addrlen,
                                   int numeric,
                                   struct GNUNET_TIME_Relative timeout,
                                   GNUNET_TRANSPORT_AddressStringCallback asc,
                                   void *asc_cls)
{
  struct Plugin *plugin = cls;
  struct PrettyPrinterContext *ppc;
  const struct sockaddr *sb;
  size_t sbs;
  struct sockaddr_in a4;
  struct sockaddr_in6 a6;
  const struct IPv4UdpAddress *u4;
  const struct IPv6UdpAddress *u6;
  uint16_t port;
  uint32_t options;

  if (addrlen == sizeof(struct IPv6UdpAddress))
  {
    u6 = addr;
    memset (&a6,
            0,
            sizeof (a6));
    a6.sin6_family = AF_INET6;
#if HAVE_SOCKADDR_IN_SIN_LEN
    a6.sin6_len = sizeof (a6);
#endif
    a6.sin6_port = u6->u6_port;
    a6.sin6_addr = u6->ipv6_addr;
    port = ntohs (u6->u6_port);
    options = ntohl (u6->options);
    sb = (const struct sockaddr *) &a6;
    sbs = sizeof (a6);
  }
  else if (addrlen == sizeof (struct IPv4UdpAddress))
  {
    u4 = addr;
    memset (&a4,
            0,
            sizeof(a4));
    a4.sin_family = AF_INET;
#if HAVE_SOCKADDR_IN_SIN_LEN
    a4.sin_len = sizeof (a4);
#endif
    a4.sin_port = u4->u4_port;
    a4.sin_addr.s_addr = u4->ipv4_addr;
    port = ntohs (u4->u4_port);
    options = ntohl (u4->options);
    sb = (const struct sockaddr *) &a4;
    sbs = sizeof(a4);
  }
  else
  {
    /* invalid address */
    GNUNET_break_op (0);
    asc (asc_cls,
         NULL,
         GNUNET_SYSERR);
    asc (asc_cls,
         NULL,
         GNUNET_OK);
    return;
  }
  ppc = GNUNET_new (struct PrettyPrinterContext);
  ppc->plugin = plugin;
  ppc->asc = asc;
  ppc->asc_cls = asc_cls;
  ppc->port = port;
  ppc->options = options;
  if (addrlen == sizeof (struct IPv6UdpAddress))
    ppc->ipv6 = GNUNET_YES;
  else
    ppc->ipv6 = GNUNET_NO;
  GNUNET_CONTAINER_DLL_insert (plugin->ppc_dll_head,
                               plugin->ppc_dll_tail,
                               ppc);
  ppc->resolver_handle
    = GNUNET_RESOLVER_hostname_get (sb,
                                    sbs,
                                    ! numeric,
                                    timeout,
                                    &append_port,
                                    ppc);
}


/**
 * Check if the given port is plausible (must be either our listen
 * port or our advertised port).  If it is neither, we return
 * #GNUNET_SYSERR.
 *
 * @param plugin global variables
 * @param in_port port number to check
 * @return #GNUNET_OK if port is either our open or advertised port
 */
static int
check_port (const struct Plugin *plugin,
            uint16_t in_port)
{
  if ( (plugin->port == in_port) ||
       (plugin->aport == in_port) )
    return GNUNET_OK;
  return GNUNET_SYSERR;
}


/**
 * Function that will be called to check if a binary address for this
 * plugin is well-formed and corresponds to an address for THIS peer
 * (as per our configuration).  Naturally, if absolutely necessary,
 * plugins can be a bit conservative in their answer, but in general
 * plugins should make sure that the address does not redirect
 * traffic to a 3rd party that might try to man-in-the-middle our
 * traffic.
 *
 * @param cls closure, should be our handle to the Plugin
 * @param addr pointer to a `union UdpAddress`
 * @param addrlen length of @a addr
 * @return #GNUNET_OK if this is a plausible address for this peer
 *         and transport, #GNUNET_SYSERR if not
 */
static int
udp_plugin_check_address (void *cls,
                          const void *addr,
                          size_t addrlen)
{
  struct Plugin *plugin = cls;
  const struct IPv4UdpAddress *v4;
  const struct IPv6UdpAddress *v6;

  if (sizeof(struct IPv4UdpAddress) == addrlen)
  {
    v4 = (const struct IPv4UdpAddress *) addr;
    if (GNUNET_OK != check_port (plugin,
                                 ntohs (v4->u4_port)))
      return GNUNET_SYSERR;
    if (GNUNET_OK !=
        GNUNET_NAT_test_address (plugin->nat,
                                 &v4->ipv4_addr,
                                 sizeof (struct in_addr)))
      return GNUNET_SYSERR;
  }
  else if (sizeof(struct IPv6UdpAddress) == addrlen)
  {
    v6 = (const struct IPv6UdpAddress *) addr;
    if (IN6_IS_ADDR_LINKLOCAL (&v6->ipv6_addr))
    {
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
    if (GNUNET_OK != check_port (plugin,
                                 ntohs (v6->u6_port)))
      return GNUNET_SYSERR;
    if (GNUNET_OK !=
        GNUNET_NAT_test_address (plugin->nat,
                                 &v6->ipv6_addr,
                                 sizeof (struct in6_addr)))
      return GNUNET_SYSERR;
  }
  else
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Our external IP address/port mapping has changed.
 *
 * @param cls closure, the `struct Plugin`
 * @param add_remove #GNUNET_YES to mean the new public IP address,
 *                   #GNUNET_NO to mean the previous (now invalid) one
 * @param addr either the previous or the new public IP address
 * @param addrlen actual length of the @a addr
 */
static void
udp_nat_port_map_callback (void *cls,
                           int add_remove,
                           const struct sockaddr *addr,
                           socklen_t addrlen)
{
  struct Plugin *plugin = cls;
  struct GNUNET_HELLO_Address *address;
  struct IPv4UdpAddress u4;
  struct IPv6UdpAddress u6;
  void *arg;
  size_t args;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       (GNUNET_YES == add_remove)
       ? "NAT notification to add address `%s'\n"
       : "NAT notification to remove address `%s'\n",
       GNUNET_a2s (addr,
                   addrlen));
  /* convert 'address' to our internal format */
  switch (addr->sa_family)
  {
  case AF_INET:
    {
      const struct sockaddr_in *i4;

      GNUNET_assert (sizeof(struct sockaddr_in) == addrlen);
      i4 = (const struct sockaddr_in *) addr;
      if (0 == ntohs (i4->sin_port))
      {
        GNUNET_break (0);
        return;
      }
      memset (&u4,
              0,
              sizeof(u4));
      u4.options = htonl (plugin->myoptions);
      u4.ipv4_addr = i4->sin_addr.s_addr;
      u4.u4_port = i4->sin_port;
      arg = &u4;
      args = sizeof (struct IPv4UdpAddress);
      break;
    }
  case AF_INET6:
    {
      const struct sockaddr_in6 *i6;

      GNUNET_assert (sizeof(struct sockaddr_in6) == addrlen);
      i6 = (const struct sockaddr_in6 *) addr;
      if (0 == ntohs (i6->sin6_port))
      {
        GNUNET_break (0);
        return;
      }
      memset (&u6,
              0,
              sizeof(u6));
      u6.options = htonl (plugin->myoptions);
      u6.ipv6_addr = i6->sin6_addr;
      u6.u6_port = i6->sin6_port;
      arg = &u6;
      args = sizeof (struct IPv6UdpAddress);
      break;
    }
  default:
    GNUNET_break (0);
    return;
  }
  /* modify our published address list */
  address = GNUNET_HELLO_address_allocate (plugin->env->my_identity,
                                           PLUGIN_NAME,
                                           arg,
                                           args,
                                           GNUNET_HELLO_ADDRESS_INFO_NONE);
  plugin->env->notify_address (plugin->env->cls,
                               add_remove,
                               address);
  GNUNET_HELLO_address_free (address);
}


/* ********************* Finding sessions ******************* */


/**
 * Closure for #session_cmp_it().
 */
struct GNUNET_ATS_SessionCompareContext
{
  /**
   * Set to session matching the address.
   */
  struct GNUNET_ATS_Session *res;

  /**
   * Address we are looking for.
   */
  const struct GNUNET_HELLO_Address *address;
};


/**
 * Find a session with a matching address.
 *
 * @param cls the `struct GNUNET_ATS_SessionCompareContext *`
 * @param key peer identity (unused)
 * @param value the `struct GNUNET_ATS_Session *`
 * @return #GNUNET_NO if we found the session, #GNUNET_OK if not
 */
static int
session_cmp_it (void *cls,
                const struct GNUNET_PeerIdentity *key,
                void *value)
{
  struct GNUNET_ATS_SessionCompareContext *cctx = cls;
  struct GNUNET_ATS_Session *s = value;

  if (0 == GNUNET_HELLO_address_cmp (s->address,
                                     cctx->address))
  {
    GNUNET_assert (GNUNET_NO == s->in_destroy);
    cctx->res = s;
    return GNUNET_NO;
  }
  return GNUNET_OK;
}


/**
 * Locate an existing session the transport service is using to
 * send data to another peer.  Performs some basic sanity checks
 * on the address and then tries to locate a matching session.
 *
 * @param cls the plugin
 * @param address the address we should locate the session by
 * @return the session if it exists, or NULL if it is not found
 */
static struct GNUNET_ATS_Session *
udp_plugin_lookup_session (void *cls,
                           const struct GNUNET_HELLO_Address *address)
{
  struct Plugin *plugin = cls;
  const struct IPv6UdpAddress *udp_a6;
  const struct IPv4UdpAddress *udp_a4;
  struct GNUNET_ATS_SessionCompareContext cctx;

  if (NULL == address->address)
  {
    GNUNET_break (0);
    return NULL;
  }
  if (sizeof(struct IPv4UdpAddress) == address->address_length)
  {
    if (NULL == plugin->sockv4)
      return NULL;
    udp_a4 = (const struct IPv4UdpAddress *) address->address;
    if (0 == udp_a4->u4_port)
    {
      GNUNET_break (0);
      return NULL;
    }
  }
  else if (sizeof(struct IPv6UdpAddress) == address->address_length)
  {
    if (NULL == plugin->sockv6)
      return NULL;
    udp_a6 = (const struct IPv6UdpAddress *) address->address;
    if (0 == udp_a6->u6_port)
    {
      GNUNET_break (0);
      return NULL;
    }
  }
  else
  {
    GNUNET_break (0);
    return NULL;
  }

  /* check if session already exists */
  cctx.address = address;
  cctx.res = NULL;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Looking for existing session for peer `%s' with address `%s'\n",
       GNUNET_i2s (&address->peer),
       udp_address_to_string (plugin,
                              address->address,
                              address->address_length));
  GNUNET_CONTAINER_multipeermap_get_multiple (plugin->sessions,
                                              &address->peer,
                                              &session_cmp_it,
                                              &cctx);
  if (NULL == cctx.res)
    return NULL;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Found existing session %p\n",
       cctx.res);
  return cctx.res;
}


/* ********************** Timeout ****************** */


/**
 * Increment session timeout due to activity.
 *
 * @param s session to reschedule timeout activity for
 */
static void
reschedule_session_timeout (struct GNUNET_ATS_Session *s)
{
  if (GNUNET_YES == s->in_destroy)
    return;
  GNUNET_assert (NULL != s->timeout_task);
  s->timeout = GNUNET_TIME_relative_to_absolute (UDP_SESSION_TIME_OUT);
}



/**
 * Function that will be called whenever the transport service wants to
 * notify the plugin that a session is still active and in use and
 * therefore the session timeout for this session has to be updated
 *
 * @param cls closure with the `struct Plugin`
 * @param peer which peer was the session for
 * @param session which session is being updated
 */
static void
udp_plugin_update_session_timeout (void *cls,
                                   const struct GNUNET_PeerIdentity *peer,
                                   struct GNUNET_ATS_Session *session)
{
  struct Plugin *plugin = cls;

  if (GNUNET_YES !=
      GNUNET_CONTAINER_multipeermap_contains_value (plugin->sessions,
                                                    peer,
                                                    session))
  {
    GNUNET_break (0);
    return;
  }
  /* Reschedule session timeout */
  reschedule_session_timeout (session);
}


/* ************************* Sending ************************ */


/**
 * Remove the given message from the transmission queue and
 * update all applicable statistics.
 *
 * @param plugin the UDP plugin
 * @param udpw message wrapper to dequeue
 */
static void
dequeue (struct Plugin *plugin,
         struct UDP_MessageWrapper *udpw)
{
  struct GNUNET_ATS_Session *session = udpw->session;

  if (plugin->bytes_in_buffer < udpw->msg_size)
  {
    GNUNET_break (0);
  }
  else
  {
    GNUNET_STATISTICS_update (plugin->env->stats,
                              "# UDP, total bytes in send buffers",
                              - (long long) udpw->msg_size,
                              GNUNET_NO);
    plugin->bytes_in_buffer -= udpw->msg_size;
  }
  GNUNET_STATISTICS_update (plugin->env->stats,
                            "# UDP, total messages in send buffers",
                            -1,
                            GNUNET_NO);
  if (sizeof(struct IPv4UdpAddress) == udpw->session->address->address_length)
  {
    GNUNET_CONTAINER_DLL_remove (plugin->ipv4_queue_head,
                                 plugin->ipv4_queue_tail,
                                 udpw);
  }
  else if (sizeof(struct IPv6UdpAddress) == udpw->session->address->address_length)
  {
    GNUNET_CONTAINER_DLL_remove (plugin->ipv6_queue_head,
                                 plugin->ipv6_queue_tail,
                                 udpw);
  }
  else
  {
    GNUNET_break (0);
    return;
  }
  GNUNET_assert (session->msgs_in_queue > 0);
  session->msgs_in_queue--;
  GNUNET_assert (session->bytes_in_queue >= udpw->msg_size);
  session->bytes_in_queue -= udpw->msg_size;
}


/**
 * Enqueue a message for transmission and update statistics.
 *
 * @param plugin the UDP plugin
 * @param udpw message wrapper to queue
 */
static void
enqueue (struct Plugin *plugin,
         struct UDP_MessageWrapper *udpw)
{
  struct GNUNET_ATS_Session *session = udpw->session;

  if (GNUNET_YES == session->in_destroy)
  {
    GNUNET_break (0);
    return;
  }
  if (plugin->bytes_in_buffer + udpw->msg_size > INT64_MAX)
  {
    GNUNET_break (0);
  }
  else
  {
    GNUNET_STATISTICS_update (plugin->env->stats,
                              "# UDP, total bytes in send buffers",
                              udpw->msg_size,
                              GNUNET_NO);
    plugin->bytes_in_buffer += udpw->msg_size;
  }
  GNUNET_STATISTICS_update (plugin->env->stats,
                            "# UDP, total messages in send buffers",
                            1,
                            GNUNET_NO);
  if (sizeof (struct IPv4UdpAddress) == udpw->session->address->address_length)
  {
    GNUNET_CONTAINER_DLL_insert(plugin->ipv4_queue_head,
                                plugin->ipv4_queue_tail,
                                udpw);
  }
  else if (sizeof (struct IPv6UdpAddress) == udpw->session->address->address_length)
  {
    GNUNET_CONTAINER_DLL_insert (plugin->ipv6_queue_head,
                                 plugin->ipv6_queue_tail,
                                 udpw);
  }
  else
  {
    GNUNET_break (0);
    udpw->cont (udpw->cont_cls,
                &session->target,
                GNUNET_SYSERR,
                udpw->msg_size,
                0);
    GNUNET_free (udpw);
    return;
  }
  session->msgs_in_queue++;
  session->bytes_in_queue += udpw->msg_size;
}


/**
 * We have completed our (attempt) to transmit a message that had to
 * be fragmented -- either because we got an ACK saying that all
 * fragments were received, or because of timeout / disconnect.  Clean
 * up our state.
 *
 * @param frag_ctx fragmentation context to clean up
 * @param result #GNUNET_OK if we succeeded (got ACK),
 *               #GNUNET_SYSERR if the transmission failed
 */
static void
fragmented_message_done (struct UDP_FragmentationContext *frag_ctx,
                         int result)
{
  struct Plugin *plugin = frag_ctx->plugin;
  struct GNUNET_ATS_Session *s = frag_ctx->session;
  struct UDP_MessageWrapper *udpw;
  struct UDP_MessageWrapper *tmp;
  size_t overhead;
  struct GNUNET_TIME_Relative delay;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "%p: Fragmented message removed with result %s\n",
       frag_ctx,
       (result == GNUNET_SYSERR) ? "FAIL" : "SUCCESS");
  /* Call continuation for fragmented message */
  if (frag_ctx->on_wire_size >= frag_ctx->payload_size)
    overhead = frag_ctx->on_wire_size - frag_ctx->payload_size;
  else
    overhead = frag_ctx->on_wire_size;
  delay = GNUNET_TIME_absolute_get_duration (frag_ctx->start_time);
  if (delay.rel_value_us > GNUNET_CONSTANTS_LATENCY_WARN.rel_value_us)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Fragmented message acknowledged after %s\n",
         GNUNET_STRINGS_relative_time_to_string (delay,
                                                 GNUNET_YES));
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Fragmented message acknowledged after %s\n",
         GNUNET_STRINGS_relative_time_to_string (delay,
                                                 GNUNET_YES));
  }

  if (NULL != frag_ctx->cont)
    frag_ctx->cont (frag_ctx->cont_cls,
                    &s->target,
                    result,
                    s->frag_ctx->payload_size,
                    frag_ctx->on_wire_size);
  GNUNET_STATISTICS_update (plugin->env->stats,
                            "# UDP, fragmented messages active",
                            -1,
                            GNUNET_NO);

  if (GNUNET_OK == result)
  {
    GNUNET_STATISTICS_update (plugin->env->stats,
                              "# UDP, fragmented msgs, messages, sent, success",
                              1,
                              GNUNET_NO);
    GNUNET_STATISTICS_update (plugin->env->stats,
                              "# UDP, fragmented msgs, bytes payload, sent, success",
                              s->frag_ctx->payload_size,
                              GNUNET_NO);
    GNUNET_STATISTICS_update (plugin->env->stats,
                              "# UDP, fragmented msgs, bytes overhead, sent, success",
                              overhead,
                              GNUNET_NO);
    GNUNET_STATISTICS_update (plugin->env->stats,
                              "# UDP, total, bytes overhead, sent",
                              overhead,
                              GNUNET_NO);
    GNUNET_STATISTICS_update (plugin->env->stats,
                              "# UDP, total, bytes payload, sent",
                              s->frag_ctx->payload_size,
                              GNUNET_NO);
  }
  else
  {
    GNUNET_STATISTICS_update (plugin->env->stats,
                              "# UDP, fragmented msgs, messages, sent, failure",
                              1,
                              GNUNET_NO);
    GNUNET_STATISTICS_update (plugin->env->stats,
                              "# UDP, fragmented msgs, bytes payload, sent, failure",
                              s->frag_ctx->payload_size,
                              GNUNET_NO);
    GNUNET_STATISTICS_update (plugin->env->stats,
                              "# UDP, fragmented msgs, bytes payload, sent, failure",
                              overhead,
                              GNUNET_NO);
    GNUNET_STATISTICS_update (plugin->env->stats,
                              "# UDP, fragmented msgs, bytes payload, sent, failure",
                              overhead,
                              GNUNET_NO);
  }

  /* Remove remaining fragments from queue, no need to transmit those
     any longer. */
  if (s->address->address_length == sizeof(struct IPv6UdpAddress))
  {
    udpw = plugin->ipv6_queue_head;
    while (NULL != udpw)
    {
      tmp = udpw->next;
      if ( (udpw->frag_ctx != NULL) &&
	   (udpw->frag_ctx == frag_ctx) )
      {
	dequeue (plugin,
                 udpw);
	GNUNET_free (udpw);
      }
      udpw = tmp;
    }
  }
  if (s->address->address_length == sizeof(struct IPv4UdpAddress))
  {
    udpw = plugin->ipv4_queue_head;
    while (NULL != udpw)
    {
      tmp = udpw->next;
      if ( (NULL != udpw->frag_ctx) &&
           (udpw->frag_ctx == frag_ctx) )
      {
        dequeue (plugin,
                 udpw);
        GNUNET_free (udpw);
      }
      udpw = tmp;
    }
  }
  notify_session_monitor (s->plugin,
                          s,
                          GNUNET_TRANSPORT_SS_UPDATE);
  GNUNET_FRAGMENT_context_destroy (frag_ctx->frag,
                                   &s->last_expected_msg_delay,
                                   &s->last_expected_ack_delay);
  s->frag_ctx = NULL;
  GNUNET_free (frag_ctx);
}


/**
 * We are finished with a fragment in the message queue.
 * Notify the continuation and update statistics.
 *
 * @param cls the `struct Plugin *`
 * @param udpw the queue entry
 * @param result #GNUNET_OK on success, #GNUNET_SYSERR on failure
 */
static void
qc_fragment_sent (void *cls,
                  struct UDP_MessageWrapper *udpw,
                  int result)
{
  struct Plugin *plugin = cls;

  GNUNET_assert (NULL != udpw->frag_ctx);
  if (GNUNET_OK == result)
  {
    GNUNET_FRAGMENT_context_transmission_done (udpw->frag_ctx->frag);
    GNUNET_STATISTICS_update (plugin->env->stats,
                              "# UDP, fragmented msgs, fragments, sent, success",
                              1,
                              GNUNET_NO);
    GNUNET_STATISTICS_update (plugin->env->stats,
                              "# UDP, fragmented msgs, fragments bytes, sent, success",
                              udpw->msg_size,
                              GNUNET_NO);
  }
  else
  {
    fragmented_message_done (udpw->frag_ctx,
                             GNUNET_SYSERR);
    GNUNET_STATISTICS_update (plugin->env->stats,
                              "# UDP, fragmented msgs, fragments, sent, failure",
                              1,
                              GNUNET_NO);
    GNUNET_STATISTICS_update (plugin->env->stats,
                              "# UDP, fragmented msgs, fragments bytes, sent, failure",
                              udpw->msg_size,
                              GNUNET_NO);
  }
}


/**
 * Function that is called with messages created by the fragmentation
 * module.  In the case of the `proc` callback of the
 * #GNUNET_FRAGMENT_context_create() function, this function must
 * eventually call #GNUNET_FRAGMENT_context_transmission_done().
 *
 * @param cls closure, the `struct UDP_FragmentationContext`
 * @param msg the message that was created
 */
static void
enqueue_fragment (void *cls,
                  const struct GNUNET_MessageHeader *msg)
{
  struct UDP_FragmentationContext *frag_ctx = cls;
  struct Plugin *plugin = frag_ctx->plugin;
  struct UDP_MessageWrapper *udpw;
  struct GNUNET_ATS_Session *session = frag_ctx->session;
  size_t msg_len = ntohs (msg->size);

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Enqueuing fragment with %u bytes\n",
       msg_len);
  udpw = GNUNET_malloc (sizeof (struct UDP_MessageWrapper) + msg_len);
  udpw->session = session;
  udpw->msg_buf = (char *) &udpw[1];
  udpw->msg_size = msg_len;
  udpw->payload_size = msg_len; /* FIXME: minus fragment overhead */
  udpw->timeout = frag_ctx->timeout;
  udpw->start_time = frag_ctx->start_time;
  udpw->transmission_time = frag_ctx->next_frag_time;
  frag_ctx->next_frag_time
    = GNUNET_TIME_absolute_add (frag_ctx->next_frag_time,
                                frag_ctx->flow_delay_from_other_peer);
  udpw->frag_ctx = frag_ctx;
  udpw->qc = &qc_fragment_sent;
  udpw->qc_cls = plugin;
  memcpy (udpw->msg_buf,
          msg,
          msg_len);
  enqueue (plugin,
           udpw);
}


/**
 * We are finished with a message from the message queue.
 * Notify the continuation and update statistics.
 *
 * @param cls the `struct Plugin *`
 * @param udpw the queue entry
 * @param result #GNUNET_OK on success, #GNUNET_SYSERR on failure
 */
static void
qc_message_sent (void *cls,
                 struct UDP_MessageWrapper *udpw,
                 int result)
{
  struct Plugin *plugin = cls;
  size_t overhead;
  struct GNUNET_TIME_Relative delay;

  if (udpw->msg_size >= udpw->payload_size)
    overhead = udpw->msg_size - udpw->payload_size;
  else
    overhead = udpw->msg_size;

  if (NULL != udpw->cont)
  {
    delay = GNUNET_TIME_absolute_get_duration (udpw->start_time);
    if (delay.rel_value_us > GNUNET_CONSTANTS_LATENCY_WARN.rel_value_us)
    {
      LOG (GNUNET_ERROR_TYPE_WARNING,
           "Message sent via UDP with delay of %s\n",
           GNUNET_STRINGS_relative_time_to_string (delay,
                                                   GNUNET_YES));
    }
    else
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Message sent via UDP with delay of %s\n",
           GNUNET_STRINGS_relative_time_to_string (delay,
                                                   GNUNET_YES));
    }
    udpw->cont (udpw->cont_cls,
                &udpw->session->target,
                result,
                udpw->payload_size,
                overhead);
  }
  if (GNUNET_OK == result)
  {
    GNUNET_STATISTICS_update (plugin->env->stats,
                              "# UDP, unfragmented msgs, messages, sent, success",
                              1,
                              GNUNET_NO);
    GNUNET_STATISTICS_update (plugin->env->stats,
                              "# UDP, unfragmented msgs, bytes payload, sent, success",
                              udpw->payload_size,
                              GNUNET_NO);
    GNUNET_STATISTICS_update (plugin->env->stats,
                              "# UDP, unfragmented msgs, bytes overhead, sent, success",
                              overhead,
                              GNUNET_NO);
    GNUNET_STATISTICS_update (plugin->env->stats,
                              "# UDP, total, bytes overhead, sent",
                              overhead,
                              GNUNET_NO);
    GNUNET_STATISTICS_update (plugin->env->stats,
                              "# UDP, total, bytes payload, sent",
                              udpw->payload_size,
                              GNUNET_NO);
  }
  else
  {
    GNUNET_STATISTICS_update (plugin->env->stats,
                              "# UDP, unfragmented msgs, messages, sent, failure",
                              1,
                              GNUNET_NO);
    GNUNET_STATISTICS_update (plugin->env->stats,
                              "# UDP, unfragmented msgs, bytes payload, sent, failure",
                              udpw->payload_size,
                              GNUNET_NO);
    GNUNET_STATISTICS_update (plugin->env->stats,
                              "# UDP, unfragmented msgs, bytes overhead, sent, failure",
                              overhead,
                              GNUNET_NO);
  }
}


/**
 * Function that can be used by the transport service to transmit a
 * message using the plugin.  Note that in the case of a peer
 * disconnecting, the continuation MUST be called prior to the
 * disconnect notification itself.  This function will be called with
 * this peer's HELLO message to initiate a fresh connection to another
 * peer.
 *
 * @param cls closure
 * @param s which session must be used
 * @param msgbuf the message to transmit
 * @param msgbuf_size number of bytes in @a msgbuf
 * @param priority how important is the message (most plugins will
 *                 ignore message priority and just FIFO)
 * @param to how long to wait at most for the transmission (does not
 *                require plugins to discard the message after the timeout,
 *                just advisory for the desired delay; most plugins will ignore
 *                this as well)
 * @param cont continuation to call once the message has
 *        been transmitted (or if the transport is ready
 *        for the next transmission call; or if the
 *        peer disconnected...); can be NULL
 * @param cont_cls closure for @a cont
 * @return number of bytes used (on the physical network, with overheads);
 *         -1 on hard errors (i.e. address invalid); 0 is a legal value
 *         and does NOT mean that the message was not transmitted (DV)
 */
static ssize_t
udp_plugin_send (void *cls,
                 struct GNUNET_ATS_Session *s,
                 const char *msgbuf,
                 size_t msgbuf_size,
                 unsigned int priority,
                 struct GNUNET_TIME_Relative to,
                 GNUNET_TRANSPORT_TransmitContinuation cont,
                 void *cont_cls)
{
  struct Plugin *plugin = cls;
  size_t udpmlen = msgbuf_size + sizeof(struct UDPMessage);
  struct UDP_FragmentationContext *frag_ctx;
  struct UDP_MessageWrapper *udpw;
  struct UDPMessage *udp;
  char mbuf[udpmlen] GNUNET_ALIGN;
  struct GNUNET_TIME_Relative latency;

  if ( (sizeof(struct IPv6UdpAddress) == s->address->address_length) &&
       (NULL == plugin->sockv6) )
    return GNUNET_SYSERR;
  if ( (sizeof(struct IPv4UdpAddress) == s->address->address_length) &&
       (NULL == plugin->sockv4) )
    return GNUNET_SYSERR;
  if (udpmlen >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (GNUNET_YES !=
      GNUNET_CONTAINER_multipeermap_contains_value (plugin->sessions,
                                                    &s->target,
                                                    s))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "UDP transmits %u-byte message to `%s' using address `%s'\n",
       udpmlen,
       GNUNET_i2s (&s->target),
       udp_address_to_string (plugin,
                              s->address->address,
                              s->address->address_length));

  udp = (struct UDPMessage *) mbuf;
  udp->header.size = htons (udpmlen);
  udp->header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_UDP_MESSAGE);
  udp->reserved = htonl (0);
  udp->sender = *plugin->env->my_identity;

  /* We do not update the session time out here!  Otherwise this
   * session will not timeout since we send keep alive before session
   * can timeout.
   *
   * For UDP we update session timeout only on receive, this will
   * cover keep alives, since remote peer will reply with keep alive
   * responses!
   */
  if (udpmlen <= UDP_MTU)
  {
    /* unfragmented message */
    udpw = GNUNET_malloc (sizeof (struct UDP_MessageWrapper) + udpmlen);
    udpw->session = s;
    udpw->msg_buf = (char *) &udpw[1];
    udpw->msg_size = udpmlen; /* message size with UDP overhead */
    udpw->payload_size = msgbuf_size; /* message size without UDP overhead */
    udpw->start_time = GNUNET_TIME_absolute_get ();
    udpw->timeout = GNUNET_TIME_relative_to_absolute (to);
    udpw->transmission_time = s->last_transmit_time;
    s->last_transmit_time
      = GNUNET_TIME_absolute_add (s->last_transmit_time,
                                  s->flow_delay_from_other_peer);
    udpw->cont = cont;
    udpw->cont_cls = cont_cls;
    udpw->frag_ctx = NULL;
    udpw->qc = &qc_message_sent;
    udpw->qc_cls = plugin;
    memcpy (udpw->msg_buf,
            udp,
            sizeof (struct UDPMessage));
    memcpy (&udpw->msg_buf[sizeof(struct UDPMessage)],
            msgbuf,
            msgbuf_size);
    enqueue (plugin,
             udpw);
    GNUNET_STATISTICS_update (plugin->env->stats,
                              "# UDP, unfragmented messages queued total",
                              1,
                              GNUNET_NO);
    GNUNET_STATISTICS_update (plugin->env->stats,
                              "# UDP, unfragmented bytes payload queued total",
                              msgbuf_size,
                              GNUNET_NO);
  }
  else
  {
    /* fragmented message */
    if (NULL != s->frag_ctx)
      return GNUNET_SYSERR;
    memcpy (&udp[1],
            msgbuf,
            msgbuf_size);
    frag_ctx = GNUNET_new (struct UDP_FragmentationContext);
    frag_ctx->plugin = plugin;
    frag_ctx->session = s;
    frag_ctx->cont = cont;
    frag_ctx->cont_cls = cont_cls;
    frag_ctx->start_time = GNUNET_TIME_absolute_get ();
    frag_ctx->next_frag_time = s->last_transmit_time;
    frag_ctx->flow_delay_from_other_peer
      = GNUNET_TIME_relative_divide (s->flow_delay_from_other_peer,
                                     1 + (msgbuf_size /
                                          UDP_MTU));
    frag_ctx->timeout = GNUNET_TIME_relative_to_absolute (to);
    frag_ctx->payload_size = msgbuf_size; /* unfragmented message size without UDP overhead */
    frag_ctx->on_wire_size = 0; /* bytes with UDP and fragmentation overhead */
    frag_ctx->frag = GNUNET_FRAGMENT_context_create (plugin->env->stats,
                                                     UDP_MTU,
                                                     &plugin->tracker,
                                                     s->last_expected_msg_delay,
                                                     s->last_expected_ack_delay,
                                                     &udp->header,
                                                     &enqueue_fragment,
                                                     frag_ctx);
    s->frag_ctx = frag_ctx;
    s->last_transmit_time = frag_ctx->next_frag_time;
    latency = GNUNET_TIME_absolute_get_remaining (s->last_transmit_time);
    if (latency.rel_value_us > GNUNET_CONSTANTS_LATENCY_WARN.rel_value_us)
      LOG (GNUNET_ERROR_TYPE_WARNING,
           "Enqueued fragments will take %s for transmission to %s (queue size: %u)\n",
           GNUNET_STRINGS_relative_time_to_string (latency,
                                                   GNUNET_YES),
           GNUNET_i2s (&s->target),
           (unsigned int) s->msgs_in_queue);
    else
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Enqueued fragments will take %s for transmission to %s (queue size: %u)\n",
           GNUNET_STRINGS_relative_time_to_string (latency,
                                                   GNUNET_YES),
           GNUNET_i2s (&s->target),
           (unsigned int) s->msgs_in_queue);

    GNUNET_STATISTICS_update (plugin->env->stats,
                              "# UDP, fragmented messages active",
                              1,
                              GNUNET_NO);
    GNUNET_STATISTICS_update (plugin->env->stats,
                              "# UDP, fragmented messages, total",
                              1,
                              GNUNET_NO);
    GNUNET_STATISTICS_update (plugin->env->stats,
                              "# UDP, fragmented bytes (payload)",
                              frag_ctx->payload_size,
                              GNUNET_NO);
  }
  notify_session_monitor (s->plugin,
                          s,
                          GNUNET_TRANSPORT_SS_UPDATE);
  if (s->address->address_length == sizeof (struct IPv4UdpAddress))
    schedule_select_v4 (plugin);
  else
    schedule_select_v6 (plugin);
  return udpmlen;
}


/* ********************** Receiving ********************** */


/**
 * Closure for #find_receive_context().
 */
struct FindReceiveContext
{
  /**
   * Where to store the result.
   */
  struct DefragContext *rc;

  /**
   * Session associated with this context.
   */
  struct GNUNET_ATS_Session *session;

  /**
   * Address to find.
   */
  const union UdpAddress *udp_addr;

  /**
   * Number of bytes in @e udp_addr.
   */
  size_t udp_addr_len;

};


/**
 * Scan the heap for a receive context with the given address.
 *
 * @param cls the `struct FindReceiveContext`
 * @param node internal node of the heap
 * @param element value stored at the node (a `struct ReceiveContext`)
 * @param cost cost associated with the node
 * @return #GNUNET_YES if we should continue to iterate,
 *         #GNUNET_NO if not.
 */
static int
find_receive_context (void *cls,
                      struct GNUNET_CONTAINER_HeapNode *node,
                      void *element,
                      GNUNET_CONTAINER_HeapCostType cost)
{
  struct FindReceiveContext *frc = cls;
  struct DefragContext *e = element;

  if ( (frc->udp_addr_len == e->udp_addr_len) &&
       (0 == memcmp (frc->udp_addr,
                     e->udp_addr,
                     frc->udp_addr_len)) )
  {
    frc->rc = e;
    return GNUNET_NO;
  }
  return GNUNET_YES;
}


/**
 * Functions with this signature are called whenever we need to close
 * a session due to a disconnect or failure to establish a connection.
 *
 * @param cls closure with the `struct Plugin`
 * @param s session to close down
 * @return #GNUNET_OK on success
 */
static int
udp_disconnect_session (void *cls,
                        struct GNUNET_ATS_Session *s)
{
  struct Plugin *plugin = cls;
  struct UDP_MessageWrapper *udpw;
  struct UDP_MessageWrapper *next;
  struct FindReceiveContext frc;

  GNUNET_assert (GNUNET_YES != s->in_destroy);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Session %p to peer `%s' at address %s ended\n",
       s,
       GNUNET_i2s (&s->target),
       udp_address_to_string (plugin,
                              s->address->address,
                              s->address->address_length));
  if (NULL != s->timeout_task)
  {
    GNUNET_SCHEDULER_cancel (s->timeout_task);
    s->timeout_task = NULL;
  }
  if (NULL != s->frag_ctx)
  {
    /* Remove fragmented message due to disconnect */
    fragmented_message_done (s->frag_ctx,
                             GNUNET_SYSERR);
  }
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multipeermap_remove (plugin->sessions,
                                                       &s->target,
                                                       s));
  frc.rc = NULL;
  frc.udp_addr = s->address->address;
  frc.udp_addr_len = s->address->address_length;
  /* Lookup existing receive context for this address */
  if (NULL != plugin->defrag_ctxs)
  {
    GNUNET_CONTAINER_heap_iterate (plugin->defrag_ctxs,
                                   &find_receive_context,
                                   &frc);
    if (NULL != frc.rc)
    {
      struct DefragContext *d_ctx = frc.rc;

      GNUNET_CONTAINER_heap_remove_node (d_ctx->hnode);
      GNUNET_DEFRAGMENT_context_destroy (d_ctx->defrag);
      GNUNET_free (d_ctx);
    }
  }
  s->in_destroy = GNUNET_YES;
  next = plugin->ipv4_queue_head;
  while (NULL != (udpw = next))
  {
    next = udpw->next;
    if (udpw->session == s)
    {
      dequeue (plugin,
               udpw);
      udpw->qc (udpw->qc_cls,
                udpw,
                GNUNET_SYSERR);
      GNUNET_free (udpw);
    }
  }
  next = plugin->ipv6_queue_head;
  while (NULL != (udpw = next))
  {
    next = udpw->next;
    if (udpw->session == s)
    {
      dequeue (plugin,
               udpw);
      udpw->qc (udpw->qc_cls,
                udpw,
                GNUNET_SYSERR);
      GNUNET_free (udpw);
    }
  }
  if ( (NULL != s->frag_ctx) &&
       (NULL != s->frag_ctx->cont) )
  {
    /* The 'frag_ctx' itself will be freed in #free_session() a bit
       later, as it might be in use right now */
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Calling continuation for fragemented message to `%s' with result SYSERR\n",
         GNUNET_i2s (&s->target));
    s->frag_ctx->cont (s->frag_ctx->cont_cls,
                       &s->target,
                       GNUNET_SYSERR,
                       s->frag_ctx->payload_size,
                       s->frag_ctx->on_wire_size);
  }
  notify_session_monitor (s->plugin,
                          s,
                          GNUNET_TRANSPORT_SS_DONE);
  plugin->env->session_end (plugin->env->cls,
                            s->address,
                            s);
  GNUNET_STATISTICS_set (plugin->env->stats,
                         "# UDP sessions active",
                         GNUNET_CONTAINER_multipeermap_size (plugin->sessions),
                         GNUNET_NO);
  if (0 == s->rc)
    free_session (s);
  return GNUNET_OK;
}


/**
 * Handle a #GNUNET_MESSAGE_TYPE_TRANSPORT_UDP_ACK message.
 *
 * @param plugin the UDP plugin
 * @param msg the (presumed) UDP ACK message
 * @param udp_addr sender address
 * @param udp_addr_len number of bytes in @a udp_addr
 */
static void
read_process_ack (struct Plugin *plugin,
                  const struct GNUNET_MessageHeader *msg,
                  const union UdpAddress *udp_addr,
                  socklen_t udp_addr_len)
{
  const struct GNUNET_MessageHeader *ack;
  const struct UDP_ACK_Message *udp_ack;
  struct GNUNET_HELLO_Address *address;
  struct GNUNET_ATS_Session *s;
  struct GNUNET_TIME_Relative flow_delay;

  /* check message format */
  if (ntohs (msg->size)
      < sizeof(struct UDP_ACK_Message) + sizeof(struct GNUNET_MessageHeader))
  {
    GNUNET_break_op (0);
    return;
  }
  udp_ack = (const struct UDP_ACK_Message *) msg;
  ack = (const struct GNUNET_MessageHeader *) &udp_ack[1];
  if (ntohs (ack->size) != ntohs (msg->size) - sizeof(struct UDP_ACK_Message))
  {
    GNUNET_break_op(0);
    return;
  }

  /* Locate session */
  address = GNUNET_HELLO_address_allocate (&udp_ack->sender,
                                           PLUGIN_NAME,
                                           udp_addr,
                                           udp_addr_len,
                                           GNUNET_HELLO_ADDRESS_INFO_NONE);
  s = udp_plugin_lookup_session (plugin,
                                 address);
  if (NULL == s)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "UDP session of address %s for ACK not found\n",
         udp_address_to_string (plugin,
                                address->address,
                                address->address_length));
    GNUNET_HELLO_address_free (address);
    return;
  }
  if (NULL == s->frag_ctx)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG | GNUNET_ERROR_TYPE_BULK,
         "Fragmentation context of address %s for ACK (%s) not found\n",
         udp_address_to_string (plugin,
                                address->address,
                                address->address_length),
         GNUNET_FRAGMENT_print_ack (ack));
    GNUNET_HELLO_address_free (address);
    return;
  }
  GNUNET_HELLO_address_free (address);

  /* evaluate flow delay: how long should we wait between messages? */
  if (UINT32_MAX == ntohl (udp_ack->delay))
  {
    /* Other peer asked for us to terminate the session */
    LOG (GNUNET_ERROR_TYPE_INFO,
         "Asked to disconnect UDP session of %s\n",
         GNUNET_i2s (&udp_ack->sender));
    udp_disconnect_session (plugin,
                            s);
    return;
  }
  flow_delay.rel_value_us = (uint64_t) ntohl (udp_ack->delay);
  if (flow_delay.rel_value_us > GNUNET_CONSTANTS_LATENCY_WARN.rel_value_us)
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "We received a sending delay of %s for %s\n",
         GNUNET_STRINGS_relative_time_to_string (flow_delay,
                                                 GNUNET_YES),
         GNUNET_i2s (&udp_ack->sender));
  else
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "We received a sending delay of %s for %s\n",
         GNUNET_STRINGS_relative_time_to_string (flow_delay,
                                                 GNUNET_YES),
         GNUNET_i2s (&udp_ack->sender));
  /* Flow delay is for the reassembled packet, however, our delay
     is per packet, so we need to adjust: */
  s->flow_delay_from_other_peer = flow_delay;

  /* Handle ACK */
  if (GNUNET_OK !=
      GNUNET_FRAGMENT_process_ack (s->frag_ctx->frag,
                                   ack))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "UDP processes %u-byte acknowledgement from `%s' at `%s'\n",
         (unsigned int) ntohs (msg->size),
         GNUNET_i2s (&udp_ack->sender),
         udp_address_to_string (plugin,
                                udp_addr,
                                udp_addr_len));
    /* Expect more ACKs to arrive */
    return;
  }

  /* Remove fragmented message after successful sending */
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Message from %s at %s full ACK'ed\n",
       GNUNET_i2s (&udp_ack->sender),
       udp_address_to_string (plugin,
                              udp_addr,
                              udp_addr_len));
  fragmented_message_done (s->frag_ctx,
                           GNUNET_OK);
}


/**
 * Message tokenizer has broken up an incomming message. Pass it on
 * to the service.
 *
 * @param cls the `struct Plugin *`
 * @param client the `struct GNUNET_ATS_Session *`
 * @param hdr the actual message
 * @return #GNUNET_OK (always)
 */
static int
process_inbound_tokenized_messages (void *cls,
                                    void *client,
                                    const struct GNUNET_MessageHeader *hdr)
{
  struct Plugin *plugin = cls;
  struct GNUNET_ATS_Session *session = client;

  if (GNUNET_YES == session->in_destroy)
    return GNUNET_OK;
  reschedule_session_timeout (session);
  session->flow_delay_for_other_peer
    = plugin->env->receive (plugin->env->cls,
                            session->address,
                            session,
                            hdr);
  return GNUNET_OK;
}


/**
 * Destroy a session, plugin is being unloaded.
 *
 * @param cls the `struct Plugin`
 * @param key hash of public key of target peer
 * @param value a `struct PeerSession *` to clean up
 * @return #GNUNET_OK (continue to iterate)
 */
static int
disconnect_and_free_it (void *cls,
                        const struct GNUNET_PeerIdentity *key,
                        void *value)
{
  struct Plugin *plugin = cls;

  udp_disconnect_session (plugin,
                          value);
  return GNUNET_OK;
}


/**
 * Disconnect from a remote node.  Clean up session if we have one for
 * this peer.
 *
 * @param cls closure for this call (should be handle to Plugin)
 * @param target the peeridentity of the peer to disconnect
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if the operation failed
 */
static void
udp_disconnect (void *cls,
                const struct GNUNET_PeerIdentity *target)
{
  struct Plugin *plugin = cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Disconnecting from peer `%s'\n",
       GNUNET_i2s (target));
  GNUNET_CONTAINER_multipeermap_get_multiple (plugin->sessions,
                                              target,
                                              &disconnect_and_free_it,
                                              plugin);
}


/**
 * Session was idle, so disconnect it.
 *
 * @param cls the `struct GNUNET_ATS_Session` to time out
 * @param tc scheduler context
 */
static void
session_timeout (void *cls,
                 const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_ATS_Session *s = cls;
  struct Plugin *plugin = s->plugin;
  struct GNUNET_TIME_Relative left;

  s->timeout_task = NULL;
  left = GNUNET_TIME_absolute_get_remaining (s->timeout);
  if (left.rel_value_us > 0)
  {
    /* not actually our turn yet, but let's at least update
       the monitor, it may think we're about to die ... */
    notify_session_monitor (s->plugin,
                            s,
                            GNUNET_TRANSPORT_SS_UPDATE);
    s->timeout_task = GNUNET_SCHEDULER_add_delayed (left,
                                                    &session_timeout,
                                                    s);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Session %p was idle for %s, disconnecting\n",
       s,
       GNUNET_STRINGS_relative_time_to_string (UDP_SESSION_TIME_OUT,
                                               GNUNET_YES));
  /* call session destroy function */
  udp_disconnect_session (plugin,
                          s);
}


/**
 * Allocate a new session for the given endpoint address.
 * Note that this function does not inform the service
 * of the new session, this is the responsibility of the
 * caller (if needed).
 *
 * @param cls the `struct Plugin`
 * @param address address of the other peer to use
 * @param network_type network type the address belongs to
 * @return NULL on error, otherwise session handle
 */
static struct GNUNET_ATS_Session *
udp_plugin_create_session (void *cls,
                           const struct GNUNET_HELLO_Address *address,
                           enum GNUNET_ATS_Network_Type network_type)
{
  struct Plugin *plugin = cls;
  struct GNUNET_ATS_Session *s;

  s = GNUNET_new (struct GNUNET_ATS_Session);
  s->plugin = plugin;
  s->address = GNUNET_HELLO_address_copy (address);
  s->target = address->peer;
  s->last_transmit_time = GNUNET_TIME_absolute_get ();
  s->last_expected_ack_delay = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS,
                                                              250);
  s->last_expected_msg_delay = GNUNET_TIME_UNIT_MILLISECONDS;
  s->flow_delay_from_other_peer = GNUNET_TIME_UNIT_ZERO;
  s->flow_delay_for_other_peer = GNUNET_TIME_UNIT_ZERO;
  s->timeout = GNUNET_TIME_relative_to_absolute (UDP_SESSION_TIME_OUT);
  s->timeout_task = GNUNET_SCHEDULER_add_delayed (UDP_SESSION_TIME_OUT,
                                                  &session_timeout,
                                                  s);
  s->scope = network_type;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Creating new session %p for peer `%s' address `%s'\n",
       s,
       GNUNET_i2s (&address->peer),
       udp_address_to_string (plugin,
                              address->address,
                              address->address_length));
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multipeermap_put (plugin->sessions,
                                                    &s->target,
                                                    s,
                                                    GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE));
  GNUNET_STATISTICS_set (plugin->env->stats,
                         "# UDP sessions active",
                         GNUNET_CONTAINER_multipeermap_size (plugin->sessions),
                         GNUNET_NO);
  notify_session_monitor (plugin,
                          s,
                          GNUNET_TRANSPORT_SS_INIT);
  return s;
}


/**
 * Creates a new outbound session the transport service will use to
 * send data to the peer.
 *
 * @param cls the `struct Plugin *`
 * @param address the address
 * @return the session or NULL of max connections exceeded
 */
static struct GNUNET_ATS_Session *
udp_plugin_get_session (void *cls,
                        const struct GNUNET_HELLO_Address *address)
{
  struct Plugin *plugin = cls;
  struct GNUNET_ATS_Session *s;
  enum GNUNET_ATS_Network_Type network_type = GNUNET_ATS_NET_UNSPECIFIED;
  const struct IPv4UdpAddress *udp_v4;
  const struct IPv6UdpAddress *udp_v6;

  if (NULL == address)
  {
    GNUNET_break (0);
    return NULL;
  }
  if ( (address->address_length != sizeof(struct IPv4UdpAddress)) &&
       (address->address_length != sizeof(struct IPv6UdpAddress)) )
  {
    GNUNET_break_op (0);
    return NULL;
  }
  if (NULL != (s = udp_plugin_lookup_session (cls,
                                              address)))
    return s;

  /* need to create new session */
  if (sizeof (struct IPv4UdpAddress) == address->address_length)
  {
    struct sockaddr_in v4;

    udp_v4 = (const struct IPv4UdpAddress *) address->address;
    memset (&v4, '\0', sizeof (v4));
    v4.sin_family = AF_INET;
#if HAVE_SOCKADDR_IN_SIN_LEN
    v4.sin_len = sizeof (struct sockaddr_in);
#endif
    v4.sin_port = udp_v4->u4_port;
    v4.sin_addr.s_addr = udp_v4->ipv4_addr;
    network_type = plugin->env->get_address_type (plugin->env->cls,
                                                  (const struct sockaddr *) &v4,
                                                  sizeof (v4));
  }
  if (sizeof (struct IPv6UdpAddress) == address->address_length)
  {
    struct sockaddr_in6 v6;

    udp_v6 = (const struct IPv6UdpAddress *) address->address;
    memset (&v6, '\0', sizeof (v6));
    v6.sin6_family = AF_INET6;
#if HAVE_SOCKADDR_IN_SIN_LEN
    v6.sin6_len = sizeof (struct sockaddr_in6);
#endif
    v6.sin6_port = udp_v6->u6_port;
    v6.sin6_addr = udp_v6->ipv6_addr;
    network_type = plugin->env->get_address_type (plugin->env->cls,
                                                  (const struct sockaddr *) &v6,
                                                  sizeof (v6));
  }
  GNUNET_break (GNUNET_ATS_NET_UNSPECIFIED != network_type);
  return udp_plugin_create_session (cls,
				    address,
				    network_type);
}


/**
 * We've received a UDP Message.  Process it (pass contents to main service).
 *
 * @param plugin plugin context
 * @param msg the message
 * @param udp_addr sender address
 * @param udp_addr_len number of bytes in @a udp_addr
 * @param network_type network type the address belongs to
 */
static void
process_udp_message (struct Plugin *plugin,
                     const struct UDPMessage *msg,
                     const union UdpAddress *udp_addr,
                     size_t udp_addr_len,
                     enum GNUNET_ATS_Network_Type network_type)
{
  struct GNUNET_ATS_Session *s;
  struct GNUNET_HELLO_Address *address;

  GNUNET_break (GNUNET_ATS_NET_UNSPECIFIED != network_type);
  if (0 != ntohl (msg->reserved))
  {
    GNUNET_break_op(0);
    return;
  }
  if (ntohs (msg->header.size)
      < sizeof(struct GNUNET_MessageHeader) + sizeof(struct UDPMessage))
  {
    GNUNET_break_op(0);
    return;
  }

  address = GNUNET_HELLO_address_allocate (&msg->sender,
                                           PLUGIN_NAME,
                                           udp_addr,
                                           udp_addr_len,
                                           GNUNET_HELLO_ADDRESS_INFO_NONE);
  if (NULL ==
      (s = udp_plugin_lookup_session (plugin,
                                      address)))
  {
    s = udp_plugin_create_session (plugin,
                                   address,
                                   network_type);
    plugin->env->session_start (plugin->env->cls,
                                address,
                                s,
                                s->scope);
    notify_session_monitor (plugin,
                            s,
                            GNUNET_TRANSPORT_SS_UP);
  }
  GNUNET_free (address);

  s->rc++;
  GNUNET_SERVER_mst_receive (plugin->mst,
                             s,
                             (const char *) &msg[1],
                             ntohs (msg->header.size) - sizeof(struct UDPMessage),
                             GNUNET_YES,
                             GNUNET_NO);
  s->rc--;
  if ( (0 == s->rc) &&
       (GNUNET_YES == s->in_destroy) )
    free_session (s);
}


/**
 * Process a defragmented message.
 *
 * @param cls the `struct DefragContext *`
 * @param msg the message
 */
static void
fragment_msg_proc (void *cls,
                   const struct GNUNET_MessageHeader *msg)
{
  struct DefragContext *dc = cls;
  const struct UDPMessage *um;

  if (ntohs (msg->type) != GNUNET_MESSAGE_TYPE_TRANSPORT_UDP_MESSAGE)
  {
    GNUNET_break_op (0);
    return;
  }
  if (ntohs (msg->size) < sizeof(struct UDPMessage))
  {
    GNUNET_break_op (0);
    return;
  }
  um = (const struct UDPMessage *) msg;
  dc->sender = um->sender;
  dc->have_sender = GNUNET_YES;
  process_udp_message (dc->plugin,
                       um,
                       dc->udp_addr,
                       dc->udp_addr_len,
                       dc->network_type);
}


/**
 * We finished sending an acknowledgement.  Update
 * statistics.
 *
 * @param cls the `struct Plugin`
 * @param udpw message queue entry of the ACK
 * @param result #GNUNET_OK if the transmission worked,
 *               #GNUNET_SYSERR if we failed to send the ACK
 */
static void
ack_message_sent (void *cls,
                  struct UDP_MessageWrapper *udpw,
                  int result)
{
  struct Plugin *plugin = cls;

  if (GNUNET_OK == result)
  {
    GNUNET_STATISTICS_update (plugin->env->stats,
                              "# UDP, ACK messages sent",
                              1,
                              GNUNET_NO);
  }
  else
  {
    GNUNET_STATISTICS_update (plugin->env->stats,
                              "# UDP, ACK transmissions failed",
                              1,
                              GNUNET_NO);
  }
}


/**
 * Transmit an acknowledgement.
 *
 * @param cls the `struct DefragContext *`
 * @param id message ID (unused)
 * @param msg ack to transmit
 */
static void
ack_proc (void *cls,
          uint32_t id,
          const struct GNUNET_MessageHeader *msg)
{
  struct DefragContext *rc = cls;
  struct Plugin *plugin = rc->plugin;
  size_t msize = sizeof(struct UDP_ACK_Message) + ntohs (msg->size);
  struct UDP_ACK_Message *udp_ack;
  uint32_t delay;
  struct UDP_MessageWrapper *udpw;
  struct GNUNET_ATS_Session *s;
  struct GNUNET_HELLO_Address *address;

  if (GNUNET_NO == rc->have_sender)
  {
    /* tried to defragment but never succeeded, hence will not ACK */
    /* This can happen if we just lost msgs */
    GNUNET_STATISTICS_update (plugin->env->stats,
                              "# UDP, fragments discarded without ACK",
                              1,
                              GNUNET_NO);
    return;
  }
  address = GNUNET_HELLO_address_allocate (&rc->sender,
                                           PLUGIN_NAME,
                                           rc->udp_addr,
                                           rc->udp_addr_len,
                                           GNUNET_HELLO_ADDRESS_INFO_NONE);
  s = udp_plugin_lookup_session (plugin,
                                 address);
  GNUNET_HELLO_address_free (address);
  if (NULL == s)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Trying to transmit ACK to peer `%s' but no session found!\n",
         udp_address_to_string (plugin,
                                rc->udp_addr,
                                rc->udp_addr_len));
    GNUNET_CONTAINER_heap_remove_node (rc->hnode);
    GNUNET_DEFRAGMENT_context_destroy (rc->defrag);
    GNUNET_free (rc);
    GNUNET_STATISTICS_update (plugin->env->stats,
                              "# UDP, ACK transmissions failed",
                              1,
                              GNUNET_NO);
    return;
  }
  if (GNUNET_TIME_UNIT_FOREVER_REL.rel_value_us ==
      s->flow_delay_for_other_peer.rel_value_us)
    delay = UINT32_MAX;
  else if (s->flow_delay_for_other_peer.rel_value_us < UINT32_MAX)
    delay = s->flow_delay_for_other_peer.rel_value_us;
  else
    delay = UINT32_MAX - 1; /* largest value we can communicate */
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Sending ACK to `%s' including delay of %s\n",
       udp_address_to_string (plugin,
                              rc->udp_addr,
                              rc->udp_addr_len),
       GNUNET_STRINGS_relative_time_to_string (s->flow_delay_for_other_peer,
                                               GNUNET_YES));
  udpw = GNUNET_malloc (sizeof (struct UDP_MessageWrapper) + msize);
  udpw->msg_size = msize;
  udpw->payload_size = 0;
  udpw->session = s;
  udpw->start_time = GNUNET_TIME_absolute_get ();
  udpw->timeout = GNUNET_TIME_UNIT_FOREVER_ABS;
  udpw->msg_buf = (char *) &udpw[1];
  udpw->qc = &ack_message_sent;
  udpw->qc_cls = plugin;
  udp_ack = (struct UDP_ACK_Message *) udpw->msg_buf;
  udp_ack->header.size = htons ((uint16_t) msize);
  udp_ack->header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_UDP_ACK);
  udp_ack->delay = htonl (delay);
  udp_ack->sender = *plugin->env->my_identity;
  memcpy (&udp_ack[1],
          msg,
          ntohs (msg->size));
  enqueue (plugin,
           udpw);
  notify_session_monitor (plugin,
                          s,
                          GNUNET_TRANSPORT_SS_UPDATE);
  if (s->address->address_length == sizeof (struct IPv4UdpAddress))
    schedule_select_v4 (plugin);
  else
    schedule_select_v6 (plugin);
}


/**
 * We received a fragment, process it.
 *
 * @param plugin our plugin
 * @param msg a message of type #GNUNET_MESSAGE_TYPE_FRAGMENT
 * @param udp_addr sender address
 * @param udp_addr_len number of bytes in @a udp_addr
 * @param network_type network type the address belongs to
 */
static void
read_process_fragment (struct Plugin *plugin,
                       const struct GNUNET_MessageHeader *msg,
                       const union UdpAddress *udp_addr,
                       size_t udp_addr_len,
                       enum GNUNET_ATS_Network_Type network_type)
{
  struct DefragContext *d_ctx;
  struct GNUNET_TIME_Absolute now;
  struct FindReceiveContext frc;

  frc.rc = NULL;
  frc.udp_addr = udp_addr;
  frc.udp_addr_len = udp_addr_len;

  /* Lookup existing receive context for this address */
  GNUNET_CONTAINER_heap_iterate (plugin->defrag_ctxs,
                                 &find_receive_context,
                                 &frc);
  now = GNUNET_TIME_absolute_get ();
  d_ctx = frc.rc;

  if (NULL == d_ctx)
  {
    /* Create a new defragmentation context */
    d_ctx = GNUNET_malloc (sizeof (struct DefragContext) + udp_addr_len);
    memcpy (&d_ctx[1],
            udp_addr,
            udp_addr_len);
    d_ctx->udp_addr = (const union UdpAddress *) &d_ctx[1];
    d_ctx->udp_addr_len = udp_addr_len;
    d_ctx->network_type = network_type;
    d_ctx->plugin = plugin;
    d_ctx->defrag = GNUNET_DEFRAGMENT_context_create (plugin->env->stats,
                                                      UDP_MTU,
                                                      UDP_MAX_MESSAGES_IN_DEFRAG,
                                                      d_ctx,
                                                      &fragment_msg_proc,
                                                      &ack_proc);
    d_ctx->hnode = GNUNET_CONTAINER_heap_insert (plugin->defrag_ctxs,
                                                 d_ctx,
                                                 (GNUNET_CONTAINER_HeapCostType) now.abs_value_us);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Created new defragmentation context for %u-byte fragment from `%s'\n",
         (unsigned int) ntohs (msg->size),
         udp_address_to_string (plugin,
                                udp_addr,
                                udp_addr_len));
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Found existing defragmentation context for %u-byte fragment from `%s'\n",
         (unsigned int) ntohs (msg->size),
         udp_address_to_string (plugin,
                                udp_addr,
                                udp_addr_len));
  }

  if (GNUNET_OK ==
      GNUNET_DEFRAGMENT_process_fragment (d_ctx->defrag,
                                          msg))
  {
    /* keep this 'rc' from expiring */
    GNUNET_CONTAINER_heap_update_cost (plugin->defrag_ctxs,
                                       d_ctx->hnode,
                                       (GNUNET_CONTAINER_HeapCostType) now.abs_value_us);
  }
  if (GNUNET_CONTAINER_heap_get_size (plugin->defrag_ctxs) >
      UDP_MAX_SENDER_ADDRESSES_WITH_DEFRAG)
  {
    /* remove 'rc' that was inactive the longest */
    d_ctx = GNUNET_CONTAINER_heap_remove_root (plugin->defrag_ctxs);
    GNUNET_assert (NULL != d_ctx);
    GNUNET_DEFRAGMENT_context_destroy (d_ctx->defrag);
    GNUNET_free (d_ctx);
    GNUNET_STATISTICS_update (plugin->env->stats,
                              "# UDP, Defragmentations aborted",
                              1,
                              GNUNET_NO);
  }
}


/**
 * Read and process a message from the given socket.
 *
 * @param plugin the overall plugin
 * @param rsock socket to read from
 */
static void
udp_select_read (struct Plugin *plugin,
                 struct GNUNET_NETWORK_Handle *rsock)
{
  socklen_t fromlen;
  struct sockaddr_storage addr;
  char buf[65536] GNUNET_ALIGN;
  ssize_t size;
  const struct GNUNET_MessageHeader *msg;
  struct IPv4UdpAddress v4;
  struct IPv6UdpAddress v6;
  const struct sockaddr *sa;
  const struct sockaddr_in *sa4;
  const struct sockaddr_in6 *sa6;
  const union UdpAddress *int_addr;
  size_t int_addr_len;
  enum GNUNET_ATS_Network_Type network_type;

  fromlen = sizeof (addr);
  memset (&addr,
          0,
          sizeof(addr));
  size = GNUNET_NETWORK_socket_recvfrom (rsock,
                                         buf,
                                         sizeof(buf),
                                         (struct sockaddr *) &addr,
                                         &fromlen);
  sa = (const struct sockaddr *) &addr;
#if MINGW
  /* On SOCK_DGRAM UDP sockets recvfrom might fail with a
   * WSAECONNRESET error to indicate that previous sendto() (yes, sendto!)
   * on this socket has failed.
   * Quote from MSDN:
   *   WSAECONNRESET - The virtual circuit was reset by the remote side
   *   executing a hard or abortive close. The application should close
   *   the socket; it is no longer usable. On a UDP-datagram socket this
   *   error indicates a previous send operation resulted in an ICMP Port
   *   Unreachable message.
   */
  if ( (-1 == size) &&
       (ECONNRESET == errno) )
    return;
#endif
  if (-1 == size)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "UDP failed to receive data: %s\n",
         STRERROR (errno));
    /* Connection failure or something. Not a protocol violation. */
    return;
  }

  /* Check if this is a STUN packet */
  if (GNUNET_NAT_is_valid_stun_packet (plugin->nat,
                                       (uint8_t *)buf,
                                       size))
    return; /* was STUN, do not process further */

  if (size < sizeof(struct GNUNET_MessageHeader))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "UDP got %u bytes from %s, which is not enough for a GNUnet message header\n",
         (unsigned int ) size,
         GNUNET_a2s (sa,
                     fromlen));
    /* _MAY_ be a connection failure (got partial message) */
    /* But it _MAY_ also be that the other side uses non-GNUnet protocol. */
    GNUNET_break_op (0);
    return;
  }

  msg = (const struct GNUNET_MessageHeader *) buf;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "UDP received %u-byte message from `%s' type %u\n",
       (unsigned int) size,
       GNUNET_a2s (sa,
                   fromlen),
       ntohs (msg->type));
  if (size != ntohs (msg->size))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "UDP malformed message header from %s\n",
         (unsigned int) size,
         GNUNET_a2s (sa,
                     fromlen));
    GNUNET_break_op (0);
    return;
  }
  GNUNET_STATISTICS_update (plugin->env->stats,
                            "# UDP, total bytes received",
                            size,
                            GNUNET_NO);
  network_type = plugin->env->get_address_type (plugin->env->cls,
                                                sa,
                                                fromlen);
  switch (sa->sa_family)
  {
  case AF_INET:
    sa4 = (const struct sockaddr_in *) &addr;
    v4.options = 0;
    v4.ipv4_addr = sa4->sin_addr.s_addr;
    v4.u4_port = sa4->sin_port;
    int_addr = (union UdpAddress *) &v4;
    int_addr_len = sizeof (v4);
    break;
  case AF_INET6:
    sa6 = (const struct sockaddr_in6 *) &addr;
    v6.options = 0;
    v6.ipv6_addr = sa6->sin6_addr;
    v6.u6_port = sa6->sin6_port;
    int_addr = (union UdpAddress *) &v6;
    int_addr_len = sizeof (v6);
    break;
  default:
    GNUNET_break (0);
    return;
  }

  switch (ntohs (msg->type))
  {
  case GNUNET_MESSAGE_TYPE_TRANSPORT_BROADCAST_BEACON:
    if (GNUNET_YES == plugin->enable_broadcasting_receiving)
      udp_broadcast_receive (plugin,
                             buf,
                             size,
                             int_addr,
                             int_addr_len,
                             network_type);
    return;
  case GNUNET_MESSAGE_TYPE_TRANSPORT_UDP_MESSAGE:
    if (ntohs (msg->size) < sizeof(struct UDPMessage))
    {
      GNUNET_break_op(0);
      return;
    }
    process_udp_message (plugin,
                         (const struct UDPMessage *) msg,
                         int_addr,
                         int_addr_len,
                         network_type);
    return;
  case GNUNET_MESSAGE_TYPE_TRANSPORT_UDP_ACK:
    read_process_ack (plugin,
                      msg,
                      int_addr,
                      int_addr_len);
    return;
  case GNUNET_MESSAGE_TYPE_FRAGMENT:
    read_process_fragment (plugin,
                           msg,
                           int_addr,
                           int_addr_len,
                           network_type);
    return;
  default:
    GNUNET_break_op(0);
    return;
  }
}


/**
 * Removes messages from the transmission queue that have
 * timed out, and then selects a message that should be
 * transmitted next.
 *
 * @param plugin the UDP plugin
 * @param sock which socket should we process the queue for (v4 or v6)
 * @return message selected for transmission, or NULL for none
 */
static struct UDP_MessageWrapper *
remove_timeout_messages_and_select (struct Plugin *plugin,
                                    struct GNUNET_NETWORK_Handle *sock)
{
  struct UDP_MessageWrapper *udpw;
  struct GNUNET_TIME_Relative remaining;
  struct GNUNET_ATS_Session *session;
  int removed;

  removed = GNUNET_NO;
  udpw = (sock == plugin->sockv4)
    ? plugin->ipv4_queue_head
    : plugin->ipv6_queue_head;
  while (NULL != udpw)
  {
    session = udpw->session;
    /* Find messages with timeout */
    remaining = GNUNET_TIME_absolute_get_remaining (udpw->timeout);
    if (GNUNET_TIME_UNIT_ZERO.rel_value_us == remaining.rel_value_us)
    {
      /* Message timed out */
      removed = GNUNET_YES;
      dequeue (plugin,
               udpw);
      udpw->qc (udpw->qc_cls,
                udpw,
                GNUNET_SYSERR);
      GNUNET_free (udpw);

      if (sock == plugin->sockv4)
      {
        udpw = plugin->ipv4_queue_head;
      }
      else if (sock == plugin->sockv6)
      {
        udpw = plugin->ipv6_queue_head;
      }
      else
      {
        GNUNET_break (0); /* should never happen */
        udpw = NULL;
      }
      GNUNET_STATISTICS_update (plugin->env->stats,
                                "# messages discarded due to timeout",
                                1,
                                GNUNET_NO);
    }
    else
    {
      /* Message did not time out, check transmission time */
      remaining = GNUNET_TIME_absolute_get_remaining (udpw->transmission_time);
      if (0 == remaining.rel_value_us)
      {
        /* this message is not delayed */
        LOG (GNUNET_ERROR_TYPE_DEBUG,
             "Message for peer `%s' (%u bytes) is not delayed \n",
             GNUNET_i2s (&udpw->session->target),
             udpw->payload_size);
        break; /* Found message to send, break */
      }
      else
      {
        /* Message is delayed, try next */
        LOG (GNUNET_ERROR_TYPE_DEBUG,
             "Message for peer `%s' (%u bytes) is delayed for %s\n",
             GNUNET_i2s (&udpw->session->target),
	     udpw->payload_size,
             GNUNET_STRINGS_relative_time_to_string (remaining,
						     GNUNET_YES));
        udpw = udpw->next;
      }
    }
  }
  if (GNUNET_YES == removed)
    notify_session_monitor (session->plugin,
                            session,
                            GNUNET_TRANSPORT_SS_UPDATE);
  return udpw;
}


/**
 * We failed to transmit a message via UDP. Generate
 * a descriptive error message.
 *
 * @param plugin our plugin
 * @param sa target address we were trying to reach
 * @param slen number of bytes in @a sa
 * @param error the errno value returned from the sendto() call
 */
static void
analyze_send_error (struct Plugin *plugin,
                    const struct sockaddr *sa,
                    socklen_t slen,
                    int error)
{
  enum GNUNET_ATS_Network_Type type;

  type = plugin->env->get_address_type (plugin->env->cls,
                                        sa,
                                        slen);
  if ( ( (GNUNET_ATS_NET_LAN == type) ||
         (GNUNET_ATS_NET_WAN == type) ) &&
       ( (ENETUNREACH == errno) ||
         (ENETDOWN == errno) ) )
  {
    if (slen == sizeof (struct sockaddr_in))
    {
      /* IPv4: "Network unreachable" or "Network down"
       *
       * This indicates we do not have connectivity
       */
      LOG (GNUNET_ERROR_TYPE_WARNING | GNUNET_ERROR_TYPE_BULK,
           _("UDP could not transmit message to `%s': "
             "Network seems down, please check your network configuration\n"),
           GNUNET_a2s (sa,
                       slen));
    }
    if (slen == sizeof (struct sockaddr_in6))
    {
      /* IPv6: "Network unreachable" or "Network down"
       *
       * This indicates that this system is IPv6 enabled, but does not
       * have a valid global IPv6 address assigned or we do not have
       * connectivity
       */
      LOG (GNUNET_ERROR_TYPE_WARNING | GNUNET_ERROR_TYPE_BULK,
           _("UDP could not transmit IPv6 message! "
             "Please check your network configuration and disable IPv6 if your "
             "connection does not have a global IPv6 address\n"));
    }
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "UDP could not transmit message to `%s': `%s'\n",
         GNUNET_a2s (sa,
                     slen),
         STRERROR (error));
  }
}


/**
 * It is time to try to transmit a UDP message.  Select one
 * and send.
 *
 * @param plugin the plugin
 * @param sock which socket (v4/v6) to send on
 */
static void
udp_select_send (struct Plugin *plugin,
                 struct GNUNET_NETWORK_Handle *sock)
{
  ssize_t sent;
  socklen_t slen;
  const struct sockaddr *a;
  const struct IPv4UdpAddress *u4;
  struct sockaddr_in a4;
  const struct IPv6UdpAddress *u6;
  struct sockaddr_in6 a6;
  struct UDP_MessageWrapper *udpw;

  /* Find message(s) to send */
  while (NULL != (udpw = remove_timeout_messages_and_select (plugin,
                                                             sock)))
  {
    if (sizeof (struct IPv4UdpAddress) == udpw->session->address->address_length)
    {
      u4 = udpw->session->address->address;
      memset (&a4,
              0,
              sizeof(a4));
      a4.sin_family = AF_INET;
#if HAVE_SOCKADDR_IN_SIN_LEN
      a4.sin_len = sizeof (a4);
#endif
      a4.sin_port = u4->u4_port;
      a4.sin_addr.s_addr = u4->ipv4_addr;
      a = (const struct sockaddr *) &a4;
      slen = sizeof (a4);
    }
    else if (sizeof (struct IPv6UdpAddress) == udpw->session->address->address_length)
    {
      u6 = udpw->session->address->address;
      memset (&a6,
              0,
              sizeof(a6));
      a6.sin6_family = AF_INET6;
#if HAVE_SOCKADDR_IN_SIN_LEN
      a6.sin6_len = sizeof (a6);
#endif
      a6.sin6_port = u6->u6_port;
      a6.sin6_addr = u6->ipv6_addr;
      a = (const struct sockaddr *) &a6;
      slen = sizeof (a6);
    }
    else
    {
      GNUNET_break (0);
      dequeue (plugin,
               udpw);
      udpw->qc (udpw->qc_cls,
                udpw,
                GNUNET_SYSERR);
      notify_session_monitor (plugin,
                              udpw->session,
                              GNUNET_TRANSPORT_SS_UPDATE);
      GNUNET_free (udpw);
      continue;
    }
    sent = GNUNET_NETWORK_socket_sendto (sock,
                                         udpw->msg_buf,
                                         udpw->msg_size,
                                         a,
                                         slen);
    udpw->session->last_transmit_time
      = GNUNET_TIME_absolute_max (GNUNET_TIME_absolute_get (),
                                  udpw->session->last_transmit_time);
    dequeue (plugin,
             udpw);
    if (GNUNET_SYSERR == sent)
    {
      /* Failure */
      analyze_send_error (plugin,
                          a,
                          slen,
                          errno);
      udpw->qc (udpw->qc_cls,
                udpw,
                GNUNET_SYSERR);
      GNUNET_STATISTICS_update (plugin->env->stats,
                                "# UDP, total, bytes, sent, failure",
                                sent,
                                GNUNET_NO);
      GNUNET_STATISTICS_update (plugin->env->stats,
                                "# UDP, total, messages, sent, failure",
                                1,
                                GNUNET_NO);
    }
    else
    {
      /* Success */
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "UDP transmitted %u-byte message to  `%s' `%s' (%d: %s)\n",
           (unsigned int) (udpw->msg_size),
           GNUNET_i2s (&udpw->session->target),
           GNUNET_a2s (a,
                       slen),
           (int ) sent,
           (sent < 0) ? STRERROR (errno) : "ok");
      GNUNET_STATISTICS_update (plugin->env->stats,
                                "# UDP, total, bytes, sent, success",
                                sent,
                                GNUNET_NO);
      GNUNET_STATISTICS_update (plugin->env->stats,
                                "# UDP, total, messages, sent, success",
                                1,
                                GNUNET_NO);
      if (NULL != udpw->frag_ctx)
        udpw->frag_ctx->on_wire_size += udpw->msg_size;
      udpw->qc (udpw->qc_cls,
                udpw,
                GNUNET_OK);
    }
    notify_session_monitor (plugin,
                            udpw->session,
                            GNUNET_TRANSPORT_SS_UPDATE);
    GNUNET_free (udpw);
  }
}


/* ***************** Event loop (part 2) *************** */


/**
 * We have been notified that our readset has something to read.  We don't
 * know which socket needs to be read, so we have to check each one
 * Then reschedule this function to be called again once more is available.
 *
 * @param cls the plugin handle
 * @param tc the scheduling context
 */
static void
udp_plugin_select_v4 (void *cls,
                      const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Plugin *plugin = cls;

  plugin->select_task_v4 = NULL;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;
  if (NULL == plugin->sockv4)
    return;
  if ((0 != (tc->reason & GNUNET_SCHEDULER_REASON_READ_READY)) &&
      (GNUNET_NETWORK_fdset_isset (tc->read_ready,
                                   plugin->sockv4)))
    udp_select_read (plugin,
                     plugin->sockv4);
  udp_select_send (plugin,
                   plugin->sockv4);
  schedule_select_v4 (plugin);
}


/**
 * We have been notified that our readset has something to read.  We don't
 * know which socket needs to be read, so we have to check each one
 * Then reschedule this function to be called again once more is available.
 *
 * @param cls the plugin handle
 * @param tc the scheduling context
 */
static void
udp_plugin_select_v6 (void *cls,
                      const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Plugin *plugin = cls;

  plugin->select_task_v6 = NULL;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;
  if (NULL == plugin->sockv6)
    return;
  if ( (0 != (tc->reason & GNUNET_SCHEDULER_REASON_READ_READY)) &&
       (GNUNET_NETWORK_fdset_isset (tc->read_ready,
                                    plugin->sockv6)) )
    udp_select_read (plugin,
                     plugin->sockv6);

  udp_select_send (plugin,
                   plugin->sockv6);
  schedule_select_v6 (plugin);
}


/* ******************* Initialization *************** */


/**
 * Setup the UDP sockets (for IPv4 and IPv6) for the plugin.
 *
 * @param plugin the plugin to initialize
 * @param bind_v6 IPv6 address to bind to (can be NULL, for 'any')
 * @param bind_v4 IPv4 address to bind to (can be NULL, for 'any')
 * @return number of sockets that were successfully bound
 */
static int
setup_sockets (struct Plugin *plugin,
               const struct sockaddr_in6 *bind_v6,
               const struct sockaddr_in *bind_v4)
{
  int tries;
  int sockets_created = 0;
  struct sockaddr_in6 server_addrv6;
  struct sockaddr_in server_addrv4;
  const struct sockaddr *server_addr;
  const struct sockaddr *addrs[2];
  socklen_t addrlens[2];
  socklen_t addrlen;
  int eno;

  /* Create IPv6 socket */
  eno = EINVAL;
  if (GNUNET_YES == plugin->enable_ipv6)
  {
    plugin->sockv6 = GNUNET_NETWORK_socket_create (PF_INET6,
                                                   SOCK_DGRAM,
                                                   0);
    if (NULL == plugin->sockv6)
    {
      LOG (GNUNET_ERROR_TYPE_INFO,
           _("Disabling IPv6 since it is not supported on this system!\n"));
      plugin->enable_ipv6 = GNUNET_NO;
    }
    else
    {
      memset (&server_addrv6,
              0,
              sizeof(struct sockaddr_in6));
#if HAVE_SOCKADDR_IN_SIN_LEN
      server_addrv6.sin6_len = sizeof (struct sockaddr_in6);
#endif
      server_addrv6.sin6_family = AF_INET6;
      if (NULL != bind_v6)
        server_addrv6.sin6_addr = bind_v6->sin6_addr;
      else
        server_addrv6.sin6_addr = in6addr_any;

      if (0 == plugin->port) /* autodetect */
        server_addrv6.sin6_port
          = htons (GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_STRONG,
                                             33537)
                   + 32000);
      else
        server_addrv6.sin6_port = htons (plugin->port);
      addrlen = sizeof (struct sockaddr_in6);
      server_addr = (const struct sockaddr *) &server_addrv6;

      tries = 0;
      while (tries < 10)
      {
        LOG(GNUNET_ERROR_TYPE_DEBUG,
            "Binding to IPv6 `%s'\n",
            GNUNET_a2s (server_addr,
                        addrlen));
        /* binding */
        if (GNUNET_OK ==
            GNUNET_NETWORK_socket_bind (plugin->sockv6,
                                        server_addr,
                                        addrlen))
          break;
        eno = errno;
        if (0 != plugin->port)
        {
          tries = 10; /* fail immediately */
          break; /* bind failed on specific port */
        }
        /* autodetect */
        server_addrv6.sin6_port
          = htons (GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_STRONG,
                                             33537)
                   + 32000);
        tries++;
      }
      if (tries >= 10)
      {
        GNUNET_NETWORK_socket_close (plugin->sockv6);
        plugin->enable_ipv6 = GNUNET_NO;
        plugin->sockv6 = NULL;
      }
      else
      {
        plugin->port = ntohs (server_addrv6.sin6_port);
      }
      if (NULL != plugin->sockv6)
      {
        LOG (GNUNET_ERROR_TYPE_DEBUG,
             "IPv6 UDP socket created listinging at %s\n",
             GNUNET_a2s (server_addr,
                         addrlen));
        addrs[sockets_created] = server_addr;
        addrlens[sockets_created] = addrlen;
        sockets_created++;
      }
      else
      {
        LOG (GNUNET_ERROR_TYPE_WARNING,
             _("Failed to bind UDP socket to %s: %s\n"),
             GNUNET_a2s (server_addr,
                         addrlen),
             STRERROR (eno));
      }
    }
  }

  /* Create IPv4 socket */
  eno = EINVAL;
  plugin->sockv4 = GNUNET_NETWORK_socket_create (PF_INET,
                                                 SOCK_DGRAM,
                                                 0);
  if (NULL == plugin->sockv4)
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING,
                         "socket");
    LOG (GNUNET_ERROR_TYPE_INFO,
         _("Disabling IPv4 since it is not supported on this system!\n"));
    plugin->enable_ipv4 = GNUNET_NO;
  }
  else
  {
    memset (&server_addrv4,
            0,
            sizeof(struct sockaddr_in));
#if HAVE_SOCKADDR_IN_SIN_LEN
    server_addrv4.sin_len = sizeof (struct sockaddr_in);
#endif
    server_addrv4.sin_family = AF_INET;
    if (NULL != bind_v4)
      server_addrv4.sin_addr = bind_v4->sin_addr;
    else
      server_addrv4.sin_addr.s_addr = INADDR_ANY;

    if (0 == plugin->port)
      /* autodetect */
      server_addrv4.sin_port
        = htons (GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_STRONG,
                                           33537)
                 + 32000);
    else
      server_addrv4.sin_port = htons (plugin->port);

    addrlen = sizeof (struct sockaddr_in);
    server_addr = (const struct sockaddr *) &server_addrv4;

    tries = 0;
    while (tries < 10)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Binding to IPv4 `%s'\n",
           GNUNET_a2s (server_addr,
                       addrlen));

      /* binding */
      if (GNUNET_OK ==
          GNUNET_NETWORK_socket_bind (plugin->sockv4,
                                      server_addr,
                                      addrlen))
        break;
      eno = errno;
      if (0 != plugin->port)
      {
        tries = 10; /* fail */
        break; /* bind failed on specific port */
      }

      /* autodetect */
      server_addrv4.sin_port
        = htons (GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_STRONG,
                                           33537)
                 + 32000);
      tries++;
    }
    if (tries >= 10)
    {
      GNUNET_NETWORK_socket_close (plugin->sockv4);
      plugin->enable_ipv4 = GNUNET_NO;
      plugin->sockv4 = NULL;
    }
    else
    {
      plugin->port = ntohs (server_addrv4.sin_port);
    }

    if (NULL != plugin->sockv4)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "IPv4 socket created on port %s\n",
           GNUNET_a2s (server_addr,
                       addrlen));
      addrs[sockets_created] = server_addr;
      addrlens[sockets_created] = addrlen;
      sockets_created++;
    }
    else
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
           _("Failed to bind UDP socket to %s: %s\n"),
           GNUNET_a2s (server_addr,
                       addrlen),
           STRERROR (eno));
    }
  }

  if (0 == sockets_created)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         _("Failed to open UDP sockets\n"));
    return 0; /* No sockets created, return */
  }
  schedule_select_v4 (plugin);
  schedule_select_v6 (plugin);
  plugin->nat = GNUNET_NAT_register (plugin->env->cfg,
                                     GNUNET_NO,
                                     plugin->port,
                                     sockets_created,
                                     addrs,
                                     addrlens,
                                     &udp_nat_port_map_callback,
                                     NULL,
                                     plugin,
                                     plugin->sockv4);
  return sockets_created;
}


/**
 * The exported method. Makes the core api available via a global and
 * returns the udp transport API.
 *
 * @param cls our `struct GNUNET_TRANSPORT_PluginEnvironment`
 * @return our `struct GNUNET_TRANSPORT_PluginFunctions`
 */
void *
libgnunet_plugin_transport_udp_init (void *cls)
{
  struct GNUNET_TRANSPORT_PluginEnvironment *env = cls;
  struct GNUNET_TRANSPORT_PluginFunctions *api;
  struct Plugin *p;
  unsigned long long port;
  unsigned long long aport;
  unsigned long long udp_max_bps;
  unsigned long long enable_v6;
  unsigned long long enable_broadcasting;
  unsigned long long enable_broadcasting_recv;
  char *bind4_address;
  char *bind6_address;
  struct GNUNET_TIME_Relative interval;
  struct sockaddr_in server_addrv4;
  struct sockaddr_in6 server_addrv6;
  int res;
  int have_bind4;
  int have_bind6;

  if (NULL == env->receive)
  {
    /* run in 'stub' mode (i.e. as part of gnunet-peerinfo), don't fully
     initialze the plugin or the API */
    api = GNUNET_new (struct GNUNET_TRANSPORT_PluginFunctions);
    api->cls = NULL;
    api->address_pretty_printer = &udp_plugin_address_pretty_printer;
    api->address_to_string = &udp_address_to_string;
    api->string_to_address = &udp_string_to_address;
    return api;
  }

  /* Get port number: port == 0 : autodetect a port,
   * > 0 : use this port, not given : 2086 default */
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (env->cfg,
                                             "transport-udp",
                                             "PORT",
                                             &port))
    port = 2086;
  if (port > 65535)
  {
    GNUNET_log_config_invalid (GNUNET_ERROR_TYPE_ERROR,
                               "transport-udp",
                               "PORT",
                               _("must be in [0,65535]"));
    return NULL;
  }
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (env->cfg,
                                             "transport-udp",
                                             "ADVERTISED_PORT",
                                             &aport))
    aport = port;
  if (aport > 65535)
  {
    GNUNET_log_config_invalid (GNUNET_ERROR_TYPE_ERROR,
                               "transport-udp",
                               "ADVERTISED_PORT",
                               _("must be in [0,65535]"));
    return NULL;
  }

  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_yesno (env->cfg,
                                            "nat",
                                            "DISABLEV6"))
    enable_v6 = GNUNET_NO;
  else
    enable_v6 = GNUNET_YES;

  have_bind4 = GNUNET_NO;
  memset (&server_addrv4,
          0,
          sizeof (server_addrv4));
  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_string (env->cfg,
                                             "transport-udp",
                                             "BINDTO",
                                             &bind4_address))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Binding UDP plugin to specific address: `%s'\n",
         bind4_address);
    if (1 != inet_pton (AF_INET,
                        bind4_address,
                        &server_addrv4.sin_addr))
    {
      GNUNET_log_config_invalid (GNUNET_ERROR_TYPE_ERROR,
                                 "transport-udp",
                                 "BINDTO",
                                 _("must be valid IPv4 address"));
      GNUNET_free (bind4_address);
      return NULL;
    }
    have_bind4 = GNUNET_YES;
  }
  GNUNET_free_non_null (bind4_address);
  have_bind6 = GNUNET_NO;
  memset (&server_addrv6,
          0,
          sizeof (server_addrv6));
  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_string (env->cfg,
                                             "transport-udp",
                                             "BINDTO6",
                                             &bind6_address))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Binding udp plugin to specific address: `%s'\n",
         bind6_address);
    if (1 != inet_pton (AF_INET6,
                        bind6_address,
                        &server_addrv6.sin6_addr))
    {
      GNUNET_log_config_invalid (GNUNET_ERROR_TYPE_ERROR,
                                 "transport-udp",
                                 "BINDTO6",
                                 _("must be valid IPv6 address"));
      GNUNET_free (bind6_address);
      return NULL;
    }
    have_bind6 = GNUNET_YES;
  }
  GNUNET_free_non_null (bind6_address);

  enable_broadcasting = GNUNET_CONFIGURATION_get_value_yesno (env->cfg,
                                                              "transport-udp",
                                                              "BROADCAST");
  if (enable_broadcasting == GNUNET_SYSERR)
    enable_broadcasting = GNUNET_NO;

  enable_broadcasting_recv = GNUNET_CONFIGURATION_get_value_yesno (env->cfg,
                                                                   "transport-udp",
                                                                   "BROADCAST_RECEIVE");
  if (enable_broadcasting_recv == GNUNET_SYSERR)
    enable_broadcasting_recv = GNUNET_YES;

  if (GNUNET_SYSERR ==
      GNUNET_CONFIGURATION_get_value_time (env->cfg,
                                           "transport-udp",
                                           "BROADCAST_INTERVAL",
                                           &interval))
  {
    interval = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS,
                                              10);
  }
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (env->cfg,
                                             "transport-udp",
                                             "MAX_BPS",
                                             &udp_max_bps))
  {
    /* 50 MB/s == infinity for practical purposes */
    udp_max_bps = 1024 * 1024 * 50;
  }

  p = GNUNET_new (struct Plugin);
  p->port = port;
  p->aport = aport;
  p->broadcast_interval = interval;
  p->enable_ipv6 = enable_v6;
  p->enable_ipv4 = GNUNET_YES; /* default */
  p->enable_broadcasting = enable_broadcasting;
  p->enable_broadcasting_receiving = enable_broadcasting_recv;
  p->env = env;
  p->sessions = GNUNET_CONTAINER_multipeermap_create (16,
                                                      GNUNET_NO);
  p->defrag_ctxs = GNUNET_CONTAINER_heap_create (GNUNET_CONTAINER_HEAP_ORDER_MIN);
  p->mst = GNUNET_SERVER_mst_create (&process_inbound_tokenized_messages,
                                     p);
  GNUNET_BANDWIDTH_tracker_init (&p->tracker,
                                 NULL,
                                 NULL,
                                 GNUNET_BANDWIDTH_value_init ((uint32_t) udp_max_bps),
                                 30);
  res = setup_sockets (p,
                       (GNUNET_YES == have_bind6) ? &server_addrv6 : NULL,
                       (GNUNET_YES == have_bind4) ? &server_addrv4 : NULL);
  if ( (0 == res) ||
       ( (NULL == p->sockv4) &&
         (NULL == p->sockv6) ) )
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
        _("Failed to create UDP network sockets\n"));
    GNUNET_CONTAINER_multipeermap_destroy (p->sessions);
    GNUNET_CONTAINER_heap_destroy (p->defrag_ctxs);
    GNUNET_SERVER_mst_destroy (p->mst);
    GNUNET_free (p);
    return NULL;
  }

  /* Setup broadcasting and receiving beacons */
  setup_broadcast (p,
                   &server_addrv6,
                   &server_addrv4);

  api = GNUNET_new (struct GNUNET_TRANSPORT_PluginFunctions);
  api->cls = p;
  api->disconnect_session = &udp_disconnect_session;
  api->query_keepalive_factor = &udp_query_keepalive_factor;
  api->disconnect_peer = &udp_disconnect;
  api->address_pretty_printer = &udp_plugin_address_pretty_printer;
  api->address_to_string = &udp_address_to_string;
  api->string_to_address = &udp_string_to_address;
  api->check_address = &udp_plugin_check_address;
  api->get_session = &udp_plugin_get_session;
  api->send = &udp_plugin_send;
  api->get_network = &udp_plugin_get_network;
  api->get_network_for_address = &udp_plugin_get_network_for_address;
  api->update_session_timeout = &udp_plugin_update_session_timeout;
  api->setup_monitor = &udp_plugin_setup_monitor;
  return api;
}


/**
 * Function called on each entry in the defragmentation heap to
 * clean it up.
 *
 * @param cls NULL
 * @param node node in the heap (to be removed)
 * @param element a `struct DefragContext` to be cleaned up
 * @param cost unused
 * @return #GNUNET_YES
 */
static int
heap_cleanup_iterator (void *cls,
                       struct GNUNET_CONTAINER_HeapNode *node,
                       void *element,
                       GNUNET_CONTAINER_HeapCostType cost)
{
  struct DefragContext *d_ctx = element;

  GNUNET_CONTAINER_heap_remove_node (node);
  GNUNET_DEFRAGMENT_context_destroy (d_ctx->defrag);
  GNUNET_free (d_ctx);
  return GNUNET_YES;
}


/**
 * The exported method. Makes the core api available via a global and
 * returns the udp transport API.
 *
 * @param cls our `struct GNUNET_TRANSPORT_PluginEnvironment`
 * @return NULL
 */
void *
libgnunet_plugin_transport_udp_done (void *cls)
{
  struct GNUNET_TRANSPORT_PluginFunctions *api = cls;
  struct Plugin *plugin = api->cls;
  struct PrettyPrinterContext *cur;
  struct UDP_MessageWrapper *udpw;

  if (NULL == plugin)
  {
    GNUNET_free (api);
    return NULL;
  }
  stop_broadcast (plugin);
  if (NULL != plugin->select_task_v4)
  {
    GNUNET_SCHEDULER_cancel (plugin->select_task_v4);
    plugin->select_task_v4 = NULL;
  }
  if (NULL != plugin->select_task_v6)
  {
    GNUNET_SCHEDULER_cancel (plugin->select_task_v6);
    plugin->select_task_v6 = NULL;
  }
  if (NULL != plugin->sockv4)
  {
    GNUNET_break (GNUNET_OK ==
                  GNUNET_NETWORK_socket_close (plugin->sockv4));
    plugin->sockv4 = NULL;
  }
  if (NULL != plugin->sockv6)
  {
    GNUNET_break (GNUNET_OK ==
                  GNUNET_NETWORK_socket_close (plugin->sockv6));
    plugin->sockv6 = NULL;
  }
  if (NULL != plugin->nat)
  {
    GNUNET_NAT_unregister (plugin->nat);
    plugin->nat = NULL;
  }
  if (NULL != plugin->defrag_ctxs)
  {
    GNUNET_CONTAINER_heap_iterate (plugin->defrag_ctxs,
                                   &heap_cleanup_iterator,
                                   NULL);
    GNUNET_CONTAINER_heap_destroy (plugin->defrag_ctxs);
    plugin->defrag_ctxs = NULL;
  }
  if (NULL != plugin->mst)
  {
    GNUNET_SERVER_mst_destroy (plugin->mst);
    plugin->mst = NULL;
  }
  while (NULL != (udpw = plugin->ipv4_queue_head))
  {
    dequeue (plugin,
             udpw);
    udpw->qc (udpw->qc_cls,
              udpw,
              GNUNET_SYSERR);
    GNUNET_free (udpw);
  }
  while (NULL != (udpw = plugin->ipv6_queue_head))
  {
    dequeue (plugin,
             udpw);
    udpw->qc (udpw->qc_cls,
              udpw,
              GNUNET_SYSERR);
    GNUNET_free (udpw);
  }
  GNUNET_CONTAINER_multipeermap_iterate (plugin->sessions,
                                         &disconnect_and_free_it,
                                         plugin);
  GNUNET_CONTAINER_multipeermap_destroy (plugin->sessions);

  while (NULL != (cur = plugin->ppc_dll_head))
  {
    GNUNET_break (0);
    GNUNET_CONTAINER_DLL_remove (plugin->ppc_dll_head,
                                 plugin->ppc_dll_tail,
                                 cur);
    GNUNET_RESOLVER_request_cancel (cur->resolver_handle);
    if (NULL != cur->timeout_task)
    {
      GNUNET_SCHEDULER_cancel (cur->timeout_task);
      cur->timeout_task = NULL;
    }
    GNUNET_free (cur);
  }
  GNUNET_free (plugin);
  GNUNET_free (api);
  return NULL;
}

/* end of plugin_transport_udp.c */
