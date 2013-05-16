/*
     This file is part of GNUnet
     (C) 2010, 2011 Christian Grothoff (and other contributing authors)

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
 * is roughly a factor of 32k * UDP_MAX_MESSAGES_IN_DEFRAG times this
 * value. (So 128 corresponds to 12 MB and should suffice for
 * connecting to roughly 128 peers via UDP).
 */
#define UDP_MAX_SENDER_ADDRESSES_WITH_DEFRAG 128

/**
 * Closure for 'append_port'.
 */
struct PrettyPrinterContext
{
  /**
   * Function to call with the result.
   */
  GNUNET_TRANSPORT_AddressStringCallback asc;

  /**
   * Clsoure for 'asc'.
   */
  void *asc_cls;

  /**
   * Port to add after the IP address.
   */
  uint16_t port;
};


enum UDP_MessageType
{
  UNDEFINED = 0,
  MSG_FRAGMENTED = 1,
  MSG_FRAGMENTED_COMPLETE = 2,
  MSG_UNFRAGMENTED = 3,
  MSG_ACK = 4,
  MSG_BEACON = 5
};

struct Session
{
  /**
   * Which peer is this session for?
   */
  struct GNUNET_PeerIdentity target;

  struct UDP_FragmentationContext * frag_ctx;

  /**
   * Address of the other peer
   */
  const struct sockaddr *sock_addr;

  /**
   * Desired delay for next sending we send to other peer
   */
  struct GNUNET_TIME_Relative flow_delay_for_other_peer;

  /**
   * Desired delay for next sending we received from other peer
   */
  struct GNUNET_TIME_Absolute flow_delay_from_other_peer;

  /**
   * Session timeout task
   */
  GNUNET_SCHEDULER_TaskIdentifier timeout_task;

  /**
   * expected delay for ACKs
   */
  struct GNUNET_TIME_Relative last_expected_ack_delay;

  /**
   * desired delay between UDP messages
   */
  struct GNUNET_TIME_Relative last_expected_msg_delay;

  struct GNUNET_ATS_Information ats;

  size_t addrlen;


  unsigned int rc;

  int in_destroy;
};


struct SessionCompareContext
{
  struct Session *res;
  const struct GNUNET_HELLO_Address *addr;
};


/**
 * Closure for 'process_inbound_tokenized_messages'
 */
struct SourceInformation
{
  /**
   * Sender identity.
   */
  struct GNUNET_PeerIdentity sender;

  /**
   * Source address.
   */
  const void *arg;

  struct Session *session;
  /**
   * Number of bytes in source address.
   */
  size_t args;

};


/**
 * Closure for 'find_receive_context'.
 */
struct FindReceiveContext
{
  /**
   * Where to store the result.
   */
  struct DefragContext *rc;

  /**
   * Address to find.
   */
  const struct sockaddr *addr;

  struct Session *session;

  /**
   * Number of bytes in 'addr'.
   */
  socklen_t addr_len;

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
   * Source address this receive context is for (allocated at the
   * end of the struct).
   */
  const struct sockaddr *src_addr;

  /**
   * Reference to master plugin struct.
   */
  struct Plugin *plugin;

  /**
   * Node in the defrag heap.
   */
  struct GNUNET_CONTAINER_HeapNode *hnode;

  /**
   * Length of 'src_addr'
   */
  size_t addr_len;
};



/**
 * Context to send fragmented messages
 */
struct UDP_FragmentationContext
{
  /**
   * Next in linked list
   */
  struct UDP_FragmentationContext * next;

  /**
   * Previous in linked list
   */
  struct UDP_FragmentationContext * prev;

  /**
   * The plugin
   */
  struct Plugin * plugin;

  /**
   * Handle for GNUNET_FRAGMENT context
   */
  struct GNUNET_FRAGMENT_Context * frag;

  /**
   * The session this fragmentation context belongs to
   */
  struct Session * session;

  /**
   * Function to call upon completion of the transmission.
   */
  GNUNET_TRANSPORT_TransmitContinuation cont;

  /**
   * Closure for 'cont'.
   */
  void *cont_cls;

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

  unsigned int fragments_used;

};


struct UDP_MessageWrapper
{
  /**
   * Session this message belongs to
   */
  struct Session *session;

  /**
   * DLL of messages
   * previous element
   */
  struct UDP_MessageWrapper *prev;

  /**
   * DLL of messages
   * previous element
   */
  struct UDP_MessageWrapper *next;

  /**
   * Message type
   * According to UDP_MessageType
   */
  int msg_type;

  /**
   * Message with size msg_size including UDP specific overhead
   */
  char *msg_buf;

  /**
   * Size of UDP message to send including UDP specific overhead
   */
  size_t msg_size;

  /**
   * Payload size of original message
   */
  size_t payload_size;

  /**
   * Message timeout
   */
  struct GNUNET_TIME_Absolute timeout;

  /**
   * Function to call upon completion of the transmission.
   */
  GNUNET_TRANSPORT_TransmitContinuation cont;

  /**
   * Closure for 'cont'.
   */
  void *cont_cls;

  /**
   * Fragmentation context
   * frag_ctx == NULL if transport <= MTU
   * frag_ctx != NULL if transport > MTU
   */
  struct UDP_FragmentationContext *frag_ctx;
};


/**
 * UDP ACK Message-Packet header (after defragmentation).
 */
struct UDP_ACK_Message
{
  /**
   * Message header.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Desired delay for flow control
   */
  uint32_t delay;

  /**
   * What is the identity of the sender
   */
  struct GNUNET_PeerIdentity sender;

};

/**
 * Encapsulation of all of the state of the plugin.
 */
struct Plugin * plugin;


/**
 * We have been notified that our readset has something to read.  We don't
 * know which socket needs to be read, so we have to check each one
 * Then reschedule this function to be called again once more is available.
 *
 * @param cls the plugin handle
 * @param tc the scheduling context (for rescheduling this function again)
 */
static void
udp_plugin_select (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * We have been notified that our readset has something to read.  We don't
 * know which socket needs to be read, so we have to check each one
 * Then reschedule this function to be called again once more is available.
 *
 * @param cls the plugin handle
 * @param tc the scheduling context (for rescheduling this function again)
 */
static void
udp_plugin_select_v6 (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Start session timeout
 */
static void
start_session_timeout (struct Session *s);

/**
 * Increment session timeout due to activity
 */
static void
reschedule_session_timeout (struct Session *s);

/**
 * Cancel timeout
 */
static void
stop_session_timeout (struct Session *s);

/**
 * (re)schedule select tasks for this plugin.
 *
 * @param plugin plugin to reschedule
 */
static void
schedule_select (struct Plugin *plugin)
{
  struct GNUNET_TIME_Relative min_delay;
  struct UDP_MessageWrapper *udpw;

  if ((GNUNET_YES == plugin->enable_ipv4) && (NULL != plugin->sockv4))
  {
    /* Find a message ready to send:
     * Flow delay from other peer is expired or not set (0) */
    min_delay = GNUNET_TIME_UNIT_FOREVER_REL;
    for (udpw = plugin->ipv4_queue_head; NULL != udpw; udpw = udpw->next)
      min_delay = GNUNET_TIME_relative_min (min_delay,
					    GNUNET_TIME_absolute_get_remaining (udpw->session->flow_delay_from_other_peer));
    
    if (plugin->select_task != GNUNET_SCHEDULER_NO_TASK)
      GNUNET_SCHEDULER_cancel(plugin->select_task);

    /* Schedule with:
     * - write active set if message is ready
     * - timeout minimum delay */
    plugin->select_task =
      GNUNET_SCHEDULER_add_select (GNUNET_SCHEDULER_PRIORITY_DEFAULT,
				   (0 == min_delay.rel_value) ? GNUNET_TIME_UNIT_FOREVER_REL : min_delay,
				   plugin->rs_v4,
				   (0 == min_delay.rel_value) ? plugin->ws_v4 : NULL,
				   &udp_plugin_select, plugin);  
  }
  if ((GNUNET_YES == plugin->enable_ipv6) && (NULL != plugin->sockv6))
  {
    min_delay = GNUNET_TIME_UNIT_FOREVER_REL;
    for (udpw = plugin->ipv6_queue_head; NULL != udpw; udpw = udpw->next)
      min_delay = GNUNET_TIME_relative_min (min_delay,
					    GNUNET_TIME_absolute_get_remaining (udpw->session->flow_delay_from_other_peer));
    
    if (GNUNET_SCHEDULER_NO_TASK != plugin->select_task_v6)
      GNUNET_SCHEDULER_cancel(plugin->select_task_v6);
    plugin->select_task_v6 =
      GNUNET_SCHEDULER_add_select (GNUNET_SCHEDULER_PRIORITY_DEFAULT,
				   (0 == min_delay.rel_value) ? GNUNET_TIME_UNIT_FOREVER_REL : min_delay,
				   plugin->rs_v6,
				   (0 == min_delay.rel_value) ? plugin->ws_v6 : NULL,
				   &udp_plugin_select_v6, plugin);
  }
}


/**
 * Function called for a quick conversion of the binary address to
 * a numeric address.  Note that the caller must not free the
 * address and that the next call to this function is allowed
 * to override the address again.
 *
 * @param cls closure
 * @param addr binary address
 * @param addrlen length of the address
 * @return string representing the same address
 */
const char *
udp_address_to_string (void *cls, const void *addr, size_t addrlen)
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

  if (addrlen == sizeof (struct IPv6UdpAddress))
  {
    t6 = addr;
    af = AF_INET6;
    port = ntohs (t6->u6_port);
    memcpy (&a6, &t6->ipv6_addr, sizeof (a6));
    sb = &a6;
  }
  else if (addrlen == sizeof (struct IPv4UdpAddress))
  {
    t4 = addr;
    af = AF_INET;
    port = ntohs (t4->u4_port);
    memcpy (&a4, &t4->ipv4_addr, sizeof (a4));
    sb = &a4;
  }
  else
  {
    GNUNET_break_op (0);
    return NULL;
  }
  inet_ntop (af, sb, buf, INET6_ADDRSTRLEN);
  GNUNET_snprintf (rbuf, sizeof (rbuf), (af == AF_INET6) ? "[%s]:%u" : "%s:%u",
                   buf, port);
  return rbuf;
}


/**
 * Function called to convert a string address to
 * a binary address.
 *
 * @param cls closure ('struct Plugin*')
 * @param addr string address
 * @param addrlen length of the address
 * @param buf location to store the buffer
 * @param added location to store the number of bytes in the buffer.
 *        If the function returns GNUNET_SYSERR, its contents are undefined.
 * @return GNUNET_OK on success, GNUNET_SYSERR on failure
 */
static int
udp_string_to_address (void *cls, const char *addr, uint16_t addrlen,
    void **buf, size_t *added)
{
  struct sockaddr_storage socket_address;
  
  if ((NULL == addr) || (0 == addrlen))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }

  if ('\0' != addr[addrlen - 1])
  {
    return GNUNET_SYSERR;
  }

  if (strlen (addr) != addrlen - 1)
  {
    return GNUNET_SYSERR;
  }

  if (GNUNET_OK != GNUNET_STRINGS_to_address_ip (addr, strlen (addr),
						 &socket_address))
  {
    return GNUNET_SYSERR;
  }

  switch (socket_address.ss_family)
  {
  case AF_INET:
    {
      struct IPv4UdpAddress *u4;
      struct sockaddr_in *in4 = (struct sockaddr_in *) &socket_address;
      u4 = GNUNET_malloc (sizeof (struct IPv4UdpAddress));
      u4->ipv4_addr = in4->sin_addr.s_addr;
      u4->u4_port = in4->sin_port;
      *buf = u4;
      *added = sizeof (struct IPv4UdpAddress);
      return GNUNET_OK;
    }
  case AF_INET6:
    {
      struct IPv6UdpAddress *u6;
      struct sockaddr_in6 *in6 = (struct sockaddr_in6 *) &socket_address;
      u6 = GNUNET_malloc (sizeof (struct IPv6UdpAddress));
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
 * @param cls a 'struct PrettyPrinterContext'
 * @param hostname result from DNS resolver
 */
static void
append_port (void *cls, const char *hostname)
{
  struct PrettyPrinterContext *ppc = cls;
  char *ret;

  if (hostname == NULL)
  {
    ppc->asc (ppc->asc_cls, NULL);
    GNUNET_free (ppc);
    return;
  }
  GNUNET_asprintf (&ret, "%s:%d", hostname, ppc->port);
  ppc->asc (ppc->asc_cls, ret);
  GNUNET_free (ret);
}


/**
 * Convert the transports address to a nice, human-readable
 * format.
 *
 * @param cls closure
 * @param type name of the transport that generated the address
 * @param addr one of the addresses of the host, NULL for the last address
 *        the specific address format depends on the transport
 * @param addrlen length of the address
 * @param numeric should (IP) addresses be displayed in numeric form?
 * @param timeout after how long should we give up?
 * @param asc function to call on each string
 * @param asc_cls closure for asc
 */
static void
udp_plugin_address_pretty_printer (void *cls, const char *type,
                                   const void *addr, size_t addrlen,
                                   int numeric,
                                   struct GNUNET_TIME_Relative timeout,
                                   GNUNET_TRANSPORT_AddressStringCallback asc,
                                   void *asc_cls)
{
  struct PrettyPrinterContext *ppc;
  const void *sb;
  size_t sbs;
  struct sockaddr_in a4;
  struct sockaddr_in6 a6;
  const struct IPv4UdpAddress *u4;
  const struct IPv6UdpAddress *u6;
  uint16_t port;

  if (addrlen == sizeof (struct IPv6UdpAddress))
  {
    u6 = addr;
    memset (&a6, 0, sizeof (a6));
    a6.sin6_family = AF_INET6;
#if HAVE_SOCKADDR_IN_SIN_LEN
    a6.sin6_len = sizeof (a6);
#endif
    a6.sin6_port = u6->u6_port;
    memcpy (&a6.sin6_addr, &u6->ipv6_addr, sizeof (struct in6_addr));
    port = ntohs (u6->u6_port);
    sb = &a6;
    sbs = sizeof (a6);
  }
  else if (addrlen == sizeof (struct IPv4UdpAddress))
  {
    u4 = addr;
    memset (&a4, 0, sizeof (a4));
    a4.sin_family = AF_INET;
#if HAVE_SOCKADDR_IN_SIN_LEN
    a4.sin_len = sizeof (a4);
#endif
    a4.sin_port = u4->u4_port;
    a4.sin_addr.s_addr = u4->ipv4_addr;
    port = ntohs (u4->u4_port);
    sb = &a4;
    sbs = sizeof (a4);
  }
  else if (0 == addrlen)
  {
    asc (asc_cls, "<inbound connection>");
    asc (asc_cls, NULL);
    return;
  }
  else
  {
    /* invalid address */
    GNUNET_break_op (0);
    asc (asc_cls, NULL);
    return;
  }
  ppc = GNUNET_malloc (sizeof (struct PrettyPrinterContext));
  ppc->asc = asc;
  ppc->asc_cls = asc_cls;
  ppc->port = port;
  GNUNET_RESOLVER_hostname_get (sb, sbs, !numeric, timeout, &append_port, ppc);
}


static void
call_continuation (struct UDP_MessageWrapper *udpw, int result)
{
  size_t overhead;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "Calling continuation for %u byte message to `%s' with result %s\n",
      udpw->payload_size, GNUNET_i2s (&udpw->session->target),
      (GNUNET_OK == result) ? "OK" : "SYSERR");

  if (udpw->msg_size >= udpw->payload_size)
    overhead = udpw->msg_size - udpw->payload_size;
  else
    overhead = udpw->msg_size;

  switch (result) {
    case GNUNET_OK:
      switch (udpw->msg_type) {
        case MSG_UNFRAGMENTED:
          if (NULL != udpw->cont)
          {
            /* Transport continuation */
            udpw->cont (udpw->cont_cls, &udpw->session->target, result,
                      udpw->payload_size, udpw->msg_size);
          }
          GNUNET_STATISTICS_update (plugin->env->stats,
                                    "# UDP, unfragmented msgs, messages, sent, success",
                                    1, GNUNET_NO);
          GNUNET_STATISTICS_update (plugin->env->stats,
                                    "# UDP, unfragmented msgs, bytes payload, sent, success",
                                    udpw->payload_size, GNUNET_NO);
          GNUNET_STATISTICS_update (plugin->env->stats,
                                    "# UDP, unfragmented msgs, bytes overhead, sent, success",
                                    overhead, GNUNET_NO);
          GNUNET_STATISTICS_update (plugin->env->stats,
                                    "# UDP, total, bytes overhead, sent",
                                    overhead, GNUNET_NO);
          GNUNET_STATISTICS_update (plugin->env->stats,
                                    "# UDP, total, bytes payload, sent",
                                    udpw->payload_size, GNUNET_NO);
          break;
        case MSG_FRAGMENTED_COMPLETE:
          GNUNET_assert (NULL != udpw->frag_ctx);
          if (udpw->frag_ctx->cont != NULL)
            udpw->frag_ctx->cont (udpw->frag_ctx->cont_cls, &udpw->session->target, GNUNET_OK,
                               udpw->frag_ctx->payload_size, udpw->frag_ctx->on_wire_size);
          GNUNET_STATISTICS_update (plugin->env->stats,
                                    "# UDP, fragmented msgs, messages, sent, success",
                                    1, GNUNET_NO);
          GNUNET_STATISTICS_update (plugin->env->stats,
                                    "# UDP, fragmented msgs, bytes payload, sent, success",
                                    udpw->payload_size, GNUNET_NO);
          GNUNET_STATISTICS_update (plugin->env->stats,
                                    "# UDP, fragmented msgs, bytes overhead, sent, success",
                                    overhead, GNUNET_NO);
          GNUNET_STATISTICS_update (plugin->env->stats,
                                    "# UDP, total, bytes overhead, sent",
                                    overhead, GNUNET_NO);
          GNUNET_STATISTICS_update (plugin->env->stats,
                                    "# UDP, total, bytes payload, sent",
                                    udpw->payload_size, GNUNET_NO);
          GNUNET_STATISTICS_update (plugin->env->stats,
                                    "# UDP, fragmented msgs, messages, pending",
                                    -1, GNUNET_NO);
          break;
        case MSG_FRAGMENTED:
          /* Fragmented message: enqueue next fragment */
          if (NULL != udpw->cont)
            udpw->cont (udpw->cont_cls, &udpw->session->target, result,
                      udpw->payload_size, udpw->msg_size);
          GNUNET_STATISTICS_update (plugin->env->stats,
                                    "# UDP, fragmented msgs, fragments, sent, success",
                                    1, GNUNET_NO);
          GNUNET_STATISTICS_update (plugin->env->stats,
                                    "# UDP, fragmented msgs, fragments bytes, sent, success",
                                    udpw->msg_size, GNUNET_NO);
          break;
        case MSG_ACK:
          /* No continuation */
          GNUNET_STATISTICS_update (plugin->env->stats,
                                    "# UDP, ACK msgs, messages, sent, success",
                                    1, GNUNET_NO);
          GNUNET_STATISTICS_update (plugin->env->stats,
                                    "# UDP, ACK msgs, bytes overhead, sent, success",
                                    overhead, GNUNET_NO);
          GNUNET_STATISTICS_update (plugin->env->stats,
                                    "# UDP, total, bytes overhead, sent",
                                    overhead, GNUNET_NO);
          break;
        case MSG_BEACON:
          GNUNET_break (0);
          break;
        default:
          LOG (GNUNET_ERROR_TYPE_ERROR,
              "ERROR: %u\n", udpw->msg_type);
          GNUNET_break (0);
          break;
      }
      break;
    case GNUNET_SYSERR:
      switch (udpw->msg_type) {
        case MSG_UNFRAGMENTED:
          /* Unfragmented message: failed to send */
          if (NULL != udpw->cont)
            udpw->cont (udpw->cont_cls, &udpw->session->target, result,
                      udpw->payload_size, overhead);
          GNUNET_STATISTICS_update (plugin->env->stats,
                                  "# UDP, unfragmented msgs, messages, sent, failure",
                                  1, GNUNET_NO);
          GNUNET_STATISTICS_update (plugin->env->stats,
                                    "# UDP, unfragmented msgs, bytes payload, sent, failure",
                                    udpw->payload_size, GNUNET_NO);
          GNUNET_STATISTICS_update (plugin->env->stats,
                                    "# UDP, unfragmented msgs, bytes overhead, sent, failure",
                                    overhead, GNUNET_NO);
          break;
        case MSG_FRAGMENTED_COMPLETE:
          GNUNET_assert (NULL != udpw->frag_ctx);
          if (udpw->frag_ctx->cont != NULL)
            udpw->frag_ctx->cont (udpw->frag_ctx->cont_cls, &udpw->session->target, GNUNET_SYSERR,
                               udpw->frag_ctx->payload_size, udpw->frag_ctx->on_wire_size);
          GNUNET_STATISTICS_update (plugin->env->stats,
                                    "# UDP, fragmented msgs, messages, sent, failure",
                                    1, GNUNET_NO);
          GNUNET_STATISTICS_update (plugin->env->stats,
                                    "# UDP, fragmented msgs, bytes payload, sent, failure",
                                    udpw->payload_size, GNUNET_NO);
          GNUNET_STATISTICS_update (plugin->env->stats,
                                    "# UDP, fragmented msgs, bytes payload, sent, failure",
                                    overhead, GNUNET_NO);
          GNUNET_STATISTICS_update (plugin->env->stats,
                                    "# UDP, fragmented msgs, bytes payload, sent, failure",
                                    overhead, GNUNET_NO);
          GNUNET_STATISTICS_update (plugin->env->stats,
                                    "# UDP, fragmented msgs, messages, pending",
                                    -1, GNUNET_NO);
          break;
        case MSG_FRAGMENTED:
          GNUNET_assert (NULL != udpw->frag_ctx);
          /* Fragmented message: failed to send */
          GNUNET_STATISTICS_update (plugin->env->stats,
                                    "# UDP, fragmented msgs, fragments, sent, failure",
                                    1, GNUNET_NO);
          GNUNET_STATISTICS_update (plugin->env->stats,
                                    "# UDP, fragmented msgs, fragments bytes, sent, failure",
                                    udpw->msg_size, GNUNET_NO);
          break;
        case MSG_ACK:
          /* ACK message: failed to send */
          GNUNET_STATISTICS_update (plugin->env->stats,
                                    "# UDP, ACK msgs, messages, sent, failure",
                                    1, GNUNET_NO);
          break;
        case MSG_BEACON:
          /* Beacon message: failed to send */
          GNUNET_break (0);
          break;
        default:
          GNUNET_break (0);
          break;
      }
      break;
    default:
      GNUNET_break (0);
      break;
  }
}


/**
 * Check if the given port is plausible (must be either our listen
 * port or our advertised port).  If it is neither, we return
 * GNUNET_SYSERR.
 *
 * @param plugin global variables
 * @param in_port port number to check
 * @return GNUNET_OK if port is either open_port or adv_port
 */
static int
check_port (struct Plugin *plugin, uint16_t in_port)
{
  if ((in_port == plugin->port) || (in_port == plugin->aport))
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
 * @param addr pointer to the address
 * @param addrlen length of addr
 * @return GNUNET_OK if this is a plausible address for this peer
 *         and transport, GNUNET_SYSERR if not
 *
 */
static int
udp_plugin_check_address (void *cls, const void *addr, size_t addrlen)
{
  struct Plugin *plugin = cls;
  struct IPv4UdpAddress *v4;
  struct IPv6UdpAddress *v6;

  if ((addrlen != sizeof (struct IPv4UdpAddress)) &&
      (addrlen != sizeof (struct IPv6UdpAddress)))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  if (addrlen == sizeof (struct IPv4UdpAddress))
  {
    v4 = (struct IPv4UdpAddress *) addr;
    if (GNUNET_OK != check_port (plugin, ntohs (v4->u4_port)))
      return GNUNET_SYSERR;
    if (GNUNET_OK !=
        GNUNET_NAT_test_address (plugin->nat, &v4->ipv4_addr,
                                 sizeof (struct in_addr)))
      return GNUNET_SYSERR;
  }
  else
  {
    v6 = (struct IPv6UdpAddress *) addr;
    if (IN6_IS_ADDR_LINKLOCAL (&v6->ipv6_addr))
    {
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
    if (GNUNET_OK != check_port (plugin, ntohs (v6->u6_port)))
      return GNUNET_SYSERR;
    if (GNUNET_OK !=
        GNUNET_NAT_test_address (plugin->nat, &v6->ipv6_addr,
                                 sizeof (struct in6_addr)))
      return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Task to free resources associated with a session.
 *
 * @param s session to free
 */
static void
free_session (struct Session *s)
{
  if (NULL != s->frag_ctx)
  {
    GNUNET_FRAGMENT_context_destroy(s->frag_ctx->frag, NULL, NULL);
    GNUNET_free (s->frag_ctx);
    s->frag_ctx = NULL;
  }
  GNUNET_free (s);
}


static void
dequeue (struct Plugin *plugin, struct UDP_MessageWrapper * udpw)
{
  if (plugin->bytes_in_buffer < udpw->msg_size)
      GNUNET_break (0);
  else
  {
    GNUNET_STATISTICS_update (plugin->env->stats,
                              "# UDP, total, bytes in buffers",
                              - (long long) udpw->msg_size, GNUNET_NO);
    plugin->bytes_in_buffer -= udpw->msg_size;
  }
  GNUNET_STATISTICS_update (plugin->env->stats,
                            "# UDP, total, msgs in buffers",
                            -1, GNUNET_NO);
  if (udpw->session->addrlen == sizeof (struct sockaddr_in))
    GNUNET_CONTAINER_DLL_remove (plugin->ipv4_queue_head,
                                 plugin->ipv4_queue_tail, udpw);
  if (udpw->session->addrlen == sizeof (struct sockaddr_in6))
    GNUNET_CONTAINER_DLL_remove (plugin->ipv6_queue_head,
                                 plugin->ipv6_queue_tail, udpw);
}

static void
fragmented_message_done (struct UDP_FragmentationContext *fc, int result)
{
  struct UDP_MessageWrapper *udpw;
  struct UDP_MessageWrapper *tmp;
  struct UDP_MessageWrapper dummy;
  struct Session *s = fc->session;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "%p : Fragmented message removed with result %s\n", fc, (result == GNUNET_SYSERR) ? "FAIL" : "SUCCESS");
  
  /* Call continuation for fragmented message */
  memset (&dummy, 0, sizeof (dummy));
  dummy.msg_type = MSG_FRAGMENTED_COMPLETE;
  dummy.msg_size = s->frag_ctx->on_wire_size;
  dummy.payload_size = s->frag_ctx->payload_size;
  dummy.frag_ctx = s->frag_ctx;
  dummy.cont = NULL;
  dummy.cont_cls = NULL;
  dummy.session = s;

  call_continuation (&dummy, result);

  /* Remove leftover fragments from queue */
  if (s->addrlen == sizeof (struct sockaddr_in6))
  {
    udpw = plugin->ipv6_queue_head;
    while (NULL != udpw)
    {
      tmp = udpw->next;
      if ((udpw->frag_ctx != NULL) && (udpw->frag_ctx == s->frag_ctx))
      {
        dequeue (plugin, udpw);
        call_continuation (udpw, GNUNET_SYSERR);
        GNUNET_free (udpw);
      }
      udpw = tmp;
    }
  }
  if (s->addrlen == sizeof (struct sockaddr_in))
  {
    udpw = plugin->ipv4_queue_head;
    while (udpw!= NULL)
    {
      tmp = udpw->next;
      if ((NULL != udpw->frag_ctx) && (udpw->frag_ctx == s->frag_ctx))
      {
        dequeue (plugin, udpw);
        call_continuation (udpw, GNUNET_SYSERR);
        GNUNET_free (udpw);
      }
      udpw = tmp;
    }
  }

  /* Destroy fragmentation context */
  GNUNET_FRAGMENT_context_destroy (fc->frag,
                                     &s->last_expected_msg_delay,
                                     &s->last_expected_ack_delay);
  s->frag_ctx = NULL;
  GNUNET_free (fc );
}

/**
 * Functions with this signature are called whenever we need
 * to close a session due to a disconnect or failure to
 * establish a connection.
 *
 * @param s session to close down
 */
static void
disconnect_session (struct Session *s)
{
  struct UDP_MessageWrapper *udpw;
  struct UDP_MessageWrapper *next;

  GNUNET_assert (GNUNET_YES != s->in_destroy);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Session %p to peer `%s' address ended \n",
         s,
         GNUNET_i2s (&s->target),
         GNUNET_a2s (s->sock_addr, s->addrlen));
  stop_session_timeout (s);

  if (NULL != s->frag_ctx)
  {
    /* Remove fragmented message due to disconnect */
    fragmented_message_done (s->frag_ctx, GNUNET_SYSERR);
  }

  next = plugin->ipv4_queue_head;
  while (NULL != (udpw = next))
  {
    next = udpw->next;
    if (udpw->session == s)
    {
      dequeue (plugin, udpw);
      call_continuation(udpw, GNUNET_SYSERR);
      GNUNET_free (udpw);
    }
  }
  next = plugin->ipv6_queue_head;
  while (NULL != (udpw = next))
  {
    next = udpw->next;
    if (udpw->session == s)
    {
      dequeue (plugin, udpw);
      call_continuation(udpw, GNUNET_SYSERR);
      GNUNET_free (udpw);
    }
    udpw = next;
  }
  plugin->env->session_end (plugin->env->cls, &s->target, s);

  if (NULL != s->frag_ctx)
  {
    if (NULL != s->frag_ctx->cont)
    {
      s->frag_ctx->cont (s->frag_ctx->cont_cls, &s->target, GNUNET_SYSERR,
                         s->frag_ctx->payload_size, s->frag_ctx->on_wire_size);
      LOG (GNUNET_ERROR_TYPE_DEBUG,
          "Calling continuation for fragemented message to `%s' with result SYSERR\n",
          GNUNET_i2s (&s->target));
    }
  }

  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap_remove (plugin->sessions,
                                                       &s->target.hashPubKey,
                                                       s));
  GNUNET_STATISTICS_set(plugin->env->stats,
                        "# UDP, sessions active",
                        GNUNET_CONTAINER_multihashmap_size(plugin->sessions),
                        GNUNET_NO);
  if (s->rc > 0)
    s->in_destroy = GNUNET_YES;
  else
    free_session (s);
}

/**
 * Destroy a session, plugin is being unloaded.
 *
 * @param cls unused
 * @param key hash of public key of target peer
 * @param value a 'struct PeerSession*' to clean up
 * @return GNUNET_OK (continue to iterate)
 */
static int
disconnect_and_free_it (void *cls, const struct GNUNET_HashCode * key, void *value)
{
  disconnect_session(value);
  return GNUNET_OK;
}


/**
 * Disconnect from a remote node.  Clean up session if we have one for this peer
 *
 * @param cls closure for this call (should be handle to Plugin)
 * @param target the peeridentity of the peer to disconnect
 * @return GNUNET_OK on success, GNUNET_SYSERR if the operation failed
 */
static void
udp_disconnect (void *cls, const struct GNUNET_PeerIdentity *target)
{
  struct Plugin *plugin = cls;
  GNUNET_assert (plugin != NULL);

  GNUNET_assert (target != NULL);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Disconnecting from peer `%s'\n", GNUNET_i2s (target));
  /* Clean up sessions */
  GNUNET_CONTAINER_multihashmap_get_multiple (plugin->sessions, &target->hashPubKey, &disconnect_and_free_it, plugin);
}


/**
 * Session was idle, so disconnect it
 */
static void
session_timeout (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_assert (NULL != cls);
  struct Session *s = cls;

  s->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Session %p was idle for %llu ms, disconnecting\n",
              s, (unsigned long long) GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT.rel_value);
  /* call session destroy function */
  disconnect_session (s);
}


/**
 * Start session timeout
 */
static void
start_session_timeout (struct Session *s)
{
  GNUNET_assert (NULL != s);
  GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == s->timeout_task);
  s->timeout_task =  GNUNET_SCHEDULER_add_delayed (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT,
                                                   &session_timeout,
                                                   s);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Timeout for session %p set to %llu ms\n",
              s,  (unsigned long long) GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT.rel_value);
}


/**
 * Increment session timeout due to activity
 */
static void
reschedule_session_timeout (struct Session *s)
{
  GNUNET_assert (NULL != s);
  GNUNET_assert (GNUNET_SCHEDULER_NO_TASK != s->timeout_task);

  GNUNET_SCHEDULER_cancel (s->timeout_task);
  s->timeout_task =  GNUNET_SCHEDULER_add_delayed (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT,
                                                   &session_timeout,
                                                   s);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Timeout rescheduled for session %p set to %llu ms\n",
              s, (unsigned long long) GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT.rel_value);
}


/**
 * Cancel timeout
 */
static void
stop_session_timeout (struct Session *s)
{
  GNUNET_assert (NULL != s);

  if (GNUNET_SCHEDULER_NO_TASK != s->timeout_task)
  {
    GNUNET_SCHEDULER_cancel (s->timeout_task);
    s->timeout_task = GNUNET_SCHEDULER_NO_TASK;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Timeout stopped for session %p canceled\n",
                s, (unsigned long long) GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT.rel_value);
  }
}


static struct Session *
create_session (struct Plugin *plugin, const struct GNUNET_PeerIdentity *target,
                const void *addr, size_t addrlen,
                GNUNET_TRANSPORT_TransmitContinuation cont, void *cont_cls)
{
  struct Session *s;
  const struct IPv4UdpAddress *t4;
  const struct IPv6UdpAddress *t6;
  struct sockaddr_in *v4;
  struct sockaddr_in6 *v6;
  size_t len;

  switch (addrlen)
  {
  case sizeof (struct IPv4UdpAddress):
    if (NULL == plugin->sockv4)
    {
      return NULL;
    }
    t4 = addr;
    s = GNUNET_malloc (sizeof (struct Session) + sizeof (struct sockaddr_in));
    len = sizeof (struct sockaddr_in);
    v4 = (struct sockaddr_in *) &s[1];
    v4->sin_family = AF_INET;
#if HAVE_SOCKADDR_IN_SIN_LEN
    v4->sin_len = sizeof (struct sockaddr_in);
#endif
    v4->sin_port = t4->u4_port;
    v4->sin_addr.s_addr = t4->ipv4_addr;
    s->ats = plugin->env->get_address_type (plugin->env->cls, (const struct sockaddr *) v4, sizeof (struct sockaddr_in));
    break;
  case sizeof (struct IPv6UdpAddress):
    if (NULL == plugin->sockv6)
    {
      return NULL;
    }
    t6 = addr;
    s =
        GNUNET_malloc (sizeof (struct Session) + sizeof (struct sockaddr_in6));
    len = sizeof (struct sockaddr_in6);
    v6 = (struct sockaddr_in6 *) &s[1];
    v6->sin6_family = AF_INET6;
#if HAVE_SOCKADDR_IN_SIN_LEN
    v6->sin6_len = sizeof (struct sockaddr_in6);
#endif
    v6->sin6_port = t6->u6_port;
    v6->sin6_addr = t6->ipv6_addr;
    s->ats = plugin->env->get_address_type (plugin->env->cls, (const struct sockaddr *) v6, sizeof (struct sockaddr_in6));
    break;
  default:
    /* Must have a valid address to send to */
    GNUNET_break_op (0);
    return NULL;
  }
  s->addrlen = len;
  s->target = *target;
  s->sock_addr = (const struct sockaddr *) &s[1];
  s->last_expected_ack_delay = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS, 250);
  s->last_expected_msg_delay = GNUNET_TIME_UNIT_MILLISECONDS;
  s->flow_delay_from_other_peer = GNUNET_TIME_UNIT_ZERO_ABS;
  s->flow_delay_for_other_peer = GNUNET_TIME_UNIT_ZERO;
  start_session_timeout (s);
  return s;
}


static int
session_cmp_it (void *cls,
		const struct GNUNET_HashCode * key,
		void *value)
{
  struct SessionCompareContext * cctx = cls;
  const struct GNUNET_HELLO_Address *address = cctx->addr;
  struct Session *s = value;

  socklen_t s_addrlen = s->addrlen;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Comparing  address %s <-> %s\n",
      udp_address_to_string (NULL, (void *) address->address, address->address_length),
      GNUNET_a2s (s->sock_addr, s->addrlen));
  if ((address->address_length == sizeof (struct IPv4UdpAddress)) &&
      (s_addrlen == sizeof (struct sockaddr_in)))
  {
    struct IPv4UdpAddress * u4 = NULL;
    u4 = (struct IPv4UdpAddress *) address->address;
    const struct sockaddr_in *s4 = (const struct sockaddr_in *) s->sock_addr;
    if ((0 == memcmp ((const void *) &u4->ipv4_addr,(const void *) &s4->sin_addr, sizeof (struct in_addr))) &&
        (u4->u4_port == s4->sin_port))
    {
      cctx->res = s;
      return GNUNET_NO;
    }

  }
  if ((address->address_length == sizeof (struct IPv6UdpAddress)) &&
      (s_addrlen == sizeof (struct sockaddr_in6)))
  {
    struct IPv6UdpAddress * u6 = NULL;
    u6 = (struct IPv6UdpAddress *) address->address;
    const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *) s->sock_addr;
    if ((0 == memcmp (&u6->ipv6_addr, &s6->sin6_addr, sizeof (struct in6_addr))) &&
        (u6->u6_port == s6->sin6_port))
    {
      cctx->res = s;
      return GNUNET_NO;
    }
  }
  return GNUNET_YES;
}


/**
 * Creates a new outbound session the transport service will use to send data to the
 * peer
 *
 * @param cls the plugin
 * @param address the address
 * @return the session or NULL of max connections exceeded
 */
static struct Session *
udp_plugin_get_session (void *cls,
                  const struct GNUNET_HELLO_Address *address)
{
  struct Session * s = NULL;
  struct Plugin * plugin = cls;
  struct IPv6UdpAddress * udp_a6;
  struct IPv4UdpAddress * udp_a4;

  GNUNET_assert (plugin != NULL);
  GNUNET_assert (address != NULL);


  if ((address->address == NULL) ||
      ((address->address_length != sizeof (struct IPv4UdpAddress)) &&
      (address->address_length != sizeof (struct IPv6UdpAddress))))
  {
    GNUNET_break (0);
    return NULL;
  }

  if (address->address_length == sizeof (struct IPv4UdpAddress))
  {
    if (plugin->sockv4 == NULL)
      return NULL;
    udp_a4 = (struct IPv4UdpAddress *) address->address;
    if (udp_a4->u4_port == 0)
      return NULL;
  }

  if (address->address_length == sizeof (struct IPv6UdpAddress))
  {
    if (plugin->sockv6 == NULL)
      return NULL;
    udp_a6 = (struct IPv6UdpAddress *) address->address;
    if (udp_a6->u6_port == 0)
      return NULL;
  }

  /* check if session already exists */
  struct SessionCompareContext cctx;
  cctx.addr = address;
  cctx.res = NULL;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Looking for existing session for peer `%s' `%s' \n", 
       GNUNET_i2s (&address->peer), 
       udp_address_to_string(NULL, address->address, address->address_length));
  GNUNET_CONTAINER_multihashmap_get_multiple(plugin->sessions, &address->peer.hashPubKey, session_cmp_it, &cctx);
  if (cctx.res != NULL)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Found existing session %p\n", cctx.res);
    return cctx.res;
  }

  /* otherwise create new */
  s = create_session (plugin,
      &address->peer,
      address->address,
      address->address_length,
      NULL, NULL);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Creating new session %p for peer `%s' address `%s'\n",
       s,
       GNUNET_i2s(&address->peer),
       udp_address_to_string(NULL,address->address,address->address_length));
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multihashmap_put (plugin->sessions,
                                                    &s->target.hashPubKey,
                                                    s,
                                                    GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE));
  GNUNET_STATISTICS_set(plugin->env->stats,
                        "# UDP, sessions active",
                        GNUNET_CONTAINER_multihashmap_size(plugin->sessions),
                        GNUNET_NO);
  return s;
}

static void 
enqueue (struct Plugin *plugin, struct UDP_MessageWrapper * udpw)
{
  if (plugin->bytes_in_buffer + udpw->msg_size > INT64_MAX)
      GNUNET_break (0);
  else
  {
    GNUNET_STATISTICS_update (plugin->env->stats,
                              "# UDP, total, bytes in buffers",
                              udpw->msg_size, GNUNET_NO);
    plugin->bytes_in_buffer += udpw->msg_size;
  }
  GNUNET_STATISTICS_update (plugin->env->stats,
                            "# UDP, total, msgs in buffers",
                            1, GNUNET_NO);
  if (udpw->session->addrlen == sizeof (struct sockaddr_in))
    GNUNET_CONTAINER_DLL_insert (plugin->ipv4_queue_head,
                                 plugin->ipv4_queue_tail, udpw);
  if (udpw->session->addrlen == sizeof (struct sockaddr_in6))
    GNUNET_CONTAINER_DLL_insert (plugin->ipv6_queue_head,
                                 plugin->ipv6_queue_tail, udpw);
}



/**
 * Fragment message was transmitted via UDP, let fragmentation know
 * to send the next fragment now.
 *
 * @param cls the 'struct UDPMessageWrapper' of the fragment
 * @param target destination peer (ignored)
 * @param result GNUNET_OK on success (ignored)
 * @param payload bytes payload sent
 * @param physical bytes physical sent
 */
static void
send_next_fragment (void *cls,
		    const struct GNUNET_PeerIdentity *target,
		    int result, size_t payload, size_t physical)
{
  struct UDP_MessageWrapper *udpw = cls;
  GNUNET_FRAGMENT_context_transmission_done (udpw->frag_ctx->frag);  
}


/**
 * Function that is called with messages created by the fragmentation
 * module.  In the case of the 'proc' callback of the
 * GNUNET_FRAGMENT_context_create function, this function must
 * eventually call 'GNUNET_FRAGMENT_context_transmission_done'.
 *
 * @param cls closure, the 'struct FragmentationContext'
 * @param msg the message that was created
 */
static void
enqueue_fragment (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct UDP_FragmentationContext *frag_ctx = cls;
  struct Plugin *plugin = frag_ctx->plugin;
  struct UDP_MessageWrapper * udpw;
  size_t msg_len = ntohs (msg->size);
 
  LOG (GNUNET_ERROR_TYPE_DEBUG, 
       "Enqueuing fragment with %u bytes\n", msg_len);
  frag_ctx->fragments_used ++;
  udpw = GNUNET_malloc (sizeof (struct UDP_MessageWrapper) + msg_len);
  udpw->session = frag_ctx->session;
  udpw->msg_buf = (char *) &udpw[1];
  udpw->msg_size = msg_len;
  udpw->payload_size = msg_len; /*FIXME: minus fragment overhead */
  udpw->cont = &send_next_fragment;
  udpw->cont_cls = udpw;
  udpw->timeout = frag_ctx->timeout;
  udpw->frag_ctx = frag_ctx;
  udpw->msg_type = MSG_FRAGMENTED;
  memcpy (udpw->msg_buf, msg, msg_len);
  enqueue (plugin, udpw);
  schedule_select (plugin);
}


/**
 * Function that can be used by the transport service to transmit
 * a message using the plugin.   Note that in the case of a
 * peer disconnecting, the continuation MUST be called
 * prior to the disconnect notification itself.  This function
 * will be called with this peer's HELLO message to initiate
 * a fresh connection to another peer.
 *
 * @param cls closure
 * @param s which session must be used
 * @param msgbuf the message to transmit
 * @param msgbuf_size number of bytes in 'msgbuf'
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
 * @param cont_cls closure for cont
 * @return number of bytes used (on the physical network, with overheads);
 *         -1 on hard errors (i.e. address invalid); 0 is a legal value
 *         and does NOT mean that the message was not transmitted (DV)
 */
static ssize_t
udp_plugin_send (void *cls,
                  struct Session *s,
                  const char *msgbuf, size_t msgbuf_size,
                  unsigned int priority,
                  struct GNUNET_TIME_Relative to,
                  GNUNET_TRANSPORT_TransmitContinuation cont, void *cont_cls)
{
  struct Plugin *plugin = cls;
  size_t udpmlen = msgbuf_size + sizeof (struct UDPMessage);
  struct UDP_FragmentationContext * frag_ctx;
  struct UDP_MessageWrapper * udpw;
  struct UDPMessage *udp;
  char mbuf[udpmlen];
  GNUNET_assert (plugin != NULL);
  GNUNET_assert (s != NULL);

  if ((s->addrlen == sizeof (struct sockaddr_in6)) && (plugin->sockv6 == NULL))
    return GNUNET_SYSERR;
  if ((s->addrlen == sizeof (struct sockaddr_in)) && (plugin->sockv4 == NULL))
    return GNUNET_SYSERR;
  if (udpmlen >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (GNUNET_YES != GNUNET_CONTAINER_multihashmap_contains_value(plugin->sessions, &s->target.hashPubKey, s))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "UDP transmits %u-byte message to `%s' using address `%s'\n",
       udpmlen,
       GNUNET_i2s (&s->target),
       GNUNET_a2s(s->sock_addr, s->addrlen));


  /* Message */
  udp = (struct UDPMessage *) mbuf;
  udp->header.size = htons (udpmlen);
  udp->header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_UDP_MESSAGE);
  udp->reserved = htonl (0);
  udp->sender = *plugin->env->my_identity;

  reschedule_session_timeout(s);
  if (udpmlen <= UDP_MTU)
  {
    /* unfragmented message */
    udpw = GNUNET_malloc (sizeof (struct UDP_MessageWrapper) + udpmlen);
    udpw->session = s;
    udpw->msg_buf = (char *) &udpw[1];
    udpw->msg_size = udpmlen; /* message size with UDP overhead */
    udpw->payload_size = msgbuf_size; /* message size without UDP overhead */
    udpw->timeout = GNUNET_TIME_absolute_add(GNUNET_TIME_absolute_get(), to);
    udpw->cont = cont;
    udpw->cont_cls = cont_cls;
    udpw->frag_ctx = NULL;
    udpw->msg_type = MSG_UNFRAGMENTED;
    memcpy (udpw->msg_buf, udp, sizeof (struct UDPMessage));
    memcpy (&udpw->msg_buf[sizeof (struct UDPMessage)], msgbuf, msgbuf_size);
    enqueue (plugin, udpw);

    GNUNET_STATISTICS_update (plugin->env->stats,
                              "# UDP, unfragmented msgs, messages, attempt",
                              1, GNUNET_NO);
    GNUNET_STATISTICS_update (plugin->env->stats,
                              "# UDP, unfragmented msgs, bytes payload, attempt",
                              udpw->payload_size, GNUNET_NO);
  }
  else
  {
    /* fragmented message */
    if  (s->frag_ctx != NULL)
      return GNUNET_SYSERR;
    memcpy (&udp[1], msgbuf, msgbuf_size);
    frag_ctx = GNUNET_malloc (sizeof (struct UDP_FragmentationContext));
    frag_ctx->plugin = plugin;
    frag_ctx->session = s;
    frag_ctx->cont = cont;
    frag_ctx->cont_cls = cont_cls;
    frag_ctx->timeout = GNUNET_TIME_absolute_add(GNUNET_TIME_absolute_get(), to);
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
    GNUNET_STATISTICS_update (plugin->env->stats,
                              "# UDP, fragmented msgs, messages, pending",
                              1, GNUNET_NO);
    GNUNET_STATISTICS_update (plugin->env->stats,
                              "# UDP, fragmented msgs, messages, attempt",
                              1, GNUNET_NO);
    GNUNET_STATISTICS_update (plugin->env->stats,
                              "# UDP, fragmented msgs, bytes payload, attempt",
                              frag_ctx->payload_size, GNUNET_NO);
  }
  schedule_select (plugin);
  return udpmlen;
}


/**
 * Our external IP address/port mapping has changed.
 *
 * @param cls closure, the 'struct LocalAddrList'
 * @param add_remove GNUNET_YES to mean the new public IP address, GNUNET_NO to mean
 *     the previous (now invalid) one
 * @param addr either the previous or the new public IP address
 * @param addrlen actual lenght of the address
 */
static void
udp_nat_port_map_callback (void *cls, int add_remove,
                           const struct sockaddr *addr, socklen_t addrlen)
{
  struct Plugin *plugin = cls;
  struct IPv4UdpAddress u4;
  struct IPv6UdpAddress u6;
  void *arg;
  size_t args;

  LOG (GNUNET_ERROR_TYPE_INFO,
       "NAT notification to %s address `%s'\n",
       (GNUNET_YES == add_remove) ? "add" : "remove",
       GNUNET_a2s (addr, addrlen));

  /* convert 'addr' to our internal format */
  switch (addr->sa_family)
  {
  case AF_INET:
    GNUNET_assert (addrlen == sizeof (struct sockaddr_in));
    u4.ipv4_addr = ((struct sockaddr_in *) addr)->sin_addr.s_addr;
    u4.u4_port = ((struct sockaddr_in *) addr)->sin_port;
    arg = &u4;
    args = sizeof (u4);
    break;
  case AF_INET6:
    GNUNET_assert (addrlen == sizeof (struct sockaddr_in6));
    memcpy (&u6.ipv6_addr, &((struct sockaddr_in6 *) addr)->sin6_addr,
            sizeof (struct in6_addr));
    u6.u6_port = ((struct sockaddr_in6 *) addr)->sin6_port;
    arg = &u6;
    args = sizeof (u6);
    break;
  default:
    GNUNET_break (0);
    return;
  }
  /* modify our published address list */
  plugin->env->notify_address (plugin->env->cls, add_remove, arg, args, "udp");
}



/**
 * Message tokenizer has broken up an incomming message. Pass it on
 * to the service.
 *
 * @param cls the 'struct Plugin'
 * @param client the 'struct SourceInformation'
 * @param hdr the actual message
 */
static int
process_inbound_tokenized_messages (void *cls, void *client,
                                    const struct GNUNET_MessageHeader *hdr)
{
  struct Plugin *plugin = cls;
  struct SourceInformation *si = client;
  struct GNUNET_TIME_Relative delay;

  GNUNET_assert (si->session != NULL);
  if (GNUNET_YES == si->session->in_destroy)
    return GNUNET_OK;
  /* setup ATS */
  GNUNET_break (ntohl(si->session->ats.value) != GNUNET_ATS_NET_UNSPECIFIED);
  delay = plugin->env->receive (plugin->env->cls,
				&si->sender,
				hdr,
				si->session,
				si->arg,
				si->args);

  plugin->env->update_address_metrics (plugin->env->cls,
				       &si->sender,
				       si->arg,
				       si->args,
				       si->session,
				       &si->session->ats, 1);

  si->session->flow_delay_for_other_peer = delay;
  reschedule_session_timeout(si->session);
  return GNUNET_OK;
}


/**
 * We've received a UDP Message.  Process it (pass contents to main service).
 *
 * @param plugin plugin context
 * @param msg the message
 * @param sender_addr sender address
 * @param sender_addr_len number of bytes in sender_addr
 */
static void
process_udp_message (struct Plugin *plugin, const struct UDPMessage *msg,
                     const struct sockaddr *sender_addr,
                     socklen_t sender_addr_len)
{
  struct SourceInformation si;
  struct Session * s;
  struct IPv4UdpAddress u4;
  struct IPv6UdpAddress u6;
  const void *arg;
  size_t args;

  if (0 != ntohl (msg->reserved))
  {
    GNUNET_break_op (0);
    return;
  }
  if (ntohs (msg->header.size) <
      sizeof (struct GNUNET_MessageHeader) + sizeof (struct UDPMessage))
  {
    GNUNET_break_op (0);
    return;
  }

  /* convert address */
  switch (sender_addr->sa_family)
  {
  case AF_INET:
    GNUNET_assert (sender_addr_len == sizeof (struct sockaddr_in));
    u4.ipv4_addr = ((struct sockaddr_in *) sender_addr)->sin_addr.s_addr;
    u4.u4_port = ((struct sockaddr_in *) sender_addr)->sin_port;
    arg = &u4;
    args = sizeof (u4);
    break;
  case AF_INET6:
    GNUNET_assert (sender_addr_len == sizeof (struct sockaddr_in6));
    u6.ipv6_addr = ((struct sockaddr_in6 *) sender_addr)->sin6_addr;
    u6.u6_port = ((struct sockaddr_in6 *) sender_addr)->sin6_port;
    arg = &u6;
    args = sizeof (u6);
    break;
  default:
    GNUNET_break (0);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received message with %u bytes from peer `%s' at `%s'\n",
       (unsigned int) ntohs (msg->header.size), GNUNET_i2s (&msg->sender),
       GNUNET_a2s (sender_addr, sender_addr_len));

  struct GNUNET_HELLO_Address * address = GNUNET_HELLO_address_allocate(&msg->sender, "udp", arg, args);
  s = udp_plugin_get_session(plugin, address);
  GNUNET_free (address);

  /* iterate over all embedded messages */
  si.session = s;
  si.sender = msg->sender;
  si.arg = arg;
  si.args = args;
  s->rc++;
  GNUNET_SERVER_mst_receive (plugin->mst, &si, (const char *) &msg[1],
                             ntohs (msg->header.size) -
                             sizeof (struct UDPMessage), GNUNET_YES, GNUNET_NO);
  s->rc--;
  if ( (0 == s->rc) && (GNUNET_YES == s->in_destroy))
    free_session (s);
}


/**
 * Scan the heap for a receive context with the given address.
 *
 * @param cls the 'struct FindReceiveContext'
 * @param node internal node of the heap
 * @param element value stored at the node (a 'struct ReceiveContext')
 * @param cost cost associated with the node
 * @return GNUNET_YES if we should continue to iterate,
 *         GNUNET_NO if not.
 */
static int
find_receive_context (void *cls, struct GNUNET_CONTAINER_HeapNode *node,
                      void *element, GNUNET_CONTAINER_HeapCostType cost)
{
  struct FindReceiveContext *frc = cls;
  struct DefragContext *e = element;

  if ((frc->addr_len == e->addr_len) &&
      (0 == memcmp (frc->addr, e->src_addr, frc->addr_len)))
  {
    frc->rc = e;
    return GNUNET_NO;
  }
  return GNUNET_YES;
}


/**
 * Process a defragmented message.
 *
 * @param cls the 'struct ReceiveContext'
 * @param msg the message
 */
static void
fragment_msg_proc (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct DefragContext *rc = cls;

  if (ntohs (msg->type) != GNUNET_MESSAGE_TYPE_TRANSPORT_UDP_MESSAGE)
  {
    GNUNET_break (0);
    return;
  }
  if (ntohs (msg->size) < sizeof (struct UDPMessage))
  {
    GNUNET_break (0);
    return;
  }
  process_udp_message (rc->plugin, (const struct UDPMessage *) msg,
                       rc->src_addr, rc->addr_len);
}


struct LookupContext
{
  const struct sockaddr * addr;

  struct Session *res;

  size_t addrlen;
};


static int
lookup_session_by_addr_it (void *cls, const struct GNUNET_HashCode * key, void *value)
{
  struct LookupContext *l_ctx = cls;
  struct Session * s = value;

  if ((s->addrlen == l_ctx->addrlen) &&
      (0 == memcmp (s->sock_addr, l_ctx->addr, s->addrlen)))
  {
    l_ctx->res = s;
    return GNUNET_NO;
  }
  return GNUNET_YES;
}


/**
 * Transmit an acknowledgement.
 *
 * @param cls the 'struct ReceiveContext'
 * @param id message ID (unused)
 * @param msg ack to transmit
 */
static void
ack_proc (void *cls, uint32_t id, const struct GNUNET_MessageHeader *msg)
{
  struct DefragContext *rc = cls;
  size_t msize = sizeof (struct UDP_ACK_Message) + ntohs (msg->size);
  struct UDP_ACK_Message *udp_ack;
  uint32_t delay = 0;
  struct UDP_MessageWrapper *udpw;
  struct Session *s;
  struct LookupContext l_ctx;

  l_ctx.addr = rc->src_addr;
  l_ctx.addrlen = rc->addr_len;
  l_ctx.res = NULL;
  GNUNET_CONTAINER_multihashmap_iterate (rc->plugin->sessions,
      &lookup_session_by_addr_it,
      &l_ctx);
  s = l_ctx.res;

  if (NULL == s)
    return;

  if (s->flow_delay_for_other_peer.rel_value <= UINT32_MAX)
    delay = s->flow_delay_for_other_peer.rel_value;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Sending ACK to `%s' including delay of %u ms\n",
       GNUNET_a2s (rc->src_addr,
                   (rc->src_addr->sa_family ==
                    AF_INET) ? sizeof (struct sockaddr_in) : sizeof (struct
                                                                     sockaddr_in6)),
       delay);
  udpw = GNUNET_malloc (sizeof (struct UDP_MessageWrapper) + msize);
  udpw->msg_size = msize;
  udpw->payload_size = 0;
  udpw->session = s;
  udpw->timeout = GNUNET_TIME_UNIT_FOREVER_ABS;
  udpw->msg_buf = (char *)&udpw[1];
  udpw->msg_type = MSG_ACK;
  udp_ack = (struct UDP_ACK_Message *) udpw->msg_buf;
  udp_ack->header.size = htons ((uint16_t) msize);
  udp_ack->header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_UDP_ACK);
  udp_ack->delay = htonl (delay);
  udp_ack->sender = *rc->plugin->env->my_identity;
  memcpy (&udp_ack[1], msg, ntohs (msg->size));
  enqueue (rc->plugin, udpw);
}


static void 
read_process_msg (struct Plugin *plugin,
		  const struct GNUNET_MessageHeader *msg,
		  const char *addr,
		  socklen_t fromlen)
{
  if (ntohs (msg->size) < sizeof (struct UDPMessage))
  {
    GNUNET_break_op (0);
    return;
  }
  process_udp_message (plugin, (const struct UDPMessage *) msg,
                       (const struct sockaddr *) addr, fromlen);
}


static void 
read_process_ack (struct Plugin *plugin,
		  const struct GNUNET_MessageHeader *msg,
		  char *addr,
		  socklen_t fromlen)
{
  const struct GNUNET_MessageHeader *ack;
  const struct UDP_ACK_Message *udp_ack;
  struct LookupContext l_ctx;
  struct Session *s;
  struct GNUNET_TIME_Relative flow_delay;

  if (ntohs (msg->size) <
      sizeof (struct UDP_ACK_Message) + sizeof (struct GNUNET_MessageHeader))
  {
    GNUNET_break_op (0);
    return;
  }
  udp_ack = (const struct UDP_ACK_Message *) msg;
  l_ctx.addr = (const struct sockaddr *) addr;
  l_ctx.addrlen = fromlen;
  l_ctx.res = NULL;
  GNUNET_CONTAINER_multihashmap_iterate (plugin->sessions,
					 &lookup_session_by_addr_it,
					 &l_ctx);
  s = l_ctx.res;

  if ((NULL == s) || (NULL == s->frag_ctx))
  {
    return;
  }

  flow_delay.rel_value = (uint64_t) ntohl (udp_ack->delay);
  LOG (GNUNET_ERROR_TYPE_DEBUG, 
       "We received a sending delay of %llu\n",
       flow_delay.rel_value);
  s->flow_delay_from_other_peer =
      GNUNET_TIME_relative_to_absolute (flow_delay);

  ack = (const struct GNUNET_MessageHeader *) &udp_ack[1];
  if (ntohs (ack->size) !=
      ntohs (msg->size) - sizeof (struct UDP_ACK_Message))
  {
    GNUNET_break_op (0);
    return;
  }

  if (0 != memcmp (&l_ctx.res->target, &udp_ack->sender, sizeof (struct GNUNET_PeerIdentity)))
    GNUNET_break (0);
  if (GNUNET_OK != GNUNET_FRAGMENT_process_ack (s->frag_ctx->frag, ack))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
	 "UDP processes %u-byte acknowledgement from `%s' at `%s'\n",
	 (unsigned int) ntohs (msg->size), GNUNET_i2s (&udp_ack->sender),
	 GNUNET_a2s ((const struct sockaddr *) addr, fromlen));
    /* Expect more ACKs to arrive */
    return;
  }

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Message full ACK'ed\n",
       (unsigned int) ntohs (msg->size), GNUNET_i2s (&udp_ack->sender),
       GNUNET_a2s ((const struct sockaddr *) addr, fromlen));

  /* Remove fragmented message after successful sending */
  fragmented_message_done (s->frag_ctx, GNUNET_OK);
}


static void 
read_process_fragment (struct Plugin *plugin,
		       const struct GNUNET_MessageHeader *msg,
		       char *addr,
		       socklen_t fromlen)
{
  struct DefragContext *d_ctx;
  struct GNUNET_TIME_Absolute now;
  struct FindReceiveContext frc;

  frc.rc = NULL;
  frc.addr = (const struct sockaddr *) addr;
  frc.addr_len = fromlen;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "UDP processes %u-byte fragment from `%s'\n",
       (unsigned int) ntohs (msg->size),
       GNUNET_a2s ((const struct sockaddr *) addr, fromlen));
  /* Lookup existing receive context for this address */
  GNUNET_CONTAINER_heap_iterate (plugin->defrag_ctxs,
                                 &find_receive_context,
                                 &frc);
  now = GNUNET_TIME_absolute_get ();
  d_ctx = frc.rc;

  if (d_ctx == NULL)
  {
    /* Create a new defragmentation context */
    d_ctx = GNUNET_malloc (sizeof (struct DefragContext) + fromlen);
    memcpy (&d_ctx[1], addr, fromlen);
    d_ctx->src_addr = (const struct sockaddr *) &d_ctx[1];
    d_ctx->addr_len = fromlen;
    d_ctx->plugin = plugin;
    d_ctx->defrag =
        GNUNET_DEFRAGMENT_context_create (plugin->env->stats, UDP_MTU,
                                          UDP_MAX_MESSAGES_IN_DEFRAG, d_ctx,
                                          &fragment_msg_proc, &ack_proc);
    d_ctx->hnode =
        GNUNET_CONTAINER_heap_insert (plugin->defrag_ctxs, d_ctx,
                                      (GNUNET_CONTAINER_HeapCostType)
                                      now.abs_value);
    LOG (GNUNET_ERROR_TYPE_DEBUG, 
	 "Created new defragmentation context for %u-byte fragment from `%s'\n",
	 (unsigned int) ntohs (msg->size),
	 GNUNET_a2s ((const struct sockaddr *) addr, fromlen));
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
	 "Found existing defragmentation context for %u-byte fragment from `%s'\n",
	 (unsigned int) ntohs (msg->size),
	 GNUNET_a2s ((const struct sockaddr *) addr, fromlen));
  }

  if (GNUNET_OK == GNUNET_DEFRAGMENT_process_fragment (d_ctx->defrag, msg))
  {
    /* keep this 'rc' from expiring */
    GNUNET_CONTAINER_heap_update_cost (plugin->defrag_ctxs, d_ctx->hnode,
                                       (GNUNET_CONTAINER_HeapCostType)
                                       now.abs_value);
  }
  if (GNUNET_CONTAINER_heap_get_size (plugin->defrag_ctxs) >
      UDP_MAX_SENDER_ADDRESSES_WITH_DEFRAG)
  {
    /* remove 'rc' that was inactive the longest */
    d_ctx = GNUNET_CONTAINER_heap_remove_root (plugin->defrag_ctxs);
    GNUNET_assert (NULL != d_ctx);
    GNUNET_DEFRAGMENT_context_destroy (d_ctx->defrag);
    GNUNET_free (d_ctx);
  }
}


/**
 * Read and process a message from the given socket.
 *
 * @param plugin the overall plugin
 * @param rsock socket to read from
 */
static void
udp_select_read (struct Plugin *plugin, struct GNUNET_NETWORK_Handle *rsock)
{
  socklen_t fromlen;
  char addr[32];
  char buf[65536] GNUNET_ALIGN;
  ssize_t size;
  const struct GNUNET_MessageHeader *msg;

  fromlen = sizeof (addr);
  memset (&addr, 0, sizeof (addr));
  size = GNUNET_NETWORK_socket_recvfrom (rsock, buf, sizeof (buf),
                                      (struct sockaddr *) &addr, &fromlen);
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
  if ( (-1 == size) && (ECONNRESET == errno) )
    return;
#endif
  if (-1 == size)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "UDP failed to receive data: %s\n", STRERROR (errno));
    /* Connection failure or something. Not a protocol violation. */
    return;
  }
  if (size < sizeof (struct GNUNET_MessageHeader))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
        "UDP got %u bytes, which is not enough for a GNUnet message header\n",
        (unsigned int) size);
    /* _MAY_ be a connection failure (got partial message) */
    /* But it _MAY_ also be that the other side uses non-GNUnet protocol. */
    GNUNET_break_op (0);
    return;
  }
  msg = (const struct GNUNET_MessageHeader *) buf;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "UDP received %u-byte message from `%s' type %i\n", (unsigned int) size,
       GNUNET_a2s ((const struct sockaddr *) addr, fromlen), ntohs (msg->type));

  if (size != ntohs (msg->size))
  {
    GNUNET_break_op (0);
    return;
  }

  GNUNET_STATISTICS_update (plugin->env->stats,
                            "# UDP, total, bytes, received",
                            size, GNUNET_NO);

  switch (ntohs (msg->type))
  {
  case GNUNET_MESSAGE_TYPE_TRANSPORT_BROADCAST_BEACON:
    udp_broadcast_receive (plugin, &buf, size, addr, fromlen);
    return;

  case GNUNET_MESSAGE_TYPE_TRANSPORT_UDP_MESSAGE:
    read_process_msg (plugin, msg, addr, fromlen);
    return;

  case GNUNET_MESSAGE_TYPE_TRANSPORT_UDP_ACK:
    read_process_ack (plugin, msg, addr, fromlen);
    return;

  case GNUNET_MESSAGE_TYPE_FRAGMENT:
    read_process_fragment (plugin, msg, addr, fromlen);
    return;

  default:
    GNUNET_break_op (0);
    return;
  }
}

static struct UDP_MessageWrapper *
remove_timeout_messages_and_select (struct UDP_MessageWrapper *head,
                                    struct GNUNET_NETWORK_Handle *sock)
{
  struct UDP_MessageWrapper *udpw = NULL;
  struct GNUNET_TIME_Relative remaining;

  udpw = head;
  while (udpw != NULL)
  {
    /* Find messages with timeout */
    remaining = GNUNET_TIME_absolute_get_remaining (udpw->timeout);
    if (GNUNET_TIME_UNIT_ZERO.rel_value == remaining.rel_value)
    {
      /* Message timed out */
      switch (udpw->msg_type) {
        case MSG_UNFRAGMENTED:
          GNUNET_STATISTICS_update (plugin->env->stats,
                                    "# UDP, total, bytes, sent, timeout",
                                    udpw->msg_size, GNUNET_NO);
          GNUNET_STATISTICS_update (plugin->env->stats,
                                    "# UDP, total, messages, sent, timeout",
                                    1, GNUNET_NO);
          GNUNET_STATISTICS_update (plugin->env->stats,
                                    "# UDP, unfragmented msgs, messages, sent, timeout",
                                    1, GNUNET_NO);
          GNUNET_STATISTICS_update (plugin->env->stats,
                                    "# UDP, unfragmented msgs, bytes, sent, timeout",
                                    udpw->payload_size, GNUNET_NO);
          /* Not fragmented message */
          LOG (GNUNET_ERROR_TYPE_DEBUG,
               "Message for peer `%s' with size %u timed out\n",
               GNUNET_i2s(&udpw->session->target), udpw->payload_size);
          call_continuation (udpw, GNUNET_SYSERR);
          /* Remove message */
          dequeue (plugin, udpw);
          GNUNET_free (udpw);
          break;
        case MSG_FRAGMENTED:
          /* Fragmented message */
          GNUNET_STATISTICS_update (plugin->env->stats,
                                    "# UDP, total, bytes, sent, timeout",
                                    udpw->frag_ctx->on_wire_size, GNUNET_NO);
          GNUNET_STATISTICS_update (plugin->env->stats,
                                    "# UDP, total, messages, sent, timeout",
                                    1, GNUNET_NO);
          call_continuation (udpw, GNUNET_SYSERR);
          LOG (GNUNET_ERROR_TYPE_DEBUG,
               "Fragment for message for peer `%s' with size %u timed out\n",
               GNUNET_i2s(&udpw->session->target), udpw->frag_ctx->payload_size);


          GNUNET_STATISTICS_update (plugin->env->stats,
                                    "# UDP, fragmented msgs, messages, sent, timeout",
                                    1, GNUNET_NO);
          GNUNET_STATISTICS_update (plugin->env->stats,
                                    "# UDP, fragmented msgs, bytes, sent, timeout",
                                    udpw->frag_ctx->payload_size, GNUNET_NO);
          /* Remove fragmented message due to timeout */
          fragmented_message_done (udpw->frag_ctx, GNUNET_SYSERR);
          break;
        case MSG_ACK:
          GNUNET_STATISTICS_update (plugin->env->stats,
                                    "# UDP, total, bytes, sent, timeout",
                                    udpw->msg_size, GNUNET_NO);
          GNUNET_STATISTICS_update (plugin->env->stats,
                                    "# UDP, total, messages, sent, timeout",
                                    1, GNUNET_NO);
          LOG (GNUNET_ERROR_TYPE_DEBUG,
               "ACK Message for peer `%s' with size %u timed out\n",
               GNUNET_i2s(&udpw->session->target), udpw->payload_size);
          call_continuation (udpw, GNUNET_SYSERR);
          dequeue (plugin, udpw);
          GNUNET_free (udpw);
          break;
        default:
          break;
      }
      if (sock == plugin->sockv4)
        udpw = plugin->ipv4_queue_head;
      else if (sock == plugin->sockv6)
        udpw = plugin->ipv6_queue_head;
      else
      {
        GNUNET_break (0); /* should never happen */
        udpw = NULL;
      }
      GNUNET_STATISTICS_update (plugin->env->stats,
                                "# messages dismissed due to timeout",
                                1, GNUNET_NO);
    }
    else
    {
      /* Message did not time out, check flow delay */
      remaining = GNUNET_TIME_absolute_get_remaining (udpw->session->flow_delay_from_other_peer);
      if (GNUNET_TIME_UNIT_ZERO.rel_value == remaining.rel_value)
      {
        /* this message is not delayed */
        LOG (GNUNET_ERROR_TYPE_DEBUG, 
             "Message for peer `%s' (%u bytes) is not delayed \n",
             GNUNET_i2s(&udpw->session->target), udpw->payload_size);
        break; /* Found message to send, break */
      }
      else
      {
        /* Message is delayed, try next */
        LOG (GNUNET_ERROR_TYPE_DEBUG,
             "Message for peer `%s' (%u bytes) is delayed for %llu \n",
             GNUNET_i2s(&udpw->session->target), udpw->payload_size, remaining.rel_value);
        udpw = udpw->next;
      }
    }
  }
  return udpw;
}


static void
analyze_send_error (struct Plugin *plugin,
                    const struct sockaddr * sa,
                    socklen_t slen,
                    int error)
{
  static int network_down_error;
  struct GNUNET_ATS_Information type;

 type = plugin->env->get_address_type (plugin->env->cls,sa, slen);
 if (((GNUNET_ATS_NET_LAN == ntohl(type.value)) || (GNUNET_ATS_NET_WAN == ntohl(type.value))) &&
     ((ENETUNREACH == errno) || (ENETDOWN == errno)))
 {
   if ((network_down_error == GNUNET_NO) && (slen == sizeof (struct sockaddr_in)))
   {
     /* IPv4: "Network unreachable" or "Network down"
      *
      * This indicates we do not have connectivity
      */
     LOG (GNUNET_ERROR_TYPE_WARNING | GNUNET_ERROR_TYPE_BULK,
         _("UDP could not transmit message to `%s': "
           "Network seems down, please check your network configuration\n"),
         GNUNET_a2s (sa, slen));
   }
   if ((network_down_error == GNUNET_NO) && (slen == sizeof (struct sockaddr_in6)))
   {
     /* IPv6: "Network unreachable" or "Network down"
      *
      * This indicates that this system is IPv6 enabled, but does not
      * have a valid global IPv6 address assigned or we do not have
      * connectivity
      */

    LOG (GNUNET_ERROR_TYPE_WARNING | GNUNET_ERROR_TYPE_BULK,
        _("UDP could not transmit message to `%s': "
          "Please check your network configuration and disable IPv6 if your "
          "connection does not have a global IPv6 address\n"),
        GNUNET_a2s (sa, slen));
   }
 }
 else
 {
   LOG (GNUNET_ERROR_TYPE_WARNING,
      "UDP could not transmit message to `%s': `%s'\n",
      GNUNET_a2s (sa, slen), STRERROR (error));
 }
}

static size_t
udp_select_send (struct Plugin *plugin, struct GNUNET_NETWORK_Handle *sock)
{
  const struct sockaddr * sa;
  ssize_t sent;
  socklen_t slen;

  struct UDP_MessageWrapper *udpw = NULL;

  /* Find message to send */
  udpw = remove_timeout_messages_and_select ((sock == plugin->sockv4) ? plugin->ipv4_queue_head : plugin->ipv6_queue_head,
                                             sock);
  if (NULL == udpw)
    return 0; /* No message to send */

  sa = udpw->session->sock_addr;
  slen = udpw->session->addrlen;

  sent = GNUNET_NETWORK_socket_sendto (sock, udpw->msg_buf, udpw->msg_size, sa, slen);

  if (GNUNET_SYSERR == sent)
  {
    /* Failure */
    analyze_send_error (plugin, sa, slen, errno);
    call_continuation(udpw, GNUNET_SYSERR);
    GNUNET_STATISTICS_update (plugin->env->stats,
                            "# UDP, total, bytes, sent, failure",
                            sent, GNUNET_NO);
    GNUNET_STATISTICS_update (plugin->env->stats,
                              "# UDP, total, messages, sent, failure",
                              1, GNUNET_NO);
  }
  else
  {
    /* Success */
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "UDP transmitted %u-byte message to  `%s' `%s' (%d: %s)\n",
         (unsigned int) (udpw->msg_size), GNUNET_i2s(&udpw->session->target) ,GNUNET_a2s (sa, slen), (int) sent,
         (sent < 0) ? STRERROR (errno) : "ok");
    GNUNET_STATISTICS_update (plugin->env->stats,
                              "# UDP, total, bytes, sent, success",
                              sent, GNUNET_NO);
    GNUNET_STATISTICS_update (plugin->env->stats,
                              "# UDP, total, messages, sent, success",
                              1, GNUNET_NO);
    if (NULL != udpw->frag_ctx)
        udpw->frag_ctx->on_wire_size += udpw->msg_size;
    call_continuation (udpw, GNUNET_OK);
  }
  dequeue (plugin, udpw);
  GNUNET_free (udpw);
  udpw = NULL;

  return sent;
}


/**
 * We have been notified that our readset has something to read.  We don't
 * know which socket needs to be read, so we have to check each one
 * Then reschedule this function to be called again once more is available.
 *
 * @param cls the plugin handle
 * @param tc the scheduling context (for rescheduling this function again)
 */
static void
udp_plugin_select (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Plugin *plugin = cls;

  plugin->select_task = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;
  if ( (0 != (tc->reason & GNUNET_SCHEDULER_REASON_READ_READY)) &&
       (NULL != plugin->sockv4) &&
       (GNUNET_NETWORK_fdset_isset (tc->read_ready, plugin->sockv4)) )
    udp_select_read (plugin, plugin->sockv4);
  if ( (0 != (tc->reason & GNUNET_SCHEDULER_REASON_WRITE_READY)) &&
       (NULL != plugin->sockv4) && 
       (NULL != plugin->ipv4_queue_head) &&
       (GNUNET_NETWORK_fdset_isset (tc->write_ready, plugin->sockv4)) )
    udp_select_send (plugin, plugin->sockv4);   
  schedule_select (plugin);
}


/**
 * We have been notified that our readset has something to read.  We don't
 * know which socket needs to be read, so we have to check each one
 * Then reschedule this function to be called again once more is available.
 *
 * @param cls the plugin handle
 * @param tc the scheduling context (for rescheduling this function again)
 */
static void
udp_plugin_select_v6 (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Plugin *plugin = cls;

  plugin->select_task_v6 = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;
  if ( ((tc->reason & GNUNET_SCHEDULER_REASON_READ_READY) != 0) &&
       (NULL != plugin->sockv6) &&
       (GNUNET_NETWORK_fdset_isset (tc->read_ready, plugin->sockv6)) )
    udp_select_read (plugin, plugin->sockv6);
  if ( (0 != (tc->reason & GNUNET_SCHEDULER_REASON_WRITE_READY)) &&
       (NULL != plugin->sockv6) && (plugin->ipv6_queue_head != NULL) &&
       (GNUNET_NETWORK_fdset_isset (tc->write_ready, plugin->sockv6)) )    
    udp_select_send (plugin, plugin->sockv6);
  schedule_select (plugin);
}


/**
 *
 * @return number of sockets that were successfully bound
 */
static int
setup_sockets (struct Plugin *plugin, 
	       const struct sockaddr_in6 *bind_v6,
	       const struct sockaddr_in *bind_v4)
{
  int tries;
  int sockets_created = 0;
  struct sockaddr_in6 serverAddrv6;
  struct sockaddr_in serverAddrv4;
  struct sockaddr *serverAddr;
  struct sockaddr *addrs[2];
  socklen_t addrlens[2];
  socklen_t addrlen;
  int eno;

  /* Create IPv6 socket */
  eno = EINVAL;
  if (plugin->enable_ipv6 == GNUNET_YES)
  {
    plugin->sockv6 = GNUNET_NETWORK_socket_create (PF_INET6, SOCK_DGRAM, 0);
    if (NULL == plugin->sockv6)
    {
    	GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "socket");
      LOG (GNUNET_ERROR_TYPE_WARNING, "Disabling IPv6 since it is not supported on this system!\n");
      plugin->enable_ipv6 = GNUNET_NO;
    }
    else
    {
    	memset (&serverAddrv6, '\0', sizeof (struct sockaddr_in6));
#if HAVE_SOCKADDR_IN_SIN_LEN
      serverAddrv6.sin6_len = sizeof (struct sockaddr_in6);
#endif
      serverAddrv6.sin6_family = AF_INET6;
      if (NULL != bind_v6)
      	serverAddrv6.sin6_addr = bind_v6->sin6_addr;
      else
      	serverAddrv6.sin6_addr = in6addr_any;

      if (0 == plugin->port) /* autodetect */
      		serverAddrv6.sin6_port = htons (GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_STRONG, 33537) + 32000);
      else
      		serverAddrv6.sin6_port = htons (plugin->port);
      addrlen = sizeof (struct sockaddr_in6);
      serverAddr = (struct sockaddr *) &serverAddrv6;

      tries = 0;
      while (tries < 10)
      {
      		LOG (GNUNET_ERROR_TYPE_DEBUG, "Binding to IPv6 `%s'\n",
      				 GNUNET_a2s (serverAddr, addrlen));
      		/* binding */
      		if (GNUNET_OK == GNUNET_NETWORK_socket_bind (plugin->sockv6,
      												serverAddr, addrlen))
      			break;
      		eno = errno;
      		if (0 != plugin->port)
      		{
      				tries = 10; /* fail */
      				break; /* bind failed on specific port */
      		}
      		/* autodetect */
      		serverAddrv6.sin6_port = htons (GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_STRONG, 33537) + 32000);
      		tries ++;
      }
      if (tries >= 10)
      {
        GNUNET_NETWORK_socket_close (plugin->sockv6);
        plugin->enable_ipv6 = GNUNET_NO;
        plugin->sockv6 = NULL;
      }

      if (plugin->sockv6 != NULL)
      {
        LOG (GNUNET_ERROR_TYPE_DEBUG,
             "IPv6 socket created on port %s\n",
             GNUNET_a2s (serverAddr, addrlen));
        addrs[sockets_created] = (struct sockaddr *) &serverAddrv6;
        addrlens[sockets_created] = sizeof (struct sockaddr_in6);
        sockets_created++;
      }
      else
      {
          LOG (GNUNET_ERROR_TYPE_ERROR,
               "Failed to bind UDP socket to %s: %s\n",
               GNUNET_a2s (serverAddr, addrlen),
	       STRERROR (eno));
      }
    }
  }

  /* Create IPv4 socket */
  eno = EINVAL;
  plugin->sockv4 = GNUNET_NETWORK_socket_create (PF_INET, SOCK_DGRAM, 0);
  if (NULL == plugin->sockv4)
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "socket");
    LOG (GNUNET_ERROR_TYPE_WARNING, "Disabling IPv4 since it is not supported on this system!\n");
    plugin->enable_ipv4 = GNUNET_NO;
  }
  else
  {
    memset (&serverAddrv4, '\0', sizeof (struct sockaddr_in));
#if HAVE_SOCKADDR_IN_SIN_LEN
    serverAddrv4.sin_len = sizeof (struct sockaddr_in);
#endif
    serverAddrv4.sin_family = AF_INET;
    if (NULL != bind_v4)
      serverAddrv4.sin_addr = bind_v4->sin_addr;
    else
      serverAddrv4.sin_addr.s_addr = INADDR_ANY;
    
    if (0 == plugin->port)
      /* autodetect */
      serverAddrv4.sin_port = htons (GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_STRONG, 33537) + 32000);
    else
      serverAddrv4.sin_port = htons (plugin->port);
    
    
    addrlen = sizeof (struct sockaddr_in);
    serverAddr = (struct sockaddr *) &serverAddrv4;
    
    tries = 0;
    while (tries < 10)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Binding to IPv4 `%s'\n",
      			GNUNET_a2s (serverAddr, addrlen));
      
      /* binding */
      if (GNUNET_OK == GNUNET_NETWORK_socket_bind (plugin->sockv4,
													 serverAddr, addrlen))
      		break;
      eno = errno;
      if (0 != plugin->port)
      {
      		tries = 10; /* fail */
      		break; /* bind failed on specific port */
      }
      
      /* autodetect */
      serverAddrv4.sin_port = htons (GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_STRONG, 33537) + 32000);
      tries ++;
    }
    
    if (tries >= 10)
    {
      GNUNET_NETWORK_socket_close (plugin->sockv4);
      plugin->enable_ipv4 = GNUNET_NO;
      plugin->sockv4 = NULL;
    }
    
    if (plugin->sockv4 != NULL)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
      		"IPv4 socket created on port %s\n", GNUNET_a2s (serverAddr, addrlen));
      addrs[sockets_created] = (struct sockaddr *) &serverAddrv4;
      addrlens[sockets_created] = sizeof (struct sockaddr_in);
      sockets_created++;
    }
    else
    {		  
      LOG (GNUNET_ERROR_TYPE_ERROR,
      		"Failed to bind UDP socket to %s: %s\n",
      		GNUNET_a2s (serverAddr, addrlen), STRERROR (eno));
    }
  }
  
  if (0 == sockets_created)
  {
  		LOG (GNUNET_ERROR_TYPE_WARNING, _("Failed to open UDP sockets\n"));
  		return 0; /* No sockets created, return */
  }

  /* Create file descriptors */
  if (plugin->enable_ipv4 == GNUNET_YES)
  {
			plugin->rs_v4 = GNUNET_NETWORK_fdset_create ();
			plugin->ws_v4 = GNUNET_NETWORK_fdset_create ();
			GNUNET_NETWORK_fdset_zero (plugin->rs_v4);
			GNUNET_NETWORK_fdset_zero (plugin->ws_v4);
			if (NULL != plugin->sockv4)
			{
				GNUNET_NETWORK_fdset_set (plugin->rs_v4, plugin->sockv4);
				GNUNET_NETWORK_fdset_set (plugin->ws_v4, plugin->sockv4);
			}
  }

  if (plugin->enable_ipv6 == GNUNET_YES)
  {
    plugin->rs_v6 = GNUNET_NETWORK_fdset_create ();
    plugin->ws_v6 = GNUNET_NETWORK_fdset_create ();
    GNUNET_NETWORK_fdset_zero (plugin->rs_v6);
    GNUNET_NETWORK_fdset_zero (plugin->ws_v6);
    if (NULL != plugin->sockv6)
    {
      GNUNET_NETWORK_fdset_set (plugin->rs_v6, plugin->sockv6);
      GNUNET_NETWORK_fdset_set (plugin->ws_v6, plugin->sockv6);
    }
  }

  schedule_select (plugin);
  plugin->nat = GNUNET_NAT_register (plugin->env->cfg,
                           GNUNET_NO, plugin->port,
                           sockets_created,
                           (const struct sockaddr **) addrs, addrlens,
                           &udp_nat_port_map_callback, NULL, plugin);

  return sockets_created;
}


/**
 * The exported method. Makes the core api available via a global and
 * returns the udp transport API.
 *
 * @param cls our 'struct GNUNET_TRANSPORT_PluginEnvironment'
 * @return our 'struct GNUNET_TRANSPORT_PluginFunctions'
 */
void *
libgnunet_plugin_transport_udp_init (void *cls)
{
  struct GNUNET_TRANSPORT_PluginEnvironment *env = cls;
  struct GNUNET_TRANSPORT_PluginFunctions *api;
  struct Plugin *p;
  unsigned long long port;
  unsigned long long aport;
  unsigned long long broadcast;
  unsigned long long udp_max_bps;
  unsigned long long enable_v6;
  char * bind4_address;
  char * bind6_address;
  char * fancy_interval;
  struct GNUNET_TIME_Relative interval;
  struct sockaddr_in serverAddrv4;
  struct sockaddr_in6 serverAddrv6;
  int res;
  int have_bind4;
  int have_bind6;

  if (NULL == env->receive)
  {
    /* run in 'stub' mode (i.e. as part of gnunet-peerinfo), don't fully
       initialze the plugin or the API */
    api = GNUNET_malloc (sizeof (struct GNUNET_TRANSPORT_PluginFunctions));
    api->cls = NULL;
    api->address_pretty_printer = &udp_plugin_address_pretty_printer;
    api->address_to_string = &udp_address_to_string;
    api->string_to_address = &udp_string_to_address;
    return api;
  }

  GNUNET_assert (NULL != env->stats);

  /* Get port number: port == 0 : autodetect a port,
   * 												> 0 : use this port,
   * 								  not given : 2086 default */
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (env->cfg, "transport-udp", "PORT",
                                             &port))
    port = 2086;
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (env->cfg, "transport-udp",
                                             "ADVERTISED_PORT", &aport))
    aport = port;
  if (port > 65535)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         _("Given `%s' option is out of range: %llu > %u\n"), "PORT", port,
         65535);
    return NULL;
  }

  /* Protocols */
  if ((GNUNET_YES ==
       GNUNET_CONFIGURATION_get_value_yesno (env->cfg, "nat",
                                             "DISABLEV6")))
    enable_v6 = GNUNET_NO;
  else
    enable_v6 = GNUNET_YES;

  /* Addresses */
  have_bind4 = GNUNET_NO;
  memset (&serverAddrv4, 0, sizeof (serverAddrv4));
  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_string (env->cfg, "transport-udp",
                                             "BINDTO", &bind4_address))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Binding udp plugin to specific address: `%s'\n",
         bind4_address);
    if (1 != inet_pton (AF_INET, bind4_address, &serverAddrv4.sin_addr))
    {
      GNUNET_free (bind4_address);
      return NULL;
    }
    have_bind4 = GNUNET_YES;
  }
  GNUNET_free_non_null (bind4_address);
  have_bind6 = GNUNET_NO;
  memset (&serverAddrv6, 0, sizeof (serverAddrv6));
  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_string (env->cfg, "transport-udp",
                                             "BINDTO6", &bind6_address))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Binding udp plugin to specific address: `%s'\n",
         bind6_address);
    if (1 !=
        inet_pton (AF_INET6, bind6_address, &serverAddrv6.sin6_addr))
    {
      LOG (GNUNET_ERROR_TYPE_ERROR, _("Invalid IPv6 address: `%s'\n"),
           bind6_address);
      GNUNET_free_non_null (bind4_address);
      GNUNET_free (bind6_address);
      return NULL;
    }
    have_bind6 = GNUNET_YES;
  }
  GNUNET_free_non_null (bind6_address);

  /* Enable neighbour discovery */
  broadcast = GNUNET_CONFIGURATION_get_value_yesno (env->cfg, "transport-udp",
                                            "BROADCAST");
  if (broadcast == GNUNET_SYSERR)
    broadcast = GNUNET_NO;

  if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_string (env->cfg, "transport-udp",
                                           "BROADCAST_INTERVAL", &fancy_interval))
  {
    interval = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10);
  }
  else
  {
     if (GNUNET_SYSERR == GNUNET_STRINGS_fancy_time_to_relative(fancy_interval, &interval))
     {
       interval = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 30);
     }
     GNUNET_free (fancy_interval);
  }

  /* Maximum datarate */
  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_number (env->cfg, "transport-udp",
                                             "MAX_BPS", &udp_max_bps))
  {
    udp_max_bps = 1024 * 1024 * 50;     /* 50 MB/s == infinity for practical purposes */
  }

  p = GNUNET_malloc (sizeof (struct Plugin));
  p->port = port;
  p->aport = aport;
  p->broadcast_interval = interval;
  p->enable_ipv6 = enable_v6;
  p->enable_ipv4 = GNUNET_YES; /* default */
  p->env = env;
  p->sessions = GNUNET_CONTAINER_multihashmap_create (10, GNUNET_NO);
  p->defrag_ctxs = GNUNET_CONTAINER_heap_create (GNUNET_CONTAINER_HEAP_ORDER_MIN);
  p->mst = GNUNET_SERVER_mst_create (&process_inbound_tokenized_messages, p);
  GNUNET_BANDWIDTH_tracker_init (&p->tracker,
                                 GNUNET_BANDWIDTH_value_init ((uint32_t)udp_max_bps), 30);
  plugin = p;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Setting up sockets\n");
  res = setup_sockets (p, (GNUNET_YES == have_bind6) ? &serverAddrv6 : NULL,
		       	 	 	 	 	 	 	 	(GNUNET_YES == have_bind4) ? &serverAddrv4 : NULL);
  if ((res == 0) || ((p->sockv4 == NULL) && (p->sockv6 == NULL)))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
	 _("Failed to create network sockets, plugin failed\n"));
    GNUNET_CONTAINER_multihashmap_destroy (p->sessions);
    GNUNET_CONTAINER_heap_destroy (p->defrag_ctxs);
    GNUNET_SERVER_mst_destroy (p->mst);
    GNUNET_free (p);
    return NULL;
  }
  else if (broadcast == GNUNET_YES)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Starting broadcasting\n");
    setup_broadcast (p, &serverAddrv6, &serverAddrv4);
  }

  api = GNUNET_malloc (sizeof (struct GNUNET_TRANSPORT_PluginFunctions));
  api->cls = p;
  api->send = NULL;
  api->disconnect = &udp_disconnect;
  api->address_pretty_printer = &udp_plugin_address_pretty_printer;
  api->address_to_string = &udp_address_to_string;
  api->string_to_address = &udp_string_to_address;
  api->check_address = &udp_plugin_check_address;
  api->get_session = &udp_plugin_get_session;
  api->send = &udp_plugin_send;

  return api;
}


static int
heap_cleanup_iterator (void *cls,
		       struct GNUNET_CONTAINER_HeapNode *
		       node, void *element,
		       GNUNET_CONTAINER_HeapCostType
		       cost)
{
  struct DefragContext * d_ctx = element;

  GNUNET_CONTAINER_heap_remove_node (node);
  GNUNET_DEFRAGMENT_context_destroy(d_ctx->defrag);
  GNUNET_free (d_ctx);

  return GNUNET_YES;
}


/**
 * The exported method. Makes the core api available via a global and
 * returns the udp transport API.
 *
 * @param cls our 'struct GNUNET_TRANSPORT_PluginEnvironment'
 * @return NULL
 */
void *
libgnunet_plugin_transport_udp_done (void *cls)
{
  struct GNUNET_TRANSPORT_PluginFunctions *api = cls;
  struct Plugin *plugin = api->cls;

  if (NULL == plugin)
  {
    GNUNET_free (api);
    return NULL;
  }

  stop_broadcast (plugin);
  if (plugin->select_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (plugin->select_task);
    plugin->select_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (plugin->select_task_v6 != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (plugin->select_task_v6);
    plugin->select_task_v6 = GNUNET_SCHEDULER_NO_TASK;
  }

  /* Closing sockets */
  if (GNUNET_YES ==plugin->enable_ipv4)
  {
		if (plugin->sockv4 != NULL)
		{
			GNUNET_break (GNUNET_OK == GNUNET_NETWORK_socket_close (plugin->sockv4));
			plugin->sockv4 = NULL;
		}
		GNUNET_NETWORK_fdset_destroy (plugin->rs_v4);
		GNUNET_NETWORK_fdset_destroy (plugin->ws_v4);
  }
  if (GNUNET_YES ==plugin->enable_ipv6)
  {
		if (plugin->sockv6 != NULL)
		{
			GNUNET_break (GNUNET_OK == GNUNET_NETWORK_socket_close (plugin->sockv6));
			plugin->sockv6 = NULL;

			GNUNET_NETWORK_fdset_destroy (plugin->rs_v6);
			GNUNET_NETWORK_fdset_destroy (plugin->ws_v6);
		}
  }
  if (NULL != plugin->nat)
  	GNUNET_NAT_unregister (plugin->nat);

  if (plugin->defrag_ctxs != NULL)
  {
    GNUNET_CONTAINER_heap_iterate(plugin->defrag_ctxs,
        heap_cleanup_iterator, NULL);
    GNUNET_CONTAINER_heap_destroy(plugin->defrag_ctxs);
    plugin->defrag_ctxs = NULL;
  }
  if (plugin->mst != NULL)
  {
    GNUNET_SERVER_mst_destroy(plugin->mst);
    plugin->mst = NULL;
  }

  /* Clean up leftover messages */
  struct UDP_MessageWrapper * udpw;
  udpw = plugin->ipv4_queue_head;
  while (udpw != NULL)
  {
    struct UDP_MessageWrapper *tmp = udpw->next;
    dequeue (plugin, udpw);
    call_continuation(udpw, GNUNET_SYSERR);
    GNUNET_free (udpw);

    udpw = tmp;
  }
  udpw = plugin->ipv6_queue_head;
  while (udpw != NULL)
  {
    struct UDP_MessageWrapper *tmp = udpw->next;
    dequeue (plugin, udpw);
    call_continuation(udpw, GNUNET_SYSERR);
    GNUNET_free (udpw);

    udpw = tmp;
  }

  /* Clean up sessions */
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Cleaning up sessions\n");
  GNUNET_CONTAINER_multihashmap_iterate (plugin->sessions, &disconnect_and_free_it, plugin);
  GNUNET_CONTAINER_multihashmap_destroy (plugin->sessions);

  plugin->nat = NULL;
  GNUNET_free (plugin);
  GNUNET_free (api);
#if DEBUG_MALLOC
  struct Allocation *allocation;
  while (NULL != ahead)
  {
      allocation = ahead;
      GNUNET_CONTAINER_DLL_remove (ahead, atail, allocation);
      GNUNET_free (allocation);
  }
  struct Allocator *allocator;
  while (NULL != aehead)
  {
      allocator = aehead;
      GNUNET_CONTAINER_DLL_remove (aehead, aetail, allocator);
      GNUNET_free (allocator);
  }
#endif
  return NULL;
}


/* end of plugin_transport_udp.c */
