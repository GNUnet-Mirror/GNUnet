/*
     This file is part of GNUnet
     (C) 2010 Christian Grothoff (and other contributing authors)

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
 * @brief Implementation of the UDP NAT punching
 *        transport service
 * @author Christian Grothoff
 * @author Nathan Evans
 *
 * The idea with this transport is to connect gnunet peers to each other
 * when ONE is behind a NAT.  This is based on pwnat (http://samy.pl/pwnat)
 * created by Samy Kamkar.  When configured with the PWNAT options, this
 * transport will start a server daemon which sends dummy ICMP and UDP
 * messages out to a predefined address (typically 1.2.3.4).
 *
 * When a non-NAT'd peer (the client) learns of the NAT'd peer (the server)
 * address, it will send ICMP RESPONSES to the NAT'd peers external address.
 * The NAT box should forward these faked responses to the server, which
 * can then connect directly to the non-NAT'd peer.
 */

#include "platform.h"
#include "gnunet_hello_lib.h"
#include "gnunet_connection_lib.h"
#include "gnunet_container_lib.h"
#include "gnunet_nat_lib.h"
#include "gnunet_os_lib.h"
#include "gnunet_peerinfo_service.h"
#include "gnunet_protocols.h"
#include "gnunet_resolver_service.h"
#include "gnunet_server_lib.h"
#include "gnunet_signatures.h"
#include "gnunet_statistics_service.h"
#include "gnunet_transport_service.h"
#include "gnunet_transport_plugin.h"
#include "transport.h"

#define DEBUG_UDP GNUNET_NO

#define MAX_PROBES 20

/*
 * Transport cost to peer, always 1 for UDP (direct connection)
 */
#define UDP_DIRECT_DISTANCE 1

#define DEFAULT_NAT_PORT 0

/**
 * How long until we give up on transmitting the welcome message?
 */
#define HOSTNAME_RESOLVE_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)

/**
 * Starting port for listening and sending, eventually a config value
 */
#define UDP_NAT_DEFAULT_PORT 22086

/**
 * UDP Message-Packet header.
 */
struct UDPMessage
{
  /**
   * Message header.
   */
  struct GNUNET_MessageHeader header;

  /**
   * What is the identity of the sender (GNUNET_hash of public key)
   */
  struct GNUNET_PeerIdentity sender;

};

/**
 * Network format for IPv4 addresses.
 */
struct IPv4UdpAddress
{
  /**
   * IPv4 address, in network byte order.
   */
  uint32_t ipv4_addr GNUNET_PACKED;

  /**
   * Port number, in network byte order.
   */
  uint16_t u4_port GNUNET_PACKED;
};


/**
 * Network format for IPv6 addresses.
 */
struct IPv6UdpAddress
{
  /**
   * IPv6 address.
   */
  struct in6_addr ipv6_addr GNUNET_PACKED;

  /**
   * Port number, in network byte order.
   */
  uint16_t u6_port GNUNET_PACKED;
};

/* Forward definition */
struct Plugin;

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
   * The address
   */
  void * addr;

  /**
   * address length
   */
  size_t addr_len;

  /**
   * Port to add after the IP address.
   */
  uint16_t port;
};


struct MessageQueue
{
  /**
   * Linked List
   */
  struct MessageQueue *next;

  /**
   * Session this message belongs to
   */
  struct PeerSession *session;

  /**
   * Actual message to be sent
   */
  char *msgbuf;

  /**
   * Size of message buffer to be sent
   */
  size_t msgbuf_size;

  /**
   * When to discard this message
   */
  struct GNUNET_TIME_Absolute timeout;

  /**
   * Continuation to call when this message goes out
   */
  GNUNET_TRANSPORT_TransmitContinuation cont;

  /**
   * closure for continuation
   */
  void *cont_cls;

};

/**
 * UDP NAT Probe message definition
 */
struct UDP_NAT_ProbeMessage
{
  /**
   * Message header
   */
  struct GNUNET_MessageHeader header;

};

/**
 * UDP NAT Probe message reply definition
 */
struct UDP_NAT_ProbeMessageReply
{
  /**
   * Message header
   */
  struct GNUNET_MessageHeader header;

};


/**
 * UDP NAT Probe message confirm definition
 */
struct UDP_NAT_ProbeMessageConfirmation
{
  /**
   * Message header
   */
  struct GNUNET_MessageHeader header;

};


/**
 * UDP NAT "Session"
 */
struct PeerSession
{

  /**
   * Stored in a linked list.
   */
  struct PeerSession *next;

  /**
   * Pointer to the global plugin struct.
   */
  struct Plugin *plugin;

  /**
   * To whom are we talking to (set to our identity
   * if we are still waiting for the welcome message)
   */
  struct GNUNET_PeerIdentity target;

  /**
   * Address of the other peer (either based on our 'connect'
   * call or on our 'accept' call).
   */
  void *connect_addr;

  /**
   * Length of connect_addr.
   */
  size_t connect_alen;

  /**
   * Are we still expecting the welcome message? (GNUNET_YES/GNUNET_NO)
   */
  int expecting_welcome;

  /**
   * From which socket do we need to send to this peer?
   */
  struct GNUNET_NETWORK_Handle *sock;

  /*
   * Queue of messages for this peer, in the case that
   * we have to await a connection...
   */
  struct MessageQueue *messages;

};

struct UDP_NAT_Probes
{

  /**
   * Linked list
   */
  struct UDP_NAT_Probes *next;

  /**
   * Timeout for this set of probes
   */
  struct GNUNET_TIME_Absolute timeout;

  /**
   * Count of how many probes we've attempted
   */
  int count;

  /**
   * The plugin this probe belongs to
   */
  struct Plugin *plugin;

  /**
   * The task used to send these probes
   */
  GNUNET_SCHEDULER_TaskIdentifier task;

  /**
   * Network address (always ipv4!)
   */
  struct IPv4UdpAddress addr;

};


/**
 * Information we keep for each of our listen sockets.
 */
struct UDP_Sock_Info
{
  /**
   * The network handle
   */
  struct GNUNET_NETWORK_Handle *desc;

  /**
   * The port we bound to
   */
  uint16_t port;
};


/**
 * Encapsulation of all of the state of the plugin.
 */
struct Plugin
{
  /**
   * Our environment.
   */
  struct GNUNET_TRANSPORT_PluginEnvironment *env;

  /*
   * Session of peers with whom we are currently connected
   */
  struct PeerSession *sessions;

  /**
   * ID of select task
   */
  GNUNET_SCHEDULER_TaskIdentifier select_task;

  /**
   * Port to listen on.
   */
  uint16_t port;

  /**
   * Address we were told to bind to exclusively (IPv4).
   */
  char *bind_address;

  /**
   * Address we were told to bind to exclusively (IPv6).
   */
  char *bind6_address;

  /**
   * Handle to NAT traversal support.
   */
  struct GNUNET_NAT_Handle *nat;

  /**
   * FD Read set
   */
  struct GNUNET_NETWORK_FDSet *rs;

  /**
   * Probes in flight
   */
  struct UDP_NAT_Probes *probes;

  /**
   * socket that we transmit all IPv4 data with
   */
  struct UDP_Sock_Info udp_sockv4;

  /**
   * socket that we transmit all IPv6 data with
   */
  struct UDP_Sock_Info udp_sockv6;

};


/**
 * Forward declaration.
 */
static void
udp_probe_continuation (void *cls, const struct GNUNET_PeerIdentity *target, int result);


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
  /** TODO: Implement! */
  return;
}


struct PeerSession *
find_session (struct Plugin *plugin,
	      const struct GNUNET_PeerIdentity *peer)
{
  struct PeerSession *pos;

  pos = plugin->sessions;
  while (pos != NULL)
    {
      if (memcmp(&pos->target, peer, sizeof(struct GNUNET_PeerIdentity)) == 0)
        return pos;
      pos = pos->next;
    }

  return pos;
}


/**
 * Actually send out the message, assume we've got the address and
 * send_handle squared away!
 *
 * @param cls closure
 * @param send_handle which handle to send message on
 * @param target who should receive this message (ignored by UDP)
 * @param msgbuf one or more GNUNET_MessageHeader(s) strung together
 * @param msgbuf_size the size of the msgbuf to send
 * @param priority how important is the message (ignored by UDP)
 * @param timeout when should we time out (give up) if we can not transmit?
 * @param addr the addr to send the message to, needs to be a sockaddr for us
 * @param addrlen the len of addr
 * @param cont continuation to call once the message has
 *        been transmitted (or if the transport is ready
 *        for the next transmission call; or if the
 *        peer disconnected...)
 * @param cont_cls closure for cont
 * @return the number of bytes written
 */
static ssize_t
udp_real_send (void *cls,
	       struct GNUNET_NETWORK_Handle *send_handle,
	       const struct GNUNET_PeerIdentity *target,
	       const char *msgbuf,
	       size_t msgbuf_size,
	       unsigned int priority,
	       struct GNUNET_TIME_Relative timeout,
	       const void *addr,
	       size_t addrlen,
	       GNUNET_TRANSPORT_TransmitContinuation cont,
	       void *cont_cls)
{
  struct Plugin *plugin = cls;
  struct UDPMessage *message;
  int ssize;
  ssize_t sent;
  struct sockaddr_in a4;
  struct sockaddr_in6 a6;
  const struct IPv4UdpAddress *t4;
  const struct IPv6UdpAddress *t6;
  const void *sb;
  size_t sbs;

  if (send_handle == NULL)
    {
      /* failed to open send socket for AF */
      if (cont != NULL)
        cont (cont_cls, target, GNUNET_SYSERR);
      return 0;
    }
  if ((addr == NULL) || (addrlen == 0))
    {
#if DEBUG_UDP
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		       "udp_real_send called without address, returning!\n");
#endif
      if (cont != NULL)
        cont (cont_cls, target, GNUNET_SYSERR);
      return 0; /* Can never send if we don't have an address!! */
    }

  /* Build the message to be sent */
  message = GNUNET_malloc (sizeof (struct UDPMessage) + msgbuf_size);
  ssize = sizeof (struct UDPMessage) + msgbuf_size;

  message->header.size = htons (ssize);
  message->header.type = htons (0);
  memcpy (&message->sender, plugin->env->my_identity,
          sizeof (struct GNUNET_PeerIdentity));
  memcpy (&message[1], msgbuf, msgbuf_size);

  if (addrlen == sizeof (struct IPv6UdpAddress))
    {
      t6 = addr;
      memset (&a6, 0, sizeof (a6));
#if HAVE_SOCKADDR_IN_SIN_LEN
      a6.sin6_len = sizeof (a6);
#endif
      a6.sin6_family = AF_INET6;
      a6.sin6_port = t6->u6_port;
      memcpy (&a6.sin6_addr,
              &t6->ipv6_addr,
              sizeof (struct in6_addr));
      sb = &a6;
      sbs = sizeof (a6);
    }
  else if (addrlen == sizeof (struct IPv4UdpAddress))
    {
      t4 = addr;
      memset (&a4, 0, sizeof (a4));
#if HAVE_SOCKADDR_IN_SIN_LEN
      a4.sin_len = sizeof (a4);
#endif
      a4.sin_family = AF_INET;
      a4.sin_port = t4->u4_port;
      a4.sin_addr.s_addr = t4->ipv4_addr;
      sb = &a4;
      sbs = sizeof (a4);
    }
  else
    {
      GNUNET_break_op (0);
      GNUNET_free (message);
      return -1;
    }

  /* Actually send the message */
  sent =
    GNUNET_NETWORK_socket_sendto (send_handle, message, ssize,
                                  sb,
                                  sbs);
  if (GNUNET_SYSERR == sent)
    GNUNET_log_strerror(GNUNET_ERROR_TYPE_DEBUG, "sendto");
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
	      "UDP transmit %u-byte message to %s (%d: %s)\n",
	      (unsigned int) ssize,
	      GNUNET_a2s (sb, sbs),
	      (int) sent,
	      (sent < 0) ? STRERROR (errno) : "ok");
  if (cont != NULL)
    {
      if (sent == GNUNET_SYSERR)
        cont (cont_cls, target, GNUNET_SYSERR);
      else
        {
          cont (cont_cls, target, GNUNET_OK);
        }
    }

  GNUNET_free (message);
  return sent;
}


/**
 * Function that can be used by the transport service to transmit
 * a message using the plugin.
 *
 * @param cls closure
 * @param target who should receive this message (ignored by UDP)
 * @param msgbuf one or more GNUNET_MessageHeader(s) strung together
 * @param msgbuf_size the size of the msgbuf to send
 * @param priority how important is the message (ignored by UDP)
 * @param timeout when should we time out (give up) if we can not transmit?
 * @param session identifier used for this session (can be NULL)
 * @param addr the addr to send the message to, needs to be a sockaddr for us
 * @param addrlen the len of addr
 * @param force_address not used, we had better have an address to send to
 *        because we are stateless!!
 * @param cont continuation to call once the message has
 *        been transmitted (or if the transport is ready
 *        for the next transmission call; or if the
 *        peer disconnected...)
 * @param cont_cls closure for cont
 *
 * @return the number of bytes written (may return 0 and the message can
 *         still be transmitted later!)
 */
static ssize_t
udp_plugin_send (void *cls,
		     const struct GNUNET_PeerIdentity *target,
		     const char *msgbuf,
		     size_t msgbuf_size,
		     unsigned int priority,
		     struct GNUNET_TIME_Relative timeout,
		     struct Session *session,
		     const void *addr,
		     size_t addrlen,
		     int force_address,
		     GNUNET_TRANSPORT_TransmitContinuation cont, void *cont_cls)
{
  struct Plugin *plugin = cls;
  ssize_t sent;
  struct MessageQueue *temp_message;
  struct PeerSession *peer_session;
  int other_peer_natd;
  const struct IPv4UdpAddress *t4;
  struct sockaddr_in sin4;

  if (force_address == GNUNET_SYSERR)
    return GNUNET_SYSERR;
  GNUNET_assert (NULL == session);

  other_peer_natd = GNUNET_NO;
  if (addrlen == sizeof(struct IPv4UdpAddress))
    {
      t4 = addr;
      if (ntohs(t4->u4_port) == 0)
        other_peer_natd = GNUNET_YES;
    }
  else if (addrlen != sizeof(struct IPv6UdpAddress))
    {
      GNUNET_break_op(0);
      return -1; /* Must have an address to send to */
    }

  sent = 0;
  if ( (other_peer_natd == GNUNET_YES) &&
       (addrlen == sizeof(struct IPv4UdpAddress)) )
    {
      peer_session = find_session(plugin, target);
      if (peer_session == NULL) /* We have a new peer to add */
        {
          /*
           * The first time, we can assume we have no knowledge of a
           * working port for this peer, call the ICMP/UDP message sender
           * and wait...
           */
          peer_session = GNUNET_malloc(sizeof(struct PeerSession));
          peer_session->connect_addr = GNUNET_malloc(addrlen);
          memcpy(peer_session->connect_addr, addr, addrlen);
          peer_session->connect_alen = addrlen;
          peer_session->plugin = plugin;
          peer_session->sock = NULL;
          memcpy(&peer_session->target, target, sizeof(struct GNUNET_PeerIdentity));
          peer_session->expecting_welcome = GNUNET_YES;

          peer_session->next = plugin->sessions;
          plugin->sessions = peer_session;

          peer_session->messages = GNUNET_malloc(sizeof(struct MessageQueue));
          peer_session->messages->msgbuf = GNUNET_malloc(msgbuf_size);
          memcpy(peer_session->messages->msgbuf, msgbuf, msgbuf_size);
          peer_session->messages->msgbuf_size = msgbuf_size;
          peer_session->messages->timeout = GNUNET_TIME_relative_to_absolute(timeout);
          peer_session->messages->cont = cont;
          peer_session->messages->cont_cls = cont_cls;
#if DEBUG_UDP
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                          _("Other peer is NAT'd, set up peer session for peer %s\n"), GNUNET_i2s(target));
#endif
	  memset (&sin4, 0, sizeof (sin4));
	  sin4.sin_family = AF_INET;
#if HAVE_SOCKADDR_IN_SIN_LEN
          sin4.sin_len = sizeof (sin4);
#endif
	  sin4.sin_port = t4->u4_port;
	  sin4.sin_addr.s_addr = t4->ipv4_addr;
          GNUNET_NAT_run_client (plugin->nat, &sin4);
        }
      else
        {
          if (peer_session->expecting_welcome == GNUNET_NO) /* We are "connected" */
            {
              sent = udp_real_send(cls,
				   peer_session->sock,
				   target,
				   msgbuf, msgbuf_size,
				   priority, timeout,
				   peer_session->connect_addr, peer_session->connect_alen,
				   cont, cont_cls);
            }
          else /* Haven't gotten a response from this peer, queue message */
            {
              temp_message = GNUNET_malloc(sizeof(struct MessageQueue));
              temp_message->msgbuf = GNUNET_malloc(msgbuf_size);
              memcpy(temp_message->msgbuf, msgbuf, msgbuf_size);
              temp_message->msgbuf_size = msgbuf_size;
              temp_message->timeout = GNUNET_TIME_relative_to_absolute(timeout);
              temp_message->cont = cont;
              temp_message->cont_cls = cont_cls;
              temp_message->next = peer_session->messages;
              peer_session->messages = temp_message;
            }
        }
    }
  else if (other_peer_natd == GNUNET_NO) /* Other peer not behind a NAT, so we can just send the message as is */
    {
      sent = udp_real_send(cls,
			   (addrlen == sizeof (struct IPv4UdpAddress)) ? plugin->udp_sockv4.desc : plugin->udp_sockv6.desc,
			   target,
			   msgbuf, msgbuf_size,
			   priority, timeout, addr, addrlen,
			   cont, cont_cls);
    }
  else /* Other peer is NAT'd, but we don't want to play with them (or can't!) */
    {
      return GNUNET_SYSERR;
    }

  /* When GNUNET_SYSERR is returned from udp_real_send, we will still call
   * the callback so must not return GNUNET_SYSERR!
   * If we did, then transport context would get freed twice. */
  if (sent == GNUNET_SYSERR)
    return 0;
  return sent;
}


/**
 * Send UDP probe messages or UDP keepalive messages, depending on the
 * state of the connection.
 *
 * @param cls closure for this call (should be the main Plugin)
 * @param tc task context for running this
 */
static void
send_udp_probe_message (void *cls, 
			const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct UDP_NAT_Probes *probe = cls;
  struct UDP_NAT_ProbeMessage message;
  struct Plugin *plugin = probe->plugin;

  memset (&message, 0, sizeof (message));
  message.header.size = htons(sizeof(struct UDP_NAT_ProbeMessage));
  message.header.type = htons(GNUNET_MESSAGE_TYPE_TRANSPORT_UDP_NAT_PROBE);
  /* If they gave us a port, use that.  If not, try our port. */
  if (ntohs(probe->addr.u4_port) == 0)
    probe->addr.u4_port = htons(plugin->port);

#if DEBUG_UDP
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      _("Sending a probe to port %d\n"), ntohs(probe->addr.u4_port));
#endif
  probe->count++;
  udp_real_send(plugin,
		plugin->udp_sockv4.desc,
		NULL,
		(char *)&message, ntohs(message.header.size), 0,
		GNUNET_TIME_relative_get_unit(),
		&probe->addr, sizeof(struct IPv4UdpAddress),
		&udp_probe_continuation, probe);
}


/**
 * Continuation for probe sends.  If the last probe was sent
 * "successfully", schedule sending of another one.  If not,
 * FIXME...
 */
static void
udp_probe_continuation (void *cls, 
			const struct GNUNET_PeerIdentity *target, 
			int result)
{
  struct UDP_NAT_Probes *probe = cls;
  /*struct Plugin *plugin = probe->plugin;*/

  if ((result == GNUNET_OK) && (probe->count < MAX_PROBES))
    {
#if DEBUG_UDP
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  _("Scheduling next probe for 10000 milliseconds\n"));
#endif
      probe->task = GNUNET_SCHEDULER_add_delayed(GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 10), 
						 &send_udp_probe_message, probe);
    }
  else /* Destroy the probe context. */
    {
#if DEBUG_UDP
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  _("Sending probe didn't go well...\n"));
#endif
    }
}


/**
 * FIXME.
 */
static void
udp_plugin_reversal_callback (void *cls,
			      const struct sockaddr *addr,
			      socklen_t addrlen)
{
  struct Plugin *plugin = cls;
  struct UDP_NAT_Probes *temp_probe;
  const struct sockaddr_in *inaddr;

  if (sizeof (struct sockaddr_in) != addrlen)
    {
      GNUNET_break (0);
      return;
    }
  inaddr = (const struct sockaddr_in *) addr;
  temp_probe = GNUNET_malloc(sizeof(struct UDP_NAT_Probes));
  temp_probe->addr.ipv4_addr = inaddr->sin_addr.s_addr;
  temp_probe->addr.u4_port = inaddr->sin_port;
  temp_probe->next = plugin->probes;
  temp_probe->plugin = plugin;
  temp_probe->task = GNUNET_SCHEDULER_add_delayed(GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MILLISECONDS, 500), 
						  &send_udp_probe_message, 
						  temp_probe);
  plugin->probes = temp_probe;
}


/**
 * Demultiplexer for UDP NAT messages
 *
 * @param plugin the main plugin for this transport
 * @param sender from which peer the message was received
 * @param currhdr pointer to the header of the message
 * @param sender_addr the address from which the message was received
 * @param fromlen the length of the address
 * @param sockinfo which socket did we receive the message on
 */
static void
udp_demultiplexer(struct Plugin *plugin, 
		  struct GNUNET_PeerIdentity *sender,
                  const struct GNUNET_MessageHeader *currhdr,
                  const void *sender_addr,
                  size_t fromlen, struct UDP_Sock_Info *sockinfo)
{
  struct UDP_NAT_ProbeMessageReply *outgoing_probe_reply;
  struct PeerSession *peer_session;
  struct MessageQueue *pending_message;
  struct MessageQueue *pending_message_temp;
  uint16_t incoming_port;
  struct GNUNET_TRANSPORT_ATS_Information distance[2];
  if (memcmp(sender, plugin->env->my_identity, sizeof(struct GNUNET_PeerIdentity)) == 0)
    {
#if DEBUG_UDP
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "udp",
                      _("Received a message from myself, dropping!!!\n"));
#endif
      return;
    }

  incoming_port = 0;
  GNUNET_assert(sender_addr != NULL); /* Can recvfrom have a NULL address? */
  if (fromlen == sizeof(struct IPv4UdpAddress))
    {
      incoming_port = ntohs(((struct IPv4UdpAddress *)sender_addr)->u4_port);
    }
  else if (fromlen == sizeof(struct IPv6UdpAddress))
    {
      incoming_port = ntohs(((struct IPv6UdpAddress *)sender_addr)->u6_port);
    }

  switch (ntohs(currhdr->type))
  {
    case GNUNET_MESSAGE_TYPE_TRANSPORT_UDP_NAT_PROBE:
      /* Send probe reply */
      outgoing_probe_reply = GNUNET_malloc(sizeof(struct UDP_NAT_ProbeMessageReply));
      outgoing_probe_reply->header.size = htons(sizeof(struct UDP_NAT_ProbeMessageReply));
      outgoing_probe_reply->header.type = htons(GNUNET_MESSAGE_TYPE_TRANSPORT_UDP_NAT_PROBE_REPLY);

#if DEBUG_UDP
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  _("Received a probe on listen port %d, sent_from port %d\n"),
                   sockinfo->port, incoming_port);
#endif

      udp_real_send(plugin, sockinfo->desc, NULL,
                    (char *)outgoing_probe_reply,
                    ntohs(outgoing_probe_reply->header.size), 0,
                    GNUNET_TIME_relative_get_unit(),
                    sender_addr, fromlen,
                    NULL, NULL);

#if DEBUG_UDP
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  _("Sent PROBE REPLY to port %d on outgoing port %d\n"),
                   incoming_port, sockinfo->port);
#endif
      GNUNET_free(outgoing_probe_reply);
      break;
    case GNUNET_MESSAGE_TYPE_TRANSPORT_UDP_NAT_PROBE_REPLY:
      /* Check for existing probe, check ports returned, send confirmation if all is well */
#if DEBUG_UDP
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  _("Received PROBE REPLY from port %d on incoming port %d\n"), incoming_port, sockinfo->port);
#endif
      if (fromlen == sizeof(struct IPv4UdpAddress))
        {
	  /* FIXME! */
#if 0
  struct UDP_NAT_ProbeMessageConfirmation *outgoing_probe_confirmation;
  struct UDP_NAT_Probes *outgoing_probe;
          outgoing_probe = find_probe(plugin, &addr_buf[0]);
          if (outgoing_probe != NULL)
            {
#if DEBUG_UDP
              GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                          _("Sending confirmation that we were reached!\n"));
#endif
              outgoing_probe_confirmation = GNUNET_malloc(sizeof(struct UDP_NAT_ProbeMessageConfirmation));
              outgoing_probe_confirmation->header.size = htons(sizeof(struct UDP_NAT_ProbeMessageConfirmation));
              outgoing_probe_confirmation->header.type = htons(GNUNET_MESSAGE_TYPE_TRANSPORT_UDP_NAT_PROBE_CONFIRM);
              udp_real_send(plugin, sockinfo->desc, NULL,
			    (char *)outgoing_probe_confirmation,
			    ntohs(outgoing_probe_confirmation->header.size), 0,
			    GNUNET_TIME_relative_get_unit(),
			    sender_addr, fromlen, NULL, NULL);

              if (outgoing_probe->task != GNUNET_SCHEDULER_NO_TASK)
                {
                  GNUNET_SCHEDULER_cancel(outgoing_probe->task);
                  outgoing_probe->task = GNUNET_SCHEDULER_NO_TASK;
                  /* Schedule task to timeout and remove probe if confirmation not received */
                }
              GNUNET_free(outgoing_probe_confirmation);
            }
          else
            {
#if DEBUG_UDP
              GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                          _("Received a probe reply, but have no record of a sent probe!\n"));
#endif
            }
#endif
        }
      else
        {
#if DEBUG_UDP
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      _("Received a probe reply, but sender address size is WRONG (should be %d, is %d)!\n"), sizeof(struct IPv4UdpAddress), fromlen);
#endif
        }
      break;
    case GNUNET_MESSAGE_TYPE_TRANSPORT_UDP_NAT_PROBE_CONFIRM:
      peer_session = find_session(plugin, sender);
#if DEBUG_UDP
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      _("Looking up peer session for peer %s\n"), GNUNET_i2s(sender));
#endif
      if (peer_session == NULL) /* Shouldn't this NOT happen? */
        {
#if DEBUG_UDP
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      _("Peer not in list, adding (THIS MAY BE A MISTAKE) %s\n"), GNUNET_i2s(sender));
#endif
          peer_session = GNUNET_malloc(sizeof(struct PeerSession));
          peer_session->connect_addr = GNUNET_malloc(fromlen);
          memcpy(peer_session->connect_addr, sender_addr, fromlen);
          peer_session->connect_alen = fromlen;
          peer_session->plugin = plugin;
          peer_session->sock = sockinfo->desc;
          memcpy(&peer_session->target, sender, sizeof(struct GNUNET_PeerIdentity));
          peer_session->expecting_welcome = GNUNET_NO;

          peer_session->next = plugin->sessions;
          plugin->sessions = peer_session;

          peer_session->messages = NULL;
        }
      else if (peer_session->expecting_welcome == GNUNET_YES)
        {
          peer_session->expecting_welcome = GNUNET_NO;
          peer_session->sock = sockinfo->desc;
          if (peer_session->connect_alen == sizeof(struct IPv4UdpAddress))
            {
              ((struct IPv4UdpAddress *)peer_session->connect_addr)->u4_port = htons(incoming_port);
            }
          else if (peer_session->connect_alen == sizeof(struct IPv4UdpAddress))
            {
              ((struct IPv6UdpAddress *)peer_session->connect_addr)->u6_port = htons(incoming_port);
            }

#if DEBUG_UDP
              GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                          _("Received a probe confirmation, will send to peer on port %d\n"), incoming_port);
#endif
          if (peer_session->messages != NULL)
            {
#if DEBUG_UDP
              GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                          _("Received a probe confirmation, sending queued messages.\n"));
#endif
              pending_message = peer_session->messages;
              int count = 0;
              while (pending_message != NULL)
                {
#if DEBUG_UDP
                  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                              _("sending queued message %d\n"), count);
#endif
                  udp_real_send(plugin,
                                peer_session->sock,
                                &peer_session->target,
                                pending_message->msgbuf,
                                pending_message->msgbuf_size, 0,
                                GNUNET_TIME_relative_get_unit(),
                                peer_session->connect_addr,
                                peer_session->connect_alen,
                                pending_message->cont,
                                pending_message->cont_cls);

                  pending_message_temp = pending_message;
                  pending_message = pending_message->next;
                  GNUNET_free(pending_message_temp->msgbuf);
                  GNUNET_free(pending_message_temp);
#if DEBUG_UDP
                  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                              _("finished sending queued message %d\n"), count);
#endif
                  count++;
                }
            }

        }
      else
        {
#if DEBUG_UDP
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      _("Received probe confirmation for already confirmed peer!\n"));
#endif
        }
      /* Received confirmation, add peer with address/port specified */
      break;
    case GNUNET_MESSAGE_TYPE_TRANSPORT_UDP_NAT_PROBE_KEEPALIVE:
      /* Once we've sent NAT_PROBE_CONFIRM change to sending keepalives */
      /* If we receive these just ignore! */
      break;
    default:

#if DEBUG_UDP
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Sending message type %d to transport!\n",
                  ntohs(currhdr->type));
#endif

      distance[0].type = htonl (GNUNET_TRANSPORT_ATS_QUALITY_NET_DISTANCE);
      distance[0].value = htonl (UDP_DIRECT_DISTANCE);
      distance[1].type = htonl (GNUNET_TRANSPORT_ATS_ARRAY_TERMINATOR);
      distance[1].value = htonl (0);

      plugin->env->receive (plugin->env->cls, sender, currhdr,
    		    (const struct GNUNET_TRANSPORT_ATS_Information *) &distance, 2,
			    NULL, sender_addr, fromlen);
  }

}


/*
 * We have been notified that our writeset has something to read.  We don't
 * know which socket needs to be read, so we have to check each one
 * Then reschedule this function to be called again once more is available.
 *
 * @param cls the plugin handle
 * @param tc the scheduling context (for rescheduling this function again)
 */
static void
udp_plugin_select (void *cls,
		   const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Plugin *plugin = cls;
  char buf[65536];
  struct UDPMessage *msg;
  struct GNUNET_PeerIdentity sender;
  socklen_t fromlen;
  char addr[32];
  ssize_t ret;
  int offset;
  int tsize;
  char *msgbuf;
  const struct GNUNET_MessageHeader *currhdr;
  struct IPv4UdpAddress t4;
  struct IPv6UdpAddress t6;
  const struct sockaddr_in *s4;
  const struct sockaddr_in6 *s6;
  const void *ca;
  size_t calen;
  struct UDP_Sock_Info *udp_sock;
  uint16_t csize;

  plugin->select_task = GNUNET_SCHEDULER_NO_TASK;
  if ( (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) != 0)
    return;
  udp_sock = NULL;
  if (GNUNET_NETWORK_fdset_isset (tc->read_ready,
				  plugin->udp_sockv4.desc))
    udp_sock = &plugin->udp_sockv4;
  else if (GNUNET_NETWORK_fdset_isset (tc->read_ready,
				       plugin->udp_sockv6.desc))
    udp_sock = &plugin->udp_sockv6;
  if (NULL == udp_sock)
    {
      GNUNET_break (0);
      return;
    }
  fromlen = sizeof (addr);
  memset (&addr, 0, sizeof(addr));
  ret =
    GNUNET_NETWORK_socket_recvfrom (udp_sock->desc, buf, sizeof (buf),
                                    (struct sockaddr *)&addr, &fromlen);

  if (AF_INET == ((struct sockaddr *)addr)->sa_family)
    {
      s4 = (const struct sockaddr_in*) &addr;
      t4.u4_port = s4->sin_port;
      t4.ipv4_addr = s4->sin_addr.s_addr;
      ca = &t4;
      calen = sizeof (t4);
    }
  else if (AF_INET6 == ((struct sockaddr *)addr)->sa_family)
    {
      s6 = (const struct sockaddr_in6*) &addr;
      t6.u6_port = s6->sin6_port;
      memcpy (&t6.ipv6_addr,
              &s6->sin6_addr,
              sizeof (struct in6_addr));
      ca = &t6;
      calen = sizeof (t6);
    }
  else
    {
      GNUNET_break (0);
      ca = NULL;
      calen = 0;
    }
  if (ret < sizeof (struct UDPMessage))
    {
      GNUNET_break_op (0);
      plugin->select_task =
	GNUNET_SCHEDULER_add_select (GNUNET_SCHEDULER_PRIORITY_DEFAULT,
				     GNUNET_SCHEDULER_NO_TASK,
				     GNUNET_TIME_UNIT_FOREVER_REL, plugin->rs,
				     NULL, &udp_plugin_select, plugin);
      return;
    }
  msg = (struct UDPMessage *) buf;
  csize = ntohs (msg->header.size);
  if ( (csize < sizeof (struct UDPMessage)) ||
       (csize > ret) )
    {
      GNUNET_break_op (0);
      plugin->select_task =
	GNUNET_SCHEDULER_add_select (GNUNET_SCHEDULER_PRIORITY_DEFAULT,
				     GNUNET_SCHEDULER_NO_TASK,
				     GNUNET_TIME_UNIT_FOREVER_REL, plugin->rs,
				     NULL, &udp_plugin_select, plugin);
      return;
    }
  msgbuf = (char *)&msg[1];
  memcpy (&sender, &msg->sender, sizeof (struct GNUNET_PeerIdentity));
  offset = 0;
  tsize = csize - sizeof (struct UDPMessage);
  while (offset + sizeof (struct GNUNET_MessageHeader) <= tsize)
    {
      currhdr = (struct GNUNET_MessageHeader *)&msgbuf[offset];
      csize = ntohs (currhdr->size);
      if ( (csize < sizeof (struct GNUNET_MessageHeader)) ||
	   (csize > tsize - offset) )
	{
	  GNUNET_break_op (0);
	  break;
	}
      udp_demultiplexer(plugin, &sender, currhdr, 
			ca, calen, udp_sock);
      offset += csize;
    }
  plugin->select_task =
    GNUNET_SCHEDULER_add_select (GNUNET_SCHEDULER_PRIORITY_DEFAULT,
                                 GNUNET_SCHEDULER_NO_TASK,
                                 GNUNET_TIME_UNIT_FOREVER_REL, plugin->rs,
                                 NULL, &udp_plugin_select, plugin);

}


/**
 * Check if the given port is plausible (must be either
 * our listen port or our advertised port).  If it is
 * neither, we return GNUNET_SYSERR.
 *
 * @param plugin global variables
 * @param in_port port number to check
 * @return GNUNET_OK if port is either open_port or adv_port
 */
static int
check_port (struct Plugin *plugin, uint16_t in_port)
{
  if (in_port == 0)
    return GNUNET_OK;
  if (in_port == plugin->port)
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
udp_plugin_check_address (void *cls,
			  const void *addr,
			  size_t addrlen)
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
      if (GNUNET_OK !=
	  check_port (plugin, ntohs (v4->u4_port)))
	return GNUNET_SYSERR;
      if (GNUNET_OK !=
	  GNUNET_NAT_test_address (plugin->nat, 
				   &v4->ipv4_addr, sizeof (struct in_addr)))
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
      if (GNUNET_OK !=
	  check_port (plugin, ntohs (v6->u6_port)))
	return GNUNET_SYSERR;
      if (GNUNET_OK !=
	  GNUNET_NAT_test_address (plugin->nat,
				   &v6->ipv6_addr, sizeof (struct in6_addr)))
	return GNUNET_SYSERR;
    }
  return GNUNET_OK;
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
static const char*
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
    return NULL;
  inet_ntop (af, sb, buf, INET6_ADDRSTRLEN);
  GNUNET_snprintf (rbuf,
                   sizeof (rbuf),
                   "%s:%u",
                   buf,
                   port);
  return rbuf;
}



/**
 * Append our port and forward the result.
 */
static void
append_port (void *cls, const char *hostname)
{
  struct PrettyPrinterContext *ppc = cls;
  char *ret;

  if (hostname == NULL)
    {
      ret = strdup(udp_address_to_string(NULL, ppc->addr, ppc->addr_len));
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Error in name resolution: `%s'\n",ret);
      ppc->asc (ppc->asc_cls, ret);
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
udp_plugin_address_pretty_printer (void *cls,
                                   const char *type,
                                   const void *addr,
                                   size_t addrlen,
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
      a6.sin6_port = u6->u6_port;
      memcpy (&a6.sin6_addr,
              &u6->ipv6_addr,
              sizeof (struct in6_addr));
      port = ntohs (u6->u6_port);
      sb = &a6;
      sbs = sizeof (a6);
    }
  else if (addrlen == sizeof (struct IPv4UdpAddress))
    {
      u4 = addr;
      memset (&a4, 0, sizeof (a4));
      a4.sin_family = AF_INET;
      a4.sin_port = u4->u4_port;
      a4.sin_addr.s_addr = u4->ipv4_addr;
      port = ntohs (u4->u4_port);
      sb = &a4;
      sbs = sizeof (a4);
    }
  else
    {
      /* invalid address */
      GNUNET_break_op (0);
      asc (asc_cls, NULL);
      return;
    }
  ppc = GNUNET_malloc (sizeof (struct PrettyPrinterContext) + addrlen);
  ppc->asc = asc;
  ppc->asc_cls = asc_cls;
  ppc->port = port;
  ppc->addr = &ppc[1];
  ppc->addr_len = addrlen;
  memcpy(ppc->addr, addr, addrlen);
  GNUNET_RESOLVER_hostname_get (sb,
                                sbs,
                                !numeric, timeout, &append_port, ppc);
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
udp_nat_port_map_callback (void *cls,
		       int add_remove,
		       const struct sockaddr *addr,
		       socklen_t addrlen)
{
  struct Plugin *plugin = cls;
  struct IPv4UdpAddress u4;
  struct IPv6UdpAddress u6;
  void *arg;
  size_t args;

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
      memcpy (&u6.ipv6_addr,
	      &((struct sockaddr_in6 *) addr)->sin6_addr,
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
  plugin->env->notify_address (plugin->env->cls,
			       add_remove,
			       arg, args);
}


/**
 * The exported method. Makes the core api available via a global and
 * returns the udp transport API.
 */
void *
libgnunet_plugin_transport_udp_init (void *cls)
{
  struct GNUNET_TRANSPORT_PluginEnvironment *env = cls;
  unsigned long long mtu;
  unsigned long long port;
  struct GNUNET_TRANSPORT_PluginFunctions *api;
  struct Plugin *plugin;
  int sockets_created;
  struct sockaddr_in serverAddrv4;
  struct sockaddr_in6 serverAddrv6;
  struct sockaddr *serverAddr;
  struct sockaddr *addrs[2];
  socklen_t addrlens[2];
  socklen_t addrlen;
  unsigned int tries;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (env->cfg,
					     "transport-udp",
					     "PORT",
					     &port))
    port = UDP_NAT_DEFAULT_PORT;
  if (port > 65535)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _("Given `%s' option is out of range: %llu > %u\n"),
                  "PORT",
                  port,
                  65535);
      return NULL;
    }

  mtu = 1240;
  if (mtu < 1200)
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _("MTU %llu for `%s' is probably too low!\n"), mtu,
                "UDP");
  plugin = GNUNET_malloc (sizeof (struct Plugin));
  plugin->port = port;
  plugin->env = env;
  api = GNUNET_malloc (sizeof (struct GNUNET_TRANSPORT_PluginFunctions));
  api->cls = plugin;

  api->send = &udp_plugin_send;
  api->disconnect = &udp_disconnect;
  api->address_pretty_printer = &udp_plugin_address_pretty_printer;
  api->address_to_string = &udp_address_to_string;
  api->check_address = &udp_plugin_check_address;

  if (GNUNET_YES == GNUNET_CONFIGURATION_get_value_string(env->cfg, 
							  "transport-udp", 
							  "BINDTO", 
							  &plugin->bind_address))
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, 
	       "Binding udp plugin to specific address: `%s'\n", 
	       plugin->bind_address);
  if (GNUNET_YES == GNUNET_CONFIGURATION_get_value_string(env->cfg, 
							  "transport-udp",
							  "BINDTO6", 
							  &plugin->bind6_address))
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
	       "Binding udp plugin to specific address: `%s'\n",
	       plugin->bind6_address);

  sockets_created = 0;
  if ( (GNUNET_YES !=
	GNUNET_CONFIGURATION_get_value_yesno (plugin->env->cfg,
					      "gnunetd",
					      "DISABLEV6")))
    {
      plugin->udp_sockv6.desc = GNUNET_NETWORK_socket_create (PF_INET6, SOCK_DGRAM, 0);
      if (NULL == plugin->udp_sockv6.desc)
	{
	  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "udp", "socket");
	}
      else
	{
          memset (&serverAddrv6, 0, sizeof (serverAddrv6));
#if HAVE_SOCKADDR_IN_SIN_LEN
          serverAddrv6.sin6_len = sizeof (serverAddrv6);
#endif

          serverAddrv6.sin6_family = AF_INET6;
          serverAddrv6.sin6_addr = in6addr_any;
          if (plugin->bind6_address != NULL)
            {
              if (1 != inet_pton(AF_INET6, plugin->bind6_address, &serverAddrv6.sin6_addr))
                return 0;
            }
          serverAddrv6.sin6_port = htons (plugin->port);
          addrlen = sizeof (serverAddrv6);
          serverAddr = (struct sockaddr *) &serverAddrv6;
#if DEBUG_UDP
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
			   "Binding to IPv6 port %d\n",
			   ntohs(serverAddrv6.sin6_port));
#endif
	  tries = 0;
	  while (GNUNET_NETWORK_socket_bind (plugin->udp_sockv6.desc, serverAddr, addrlen) !=
		 GNUNET_OK)
	    {
	      serverAddrv6.sin6_port
		= htons (GNUNET_CRYPTO_random_u32(GNUNET_CRYPTO_QUALITY_STRONG, 33537) + 32000); /* Find a good, non-root port */
#if DEBUG_UDP
	      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
			       "IPv6 Binding failed, trying new port %d\n",
			       ntohs(serverAddrv6.sin6_port));
#endif
	      tries++;
	      if (tries > 10)
		{
		  GNUNET_NETWORK_socket_close (plugin->udp_sockv6.desc);
		  plugin->udp_sockv6.desc = NULL;
		  break;
		}	
	    }
	  if (plugin->udp_sockv6.desc != NULL)
	    {
	      plugin->udp_sockv6.port = ntohs(serverAddrv6.sin6_port);
	      addrs[sockets_created] = (struct sockaddr*)  &serverAddrv6;
	      addrlens[sockets_created] = sizeof (serverAddrv6);
	      sockets_created++;
	    }
	}
    }

  plugin->udp_sockv4.desc = GNUNET_NETWORK_socket_create (PF_INET, SOCK_DGRAM, 0);
  if (NULL == plugin->udp_sockv4.desc)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "socket");
    }
  else
    {
      memset (&serverAddrv4, 0, sizeof (serverAddrv4));
#if HAVE_SOCKADDR_IN_SIN_LEN
      serverAddrv4.sin_len = sizeof (serverAddrv4);
#endif
      serverAddrv4.sin_family = AF_INET;
      serverAddrv4.sin_addr.s_addr = INADDR_ANY;
      if (plugin->bind_address != NULL)
        {
          if (1 != inet_pton(AF_INET, plugin->bind_address, &serverAddrv4.sin_addr))
            return 0;
        }
      serverAddrv4.sin_port = htons (plugin->port);
      addrlen = sizeof (serverAddrv4);
      serverAddr = (struct sockaddr *) &serverAddrv4;
#if DEBUG_UDP
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		       "Binding to IPv4 port %d\n",
		       ntohs(serverAddrv4.sin_port));
#endif
      tries = 0;
      while (GNUNET_NETWORK_socket_bind (plugin->udp_sockv4.desc, serverAddr, addrlen) !=
	     GNUNET_OK)
	{
	  serverAddrv4.sin_port = htons (GNUNET_CRYPTO_random_u32(GNUNET_CRYPTO_QUALITY_STRONG, 33537) + 32000); /* Find a good, non-root port */
#if DEBUG_UDP
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
			   "IPv4 Binding failed, trying new port %d\n",
			   ntohs(serverAddrv4.sin_port));
#endif
	  tries++;
	  if (tries > 10)
	    {
	      GNUNET_NETWORK_socket_close (plugin->udp_sockv4.desc);
	      plugin->udp_sockv4.desc = NULL;
	      break;
	    }	
	}
      if (plugin->udp_sockv4.desc != NULL)
	{
	  plugin->udp_sockv4.port = ntohs(serverAddrv4.sin_port);
	  addrs[sockets_created] = (struct sockaddr*) &serverAddrv4;
	  addrlens[sockets_created] = sizeof (serverAddrv4);
	  sockets_created++;
	}
    }

  plugin->rs = GNUNET_NETWORK_fdset_create ();
  GNUNET_NETWORK_fdset_zero (plugin->rs);
  if (NULL != plugin->udp_sockv4.desc)
    GNUNET_NETWORK_fdset_set (plugin->rs,
			      plugin->udp_sockv4.desc);
  if (NULL != plugin->udp_sockv6.desc)
    GNUNET_NETWORK_fdset_set (plugin->rs,
			      plugin->udp_sockv6.desc);

  plugin->select_task =
    GNUNET_SCHEDULER_add_select (GNUNET_SCHEDULER_PRIORITY_DEFAULT,
                                 GNUNET_SCHEDULER_NO_TASK,
                                 GNUNET_TIME_UNIT_FOREVER_REL, plugin->rs,
                                 NULL, &udp_plugin_select, plugin);
  if (sockets_created == 0)
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		_("Failed to open UDP sockets\n"));
  plugin->nat = GNUNET_NAT_register (env->cfg,
				     GNUNET_NO,
				     port,
				     sockets_created,
				     (const struct sockaddr**) addrs, addrlens,
				     &udp_nat_port_map_callback, 
				     &udp_plugin_reversal_callback,
				     plugin);
  return api;
}


void *
libgnunet_plugin_transport_udp_done (void *cls)
{
  struct GNUNET_TRANSPORT_PluginFunctions *api = cls;
  struct Plugin *plugin = api->cls;

  if (plugin->select_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (plugin->select_task);
      plugin->select_task = GNUNET_SCHEDULER_NO_TASK;
    }
  if (plugin->udp_sockv4.desc != NULL)
    {
      GNUNET_break (GNUNET_OK == GNUNET_NETWORK_socket_close (plugin->udp_sockv4.desc));
      plugin->udp_sockv4.desc = NULL;
    }
  if (plugin->udp_sockv6.desc != NULL)
    {
      GNUNET_break (GNUNET_OK == GNUNET_NETWORK_socket_close (plugin->udp_sockv6.desc));
      plugin->udp_sockv6.desc = NULL;
    }
  GNUNET_NETWORK_fdset_destroy (plugin->rs);
  GNUNET_NAT_unregister (plugin->nat);
  plugin->nat = NULL;
  GNUNET_free (plugin);
  GNUNET_free (api);
  return NULL;
}

/* end of plugin_transport_udp.c */
