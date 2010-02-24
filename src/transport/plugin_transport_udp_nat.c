/*
     This file is part of GNUnet
     (C) 2010 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
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
 * when one or both is behind a NAT.  This is based on pwnat
 * (http://samy.pl/pwnat) created by Samy Kamkar.  This transport will
 * take external IP addresses for a NAT'd peer, start a server daemon
 * which sends ICMP messages out to a predefined address.  Then it forks
 * a client process which sends ICMP death messages to the given external
 * IP address for the other peer (which has already also started the
 * server).  If everything works according to plan, the transport will
 * be given a port which has worked to punch into the other external
 * addresses NAT to communicate with the other gnunet peer.  Then keep
 * alive messages will be sent every (???)ms or so to keep the tunnel
 * safe.
 */

#include "platform.h"
#include "gnunet_hello_lib.h"
#include "gnunet_connection_lib.h"
#include "gnunet_os_lib.h"
#include "gnunet_peerinfo_service.h"
#include "gnunet_protocols.h"
#include "gnunet_resolver_service.h"
#include "gnunet_server_lib.h"
#include "gnunet_service_lib.h"
#include "gnunet_signatures.h"
#include "gnunet_statistics_service.h"
#include "gnunet_transport_service.h"
#include "plugin_transport.h"
#include "transport.h"

#define DEBUG_UDP_NAT GNUNET_YES

/*
 * Transport cost to peer, always 1 for UDP (direct connection)
 */
#define UDP_DIRECT_DISTANCE 1

/**
 * Handle for request of hostname resolution, non-NULL if pending.
 */
static struct GNUNET_RESOLVER_RequestHandle *hostname_dns;

/**
 * How long until we give up on transmitting the welcome message?
 */
#define HOSTNAME_RESOLVE_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)

/*
 * How many ports do we want to listen on (and send on) in order to get replies?
 *
 * FIXME: make this value dynamic, specified by configuration
 */
#define UDP_NAT_LISTEN_PORTS 257

/*
 * Starting port for listening and sending, eventually a config value
 */
#define UDP_NAT_STARTING_PORT 22086

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



/* Forward definition */
struct Plugin;

struct PrettyPrinterContext
{
  GNUNET_TRANSPORT_AddressStringCallback asc;
  void *asc_cls;
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
   * Address string that the server process returned to us
   */
  char *address_string;

  /**
   * Timeout for this set of probes
   */
  struct GNUNET_TIME_Absolute timeout;

  /**
   * Current index (which port to send on next basically)
   */
  int index;

  /**
   * The plugin this probe belongs to
   */
  struct Plugin *plugin;

  /**
   * The task used to send these probes
   */
  GNUNET_SCHEDULER_TaskIdentifier task;

  /**
   * Network address (always ipv4)
   */
  struct sockaddr_in sock_addr;

  /**
   * The port to send this probe to, 0 to choose randomly
   */
  int port;

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

  /**
   * Handle for the statistics service.
   */
  struct GNUNET_STATISTICS_Handle *statistics;

  /**
   * Handle to the network service.
   */
  struct GNUNET_SERVICE_Context *service;

  /*
   * Session of peers with whom we are currently connected
   */
  struct PeerSession *sessions;

  /**
   * Handle for request of hostname resolution, non-NULL if pending.
   */
  struct GNUNET_RESOLVER_RequestHandle *hostname_dns;

  /**
   * ID of task used to update our addresses when one expires.
   */
  GNUNET_SCHEDULER_TaskIdentifier address_update_task;

  /**
   * ID of select task
   */
  GNUNET_SCHEDULER_TaskIdentifier select_task;

  /**
   * Starting port, will listen on num_ports (if available) starting
   * at this number (or will listen only on this port if non-nat'd)
   */
  uint16_t starting_port;


  /**
   * Starting port for sending out crazy messages
   */
  uint32_t random_starting_port;

  /**
   * How many ports should we be using?
   */
  uint16_t num_ports;

  /**
   * The external address given to us by the user.  Must be actual
   * outside visible address for NAT punching to work.
   */
  char *external_address;

  /**
   * The internal address given to us by the user (or discovered).
   */
  char *internal_address;

  /*
   * FD Read set
   */
  struct GNUNET_NETWORK_FDSet *rs;

  /*
   * stdout pipe handle for the gnunet-nat-server process
   */
  struct GNUNET_DISK_PipeHandle *server_stdout;

  /*
   * stdout file handle (for reading) for the gnunet-nat-server process
   */
  const struct GNUNET_DISK_FileHandle *server_stdout_handle;

  /**
   * ID of select gnunet-nat-server stdout read task
   */
  GNUNET_SCHEDULER_TaskIdentifier server_read_task;

  /**
   * Is this transport configured to be behind a NAT?
   */
  int behind_nat;

  /**
   * The process id of the server process (if behind NAT)
   */
  pid_t server_pid;

  /**
   * Probes in flight
   */
  struct UDP_NAT_Probes *probes;

};


struct UDP_Sock_Info
{
  /* The network handle */
  struct GNUNET_NETWORK_Handle *desc;

  /* The port we bound to */
  int port;
};

/* *********** globals ************* */

/**
 * the socket that we transmit all data with
 */
static struct UDP_Sock_Info *udp_nat_socks[UDP_NAT_LISTEN_PORTS];


/**
 * Forward declaration.
 */
void
udp_probe_continuation (void *cls, const struct GNUNET_PeerIdentity *target, int result);


/**
 * Disconnect from a remote node.
 *
 * @param tsession the session that is closed
 * @return GNUNET_OK on success, GNUNET_SYSERR if the operation failed
 */
void
udp_nat_disconnect (void *cls, const struct GNUNET_PeerIdentity *target)
{
  return;
}

/**
 * Shutdown the server process (stop receiving inbound traffic). Maybe
 * restarted later!
 */
static int
udp_nat_transport_server_stop (void *cls)
{
  struct Plugin *plugin = cls;
  int ret;
  int ok;
  int i;

  if (plugin->select_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (plugin->env->sched, plugin->select_task);
      plugin->select_task = GNUNET_SCHEDULER_NO_TASK;
    }

  for (i = 0; i < plugin->num_ports; i++)
    {
      ok = GNUNET_NETWORK_socket_close (udp_nat_socks[i]->desc);
      if (ok == GNUNET_OK)
        udp_nat_socks[i]->desc = NULL;
      ret += ok;
    }

  if (plugin->behind_nat == GNUNET_YES)
    {
      if (0 != PLIBC_KILL (plugin->server_pid, SIGTERM))
        {
          GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "kill");
        }
      GNUNET_OS_process_wait (plugin->server_pid);
    }

  if (ret != GNUNET_OK)
    return GNUNET_SYSERR;
  return ret;
}


struct PeerSession *
find_session (struct Plugin *plugin, const struct GNUNET_PeerIdentity *peer)
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
 * @param msgbufsize the size of the msgbuf to send
 * @param priority how important is the message (ignored by UDP)
 * @param timeout when should we time out (give up) if we can not transmit?
 * @param addr the addr to send the message to, needs to be a sockaddr for us
 * @param addrlen the len of addr
 * @param cont continuation to call once the message has
 *        been transmitted (or if the transport is ready
 *        for the next transmission call; or if the
 *        peer disconnected...)
 * @param cont_cls closure for cont
 *
 * @return the number of bytes written
 *
 */
static ssize_t
udp_nat_real_send (void *cls,
                  struct GNUNET_NETWORK_Handle *send_handle,
                  const struct GNUNET_PeerIdentity *target,
                  const char *msgbuf,
                  size_t msgbuf_size,
                  unsigned int priority,
                  struct GNUNET_TIME_Relative timeout,
                  const void *addr,
                  size_t addrlen,
                  GNUNET_TRANSPORT_TransmitContinuation cont, void *cont_cls)
{
  struct Plugin *plugin = cls;
  struct UDPMessage *message;
  int ssize;
  ssize_t sent;

  if ((addr == NULL) || (addrlen == 0))
    {
#if DEBUG_UDP_NAT
  GNUNET_log_from (GNUNET_ERROR_TYPE_INFO, "udp", _
                   ("udp_nat_plugin_send called without address, returning!\n"));
#endif
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

  /* Actually send the message */
  sent =
    GNUNET_NETWORK_socket_sendto (send_handle, message, ssize,
                                  addr,
                                  addrlen);

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
 * We learned about a peer (possibly behind NAT) so run the
 * gnunet-nat-client to send a dummy ICMP response
 *
 * @param plugin the plugin for this transport
 * @param addr the address of the peer
 * @param addrlen the length of the address
 */
void
run_gnunet_nat_client (struct Plugin *plugin, const char *addr, size_t addrlen)
{
  char inet4[INET_ADDRSTRLEN];
  char *address_as_string;
  char *port_as_string;
  pid_t pid;
  const struct sockaddr *sa = (const struct sockaddr *)addr;

  if (addrlen < sizeof (struct sockaddr))
    return;
  switch (sa->sa_family)
    {
    case AF_INET:
      if (addrlen != sizeof (struct sockaddr_in))
        return;
      inet_ntop (AF_INET,
                 &((struct sockaddr_in *) sa)->sin_addr,
                 inet4, INET_ADDRSTRLEN);
      address_as_string = GNUNET_strdup (inet4);
      break;
    case AF_INET6:
    default:
      return;
    }

  GNUNET_asprintf(&port_as_string, "%d", plugin->starting_port);
#if DEBUG_UDP_NAT
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "udp-nat",
                  _("Running gnunet-nat-client with arguments: %s %s %d\n"), plugin->external_address, address_as_string, plugin->starting_port);
#endif
  /* Start the server process */
  pid = GNUNET_OS_start_process(NULL, NULL, "gnunet-nat-client", "gnunet-nat-client", plugin->external_address, address_as_string, port_as_string, NULL);
  GNUNET_free(address_as_string);
  GNUNET_free(port_as_string);
  GNUNET_OS_process_wait (pid);
}

/**
 * Function that can be used by the transport service to transmit
 * a message using the plugin.
 *
 * @param cls closure
 * @param target who should receive this message (ignored by UDP)
 * @param msgbuf one or more GNUNET_MessageHeader(s) strung together
 * @param msgbufsize the size of the msgbuf to send
 * @param priority how important is the message (ignored by UDP)
 * @param timeout when should we time out (give up) if we can not transmit?
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
 * @return the number of bytes written
 */
static ssize_t
udp_nat_plugin_send (void *cls,
                 const struct GNUNET_PeerIdentity *target,
                 const char *msgbuf,
                 size_t msgbuf_size,
                 unsigned int priority,
                 struct GNUNET_TIME_Relative timeout,
                 const void *addr,
                 size_t addrlen,
                 int force_address,
                 GNUNET_TRANSPORT_TransmitContinuation cont, void *cont_cls)
{
  struct Plugin *plugin = cls;
  ssize_t sent;
  struct MessageQueue *temp_message;
  struct PeerSession *peer_session;
  struct sockaddr_in *sockaddr = (struct sockaddr_in *)addr;
  int other_peer_natd;

  other_peer_natd = GNUNET_NO;
  if ((sockaddr->sin_family == AF_INET) && (ntohs(sockaddr->sin_port) == 0))
    {
      other_peer_natd = GNUNET_YES;
    }

  /**
   * FIXME: find which sock in udp_nat_socks to actually send the message on,
   * also this means creating some sort of structure to remember target to
   * udp sock (or address, or index of udp sock array...)
   */
  sent = 0;

  if (other_peer_natd == GNUNET_YES)
    {
      peer_session = find_session(plugin, target);
      if (peer_session == NULL) /* We have a new peer to add */
        {
          /*
           * The first time, we can assume we have no knowledge of a
           * working port for this peer, call the ICMP message sender
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
          peer_session->messages->next = NULL;
          peer_session->messages->timeout = GNUNET_TIME_relative_to_absolute(timeout);
          peer_session->messages->cont = cont;
          peer_session->messages->cont_cls = cont_cls;
#if DEBUG_UDP_NAT
          GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "udp-nat",
                          _("Other peer is NAT'd, set up peer session for peer %s\n"), GNUNET_i2s(target));
#endif
          run_gnunet_nat_client(plugin, addr, addrlen);

        }
      else
        {
          if (peer_session->expecting_welcome == GNUNET_NO) /* We are "connected" */
            {
              sent = udp_nat_real_send(cls, peer_session->sock, target, msgbuf, msgbuf_size, priority, timeout, peer_session->connect_addr, peer_session->connect_alen, cont, cont_cls);
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
  else /* Other peer not behind a NAT, so we can just send the message as is */
    {
      sent = udp_nat_real_send(cls, udp_nat_socks[0]->desc, target, msgbuf, msgbuf_size, priority, timeout, addr, addrlen, cont, cont_cls);
    }

  return sent;
}


/**
 * Add the IP of our network interface to the list of
 * our external IP addresses.
 */
static int
process_interfaces (void *cls,
                    const char *name,
                    int isDefault,
                    const struct sockaddr *addr, socklen_t addrlen)
{
  struct Plugin *plugin = cls;
  int af;
  struct sockaddr_in *v4;
  struct sockaddr_in6 *v6;

  /*
   * FIXME: Do we want to advertise _all_ of our UDP NAT addresses?
   * Probably not.  Can we assume that we'll only send these out of band?
   * Ostensibly we won't accept just any connection on these ports anyways
   * right?
   */

  af = addr->sa_family;
  if (af == AF_INET)
    {
      v4 = (struct sockaddr_in *) addr;
      if (plugin->behind_nat == GNUNET_YES)
        {
          inet_pton(AF_INET, plugin->external_address, &v4->sin_addr);
          v4->sin_port = htons (0); /* Indicates to receiver we are behind NAT */
        }
      else
        v4->sin_port = htons (plugin->starting_port);
    }
  else
    {
      GNUNET_assert (af == AF_INET6);
      v6 = (struct sockaddr_in6 *) addr;
      if (plugin->behind_nat == GNUNET_YES)
        v6->sin6_port = htons (0);
      else
        v6->sin6_port = htons (plugin->starting_port);
    }

#if !IPV6
  if (af == AF_INET)
    {
#endif
      GNUNET_log_from (GNUNET_ERROR_TYPE_INFO |
                        GNUNET_ERROR_TYPE_BULK,
                        "udp-nat", _("Found address `%s' (%s)\n"),
                        GNUNET_a2s (addr, addrlen), name);
      plugin->env->notify_address (plugin->env->cls,
                                  "udp_nat",
                                  addr, addrlen, GNUNET_TIME_UNIT_FOREVER_REL);
#if !IPV6
    }
#endif

  return GNUNET_OK;
}


/**
 * Function called by the resolver for each address obtained from DNS
 * for our own hostname.  Add the addresses to the list of our
 * external IP addresses.
 *
 * @param cls closure
 * @param addr one of the addresses of the host, NULL for the last address
 * @param addrlen length of the address
 */
static void
process_hostname_ips (void *cls,
                      const struct sockaddr *addr, socklen_t addrlen)
{
  struct Plugin *plugin = cls;

  if (addr == NULL)
    {
      plugin->hostname_dns = NULL;
      return;
    }
  process_interfaces (plugin, "<hostname>", GNUNET_YES, addr, addrlen);
}


/**
 * Send UDP probe messages or UDP keepalive messages, depending on the
 * state of the connection.
 *
 * @param cls closure for this call (should be the main Plugin)
 * @param tc task context for running this
 */
static void
send_udp_probe_message (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct UDP_NAT_Probes *probe = cls;
  struct UDP_NAT_ProbeMessage *message;
  struct Plugin *plugin = probe->plugin;
  int sent;

  message = GNUNET_malloc(sizeof(struct UDP_NAT_ProbeMessage));
  message->header.size = htons(sizeof(struct UDP_NAT_ProbeMessage));
  message->header.type = htons(GNUNET_MESSAGE_TYPE_TRANSPORT_UDP_NAT_PROBE);
  /* Try the agreed upon port first, then go in order starting with our randomly chosen port */
  if (probe->index == 0)
    {
      if (probe->port != 0)
        probe->sock_addr.sin_port = htons(probe->port);
      else
        probe->sock_addr.sin_port = htons(plugin->starting_port);
    }
  else
    probe->sock_addr.sin_port = htons (GNUNET_CRYPTO_random_u32(GNUNET_CRYPTO_QUALITY_STRONG, 33537) + 32000); /* Find a non-root port */
#if DEBUG_UDP_NAT
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "udp-nat",
                      _("Sending a probe to port %d\n"), ntohs(probe->sock_addr.sin_port));
#endif
  if (probe->index + 1 < plugin->num_ports)
    probe->index += 1;
  else
    probe->index = 0;

  sent = udp_nat_real_send(plugin, udp_nat_socks[probe->index]->desc, NULL, (char *)message, ntohs(message->header.size), 0, GNUNET_TIME_relative_get_unit(), &probe->sock_addr, sizeof(probe->sock_addr), &udp_probe_continuation, probe);

  GNUNET_free(message);
}


void
dummy_continuation (void *cls, const struct GNUNET_PeerIdentity *target, int result)
{
  return;
}


/**
 * Continuation for probe sends.  If the last probe was sent
 * "successfully", schedule sending of another one.  If not,
 *
 */
void
udp_probe_continuation (void *cls, const struct GNUNET_PeerIdentity *target, int result)
{
  struct UDP_NAT_Probes *probe = cls;
  struct Plugin *plugin = probe->plugin;

  if (result == GNUNET_OK)
    {
      if (probe->index == 0)
        {
#if DEBUG_UDP_NAT
          GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "udp-nat",
                          _("Scheduling next probe for 10000 milliseconds\n"));
#endif
          probe->task = GNUNET_SCHEDULER_add_delayed(plugin->env->sched, GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MILLISECONDS, 10000), &send_udp_probe_message, probe);
        }

      else
        {
          probe->task = GNUNET_SCHEDULER_add_delayed(plugin->env->sched, GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MILLISECONDS, 50), &send_udp_probe_message, probe);
        }
    }
  else /* Destroy the probe context? */
    {
#if DEBUG_UDP_NAT
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "udp-nat",
                      _("Sending probe didn't go well...\n"));
#endif

    }
}

/**
 * Find probe message by address
 *
 * @param plugin the plugin for this transport
 * @param address_string the ip address as a string
 */
struct UDP_NAT_Probes *
find_probe(struct Plugin *plugin, char * address_string)
{
  struct UDP_NAT_Probes *pos;

  pos = plugin->probes;
  while (pos != NULL)
    if (strcmp(pos->address_string, address_string) == 0)
      return pos;

  return pos;
}


/*
 * @param cls the plugin handle
 * @param tc the scheduling context (for rescheduling this function again)
 *
 * We have been notified that gnunet-nat-server has written something to stdout.
 * Handle the output, then reschedule this function to be called again once
 * more is available.
 *
 */
static void
udp_nat_plugin_server_read (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Plugin *plugin = cls;
  char mybuf[40];
  ssize_t bytes;
  memset(&mybuf, 0, sizeof(mybuf));
  int i;
  struct UDP_NAT_Probes *temp_probe;
  int port;
  char *port_start;
  bytes = GNUNET_DISK_file_read(plugin->server_stdout_handle, &mybuf, sizeof(mybuf));

  if (bytes < 1)
    {
#if DEBUG_UDP_NAT
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "udp-nat",
                      _("Finished reading from server stdout with code: %d\n"), bytes);
#endif
      return;
    }

  port = 0;
  port_start = NULL;
  for (i = 0; i < sizeof(mybuf); i++)
    {
      if (mybuf[i] == '\n')
        mybuf[i] = '\0';

      if ((mybuf[i] == ':') && (i + 1 < sizeof(mybuf)))
        {
          mybuf[i] = '\0';
          port_start = &mybuf[i + 1];
        }
    }

  if (port_start != NULL)
    port = atoi(port_start);

#if DEBUG_UDP_NAT
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "udp-nat",
                  _("nat-server-read read: %s port %d\n"), &mybuf, port);
#endif

  /* Schedule sending of messages to peer on random ports */
  temp_probe = find_probe(plugin, &mybuf[0]);

  if (temp_probe == NULL)
    {
      temp_probe = GNUNET_malloc(sizeof(struct UDP_NAT_Probes));
      temp_probe->address_string = strdup(&mybuf[0]);
      temp_probe->sock_addr.sin_family = AF_INET;
      GNUNET_assert(inet_pton(AF_INET, &mybuf[0], &temp_probe->sock_addr.sin_addr) == 1);
      temp_probe->index = 0;
      temp_probe->port = port;
      temp_probe->next = plugin->probes;
      temp_probe->plugin = plugin;
      temp_probe->task = GNUNET_SCHEDULER_add_delayed(plugin->env->sched, GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MILLISECONDS, 500), &send_udp_probe_message, temp_probe);
      plugin->probes = temp_probe;
    }

  plugin->server_read_task =
       GNUNET_SCHEDULER_add_read_file (plugin->env->sched,
                                       GNUNET_TIME_UNIT_FOREVER_REL,
                                       plugin->server_stdout_handle, &udp_nat_plugin_server_read, plugin);

}


/**
 * Demultiplexer for UDP NAT messages
 *
 * @param plugin the main plugin for this transport
 *
 */
static void
udp_nat_demultiplexer(struct Plugin *plugin, struct GNUNET_PeerIdentity *sender, const struct GNUNET_MessageHeader *currhdr, struct sockaddr_storage *sender_addr, socklen_t fromlen,   struct UDP_Sock_Info *sockinfo)
{
  struct UDP_NAT_ProbeMessageReply *outgoing_probe_reply;
  struct UDP_NAT_ProbeMessageConfirmation *outgoing_probe_confirmation;

  struct UDP_NAT_ProbeMessage *incoming_probe;
  struct UDP_NAT_ProbeMessageReply *incoming_probe_reply;
  struct UDP_NAT_ProbeMessageConfirmation *incoming_probe_confirmation;
  char addr_buf[INET_ADDRSTRLEN];
  struct UDP_NAT_Probes *outgoing_probe;
  struct PeerSession *peer_session;
  struct MessageQueue *pending_message;
  struct MessageQueue *pending_message_temp;
  int sent;

  if (memcmp(sender, plugin->env->my_identity, sizeof(struct GNUNET_PeerIdentity)) == 0)
    {
#if DEBUG_UDP_NAT
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "udp-nat",
                      _("Received a message from myself, dropping!!!\n"));
#endif
      return;
    }

  switch (ntohs(currhdr->type))
  {
    case GNUNET_MESSAGE_TYPE_TRANSPORT_UDP_NAT_PROBE:
      /* Send probe reply */
      incoming_probe = (struct UDP_NAT_ProbeMessage *)currhdr;
      outgoing_probe_reply = GNUNET_malloc(sizeof(struct UDP_NAT_ProbeMessageReply));
      outgoing_probe_reply->header.size = htons(sizeof(struct UDP_NAT_ProbeMessageReply));
      outgoing_probe_reply->header.type = htons(GNUNET_MESSAGE_TYPE_TRANSPORT_UDP_NAT_PROBE_REPLY);

#if DEBUG_UDP_NAT
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "udp-nat",
                      _("Received a probe on listen port %d, sent_from port %d\n"), sockinfo->port, ntohs(((struct sockaddr_in *)sender_addr)->sin_port));
#endif

      sent = udp_nat_real_send(plugin, sockinfo->desc, NULL, (char *)outgoing_probe_reply, ntohs(outgoing_probe_reply->header.size), 0, GNUNET_TIME_relative_get_unit(), sender_addr, fromlen, &dummy_continuation, NULL);
#if DEBUG_UDP_NAT
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "udp-nat",
                      _("Sent PROBE REPLY to port %d on outgoing port %d\n"), ntohs(((struct sockaddr_in *)sender_addr)->sin_port), sockinfo->port);
#endif

      break;
    case GNUNET_MESSAGE_TYPE_TRANSPORT_UDP_NAT_PROBE_REPLY:
      /* Check for existing probe, check ports returned, send confirmation if all is well */
      incoming_probe_reply = (struct UDP_NAT_ProbeMessageReply *)currhdr;
#if DEBUG_UDP_NAT
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "udp-nat",
                      _("Received PROBE REPLY from port %d on incoming port %d\n"), ntohs(((struct sockaddr_in *)sender_addr)->sin_port), sockinfo->port);
#endif
      /* FIXME: use nonce, then IPv6 replies could work I think... */
      if (sender_addr->ss_family == AF_INET)
        {
          memset(&addr_buf, 0, sizeof(addr_buf));
          inet_ntop(AF_INET, &((struct sockaddr_in *) sender_addr)->sin_addr, addr_buf, INET_ADDRSTRLEN);
          outgoing_probe = find_probe(plugin, &addr_buf[0]);
          if (outgoing_probe != NULL)
            {
#if DEBUG_UDP_NAT
              GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "udp-nat",
                              _("Sending confirmation that we were reached!\n"));
#endif
              outgoing_probe_confirmation = GNUNET_malloc(sizeof(struct UDP_NAT_ProbeMessageConfirmation));
              outgoing_probe_confirmation->header.size = htons(sizeof(struct UDP_NAT_ProbeMessageConfirmation));
              outgoing_probe_confirmation->header.type = htons(GNUNET_MESSAGE_TYPE_TRANSPORT_UDP_NAT_PROBE_CONFIRM);
              sent = udp_nat_real_send(plugin, sockinfo->desc, NULL, (char *)outgoing_probe_confirmation, ntohs(outgoing_probe_confirmation->header.size), 0, GNUNET_TIME_relative_get_unit(), sender_addr, fromlen, &dummy_continuation, NULL);
              if (outgoing_probe->task != GNUNET_SCHEDULER_NO_TASK)
                {
                  GNUNET_SCHEDULER_cancel(plugin->env->sched, outgoing_probe->task);
                  outgoing_probe->task = GNUNET_SCHEDULER_NO_TASK;
                  /* Schedule task to timeout and remove probe if confirmation not received */
                }
            }
          else
            {
#if DEBUG_UDP_NAT
              GNUNET_log_from (GNUNET_ERROR_TYPE_INFO, "udp-nat",
                              _("Received a probe reply, but have no record of a sent probe!\n"));
#endif
            }
        }
      break;
    case GNUNET_MESSAGE_TYPE_TRANSPORT_UDP_NAT_PROBE_CONFIRM:
      incoming_probe_confirmation = (struct UDP_NAT_ProbeMessageConfirmation *)currhdr;
      peer_session = find_session(plugin, sender);
#if DEBUG_UDP_NAT
          GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "udp-nat",
                          _("Looking up peer session for peer %s\n"), GNUNET_i2s(sender));
#endif
      if (peer_session == NULL) /* Shouldn't this NOT happen? */
        {
#if DEBUG_UDP_NAT
          GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "udp-nat",
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
          /* FIXME: There is no way to find this based on receiving port at the moment! */
          peer_session->sock = sockinfo->desc; /* This may matter, not sure right now... */
          ((struct sockaddr_in *)peer_session->connect_addr)->sin_port = ((struct sockaddr_in *) sender_addr)->sin_port;
#if DEBUG_UDP_NAT
              GNUNET_log_from (GNUNET_ERROR_TYPE_INFO, "udp-nat",
                              _("Received a probe confirmation, will send to peer on port %d\n"), ntohs(((struct sockaddr_in *)peer_session->connect_addr)->sin_port));
#endif
          if (peer_session->messages != NULL)
            {
#if DEBUG_UDP_NAT
              GNUNET_log_from (GNUNET_ERROR_TYPE_INFO, "udp-nat",
                              _("Received a probe confirmation, sending queued messages.\n"));
#endif
              pending_message = peer_session->messages;
              int count = 0;
              while (pending_message != NULL)
                {
#if DEBUG_UDP_NAT
                  GNUNET_log_from (GNUNET_ERROR_TYPE_INFO, "udp-nat",
                                  _("sending queued message %d\n"), count);
#endif
                  udp_nat_real_send(plugin, peer_session->sock, &peer_session->target, pending_message->msgbuf, pending_message->msgbuf_size, 0, GNUNET_TIME_relative_get_unit(), peer_session->connect_addr, peer_session->connect_alen, pending_message->cont, pending_message->cont_cls);
                  pending_message_temp = pending_message;
                  pending_message = pending_message->next;
                  GNUNET_free(pending_message_temp->msgbuf);
                  GNUNET_free(pending_message_temp);
#if DEBUG_UDP_NAT
                  GNUNET_log_from (GNUNET_ERROR_TYPE_INFO, "udp-nat",
                                  _("finished sending queued message %d\n"), count);
#endif
                  count++;
                }
            }

        }
      else
        {
#if DEBUG_UDP_NAT
          GNUNET_log_from (GNUNET_ERROR_TYPE_INFO, "udp-nat",
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
      plugin->env->receive (plugin->env->cls, sender, currhdr, UDP_DIRECT_DISTANCE, (char *)sender_addr, fromlen);
  }

}


/*
 * @param cls the plugin handle
 * @param tc the scheduling context (for rescheduling this function again)
 *
 * We have been notified that our writeset has something to read.  We don't
 * know which socket needs to be read, so we have to check each one
 * Then reschedule this function to be called again once more is available.
 *
 */
static void
udp_nat_plugin_select (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Plugin *plugin = cls;
  char *buf;
  struct UDPMessage *msg;
  const struct GNUNET_MessageHeader *hdr;
  struct GNUNET_PeerIdentity *sender;
  unsigned int buflen;
  socklen_t fromlen;
  struct sockaddr_storage addr;
  ssize_t ret;
  int offset;
  int count;
  int tsize;
  int i;
  char *msgbuf;
  const struct GNUNET_MessageHeader *currhdr;

  buf = NULL;
  sender = NULL;

  for (i = 0; i < plugin->num_ports; i++)
    {
      buflen = GNUNET_NETWORK_socket_recvfrom_amount (udp_nat_socks[i]->desc);

      if (buflen == GNUNET_NO)
        continue;

      buf = GNUNET_malloc (buflen);
      fromlen = sizeof (addr);
      memset (&addr, 0, fromlen);
      ret =
        GNUNET_NETWORK_socket_recvfrom (udp_nat_socks[i]->desc, buf, buflen,
                                        (struct sockaddr *) &addr, &fromlen);

#if DEBUG_UDP_NAT
      GNUNET_log_from (GNUNET_ERROR_TYPE_INFO, "udp-nat", _
                       ("socket_recv returned %u, src_addr_len is %u\n"), ret,
                       fromlen);
#endif

      if (ret <= 0)
        {
          GNUNET_free (buf);
          continue;
        }
      msg = (struct UDPMessage *) buf;

#if DEBUG_UDP_NAT
      GNUNET_log_from (GNUNET_ERROR_TYPE_INFO, "udp", _
                      ("header reports message size of %d, type %d\n"),
                      ntohs (msg->header.size), ntohs (msg->header.type));
#endif
      if (ntohs (msg->header.size) < sizeof (struct UDPMessage))
        {
          GNUNET_free (buf);
          continue;
        }
      hdr = (const struct GNUNET_MessageHeader *) &msg[1];
      msgbuf = (char *)&msg[1];
      sender = GNUNET_malloc (sizeof (struct GNUNET_PeerIdentity));
      memcpy (sender, &msg->sender, sizeof (struct GNUNET_PeerIdentity));

      offset = 0;
      count = 0;
      tsize = ntohs (msg->header.size) - sizeof(struct UDPMessage);

      while (offset < tsize)
        {
          currhdr = (struct GNUNET_MessageHeader *)&msgbuf[offset];
#if DEBUG_UDP_NAT
          GNUNET_log_from (GNUNET_ERROR_TYPE_INFO, "udp", _
                           ("processing msg %d: type %d, size %d at offset %d\n"),
                           count, ntohs(currhdr->type), ntohs(currhdr->size), offset);
#endif
          udp_nat_demultiplexer(plugin, sender, currhdr, &addr, fromlen, udp_nat_socks[i]);
#if DEBUG_UDP_NAT
          GNUNET_log_from (GNUNET_ERROR_TYPE_INFO, "udp", _
                           ("processing done msg %d: type %d, size %d at offset %d\n"),
                           count, ntohs(currhdr->type), ntohs(currhdr->size), offset);
#endif
          offset += ntohs(currhdr->size);
          count++;
        }
    }

  GNUNET_free_non_null (sender);
  GNUNET_free_non_null (buf);

  plugin->select_task =
    GNUNET_SCHEDULER_add_select (plugin->env->sched,
                                 GNUNET_SCHEDULER_PRIORITY_DEFAULT,
                                 GNUNET_SCHEDULER_NO_TASK,
                                 GNUNET_TIME_UNIT_FOREVER_REL, plugin->rs,
                                 NULL, &udp_nat_plugin_select, plugin);

}

/**
 * Create a slew of UDP sockets.  If possible, use IPv6, otherwise
 * try IPv4.
 *
 * @param cls closure for server start, should be a struct Plugin *
 *
 * @return number of sockets created or GNUNET_SYSERR on error
 */
static int
udp_nat_transport_server_start (void *cls)
{
  struct Plugin *plugin = cls;
  struct sockaddr_in serverAddrv4;
#if IPV6
  struct sockaddr_in6 serverAddrv6;
#endif
  struct sockaddr *serverAddr;
  socklen_t addrlen;
  int i;
  int sockets_created;

  /* Pipe to read from started processes stdout (on read end) */
  plugin->server_stdout = GNUNET_DISK_pipe(GNUNET_YES);

  sockets_created = 0;
  if (plugin->server_stdout == NULL)
    return sockets_created;

  if (plugin->behind_nat == GNUNET_YES)
    {
#if DEBUG_UDP_NAT
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                   "udp_nat",
                   "Starting gnunet-nat-server process\n");
#endif
      /* Start the server process */
      plugin->server_pid = GNUNET_OS_start_process(NULL, plugin->server_stdout, "gnunet-nat-server", "gnunet-nat-server", plugin->internal_address, NULL);
      if (plugin->server_pid == GNUNET_SYSERR)
        return GNUNET_SYSERR;
      /* Close the write end of the read pipe */
      GNUNET_DISK_pipe_close_end(plugin->server_stdout, GNUNET_DISK_PIPE_END_WRITE);

      plugin->server_stdout_handle = GNUNET_DISK_pipe_handle(plugin->server_stdout, GNUNET_DISK_PIPE_END_READ);
      plugin->server_read_task =
          GNUNET_SCHEDULER_add_read_file (plugin->env->sched,
                                          GNUNET_TIME_UNIT_FOREVER_REL,
                                          plugin->server_stdout_handle, &udp_nat_plugin_server_read, plugin);
    }

  /* Open all our sockets for reading/writing */
  for (i = 0; i < plugin->num_ports; i++)
    {
      udp_nat_socks[i] = GNUNET_malloc(sizeof(struct UDP_Sock_Info));
      udp_nat_socks[i]->desc = NULL;
#if IPV6
      if (GNUNET_YES !=
          GNUNET_CONFIGURATION_get_value_yesno (plugin->env->cfg, "GNUNETD",
                                                "DISABLE-IPV6"))
        {
          udp_nat_socks[i] = GNUNET_NETWORK_socket_create (PF_INET6, SOCK_DGRAM, 17);
          if (udp_nat_socks[i] != NULL)
            {
              memset (&serverAddrv6, 0, sizeof (serverAddrv6));
    #if HAVE_SOCKADDR_IN_SIN_LEN
              serverAddrv6.sin6_len = sizeof (serverAddrv6);
    #endif
              serverAddrv6.sin6_family = AF_INET6;
              serverAddrv6.sin6_addr = in6addr_any;
              serverAddrv6.sin6_port = htons (i + plugin->starting_port);
              addrlen = sizeof (serverAddrv6);
              serverAddr = (struct sockaddr *) &serverAddrv6;
            }
        }
#endif
      if (NULL == udp_nat_socks[i]->desc)
        {
          udp_nat_socks[i]->desc = GNUNET_NETWORK_socket_create (PF_INET, SOCK_DGRAM, 17);
          if (NULL == udp_nat_socks[i]->desc)
            {
              GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "udp-nat", "socket");
              return sockets_created;
            }
          else
            {
              memset (&serverAddrv4, 0, sizeof (serverAddrv4));
    #if HAVE_SOCKADDR_IN_SIN_LEN
              serverAddrv4.sin_len = sizeof (serverAddrv4);
    #endif
              serverAddrv4.sin_family = AF_INET;
              serverAddrv4.sin_addr.s_addr = INADDR_ANY;
              if (i == 0)
                serverAddrv4.sin_port = htons (plugin->starting_port);
              else
                serverAddrv4.sin_port = htons (GNUNET_CRYPTO_random_u32(GNUNET_CRYPTO_QUALITY_STRONG, 33537) + 32000); /* Find a non-root port */
              addrlen = sizeof (serverAddrv4);
              serverAddr = (struct sockaddr *) &serverAddrv4;
            }
        }

      if (udp_nat_socks[i]->desc != NULL)
        {
#if DEBUG_UDP_NAT
          GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                           "udp_nat",
                           "Binding to port %d\n", ntohs(serverAddrv4.sin_port));
#endif
          while (GNUNET_NETWORK_socket_bind (udp_nat_socks[i]->desc, serverAddr, addrlen) !=
                         GNUNET_OK)
            {
              serverAddrv4.sin_port = htons (GNUNET_CRYPTO_random_u32(GNUNET_CRYPTO_QUALITY_STRONG, 33537) + 32000); /* Find a good, non-root port */
#if DEBUG_UDP_NAT
              GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                              "udp_nat",
                              "Binding failed, trying new port %d\n", ntohs(serverAddrv4.sin_port));
#endif
            }
          udp_nat_socks[i]->port = ntohs(serverAddrv4.sin_port);
          sockets_created++;
        }
    }

  plugin->rs = GNUNET_NETWORK_fdset_create ();

  GNUNET_NETWORK_fdset_zero (plugin->rs);

  for (i = 0; i < plugin->num_ports; i++)
    {
      GNUNET_NETWORK_fdset_set (plugin->rs, udp_nat_socks[i]->desc);
    }

  plugin->select_task =
    GNUNET_SCHEDULER_add_select (plugin->env->sched,
                                 GNUNET_SCHEDULER_PRIORITY_DEFAULT,
                                 GNUNET_SCHEDULER_NO_TASK,
                                 GNUNET_TIME_UNIT_FOREVER_REL, plugin->rs,
                                 NULL, &udp_nat_plugin_select, plugin);

  return sockets_created;
}


/**
 * Check if the given port is plausible (must be either
 * our listen port or our advertised port).  If it is
 * neither, we return one of these two ports at random.
 *
 * @return either in_port or a more plausible port
 */
static uint16_t
check_port (struct Plugin *plugin, uint16_t in_port)
{

  /* FIXME: remember what ports we are using to better respond to this */
  return in_port;
  /*
  for (i = plugin->starting_port; i < plugin->num_ports + plugin->starting_port; i++)
    {
      if (in_port == i)
        return in_port;
    }

  return GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
                                    plugin->num_ports) + plugin->starting_port;
  */
}


/**
 * Another peer has suggested an address for this peer and transport
 * plugin.  Check that this could be a valid address.  This function
 * is not expected to 'validate' the address in the sense of trying to
 * connect to it but simply to see if the binary format is technically
 * legal for establishing a connection.
 *
 * @param addr pointer to the address, may be modified (slightly)
 * @param addrlen length of addr
 * @return GNUNET_OK if this is a plausible address for this peer
 *         and transport, GNUNET_SYSERR if not
 *
 * TODO: perhaps make everything work with sockaddr_storage, it may
 *       be a cleaner way to handle addresses in UDP
 */
static int
udp_nat_check_address (void *cls, void *addr, size_t addrlen)
{
  struct Plugin *plugin = cls;
  char buf[sizeof (struct sockaddr_in6)];

  struct sockaddr_in *v4;
  struct sockaddr_in6 *v6;

#if IPV6
  if ((addrlen != sizeof (struct sockaddr_in)) &&
      (addrlen != sizeof (struct sockaddr_in6)))
#else
    if (addrlen != sizeof (struct sockaddr_in))
#endif
    {
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
  memcpy (buf, addr, sizeof (struct sockaddr_in6));
  if (addrlen == sizeof (struct sockaddr_in))
    {
      v4 = (struct sockaddr_in *) buf;
      v4->sin_port = htons (check_port (plugin, ntohs (v4->sin_port)));
    }
  else
    {
      v6 = (struct sockaddr_in6 *) buf;
      v6->sin6_port = htons (check_port (plugin, ntohs (v6->sin6_port)));
    }
#if DEBUG_UDP_NAT
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                   "udp_nat",
                   "Informing transport service about my address `%s'.\n",
                   GNUNET_a2s (addr, addrlen));
#endif
  return GNUNET_OK;
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
udp_nat_plugin_address_pretty_printer (void *cls,
                                   const char *type,
                                   const void *addr,
                                   size_t addrlen,
                                   int numeric,
                                   struct GNUNET_TIME_Relative timeout,
                                   GNUNET_TRANSPORT_AddressStringCallback asc,
                                   void *asc_cls)
{
  struct Plugin *plugin = cls;
  const struct sockaddr_in *v4;
  const struct sockaddr_in6 *v6;
  struct PrettyPrinterContext *ppc;

  if ((addrlen != sizeof (struct sockaddr_in)) &&
      (addrlen != sizeof (struct sockaddr_in6)))
    {
      /* invalid address */
      GNUNET_break_op (0);
      asc (asc_cls, NULL);
      return;
    }
  ppc = GNUNET_malloc (sizeof (struct PrettyPrinterContext));
  ppc->asc = asc;
  ppc->asc_cls = asc_cls;
  if (addrlen == sizeof (struct sockaddr_in))
    {
      v4 = (const struct sockaddr_in *) addr;
      ppc->port = ntohs (v4->sin_port);
    }
  else
    {
      v6 = (const struct sockaddr_in6 *) addr;
      ppc->port = ntohs (v6->sin6_port);

    }
  GNUNET_RESOLVER_hostname_get (plugin->env->sched,
                                plugin->env->cfg,
                                addr,
                                addrlen,
                                !numeric, timeout, &append_port, ppc);
}

/**
 * Set a quota for receiving data from the given peer; this is a
 * per-transport limit.  This call has no meaning for UDP, as if
 * we don't receive data it still comes in.  UDP has no friendliness
 * guarantees, and our buffers will fill at some level.
 *
 * @param cls closure
 * @param target the peer for whom the quota is given
 * @param quota_in quota for receiving/sending data in bytes per ms
 */
static void
udp_nat_plugin_set_receive_quota (void *cls,
                              const struct GNUNET_PeerIdentity *target,
                              uint32_t quota_in)
{
  return; /* Do nothing */
}

/**
 * The exported method. Makes the core api available via a global and
 * returns the udp transport API.
 */
void *
libgnunet_plugin_transport_udp_nat_init (void *cls)
{
  unsigned long long mtu;

  struct GNUNET_TRANSPORT_PluginEnvironment *env = cls;
  struct GNUNET_TRANSPORT_PluginFunctions *api;
  struct Plugin *plugin;
  struct GNUNET_SERVICE_Context *service;
  int sockets_created;
  int behind_nat;

  char *internal_address;
  char *external_address;
  char *starting_port;

  service = GNUNET_SERVICE_start ("transport-udp-nat", env->sched, env->cfg);
  if (service == NULL)
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_WARNING, "udp_nat", _
                       ("Failed to start service for `%s' transport plugin.\n"),
                       "udp-nat");
      return NULL;
    }

  if (GNUNET_OK !=
         GNUNET_CONFIGURATION_get_value_string (env->cfg,
                                                "transport-udp-nat",
                                                "EXTERNAL_ADDRESS",
                                                &external_address))
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR,
                       "udp_nat",
                       _
                       ("Require EXTERNAL_ADDRESS for service `%s' in configuration!\n"),
                       "transport-udp");
      GNUNET_SERVICE_stop (service);
    }

  if (GNUNET_OK !=
         GNUNET_CONFIGURATION_get_value_string (env->cfg,
                                                "transport-udp-nat",
                                                "INTERNAL_ADDRESS",
                                                &internal_address))
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR,
                       "udp_nat",
                       _
                       ("Require INTERNAL_ADDRESS for service `%s' in configuration!\n"),
                       "transport-udp");
      GNUNET_SERVICE_stop (service);
    }

  if (GNUNET_NO == GNUNET_CONFIGURATION_get_value_yesno (env->cfg,
      "transport-udp-nat",
      "BEHIND_NAT"))
    behind_nat = GNUNET_NO; /* We are not behind nat, or so says the user! */
  else
    behind_nat = GNUNET_YES; /* Assume we are behind nat (default) */

  GNUNET_CONFIGURATION_get_value_string (env->cfg,
                                         "transport-udp-nat",
                                         "PORT",
                                         &starting_port);


  mtu = 1240;
  if (mtu < 1200)
    GNUNET_log_from (GNUNET_ERROR_TYPE_INFO,
                     "udp_nat",
                     _("MTU %llu for `%s' is probably too low!\n"), mtu,
                     "UDP");

  plugin = GNUNET_malloc (sizeof (struct Plugin));
  plugin->external_address = external_address;
  plugin->internal_address = internal_address;

  if (starting_port != NULL)
    plugin->starting_port = atoi(starting_port);
  else
    plugin->starting_port = UDP_NAT_STARTING_PORT;
  plugin->behind_nat = behind_nat;
  if (plugin->behind_nat == GNUNET_NO)
    plugin->num_ports = 1; /* Only use one port/socket */
  else
    plugin->num_ports = UDP_NAT_LISTEN_PORTS;

  plugin->env = env;
  plugin->statistics = NULL;
  api = GNUNET_malloc (sizeof (struct GNUNET_TRANSPORT_PluginFunctions));
  api->cls = plugin;

  api->send = &udp_nat_plugin_send;
  api->disconnect = &udp_nat_disconnect;
  api->address_pretty_printer = &udp_nat_plugin_address_pretty_printer;
  api->set_receive_quota = &udp_nat_plugin_set_receive_quota;
  api->check_address = &udp_nat_check_address;

  plugin->service = service;

  plugin->random_starting_port = GNUNET_CRYPTO_random_u32(GNUNET_CRYPTO_QUALITY_STRONG, 33537) + 32000;

  /* FIXME: do the two calls below periodically again and
     not just once (since the info we get might change...) */
  GNUNET_OS_network_interfaces_list (&process_interfaces, plugin);
  plugin->hostname_dns = GNUNET_RESOLVER_hostname_resolve (env->sched,
                                                           env->cfg,
                                                           AF_UNSPEC,
                                                           HOSTNAME_RESOLVE_TIMEOUT,
                                                           &process_hostname_ips,
                                                           plugin);

  sockets_created = udp_nat_transport_server_start (plugin);

  GNUNET_assert (sockets_created == plugin->num_ports);

  return api;
}

void *
libgnunet_plugin_transport_udp_nat_done (void *cls)
{
  struct GNUNET_TRANSPORT_PluginFunctions *api = cls;
  struct Plugin *plugin = api->cls;

  udp_nat_transport_server_stop (plugin);
  if (NULL != hostname_dns)
    {
      GNUNET_RESOLVER_request_cancel (hostname_dns);
      hostname_dns = NULL;
    }
  GNUNET_SERVICE_stop (plugin->service);

  GNUNET_NETWORK_fdset_destroy (plugin->rs);
  GNUNET_free (plugin);
  GNUNET_free (api);
  return NULL;
}

/* end of plugin_transport_udp.c */
