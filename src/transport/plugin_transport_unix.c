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
 * @file transport/plugin_transport_unix.c
 * @brief Transport plugin using unix domain sockets (!)
 *        Clearly, can only be used locally on Unix/Linux hosts...
 *        ONLY INTENDED FOR TESTING!!!
 * @author Christian Grothoff
 * @author Nathan Evans
 */

#include "platform.h"
#include "gnunet_hello_lib.h"
#include "gnunet_connection_lib.h"
#include "gnunet_container_lib.h"
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

#define MAX_PROBES 20

/*
 * Transport cost to peer, always 1 for UNIX (direct connection)
 */
#define UNIX_DIRECT_DISTANCE 1

#define DEFAULT_NAT_PORT 0

/**
 * How long until we give up on transmitting the welcome message?
 */
#define HOSTNAME_RESOLVE_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)

/**
 * Starting port for listening and sending, eventually a config value
 */
#define UNIX_NAT_DEFAULT_PORT 22086

GNUNET_NETWORK_STRUCT_BEGIN

/**
 * UNIX Message-Packet header.
 */
struct UNIXMessage
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

struct Session
{
  void *addr;
  size_t addrlen;
  struct GNUNET_PeerIdentity target;

  /**
   * Session timeout task
   */
  GNUNET_SCHEDULER_TaskIdentifier timeout_task;

  struct Plugin * plugin;
};

struct UNIXMessageWrapper
{
  struct UNIXMessageWrapper *next;
  struct UNIXMessageWrapper *prev;

  struct UNIXMessage * msg;
  size_t msgsize;

  struct GNUNET_TIME_Relative timeout;
  unsigned int priority;

  struct Session *session;
  GNUNET_TRANSPORT_TransmitContinuation cont;
  void *cont_cls;
};

/* Forward definition */
struct Plugin;


/**
 * UNIX NAT "Session"
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

/**
 * Information we keep for each of our listen sockets.
 */
struct UNIX_Sock_Info
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

  /**
   * Sessions
   */
  struct GNUNET_CONTAINER_MultiHashMap *session_map;

  /**
   * ID of task used to update our addresses when one expires.
   */
  GNUNET_SCHEDULER_TaskIdentifier address_update_task;

  /**
   * ID of select task
   */
  GNUNET_SCHEDULER_TaskIdentifier select_task;

  /**
   * Integer to append to unix domain socket.
   */
  uint16_t port;

  /**
   * FD Read set
   */
  struct GNUNET_NETWORK_FDSet *rs;

  /**
   * FD Write set
   */
  struct GNUNET_NETWORK_FDSet *ws;

  int with_ws;

  /**
   * socket that we transmit all data with
   */
  struct UNIX_Sock_Info unix_sock;

  /**
   * Path of our unix domain socket (/tmp/unix-plugin-PORT)
   */
  char *unix_socket_path;

  struct UNIXMessageWrapper *msg_head;
  struct UNIXMessageWrapper *msg_tail;

  /**
   * ATS network
   */
  struct GNUNET_ATS_Information ats_network;

  unsigned int bytes_in_queue;
  unsigned int bytes_in_sent;
  unsigned int bytes_in_recv;
  unsigned int bytes_discarded;
};

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


static void
unix_plugin_select (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


static void
reschedule_select (struct Plugin * plugin)
{

  if (plugin->select_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (plugin->select_task);
    plugin->select_task = GNUNET_SCHEDULER_NO_TASK;
  }

  if (NULL != plugin->msg_head)
  {
    plugin->select_task =
      GNUNET_SCHEDULER_add_select (GNUNET_SCHEDULER_PRIORITY_DEFAULT,
                                   GNUNET_TIME_UNIT_FOREVER_REL,
                                   plugin->rs,
                                   plugin->ws,
                                   &unix_plugin_select, plugin);
    plugin->with_ws = GNUNET_YES;
  }
  else
  {
    plugin->select_task =
      GNUNET_SCHEDULER_add_select (GNUNET_SCHEDULER_PRIORITY_DEFAULT,
                                   GNUNET_TIME_UNIT_FOREVER_REL,
                                   plugin->rs,
                                   NULL,
                                   &unix_plugin_select, plugin);
    plugin->with_ws = GNUNET_NO;
  }
}

struct LookupCtx
{
  struct Session *s;
  const struct sockaddr_un *addr;
};

int lookup_session_it (void *cls,
                       const GNUNET_HashCode * key,
                       void *value)
{
  struct LookupCtx *lctx = cls;
  struct Session *t = value;

  if (0 == strcmp (t->addr, lctx->addr->sun_path))
  {
    lctx->s = t;
    return GNUNET_NO;
  }
  return GNUNET_YES;
}


static struct Session *
lookup_session (struct Plugin *plugin, struct GNUNET_PeerIdentity *sender, const struct sockaddr_un *addr)
{
  struct LookupCtx lctx;

  GNUNET_assert (NULL != plugin);
  GNUNET_assert (NULL != sender);
  GNUNET_assert (NULL != addr);

  lctx.s = NULL;
  lctx.addr = addr;

  GNUNET_CONTAINER_multihashmap_get_multiple (plugin->session_map, &sender->hashPubKey, &lookup_session_it, &lctx);

  return lctx.s;
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
  struct UNIXMessageWrapper *msgw;
  struct UNIXMessageWrapper *next;
  struct Plugin * plugin = s->plugin;
  int removed;
  GNUNET_assert (plugin != NULL);
  GNUNET_assert (s != NULL);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Disconnecting session for peer `%s' `%s' \n", GNUNET_i2s (&s->target), s->addr);
  stop_session_timeout (s);
  plugin->env->session_end (plugin->env->cls, &s->target, s);

  msgw = plugin->msg_head;
  removed = GNUNET_NO;
  next = plugin->msg_head;
  while (NULL != next)
  {
    msgw = next;
    next = msgw->next;
    if (msgw->session != s)
      continue;
    GNUNET_CONTAINER_DLL_remove (plugin->msg_head, plugin->msg_tail, msgw);
    if (NULL != msgw->cont)
      msgw->cont (msgw->cont_cls,  &msgw->session->target, GNUNET_SYSERR);
    GNUNET_free (msgw->msg);
    GNUNET_free (msgw);
    removed = GNUNET_YES;    
  }
  if ((GNUNET_YES == removed) && (NULL == plugin->msg_head))
    reschedule_select (plugin);

  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap_remove(plugin->session_map, &s->target.hashPubKey, s));

  GNUNET_STATISTICS_set(plugin->env->stats,
                        "# UNIX sessions active",
                        GNUNET_CONTAINER_multihashmap_size(plugin->session_map),
                        GNUNET_NO);

  GNUNET_free (s);
}

static int
get_session_delete_it (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct Session *s = value;
  disconnect_session (s);
  return GNUNET_YES;
}


/**
 * Disconnect from a remote node.  Clean up session if we have one for this peer
 *
 * @param cls closure for this call (should be handle to Plugin)
 * @param target the peeridentity of the peer to disconnect
 * @return GNUNET_OK on success, GNUNET_SYSERR if the operation failed
 */
static void
unix_disconnect (void *cls, const struct GNUNET_PeerIdentity *target)
{
  struct Plugin *plugin = cls;
  GNUNET_assert (plugin != NULL);

  GNUNET_CONTAINER_multihashmap_get_multiple (plugin->session_map, &target->hashPubKey, &get_session_delete_it, plugin);
  return;
}

/**
 * Shutdown the server process (stop receiving inbound traffic). Maybe
 * restarted later!
 *
 * @param cls Handle to the plugin for this transport
 *
 * @return returns the number of sockets successfully closed,
 *         should equal the number of sockets successfully opened
 */
static int
unix_transport_server_stop (void *cls)
{
  struct Plugin *plugin = cls;

  struct UNIXMessageWrapper * msgw = plugin->msg_head;

  while (NULL != (msgw = plugin->msg_head))
  {
    GNUNET_CONTAINER_DLL_remove (plugin->msg_head, plugin->msg_tail, msgw);
    if (msgw->cont != NULL)
      msgw->cont (msgw->cont_cls,  &msgw->session->target, GNUNET_SYSERR);
    GNUNET_free (msgw->msg);
    GNUNET_free (msgw);
  }

  if (plugin->select_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (plugin->select_task);
    plugin->select_task = GNUNET_SCHEDULER_NO_TASK;
  }

  if (NULL != plugin->unix_sock.desc)
  {
    GNUNET_break (GNUNET_OK ==
                  GNUNET_NETWORK_socket_close (plugin->unix_sock.desc));
    plugin->unix_sock.desc = NULL;
    plugin->with_ws = GNUNET_NO;
  }
  return GNUNET_OK;
}


/**
 * Actually send out the message, assume we've got the address and
 * send_handle squared away!
 *
 * @param cls closure
 * @param send_handle which handle to send message on
 * @param target who should receive this message (ignored by UNIX)
 * @param msgbuf one or more GNUNET_MessageHeader(s) strung together
 * @param msgbuf_size the size of the msgbuf to send
 * @param priority how important is the message (ignored by UNIX)
 * @param timeout when should we time out (give up) if we can not transmit?
 * @param addr the addr to send the message to, needs to be a sockaddr for us
 * @param addrlen the len of addr
 * @param cont continuation to call once the message has
 *        been transmitted (or if the transport is ready
 *        for the next transmission call; or if the
 *        peer disconnected...)
 * @param cont_cls closure for cont
 *
 * @return the number of bytes written, -1 on errors
 */
static ssize_t
unix_real_send (void *cls,
                struct GNUNET_NETWORK_Handle *send_handle,
                const struct GNUNET_PeerIdentity *target, const char *msgbuf,
                size_t msgbuf_size, unsigned int priority,
                struct GNUNET_TIME_Relative timeout, const void *addr,
                size_t addrlen, GNUNET_TRANSPORT_TransmitContinuation cont,
                void *cont_cls)
{
  struct Plugin *plugin = cls;
  ssize_t sent;
  const void *sb;
  size_t sbs;
  struct sockaddr_un un;
  size_t slen;
  int retry;

  GNUNET_assert (NULL != plugin);

  if (send_handle == NULL)
  {
    /* We do not have a send handle */
    GNUNET_break (0);
    if (cont != NULL)
      cont (cont_cls, target, GNUNET_SYSERR);
    return -1;
  }
  if ((addr == NULL) || (addrlen == 0))
  {
    /* Can never send if we don't have an address */
    GNUNET_break (0);
    if (cont != NULL)
      cont (cont_cls, target, GNUNET_SYSERR);
    return -1;
  }

  /* Prepare address */
  memset (&un, 0, sizeof (un));
  un.sun_family = AF_UNIX;
  slen = strlen (addr) + 1;
  if (slen >= sizeof (un.sun_path))
    slen = sizeof (un.sun_path) - 1;
  GNUNET_assert (slen < sizeof (un.sun_path));
  memcpy (un.sun_path, addr, slen);
  un.sun_path[slen] = '\0';
  slen = sizeof (struct sockaddr_un);
#if LINUX
  un.sun_path[0] = '\0';
#endif
#if HAVE_SOCKADDR_IN_SIN_LEN
  un.sun_len = (u_char) slen;
#endif
  sb = (struct sockaddr *) &un;
  sbs = slen;

  /* Send the data */
  sent = 0;
  retry = GNUNET_NO;
  sent = GNUNET_NETWORK_socket_sendto (send_handle, msgbuf, msgbuf_size, sb, sbs);

  if ((GNUNET_SYSERR == sent) && ((errno == EAGAIN) || (errno == ENOBUFS)))
  {
    /* We have to retry later: retry */
    return 0;
  }

  if ((GNUNET_SYSERR == sent) && (errno == EMSGSIZE))
  {
    socklen_t size = 0;
    socklen_t len = sizeof (size);

    GNUNET_NETWORK_socket_getsockopt ((struct GNUNET_NETWORK_Handle *)
                                      send_handle, SOL_SOCKET, SO_SNDBUF, &size,
                                      &len);

    if (size < msgbuf_size)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Trying to increase socket buffer size from %i to %i for message size %i\n",
                  size,
                  ((msgbuf_size / 1000) + 2) * 1000,
                  msgbuf_size);
      size = ((msgbuf_size / 1000) + 2) * 1000;
      if (GNUNET_NETWORK_socket_setsockopt
          ((struct GNUNET_NETWORK_Handle *) send_handle, SOL_SOCKET, SO_SNDBUF,
           &size, sizeof (size)) == GNUNET_OK)
      {
        /* Increased buffer size, retry sending */
        return 0;
      }
      else
      {
        /* Could not increase buffer size: error, no retry */
        GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "setsockopt");
        return -1;
      }
    }
    else
    {
      /* Buffer is bigger than message:  error, no retry
       * This should never happen!*/
      GNUNET_break (0);
      return -1;
    }
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "UNIX transmit %u-byte message to %s (%d: %s)\n",
              (unsigned int) msgbuf_size, GNUNET_a2s (sb, sbs), (int) sent,
              (sent < 0) ? STRERROR (errno) : "ok");

  /* Calling continuation */
  if (cont != NULL)
  {
    if ((sent == GNUNET_SYSERR) && (retry == GNUNET_NO))
      cont (cont_cls, target, GNUNET_SYSERR);
    if (sent > 0)
      cont (cont_cls, target, GNUNET_OK);
  }

  /* return number of bytes successfully sent */
  if (sent > 0)
    return sent;
  if (sent == 0)
  {
    /* That should never happen */
    GNUNET_break (0);
    return -1;
  }
  /* failed and retry: return 0 */
  if ((GNUNET_SYSERR == sent) && (retry == GNUNET_YES))
    return 0;
  /* failed and no retry: return -1 */
  if ((GNUNET_SYSERR == sent) && (retry == GNUNET_NO))
    return -1;
  /* default */
  return -1;
}

struct gsi_ctx
{
  char *address;
  size_t addrlen;
  struct Session *res;
};


static int
get_session_it (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct gsi_ctx *gsi = cls;
  struct Session *s = value;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Comparing session %s %s\n", gsi->address, s->addr);
  if ((gsi->addrlen == s->addrlen) &&
      (0 == memcmp (gsi->address, s->addr, s->addrlen)))
  {
    gsi->res = s;
    return GNUNET_NO;
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
unix_plugin_get_session (void *cls,
                  const struct GNUNET_HELLO_Address *address)
{
  struct Session * s = NULL;
  struct Plugin *plugin = cls;
  struct gsi_ctx gsi;

  /* Checks */
  GNUNET_assert (plugin != NULL);
  GNUNET_assert (address != NULL);

  /* Check if already existing */
  gsi.address = (char *) address->address;
  gsi.addrlen = address->address_length;
  gsi.res = NULL;
  GNUNET_CONTAINER_multihashmap_get_multiple (plugin->session_map, &address->peer.hashPubKey, &get_session_it, &gsi);
  if (gsi.res != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Found existing session\n");
    return gsi.res;
  }

  /* Create a new session */
  s = GNUNET_malloc (sizeof (struct Session) + address->address_length);
  s->addr = &s[1];
  s->addrlen = address->address_length;
  s->plugin = plugin;
  memcpy(s->addr, address->address, s->addrlen);
  memcpy(&s->target, &address->peer, sizeof (struct GNUNET_PeerIdentity));

  start_session_timeout (s);

  GNUNET_CONTAINER_multihashmap_put (plugin->session_map,
      &address->peer.hashPubKey, s,
      GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);

  GNUNET_STATISTICS_set(plugin->env->stats,
                        "# UNIX sessions active",
                        GNUNET_CONTAINER_multihashmap_size(plugin->session_map),
                        GNUNET_NO);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Creating new session\n");
  return s;
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
unix_plugin_select (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);

/**
 * Function that can be used by the transport service to transmit
 * a message using the plugin.   Note that in the case of a
 * peer disconnecting, the continuation MUST be called
 * prior to the disconnect notification itself.  This function
 * will be called with this peer's HELLO message to initiate
 * a fresh connection to another peer.
 *
 * @param cls closure
 * @param session which session must be used
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
unix_plugin_send (void *cls,
                  struct Session *session,
                  const char *msgbuf, size_t msgbuf_size,
                  unsigned int priority,
                  struct GNUNET_TIME_Relative to,
                  GNUNET_TRANSPORT_TransmitContinuation cont, void *cont_cls)
{
  struct Plugin *plugin = cls;
  struct UNIXMessageWrapper *wrapper;
  struct UNIXMessage *message;
  int ssize;

  GNUNET_assert (plugin != NULL);
  GNUNET_assert (session != NULL);

  if (GNUNET_OK != GNUNET_CONTAINER_multihashmap_contains_value(plugin->session_map,
      &session->target.hashPubKey, session))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Invalid session for peer `%s' `%s'\n",
                GNUNET_i2s (&session->target),
                (char *) session->addr);
    GNUNET_break (0);

    return GNUNET_SYSERR;
  }

  ssize = sizeof (struct UNIXMessage) + msgbuf_size;
  message = GNUNET_malloc (sizeof (struct UNIXMessage) + msgbuf_size);
  message->header.size = htons (ssize);
  message->header.type = htons (0);
  memcpy (&message->sender, plugin->env->my_identity,
          sizeof (struct GNUNET_PeerIdentity));
  memcpy (&message[1], msgbuf, msgbuf_size);

  reschedule_session_timeout (session);

  wrapper = GNUNET_malloc (sizeof (struct UNIXMessageWrapper));
  wrapper->msg = message;
  wrapper->msgsize = ssize;
  wrapper->priority = priority;
  wrapper->timeout = to;
  wrapper->cont = cont;
  wrapper->cont_cls = cont_cls;
  wrapper->session = session;

  GNUNET_CONTAINER_DLL_insert(plugin->msg_head, plugin->msg_tail, wrapper);

  plugin->bytes_in_queue += ssize;
  GNUNET_STATISTICS_set (plugin->env->stats,"# UNIX bytes in send queue",
      plugin->bytes_in_queue, GNUNET_NO);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sent %d bytes to `%s'\n", ssize,
              (char *) session->addr);
  if (plugin->with_ws == GNUNET_NO)
  {
    reschedule_select (plugin);
  }
  return ssize;
}


/**
 * Demultiplexer for UNIX messages
 *
 * @param plugin the main plugin for this transport
 * @param sender from which peer the message was received
 * @param currhdr pointer to the header of the message
 * @param un the address from which the message was received
 * @param fromlen the length of the address
 */
static void
unix_demultiplexer (struct Plugin *plugin, struct GNUNET_PeerIdentity *sender,
                    const struct GNUNET_MessageHeader *currhdr,
                    const struct sockaddr_un *un, size_t fromlen)
{
  struct GNUNET_ATS_Information ats[2];
  struct Session *s = NULL;
  struct GNUNET_HELLO_Address * addr;

  ats[0].type = htonl (GNUNET_ATS_QUALITY_NET_DISTANCE);
  ats[0].value = htonl (UNIX_DIRECT_DISTANCE);
  ats[1] = plugin->ats_network;
  GNUNET_break (ntohl(plugin->ats_network.value) != GNUNET_ATS_NET_UNSPECIFIED);

  GNUNET_assert (fromlen >= sizeof (struct sockaddr_un));

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received message from %s\n",
              un->sun_path);

  plugin->bytes_in_recv += ntohs(currhdr->size);
  GNUNET_STATISTICS_set (plugin->env->stats,"# UNIX bytes received",
      plugin->bytes_in_recv, GNUNET_NO);

  addr = GNUNET_HELLO_address_allocate(sender, "unix", un->sun_path, strlen (un->sun_path) + 1);
  s = lookup_session (plugin, sender, un);
  if (NULL == s)
    s = unix_plugin_get_session (plugin, addr);
  reschedule_session_timeout (s);

  plugin->env->receive (plugin->env->cls, sender, currhdr,
                        (const struct GNUNET_ATS_Information *) &ats, 2,
                        s, un->sun_path, strlen (un->sun_path) + 1);
  GNUNET_free (addr);
}


static void
unix_plugin_select_read (struct Plugin * plugin)
{
  char buf[65536] GNUNET_ALIGN;
  struct UNIXMessage *msg;
  struct GNUNET_PeerIdentity sender;
  struct sockaddr_un un;
  socklen_t addrlen;
  ssize_t ret;
  int offset;
  int tsize;
  char *msgbuf;
  const struct GNUNET_MessageHeader *currhdr;
  uint16_t csize;

  addrlen = sizeof (un);
  memset (&un, 0, sizeof (un));

  ret =
      GNUNET_NETWORK_socket_recvfrom (plugin->unix_sock.desc, buf, sizeof (buf),
                                      (struct sockaddr *) &un, &addrlen);

  if ((GNUNET_SYSERR == ret) && ((errno == EAGAIN) || (errno == ENOBUFS)))
    return;

  if (ret == GNUNET_SYSERR)
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "recvfrom");
    return;
  }
  else
  {
#if LINUX
    un.sun_path[0] = '/';
#endif
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Read %d bytes from socket %s\n", ret,
                &un.sun_path[0]);
  }

  GNUNET_assert (AF_UNIX == (un.sun_family));

  msg = (struct UNIXMessage *) buf;
  csize = ntohs (msg->header.size);
  if ((csize < sizeof (struct UNIXMessage)) || (csize > ret))
  {
    GNUNET_break_op (0);
    return;
  }
  msgbuf = (char *) &msg[1];
  memcpy (&sender, &msg->sender, sizeof (struct GNUNET_PeerIdentity));
  offset = 0;
  tsize = csize - sizeof (struct UNIXMessage);
  while (offset + sizeof (struct GNUNET_MessageHeader) <= tsize)
  {
    currhdr = (struct GNUNET_MessageHeader *) &msgbuf[offset];
    csize = ntohs (currhdr->size);
    if ((csize < sizeof (struct GNUNET_MessageHeader)) ||
        (csize > tsize - offset))
    {
      GNUNET_break_op (0);
      break;
    }

    unix_demultiplexer (plugin, &sender, currhdr, &un, sizeof (un));
    offset += csize;
  }
}


static void
unix_plugin_select_write (struct Plugin * plugin)
{
  static int retry_counter;
  int sent = 0;
  struct UNIXMessageWrapper * msgw = plugin->msg_head;

  sent = unix_real_send (plugin,
                         plugin->unix_sock.desc,
                         &msgw->session->target,
                         (const char *) msgw->msg,
                         msgw->msgsize,
                         msgw->priority,
                         msgw->timeout,
                         msgw->session->addr,
                         msgw->session->addrlen,
                         msgw->cont, msgw->cont_cls);

  if (sent == 0)
  {
    /* failed and retry */
    retry_counter++;
    GNUNET_STATISTICS_set (plugin->env->stats,"# UNIX retry attempt",
        retry_counter, GNUNET_NO);
    return;
  }

  if (retry_counter > 0 )
  {
    /* no retry: reset counter */
    retry_counter = 0;
    GNUNET_STATISTICS_set (plugin->env->stats,"# UNIX retry attempt",
        retry_counter, GNUNET_NO);
  }

  if (sent == -1)
  {
    /* failed and no retry */
    GNUNET_CONTAINER_DLL_remove(plugin->msg_head, plugin->msg_tail, msgw);

    GNUNET_assert (plugin->bytes_in_queue >= msgw->msgsize);
    plugin->bytes_in_queue -= msgw->msgsize;
    GNUNET_STATISTICS_set (plugin->env->stats,"# UNIX bytes in send queue",
        plugin->bytes_in_queue, GNUNET_NO);
    plugin->bytes_discarded += msgw->msgsize;
    GNUNET_STATISTICS_set (plugin->env->stats,"# UNIX bytes discarded",
        plugin->bytes_discarded, GNUNET_NO);

    GNUNET_free (msgw->msg);
    GNUNET_free (msgw);
    return;
  }

  if (sent > 0)
  {
    /* successfully sent bytes */
    GNUNET_CONTAINER_DLL_remove(plugin->msg_head, plugin->msg_tail, msgw);

    GNUNET_assert (plugin->bytes_in_queue >= msgw->msgsize);
    plugin->bytes_in_queue -= msgw->msgsize;
    GNUNET_STATISTICS_set (plugin->env->stats,"# UNIX bytes in send queue",
        plugin->bytes_in_queue, GNUNET_NO);
    plugin->bytes_in_sent += msgw->msgsize;
    GNUNET_STATISTICS_set (plugin->env->stats,"# UNIX bytes sent",
        plugin->bytes_in_sent, GNUNET_NO);

    GNUNET_free (msgw->msg);
    GNUNET_free (msgw);
    return;
  }

}


/**
 * We have been notified that our writeset has something to read.  We don't
 * know which socket needs to be read, so we have to check each one
 * Then reschedule this function to be called again once more is available.
 *
 * @param cls the plugin handle
 * @param tc the scheduling context (for rescheduling this function again)
 */
static void
unix_plugin_select (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Plugin *plugin = cls;

  plugin->select_task = GNUNET_SCHEDULER_NO_TASK;
  if ((tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) != 0)
    return;

  if ((tc->reason & GNUNET_SCHEDULER_REASON_WRITE_READY) != 0)
  {
    /* Ready to send data */
    GNUNET_assert (GNUNET_NETWORK_fdset_isset
                   (tc->write_ready, plugin->unix_sock.desc));
    if (plugin->msg_head != NULL)
      unix_plugin_select_write (plugin);
  }

  if ((tc->reason & GNUNET_SCHEDULER_REASON_READ_READY) != 0)
  {
    /* Ready to receive data */
    GNUNET_assert (GNUNET_NETWORK_fdset_isset
                   (tc->read_ready, plugin->unix_sock.desc));
    unix_plugin_select_read (plugin);
  }

  reschedule_select (plugin);
}


/**
 * Create a slew of UNIX sockets.  If possible, use IPv6 and IPv4.
 *
 * @param cls closure for server start, should be a struct Plugin *
 * @return number of sockets created or GNUNET_SYSERR on error
 */
static int
unix_transport_server_start (void *cls)
{
  struct Plugin *plugin = cls;
  struct sockaddr *serverAddr;
  socklen_t addrlen;
  struct sockaddr_un un;
  size_t slen;

  memset (&un, 0, sizeof (un));
  un.sun_family = AF_UNIX;
  slen = strlen (plugin->unix_socket_path) + 1;
  if (slen >= sizeof (un.sun_path))
    slen = sizeof (un.sun_path) - 1;

  memcpy (un.sun_path, plugin->unix_socket_path, slen);
  un.sun_path[slen] = '\0';
  slen = sizeof (struct sockaddr_un);
#if HAVE_SOCKADDR_IN_SIN_LEN
  un.sun_len = (u_char) slen;
#endif

  serverAddr = (struct sockaddr *) &un;
  addrlen = slen;
#if LINUX
  un.sun_path[0] = '\0';
#endif
  plugin->ats_network = plugin->env->get_address_type (plugin->env->cls, serverAddr, addrlen);
  plugin->unix_sock.desc =
      GNUNET_NETWORK_socket_create (AF_UNIX, SOCK_DGRAM, 0);
  if (NULL == plugin->unix_sock.desc)
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "socket");
    return GNUNET_SYSERR;
  }
  if (GNUNET_NETWORK_socket_bind (plugin->unix_sock.desc, serverAddr, addrlen)
      != GNUNET_OK)
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "bind");
    GNUNET_NETWORK_socket_close (plugin->unix_sock.desc);
    plugin->unix_sock.desc = NULL;
    return GNUNET_SYSERR;
  }
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "unix", "Bound to `%s'\n",
                   &un.sun_path[0]);
  plugin->rs = GNUNET_NETWORK_fdset_create ();
  plugin->ws = GNUNET_NETWORK_fdset_create ();
  GNUNET_NETWORK_fdset_zero (plugin->rs);
  GNUNET_NETWORK_fdset_zero (plugin->ws);
  GNUNET_NETWORK_fdset_set (plugin->rs, plugin->unix_sock.desc);
  GNUNET_NETWORK_fdset_set (plugin->ws, plugin->unix_sock.desc);

  reschedule_select (plugin);

  return 1;
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
unix_check_address (void *cls, const void *addr, size_t addrlen)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Informing transport service about my address `%s'\n",
              (char *) addr);
  return GNUNET_OK;
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
unix_plugin_address_pretty_printer (void *cls, const char *type,
                                    const void *addr, size_t addrlen,
                                    int numeric,
                                    struct GNUNET_TIME_Relative timeout,
                                    GNUNET_TRANSPORT_AddressStringCallback asc,
                                    void *asc_cls)
{
  if ((NULL != addr) && (addrlen > 0))
  {
    asc (asc_cls, (const char *) addr);
  }
  else
  {
    GNUNET_break (0);
    asc (asc_cls, "<invalid UNIX address>");
  }
  asc (asc_cls, NULL);
}


/**
 * Function called to convert a string address to
 * a binary address.
 *
 * @param cls closure ('struct Plugin*')
 * @param addr string address
 * @param addrlen length of the address (strlen(addr) + '\0')
 * @param buf location to store the buffer
 *        If the function returns GNUNET_SYSERR, its contents are undefined.
 * @param added length of created address
 * @return GNUNET_OK on success, GNUNET_SYSERR on failure
 */
static int
unix_string_to_address (void *cls, const char *addr, uint16_t addrlen,
    void **buf, size_t *added)
{
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

  (*buf) = strdup (addr);
  (*added) = strlen (addr) + 1;
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
static const char *
unix_address_to_string (void *cls, const void *addr, size_t addrlen)
{
  if ((addr != NULL) && (addrlen > 0))
    return (const char *) addr;
  return NULL;
}


/**
 * Notify transport service about address
 *
 * @param cls the plugin
 * @param tc unused
 */
static void
address_notification (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Plugin *plugin = cls;

  plugin->env->notify_address (plugin->env->cls, GNUNET_YES,
                               plugin->unix_socket_path,
                               strlen (plugin->unix_socket_path) + 1);
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

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Session %p was idle for %llu, disconnecting\n",
      s, GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT.rel_value);

  /* call session destroy function */
  disconnect_session(s);

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

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Timeout for session %p set to %llu\n",
      s, GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT.rel_value);
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

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Timeout rescheduled for session %p set to %llu\n",
      s, GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT.rel_value);
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

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Timeout rescheduled for session %p canceled\n",
      s, GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT.rel_value);
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Timeout for session %p was not active\n",
      s);
  }
}


/**
 * The exported method. Makes the core api available via a global and
 * returns the unix transport API.
 */
void *
libgnunet_plugin_transport_unix_init (void *cls)
{
  struct GNUNET_TRANSPORT_PluginEnvironment *env = cls;
  unsigned long long port;
  struct GNUNET_TRANSPORT_PluginFunctions *api;
  struct Plugin *plugin;
  int sockets_created;

  if (NULL == env->receive)
  {
    /* run in 'stub' mode (i.e. as part of gnunet-peerinfo), don't fully
       initialze the plugin or the API */
    api = GNUNET_malloc (sizeof (struct GNUNET_TRANSPORT_PluginFunctions));
    api->cls = NULL;
    api->address_pretty_printer = &unix_plugin_address_pretty_printer;
    api->address_to_string = &unix_address_to_string;
    api->string_to_address = &unix_string_to_address;
    return api;
  }
  GNUNET_assert( NULL != env->stats);

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (env->cfg, "transport-unix", "PORT",
                                             &port))
    port = UNIX_NAT_DEFAULT_PORT;
  plugin = GNUNET_malloc (sizeof (struct Plugin));
  plugin->port = port;
  plugin->env = env;
  GNUNET_asprintf (&plugin->unix_socket_path, "/tmp/unix-plugin-sock.%d",
                   plugin->port);

  api = GNUNET_malloc (sizeof (struct GNUNET_TRANSPORT_PluginFunctions));
  api->cls = plugin;

  api->get_session = &unix_plugin_get_session;
  api->send = &unix_plugin_send;
  api->disconnect = &unix_disconnect;
  api->address_pretty_printer = &unix_plugin_address_pretty_printer;
  api->address_to_string = &unix_address_to_string;
  api->check_address = &unix_check_address;
  api->string_to_address = &unix_string_to_address;
  sockets_created = unix_transport_server_start (plugin);
  if (sockets_created == 0)
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, _("Failed to open UNIX sockets\n"));

  plugin->session_map = GNUNET_CONTAINER_multihashmap_create(10);

  GNUNET_SCHEDULER_add_now (address_notification, plugin);
  return api;
}

void *
libgnunet_plugin_transport_unix_done (void *cls)
{
  struct GNUNET_TRANSPORT_PluginFunctions *api = cls;
  struct Plugin *plugin = api->cls;

  if (NULL == plugin)
  {
    GNUNET_free (api);
    return NULL;
  }
  unix_transport_server_stop (plugin);

  GNUNET_CONTAINER_multihashmap_iterate (plugin->session_map, &get_session_delete_it, plugin);
  GNUNET_CONTAINER_multihashmap_destroy (plugin->session_map);

  if (NULL != plugin->rs)
    GNUNET_NETWORK_fdset_destroy (plugin->rs);
  if (NULL != plugin->ws)
    GNUNET_NETWORK_fdset_destroy (plugin->ws);
  GNUNET_free (plugin->unix_socket_path);
  GNUNET_free (plugin);
  GNUNET_free (api);
  return NULL;
}

/* end of plugin_transport_unix.c */
