/*
     This file is part of GNUnet
     Copyright (C) 2010-2014, 2018 GNUnet e.V.

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
*/

/**
 * @file transport/gnunet-communicator-unix.c
 * @brief Transport plugin using unix domain sockets (!)
 *        Clearly, can only be used locally on Unix/Linux hosts...
 *        ONLY INTENDED FOR TESTING!!!
 * @author Christian Grothoff
 * @author Nathan Evans
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_statistics_service.h"
#include "gnunet_transport_communication_service.h"

/**
 * Name of the communicator.
 */
#define COMMUNICATOR_NAME "unix"


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

GNUNET_NETWORK_STRUCT_END


/**
 * Information we track for a message awaiting transmission.
 */
struct UNIXMessageWrapper
{
  /**
   * We keep messages in a doubly linked list.
   */
  struct UNIXMessageWrapper *next;

  /**
   * We keep messages in a doubly linked list.
   */
  struct UNIXMessageWrapper *prev;

  /**
   * The actual payload (allocated separately right now).
   */
  struct UNIXMessage *msg;

  /**
   * Queue this message belongs to.
   */
  struct Queue *queue;

  /**
   * Function to call upon transmission.
   */
  GNUNET_TRANSPORT_TransmitContinuation cont;

  /**
   * Closure for @e cont.
   */
  void *cont_cls;

  /**
   * Timeout for this message.
   */
  struct GNUNET_TIME_Absolute timeout;

  /**
   * Number of bytes in @e msg.
   */
  size_t msgsize;

  /**
   * Number of bytes of payload encapsulated in @e msg.
   */
  size_t payload;

  /**
   * Priority of the message (ignored, just dragged along in UNIX).
   */
  unsigned int priority;
};


/**
 * Handle for a queue.
 */
struct Queue
{

  /**
   * Queues with pending messages (!) are kept in a DLL.
   */
  struct Queue *next;

  /**
   * Queues with pending messages (!) are kept in a DLL.
   */
  struct Queue *prev;

  /**
   * To whom are we talking to (set to our identity
   * if we are still waiting for the welcome message).
   *
   * FIXME: information duplicated with 'peer' in address!
   */
  struct GNUNET_PeerIdentity target;

  /**
   * Address of the other peer.
   */
  struct sockaddr_un *address;

  /**
   * Length of the address.
   */
  socklen_t address_len;

  /**
   * Message queue we are providing for the #ch.
   */
  struct GNUNET_MQ_Handle *mq;
  
  /**
   * handle for this queue with the #ch.
   */ 
  struct GNUNET_TRANSPORT_QueueHandle *qh;
  
  /**
   * Number of bytes we currently have in our write queue.
   */
  unsigned long long bytes_in_queue;

  /**
   * Timeout for this queue.
   */
  struct GNUNET_TIME_Absolute timeout;

  /**
   * Queue timeout task.
   */
  struct GNUNET_SCHEDULER_Task * timeout_task;

  /**
   * Number of messages we currently have in our write queue.
   */
  unsigned int msgs_in_queue;

};



/**
 * ID of read task
 */
static struct GNUNET_SCHEDULER_Task *read_task;

/**
 * ID of write task
 */
static struct GNUNET_SCHEDULER_Task *write_task;

/**
 * Number of bytes we currently have in our write queues.
 */
static unsigned long long bytes_in_queue;

/**
 * Our environment.
 */
static struct GNUNET_TRANSPORT_CommunicatorHandle *ch;

/**
 * Queues (map from peer identity to `struct Queue`)
 */
static struct GNUNET_CONTAINER_MultiPeerMap *queue_map;

/**
 * Head of queue of messages to transmit.
 */
static struct UNIXMessageWrapper *msg_head;

/**
 * Tail of queue of messages to transmit.
 */
static struct UNIXMessageWrapper *msg_tail;

/**
 * socket that we transmit all data with
 */
static struct GNUNET_NETWORK_Handle *unix_sock;

/**
 * Handle to the operation that publishes our address.
 */
static struct GNUNET_TRANSPORT_AddressIdentifier *ai;


/**
 * If a queue monitor is attached, notify it about the new
 * queue state.
 *
 * @param plugin our plugin
 * @param queue queue that changed state
 * @param state new state of the queue
 */
static void
notify_queue_monitor (struct Plugin *plugin,
                        struct Queue *queue,
                        enum GNUNET_TRANSPORT_QueueState state)
{
  struct GNUNET_TRANSPORT_QueueInfo info;

  if (NULL == plugin->sic)
    return;
  memset (&info, 0, sizeof (info));
  info.state = state;
  info.is_inbound = GNUNET_SYSERR; /* hard to say */
  info.num_msg_pending = queue->msgs_in_queue;
  info.num_bytes_pending = queue->bytes_in_queue;
  /* info.receive_delay remains zero as this is not supported by UNIX
     (cannot selectively not receive from 'some' peer while continuing
     to receive from others) */
  info.queue_timeout = queue->timeout;
  info.address = queue->address;
  plugin->sic (plugin->sic_cls,
               queue,
               &info);
}


/**
 * Function called for a quick conversion of the binary address to
 * a numeric address.  Note that the caller must not free the
 * address and that the next call to this function is allowed
 * to override the address again.
 *
 * @param cls closure
 * @param addr binary address
 * @param addrlen length of the @a addr
 * @return string representing the same address
 */
static const char *
unix_plugin_address_to_string (void *cls,
                               const void *addr,
                               size_t addrlen)
{
  static char rbuf[1024];
  struct UnixAddress *ua = (struct UnixAddress *) addr;
  char *addrstr;
  size_t addr_str_len;
  unsigned int off;

  if ((NULL == addr) || (sizeof (struct UnixAddress) > addrlen))
  {
    GNUNET_break(0);
    return NULL;
  }
  addrstr = (char *) &ua[1];
  addr_str_len = ntohl (ua->addrlen);

  if (addr_str_len != addrlen - sizeof(struct UnixAddress))
  {
    GNUNET_break(0);
    return NULL;
  }
  if ('\0' != addrstr[addr_str_len - 1])
  {
    GNUNET_break(0);
    return NULL;
  }
  if (strlen (addrstr) + 1 != addr_str_len)
  {
    GNUNET_break(0);
    return NULL;
  }

  off = 0;
  if ('\0' == addrstr[0])
    off++;
  memset (rbuf, 0, sizeof (rbuf));
  GNUNET_snprintf (rbuf,
                   sizeof (rbuf) - 1,
                   "%s.%u.%s%.*s",
                   PLUGIN_NAME,
                   ntohl (ua->options),
                   (off == 1) ? "@" : "",
                   (int) (addr_str_len - off),
                   &addrstr[off]);
  return rbuf;
}


/**
 * Functions with this signature are called whenever we need
 * to close a queue due to a disconnect or failure to
 * establish a connection.
 *
 * @param queue queue to close down
 */
static void
unix_plugin_queue_disconnect (struct Queue *queue)
{
  struct Plugin *plugin = cls;
  struct UNIXMessageWrapper *msgw;
  struct UNIXMessageWrapper *next;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Disconnecting queue for peer `%s'\n",
       GNUNET_i2s (&queue->target));
  plugin->env->queue_end (plugin->env->cls,
			  queue->address,
			  queue);
  next = plugin->msg_head;
  while (NULL != next)
  {
    msgw = next;
    next = msgw->next;
    if (msgw->queue != queue)
      continue;
    GNUNET_CONTAINER_DLL_remove (plugin->msg_head,
                                 plugin->msg_tail,
                                 msgw);
    queue->msgs_in_queue--;
    GNUNET_assert (queue->bytes_in_queue >= msgw->msgsize);
    queue->bytes_in_queue -= msgw->msgsize;
    GNUNET_assert (plugin->bytes_in_queue >= msgw->msgsize);
    plugin->bytes_in_queue -= msgw->msgsize;
    if (NULL != msgw->cont)
      msgw->cont (msgw->cont_cls,
                  &msgw->queue->target,
                  GNUNET_SYSERR,
                  msgw->payload, 0);
    GNUNET_free (msgw->msg);
    GNUNET_free (msgw);
  }
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multipeermap_remove (plugin->queue_map,
						       &queue->target,
						       queue));
  GNUNET_STATISTICS_set (stats,
			 "# UNIX queues active",
			 GNUNET_CONTAINER_multipeermap_size (plugin->queue_map),
			 GNUNET_NO);
  if (NULL != queue->timeout_task)
  {
    GNUNET_SCHEDULER_cancel (queue->timeout_task);
    queue->timeout_task = NULL;
    queue->timeout = GNUNET_TIME_UNIT_ZERO_ABS;
  }
  GNUNET_free (queue->address);
  GNUNET_break (0 == queue->bytes_in_queue);
  GNUNET_break (0 == queue->msgs_in_queue);
  GNUNET_free (queue);
}


/**
 * Queue was idle for too long, so disconnect it
 *
 * @param cls the `struct Queue *` to disconnect
 */
static void
queue_timeout (void *cls)
{
  struct Queue *queue = cls;
  struct GNUNET_TIME_Relative left;

  queue->timeout_task = NULL;
  left = GNUNET_TIME_absolute_get_remaining (queue->timeout);
  if (0 != left.rel_value_us)
  {
    /* not actually our turn yet, but let's at least update
       the monitor, it may think we're about to die ... */
    queue->timeout_task
      = GNUNET_SCHEDULER_add_delayed (left,
				      &queue_timeout,
				      queue);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Queue %p was idle for %s, disconnecting\n",
       queue,
       GNUNET_STRINGS_relative_time_to_string (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT,
					       GNUNET_YES));
  unix_plugin_queue_disconnect (queue);
}


/**
 * Increment queue timeout due to activity.  We do not immediately
 * notify the monitor here as that might generate excessive
 * signalling.
 *
 * @param queue queue for which the timeout should be rescheduled
 */
static void
reschedule_queue_timeout (struct Queue *queue)
{
  GNUNET_assert (NULL != queue->timeout_task);
  queue->timeout
    = GNUNET_TIME_relative_to_absolute (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT);
}


/**
 * Convert unix path to a `struct sockaddr_un *`
 *
 * @param unixpath path to convert
 * @param[out] sock_len set to the length of the address
 * @param is_abstract is this an abstract @a unixpath
 * @return converted unix path
 */
static struct sockaddr_un *
unix_address_to_sockaddr (const char *unixpath,
                          socklen_t *sock_len,
			  int is_abstract)
{
  struct sockaddr_un *un;
  size_t slen;

  GNUNET_assert (0 < strlen (unixpath));        /* sanity check */
  un = GNUNET_new (struct sockaddr_un);
  un->sun_family = AF_UNIX;
  slen = strlen (unixpath);
  if (slen >= sizeof (un->sun_path))
    slen = sizeof (un->sun_path) - 1;
  GNUNET_memcpy (un->sun_path, unixpath, slen);
  un->sun_path[slen] = '\0';
  slen = sizeof (struct sockaddr_un);
#if HAVE_SOCKADDR_UN_SUN_LEN
  un->sun_len = (u_char) slen;
#endif
  (*sock_len) = slen;
  if (GNUNET_YES == is_abstract)
    un->sun_path[0] = '\0';
  return un;
}


/**
 * Closure to #lookup_queue_it().
 */
struct LookupCtx
{
  /**
   * Location to store the queue, if found.
   */
  struct Queue *res;

  /**
   * Address we are looking for.
   */
  const sockaddr_un *un;

  /**
   * Number of bytes in @a un
   */
  socklen_t un_len;
};


/**
 * Function called to find a queue by address.
 *
 * @param cls the `struct LookupCtx *`
 * @param key peer we are looking for (unused)
 * @param value a queue
 * @return #GNUNET_YES if not found (continue looking), #GNUNET_NO on success
 */
static int
lookup_queue_it (void *cls,
		 const struct GNUNET_PeerIdentity * key,
		 void *value)
{
  struct LookupCtx *lctx = cls;
  struct Queue *queue = value;

  if ( (queue->address_len = lctx->un_len) &&
       (0 == memcmp (lctx->un,
		     queue->address,
		     queue->address_len)) )
  {
    lctx->res = queue;
    return GNUNET_NO;
  }
  return GNUNET_YES;
}


/**
 * Find an existing queue by address.
 *
 * @param plugin the plugin
 * @param address the address to find
 * @return NULL if queue was not found
 */
static struct Queue *
lookup_queue (const struct GNUNET_PeerIdentity *peer,
	      const sockaddr_un *un,
	      socklen_t un_len)
{
  struct LookupCtx lctx;

  lctx.un = un;
  lctx.un_len = un_len;
  GNUNET_CONTAINER_multipeermap_get_multiple (plugin->queue_map,
					      peer,
					      &lookup_queue_it,
					      &lctx);
  return lctx.res;
}



/**
 * Actually send out the message, assume we've got the address and
 * send_handle squared away!
 *
 * @param cls closure
 * @param send_handle which handle to send message on
 * @param target who should receive this message (ignored by UNIX)
 * @param msgbuf one or more GNUNET_MessageHeader(s) strung together
 * @param msgbuf_size the size of the @a msgbuf to send
 * @param priority how important is the message (ignored by UNIX)
 * @param timeout when should we time out (give up) if we can not transmit?
 * @param addr the addr to send the message to, needs to be a sockaddr for us
 * @param addrlen the len of @a addr
 * @param payload bytes payload to send
 * @param cont continuation to call once the message has
 *        been transmitted (or if the transport is ready
 *        for the next transmission call; or if the
 *        peer disconnected...)
 * @param cont_cls closure for @a cont
 * @return on success the number of bytes written, RETRY for retry, -1 on errors
 */
static ssize_t
unix_real_send (void *cls,
                struct GNUNET_NETWORK_Handle *send_handle,
                const struct GNUNET_PeerIdentity *target,
                const char *msgbuf,
                size_t msgbuf_size,
                unsigned int priority,
                struct GNUNET_TIME_Absolute timeout,
                const struct UnixAddress *addr,
                size_t addrlen,
                size_t payload,
                GNUNET_TRANSPORT_TransmitContinuation cont,
                void *cont_cls)
{
  struct Plugin *plugin = cls;
  ssize_t sent;
  struct sockaddr_un *un;
  socklen_t un_len;
  const char *unixpath;

  if (NULL == send_handle)
  {
    GNUNET_break (0); /* We do not have a send handle */
    return GNUNET_SYSERR;
  }
  if ((NULL == addr) || (0 == addrlen))
  {
    GNUNET_break (0); /* Can never send if we don't have an address */
    return GNUNET_SYSERR;
  }

  /* Prepare address */
  unixpath = (const char *)  &addr[1];
  if (NULL == (un = unix_address_to_sockaddr (unixpath,
                                              &un_len)))
  {
    GNUNET_break (0);
    return -1;
  }

  if ((GNUNET_YES == plugin->is_abstract) &&
      (0 != (UNIX_OPTIONS_USE_ABSTRACT_SOCKETS & ntohl(addr->options) )) )
  {
    un->sun_path[0] = '\0';
  }
resend:
  /* Send the data */
  sent = GNUNET_NETWORK_socket_sendto (send_handle,
                                       msgbuf,
                                       msgbuf_size,
                                       (const struct sockaddr *) un,
                                       un_len);
  if (GNUNET_SYSERR == sent)
  {
    if ( (EAGAIN == errno) ||
	 (ENOBUFS == errno) )
    {
      GNUNET_free (un);
      return RETRY; /* We have to retry later  */
    }
    if (EMSGSIZE == errno)
    {
      socklen_t size = 0;
      socklen_t len = sizeof (size);

      GNUNET_NETWORK_socket_getsockopt ((struct GNUNET_NETWORK_Handle *)
                                        send_handle, SOL_SOCKET, SO_SNDBUF, &size,
                                        &len);
      if (size < msgbuf_size)
      {
        LOG (GNUNET_ERROR_TYPE_DEBUG,
             "Trying to increase socket buffer size from %u to %u for message size %u\n",
             (unsigned int) size,
             (unsigned int) ((msgbuf_size / 1000) + 2) * 1000,
             (unsigned int) msgbuf_size);
        size = ((msgbuf_size / 1000) + 2) * 1000;
        if (GNUNET_OK ==
            GNUNET_NETWORK_socket_setsockopt ((struct GNUNET_NETWORK_Handle *) send_handle,
                                              SOL_SOCKET, SO_SNDBUF,
                                              &size, sizeof (size)))
          goto resend; /* Increased buffer size, retry sending */
        else
        {
          /* Could not increase buffer size: error, no retry */
          GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "setsockopt");
          GNUNET_free (un);
          return GNUNET_SYSERR;
        }
      }
      else
      {
        /* Buffer is bigger than message:  error, no retry
         * This should never happen!*/
        GNUNET_break (0);
        GNUNET_free (un);
        return GNUNET_SYSERR;
      }
    }
  }

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "UNIX transmitted %u-byte message to %s (%d: %s)\n",
       (unsigned int) msgbuf_size,
       GNUNET_a2s ((const struct sockaddr *)un, un_len),
       (int) sent,
       (sent < 0) ? STRERROR (errno) : "ok");
  GNUNET_free (un);
  return sent;
}


/**
 * Function obtain the network type for a queue
 *
 * @param cls closure ('struct Plugin*')
 * @param queue the queue
 * @return the network type in HBO or #GNUNET_SYSERR
 */
static enum GNUNET_ATS_Network_Type
unix_plugin_get_network (void *cls,
                         struct Queue *queue)
{
  GNUNET_assert (NULL != queue);
  return GNUNET_ATS_NET_LOOPBACK;
}


/**
 * Function obtain the network type for a queue
 *
 * @param cls closure (`struct Plugin *`)
 * @param address the address
 * @return the network type
 */
static enum GNUNET_ATS_Network_Type
unix_plugin_get_network_for_address (void *cls,
                                     const struct GNUNET_HELLO_Address *address)

{
  return GNUNET_ATS_NET_LOOPBACK;
}


/**
 * Creates a new outbound queue the transport service will use to send data to the
 * peer
 *
 * @param cls the plugin
 * @param address the address
 * @return the queue or NULL of max connections exceeded
 */
static struct Queue *
unix_plugin_get_queue (void *cls,
			 const struct GNUNET_HELLO_Address *address)
{
  struct Plugin *plugin = cls;
  struct Queue *queue;
  struct UnixAddress *ua;
  char * addrstr;
  uint32_t addr_str_len;
  uint32_t addr_option;

  ua = (struct UnixAddress *) address->address;
  if ((NULL == address->address) || (0 == address->address_length) ||
  		(sizeof (struct UnixAddress) > address->address_length))
  {
    GNUNET_break (0);
    return NULL;
  }
  addrstr = (char *) &ua[1];
  addr_str_len = ntohl (ua->addrlen);
  addr_option = ntohl (ua->options);

  if ( (0 != (UNIX_OPTIONS_USE_ABSTRACT_SOCKETS & addr_option)) &&
    (GNUNET_NO == plugin->is_abstract))
  {
    return NULL;
  }

  if (addr_str_len != address->address_length - sizeof (struct UnixAddress))
  {
    return NULL; /* This can be a legacy address */
  }

  if ('\0' != addrstr[addr_str_len - 1])
  {
    GNUNET_break (0);
    return NULL;
  }
  if (strlen (addrstr) + 1 != addr_str_len)
  {
    GNUNET_break (0);
    return NULL;
  }

  /* Check if a queue for this address already exists */
  if (NULL != (queue = lookup_queue (plugin,
                                         address)))
    {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Found existing queue %p for address `%s'\n",
	 queue,
	 unix_plugin_address_to_string (NULL,
                                        address->address,
                                        address->address_length));
    return queue;
  }

  /* create a new queue */
  queue = GNUNET_new (struct Queue);
  queue->target = address->peer;
  queue->address = GNUNET_HELLO_address_copy (address);
  queue->plugin = plugin;
  queue->timeout = GNUNET_TIME_relative_to_absolute (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT);
  queue->timeout_task = GNUNET_SCHEDULER_add_delayed (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT,
                                                        &queue_timeout,
                                                        queue);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Creating a new queue %p for address `%s'\n",
       queue,
       unix_plugin_address_to_string (NULL,
                                      address->address,
                                      address->address_length));
  (void) GNUNET_CONTAINER_multipeermap_put (plugin->queue_map,
					    &address->peer, queue,
					    GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  GNUNET_STATISTICS_set (plugin->env->stats,
			 "# UNIX queues active",
			 GNUNET_CONTAINER_multipeermap_size (plugin->queue_map),
			 GNUNET_NO);
  notify_queue_monitor (plugin,
                          queue,
                          GNUNET_TRANSPORT_SS_INIT);
  notify_queue_monitor (plugin,
                          queue,
                          GNUNET_TRANSPORT_SS_UP);
  return queue;
}


/**
 * Function that will be called whenever the transport service wants
 * to notify the plugin that a queue is still active and in use and
 * therefore the queue timeout for this queue has to be updated
 *
 * @param cls closure with the `struct Plugin *`
 * @param peer which peer was the queue for
 * @param queue which queue is being updated
 */
static void
unix_plugin_update_queue_timeout (void *cls,
				  const struct GNUNET_PeerIdentity *peer,
				  struct Queue *queue)
{
  struct Plugin *plugin = cls;

  if (GNUNET_OK !=
      GNUNET_CONTAINER_multipeermap_contains_value (plugin->queue_map,
                                                    &queue->target,
                                                    queue))
  {
    GNUNET_break (0);
    return;
  }
  reschedule_queue_timeout (queue);
}


/**
 * Demultiplexer for UNIX messages
 *
 * @param plugin the main plugin for this transport
 * @param sender from which peer the message was received
 * @param currhdr pointer to the header of the message
 * @param ua address to look for
 * @param ua_len length of the address @a ua
 */
static void
unix_demultiplexer (struct Plugin *plugin,
                    struct GNUNET_PeerIdentity *sender,
                    const struct GNUNET_MessageHeader *currhdr,
                    const struct UnixAddress *ua,
                    size_t ua_len)
{
  struct Queue *queue;
  struct GNUNET_HELLO_Address *address;

  GNUNET_assert (ua_len >= sizeof (struct UnixAddress));
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received message from %s\n",
       unix_plugin_address_to_string (NULL, ua, ua_len));
  GNUNET_STATISTICS_update (plugin->env->stats,
			    "# bytes received via UNIX",
			    ntohs (currhdr->size),
			    GNUNET_NO);

  /* Look for existing queue */
  address = GNUNET_HELLO_address_allocate (sender,
                                           PLUGIN_NAME,
                                           ua, ua_len,
                                           GNUNET_HELLO_ADDRESS_INFO_NONE); /* UNIX does not have "inbound" queues */
  queue = lookup_queue (plugin, address);
  if (NULL == queue)
  {
    queue = unix_plugin_get_queue (plugin, address);
    /* Notify transport and ATS about new inbound queue */
    plugin->env->queue_start (NULL,
                                queue->address,
                                queue,
                                GNUNET_ATS_NET_LOOPBACK);
  }
  else
  {
    reschedule_queue_timeout (queue);
  }
  GNUNET_HELLO_address_free (address);
  plugin->env->receive (plugin->env->cls,
                        queue->address,
                        queue,
                        currhdr);
}


/**
 * Read from UNIX domain socket (it is ready).
 *
 * @param plugin the plugin
 */
static void
unix_plugin_do_read (struct Plugin *plugin)
{
  char buf[65536] GNUNET_ALIGN;
  struct UnixAddress *ua;
  struct UNIXMessage *msg;
  struct GNUNET_PeerIdentity sender;
  struct sockaddr_un un;
  socklen_t addrlen;
  ssize_t ret;
  int offset;
  int tsize;
  int is_abstract;
  char *msgbuf;
  const struct GNUNET_MessageHeader *currhdr;
  uint16_t csize;
  size_t ua_len;

  addrlen = sizeof (un);
  memset (&un, 0, sizeof (un));
  ret = GNUNET_NETWORK_socket_recvfrom (unix_sock,
                                        buf, sizeof (buf),
                                        (struct sockaddr *) &un,
                                        &addrlen);
  if ((GNUNET_SYSERR == ret) && ((errno == EAGAIN) || (errno == ENOBUFS)))
    return;
  if (GNUNET_SYSERR == ret)
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING,
                         "recvfrom");
    return;
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
	 "Read %d bytes from socket %s\n",
	 (int) ret,
	 un.sun_path);
  }

  GNUNET_assert (AF_UNIX == (un.sun_family));
  is_abstract = GNUNET_NO;
  if ('\0' == un.sun_path[0])
  {
    un.sun_path[0] = '@';
    is_abstract = GNUNET_YES;
  }

  ua_len = sizeof (struct UnixAddress) + strlen (un.sun_path) + 1;
  ua = GNUNET_malloc (ua_len);
  ua->addrlen = htonl (strlen (&un.sun_path[0]) +1);
  GNUNET_memcpy (&ua[1], &un.sun_path[0], strlen (un.sun_path) + 1);
  if (is_abstract)
    ua->options = htonl(UNIX_OPTIONS_USE_ABSTRACT_SOCKETS);
  else
    ua->options = htonl(UNIX_OPTIONS_NONE);

  msg = (struct UNIXMessage *) buf;
  csize = ntohs (msg->header.size);
  if ((csize < sizeof (struct UNIXMessage)) || (csize > ret))
  {
    GNUNET_break_op (0);
    GNUNET_free (ua);
    return;
  }
  msgbuf = (char *) &msg[1];
  GNUNET_memcpy (&sender,
          &msg->sender,
          sizeof (struct GNUNET_PeerIdentity));
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
    unix_demultiplexer (plugin, &sender, currhdr, ua, ua_len);
    offset += csize;
  }
  GNUNET_free (ua);
}


/**
 * Write to UNIX domain socket (it is ready).
 *
 * @param plugin handle to the plugin
 */
static void
unix_plugin_do_write (struct Plugin *plugin)
{
  ssize_t sent = 0;
  struct UNIXMessageWrapper *msgw;
  struct Queue *queue;
  int did_delete;

  queue = NULL;
  did_delete = GNUNET_NO;
  while (NULL != (msgw = plugin->msg_head))
  {
    if (GNUNET_TIME_absolute_get_remaining (msgw->timeout).rel_value_us > 0)
      break; /* Message is ready for sending */
    /* Message has a timeout */
    did_delete = GNUNET_YES;
    LOG (GNUNET_ERROR_TYPE_DEBUG,
	 "Timeout for message with %u bytes \n",
	 (unsigned int) msgw->msgsize);
    GNUNET_CONTAINER_DLL_remove (plugin->msg_head,
                                 plugin->msg_tail,
                                 msgw);
    queue = msgw->queue;
    queue->msgs_in_queue--;
    GNUNET_assert (queue->bytes_in_queue >= msgw->msgsize);
    queue->bytes_in_queue -= msgw->msgsize;
    GNUNET_assert (plugin->bytes_in_queue >= msgw->msgsize);
    plugin->bytes_in_queue -= msgw->msgsize;
    GNUNET_STATISTICS_set (plugin->env->stats,
			   "# bytes currently in UNIX buffers",
			   plugin->bytes_in_queue,
                           GNUNET_NO);
    GNUNET_STATISTICS_update (plugin->env->stats,
			      "# UNIX bytes discarded",
			      msgw->msgsize,
			      GNUNET_NO);
    if (NULL != msgw->cont)
      msgw->cont (msgw->cont_cls,
		  &msgw->queue->target,
		  GNUNET_SYSERR,
		  msgw->payload,
		  0);
    GNUNET_free (msgw->msg);
    GNUNET_free (msgw);
  }
  if (NULL == msgw)
  {
    if (GNUNET_YES == did_delete)
      notify_queue_monitor (plugin,
                              queue,
                              GNUNET_TRANSPORT_SS_UPDATE);
    return; /* Nothing to send at the moment */
  }
  queue = msgw->queue;
  sent = unix_real_send (plugin,
                         unix_sock,
                         &queue->target,
                         (const char *) msgw->msg,
                         msgw->msgsize,
                         msgw->priority,
                         msgw->timeout,
                         msgw->queue->address->address,
                         msgw->queue->address->address_length,
                         msgw->payload,
                         msgw->cont, msgw->cont_cls);
  if (RETRY == sent)
  {
    GNUNET_STATISTICS_update (plugin->env->stats,
			      "# UNIX retry attempts",
			      1, GNUNET_NO);
    notify_queue_monitor (plugin,
                            queue,
                            GNUNET_TRANSPORT_SS_UPDATE);
    return;
  }
  GNUNET_CONTAINER_DLL_remove (plugin->msg_head,
                               plugin->msg_tail,
                               msgw);
  queue->msgs_in_queue--;
  GNUNET_assert (queue->bytes_in_queue >= msgw->msgsize);
  queue->bytes_in_queue -= msgw->msgsize;
  GNUNET_assert (plugin->bytes_in_queue >= msgw->msgsize);
  plugin->bytes_in_queue -= msgw->msgsize;
  GNUNET_STATISTICS_set (plugin->env->stats,
                         "# bytes currently in UNIX buffers",
                         plugin->bytes_in_queue, GNUNET_NO);
  notify_queue_monitor (plugin,
                          queue,
                          GNUNET_TRANSPORT_SS_UPDATE);
  if (GNUNET_SYSERR == sent)
  {
    /* failed and no retry */
    if (NULL != msgw->cont)
      msgw->cont (msgw->cont_cls,
                  &msgw->queue->target,
                  GNUNET_SYSERR,
                  msgw->payload, 0);
    GNUNET_STATISTICS_update (plugin->env->stats,
			      "# UNIX bytes discarded",
			      msgw->msgsize,
			      GNUNET_NO);
    GNUNET_free (msgw->msg);
    GNUNET_free (msgw);
    return;
  }
  /* successfully sent bytes */
  GNUNET_break (sent > 0);
  GNUNET_STATISTICS_update (plugin->env->stats,
			    "# bytes transmitted via UNIX",
			    msgw->msgsize,
			    GNUNET_NO);
  if (NULL != msgw->cont)
    msgw->cont (msgw->cont_cls,
                &msgw->queue->target,
		GNUNET_OK,
		msgw->payload,
		msgw->msgsize);
  GNUNET_free (msgw->msg);
  GNUNET_free (msgw);
}


/**
 * We have been notified that our socket has something to read.
 * Then reschedule this function to be called again once more is available.
 *
 * @param cls the plugin handle
 */
static void
unix_plugin_select_read (void *cls)
{
  struct Plugin *plugin = cls;
  const struct GNUNET_SCHEDULER_TaskContext *tc;

  plugin->read_task = NULL;
  tc = GNUNET_SCHEDULER_get_task_context ();
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_READ_READY))
    unix_plugin_do_read (plugin);
  plugin->read_task =
    GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                   unix_sock,
                                   &unix_plugin_select_read, plugin);
}


/**
 * We have been notified that our socket is ready to write.
 * Then reschedule this function to be called again once more is available.
 *
 * @param cls the plugin handle
 */
static void
unix_plugin_select_write (void *cls)
{
  struct Plugin *plugin = cls;
  const struct GNUNET_SCHEDULER_TaskContext *tc;

  plugin->write_task = NULL;
  tc = GNUNET_SCHEDULER_get_task_context ();
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_WRITE_READY))
    unix_plugin_do_write (plugin);
  if (NULL == plugin->msg_head)
    return; /* write queue empty */
  plugin->write_task =
    GNUNET_SCHEDULER_add_write_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                    unix_sock,
                                    &unix_plugin_select_write, plugin);
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
 * @param queue which queue must be used
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
unix_plugin_send (void *cls,
                  struct Queue *queue,
                  const char *msgbuf,
                  size_t msgbuf_size,
                  unsigned int priority,
                  struct GNUNET_TIME_Relative to,
                  GNUNET_TRANSPORT_TransmitContinuation cont,
                  void *cont_cls)
{
  struct Plugin *plugin = cls;
  struct UNIXMessageWrapper *wrapper;
  struct UNIXMessage *message;
  int ssize;

  if (GNUNET_OK !=
      GNUNET_CONTAINER_multipeermap_contains_value (plugin->queue_map,
						    &queue->target,
						    queue))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
	 "Invalid queue for peer `%s' `%s'\n",
	 GNUNET_i2s (&queue->target),
	 unix_plugin_address_to_string (NULL,
                                        queue->address->address,
                                        queue->address->address_length));
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Sending %u bytes with queue for peer `%s' `%s'\n",
       msgbuf_size,
       GNUNET_i2s (&queue->target),
       unix_plugin_address_to_string (NULL,
                                      queue->address->address,
                                      queue->address->address_length));
  ssize = sizeof (struct UNIXMessage) + msgbuf_size;
  message = GNUNET_malloc (sizeof (struct UNIXMessage) + msgbuf_size);
  message->header.size = htons (ssize);
  message->header.type = htons (0);
  GNUNET_memcpy (&message->sender, plugin->env->my_identity,
          sizeof (struct GNUNET_PeerIdentity));
  GNUNET_memcpy (&message[1], msgbuf, msgbuf_size);
  wrapper = GNUNET_new (struct UNIXMessageWrapper);
  wrapper->msg = message;
  wrapper->msgsize = ssize;
  wrapper->payload = msgbuf_size;
  wrapper->priority = priority;
  wrapper->timeout = GNUNET_TIME_absolute_add (GNUNET_TIME_absolute_get (),
                                               to);
  wrapper->cont = cont;
  wrapper->cont_cls = cont_cls;
  wrapper->queue = queue;
  GNUNET_CONTAINER_DLL_insert_tail (plugin->msg_head,
                                    plugin->msg_tail,
                                    wrapper);
  plugin->bytes_in_queue += ssize;
  queue->bytes_in_queue += ssize;
  queue->msgs_in_queue++;
  GNUNET_STATISTICS_set (plugin->env->stats,
			 "# bytes currently in UNIX buffers",
			 plugin->bytes_in_queue,
			 GNUNET_NO);
  notify_queue_monitor (plugin,
                          queue,
                          GNUNET_TRANSPORT_SS_UPDATE);
  if (NULL == plugin->write_task)
    plugin->write_task =
      GNUNET_SCHEDULER_add_write_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                      unix_sock,
                                      &unix_plugin_select_write, plugin);
  return ssize;
}


/**
 * Signature of functions implementing the
 * sending functionality of a message queue.
 *
 * @param mq the message queue
 * @param msg the message to send
 * @param impl_state state of the implementation
 */
static void
mq_send (struct GNUNET_MQ_Handle *mq,
	 const struct GNUNET_MessageHeader *msg,
	 void *impl_state)
{
}


/**
 * Signature of functions implementing the
 * destruction of a message queue.
 * Implementations must not free @a mq, but should
 * take care of @a impl_state.
 *
 * @param mq the message queue to destroy
 * @param impl_state state of the implementation
 */
static void
mq_destroy (struct GNUNET_MQ_Handle *mq,
	    void *impl_state)
{
}


/**
 * Implementation function that cancels the currently sent message.
 *
 * @param mq message queue
 * @param impl_state state specific to the implementation
 */
static void
mq_cancel (struct GNUNET_MQ_Handle *mq,
	   void *impl_state)
{
}


/**
 * Generic error handler, called with the appropriate
 * error code and the same closure specified at the creation of
 * the message queue.
 * Not every message queue implementation supports an error handler.
 *
 * @param cls closure
 * @param error error code
 */
static void
mq_error (void *cls,
	  enum GNUNET_MQ_Error error)
{
}



/**
 * Function called by the transport service to initialize a
 * message queue given address information about another peer.
 * If and when the communication channel is established, the
 * communicator must call #GNUNET_TRANSPORT_communicator_mq_add()
 * to notify the service that the channel is now up.  It is
 * the responsibility of the communicator to manage sane
 * retries and timeouts for any @a peer/@a address combination
 * provided by the transport service.  Timeouts and retries
 * do not need to be signalled to the transport service.
 *
 * @param cls closure
 * @param peer identity of the other peer
 * @param address where to send the message, human-readable
 *        communicator-specific format, 0-terminated, UTF-8
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if the provided address is invalid
 */
static int
mq_init (void *cls,
	 const struct GNUNET_PeerIdentity *peer,
	 const void *address)
{
  struct Queue *queue;
  char *a;
  char *e;
  int is_abs;
  sockaddr_un *un;
  socklen_t un_len;
  
  if (NULL == strncmp (address,
		       COMMUNICATOR_NAME "-",
		       strlen (COMMUNICATOR_NAME "-")))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  a = GNUNET_strdup (&address[strlen (COMMUNICATOR_NAME "-")]);
  e = strchr (a,
	      (unsigned char) '#');
  if (NULL == e)
  {
    GNUNET_free (a);
    GNUNET_break_op (0);
    return GNUNET_SYSERR;    
  }
  is_abs = ('1' == e[1]);
  *e = '\0';
  un = unix_address_to_sockaddr (a,
				 &un_len,
				 is_abs);
  queue = lookup_queue (peer,
			un,
			un_len);
  if (NULL != queue)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		"Address `%s' ignored, queue exists\n",
		address);
    GNUNET_free (un);
    return GNUNET_OK;
  }
  queue = GNUNET_new (struct Queue);
  queue->target = *peer;
  queue->address = un;
  queue->address_len = un_len;
  (void) GNUNET_CONTAINER_multihashmap_put (queue_map,
					    &queue->target,
					    queue,
					    GNUET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  GNUNET_STATISTICS_set (stats,
			 "# UNIX queues active",
			 GNUNET_CONTAINER_multipeermap_size (plugin->queue_map),
			 GNUNET_NO);
  queue->timeout = GNUNET_SCHEDULER_add_delayed (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT,
						 &queue_timeout,
						 queue);
  queue->mq
    = GNUNET_MQ_queue_for_callbacks (&mq_send,
				     &mq_destroy,
				     &mq_cancel,
				     queue,
				     NULL,
				     &mq_error,
				     queue);
  queue->qh
    = GNUNET_TRANSPORT_communicator_mq_add (ch,
					    &queue->target,
					    address,
					    ATS,
					    queue->mq);
  return GNUNET_OK;
}


/**
 * Shutdown the UNIX communicator.
 *
 * @param cls NULL (always)
 */
static void
do_shutdown (void *cls)
{
  struct UNIXMessageWrapper *msgw;

  while (NULL != (msgw = msg_head))
  {
    GNUNET_CONTAINER_DLL_remove (msg_head,
                                 msg_tail,
                                 msgw);
    queue = msgw->queue;
    queue->msgs_in_queue--;
    GNUNET_assert (queue->bytes_in_queue >= msgw->msgsize);
    queue->bytes_in_queue -= msgw->msgsize;
    GNUNET_assert (bytes_in_queue >= msgw->msgsize);
    bytes_in_queue -= msgw->msgsize;
    GNUNET_free (msgw->msg);
    GNUNET_free (msgw);
  }
  if (NULL != read_task)
  {
    GNUNET_SCHEDULER_cancel (read_task);
    read_task = NULL;
  }
  if (NULL != write_task)
  {
    GNUNET_SCHEDULER_cancel (write_task);
    write_task = NULL;
  }
  if (NULL != unix_sock)
  {
    GNUNET_break (GNUNET_OK ==
                  GNUNET_NETWORK_socket_close (unix_sock));
    unix_sock = NULL;
  }
  GNUNET_CONTAINER_multipeermap_iterate (queue_map,
					 &get_queue_delete_it,
                                         NULL);
  GNUNET_CONTAINER_multipeermap_destroy (queue_map);
  if (NULL != ai)
  {
    GNUNET_TRANSPORT_communicator_address_remove (ai);
    ai = NULL;
  }
  if (NULL != ch)
  {
    GNUNET_TRANSPORT_communicator_disconnect (ch);
    ch = NULL;
  }
  GNUNET_break (0 == bytes_in_queue);
}


/**
 * Setup communicator and launch network interactions.
 * 
 * @param cls NULL (always)
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param cfg configuration
 */
static void
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  char *unix_socket_path;
  int is_abstract;
  struct sockaddr_un *un;
  socklen_t un_len;
  char *my_addr;
  (void) cls;
  
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (cfg,
					       "transport-unix",
					       "UNIXPATH",
					       &unix_socket_path))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
                               "communicator-unix",
                               "UNIXPATH");
    return;
  }

  /* Initialize my flags */
  is_abstract = 0;
#ifdef LINUX
  is_abstract
    = GNUNET_CONFIGURATION_get_value_yesno (cfg,
					    "testing",
					    "USE_ABSTRACT_SOCKETS");
#endif
  un = unix_address_to_sockaddr (unix_socket_path,
                                 &un_len,
				 is_abstract);
  unix_sock = GNUNET_NETWORK_socket_create (AF_UNIX,
					    SOCK_DGRAM,
					    0);
  if (NULL == unix_sock)
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR,
			 "socket");
    GNUNET_free (un);
    GNUNET_free (unix_socket_path);
    return;
  }
  if ( ('\0' != un->sun_path[0]) &&
       (GNUNET_OK !=
	GNUNET_DISK_directory_create_for_file (un->sun_path)) )
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
	 _("Cannot create path to `%s'\n"),
	 un->sun_path);
    GNUNET_NETWORK_socket_close (unix_sock);
    unix_sock = NULL;
    GNUNET_free (un);
    GNUNET_free (unix_socket_path);
    return;
  }
  if (GNUNET_OK !=
      GNUNET_NETWORK_socket_bind (unix_sock,
                                  (const struct sockaddr *) un,
				  un_len))
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR,
			 "bind");
    LOG (GNUNET_ERROR_TYPE_ERROR,
	 _("Cannot bind to `%s'\n"),
	 un->sun_path);
    GNUNET_NETWORK_socket_close (unix_sock);
    unix_sock = NULL;
    GNUNET_free (un);
    GNUNET_free (unix_socket_path);
    return;
  }
  GNUNET_free (un);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Bound to `%s'\n",
       unix_socket_path);
  GNUNET_SCHEDULER_add_shutdown (&do_shutdown,
				 NULL);
  read_task = GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
					     unix_sock,
					     &unix_plugin_select_read,
					     NULL);
  queue_map = GNUNET_CONTAINER_multipeermap_create (10,
						      GNUNET_NO);
  ch = GNUNET_TRANSPORT_communicator_connect (cfg,
					      "unix",
					      65535,
					      &mq_init,
					      NULL);
  if (NULL == ch)
  {
    GNUNET_break (0);
    GNUNET_SCHEDULER_shutdown ();
    GNUNET_free (unix_socket_path);
    return;
  }
  GNUNET_asprintf (&my_addr,
		   "%s-%s#%d",
		   COMMUNICATOR_NAME,
		   unix_socket_path,
		   is_abstract);
  
  ai = GNUNET_TRANSPORT_communicator_address_add (ch,
						  my_addr,
						  GNUNET_ATS_NET_LOOPBACK,
						  GNUNET_TIME_UNIT_FOREVER_REL);
  GNUNET_free (my_addr);
  GNUNET_free (unix_socket_path);
}


/**
 * The main function for the UNIX communicator.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc,
      char *const *argv)
{
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  int ret;

  if (GNUNET_OK !=
      GNUNET_STRINGS_get_utf8_args (argc, argv,
				    &argc, &argv))
    return 2;

  ret =
      (GNUNET_OK ==
       GNUNET_PROGRAM_run (argc, argv,
                           "gnunet-communicator-unix",
                           _("GNUnet UNIX domain socket communicator"),
                           options,
			   &run,
			   NULL)) ? 0 : 1;
  GNUNET_free ((void*) argv);
  return ret;
}


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

/* end of gnunet-communicator-unix.c */
