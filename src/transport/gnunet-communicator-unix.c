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

     SPDX-License-Identifier: AGPL3.0-or-later
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
#include "gnunet_constants.h"
#include "gnunet_nt_lib.h"
#include "gnunet_statistics_service.h"
#include "gnunet_transport_communication_service.h"

/**
 * How many messages do we keep at most in the queue to the
 * transport service before we start to drop (default,
 * can be changed via the configuration file).
 * Should be _below_ the level of the communicator API, as
 * otherwise we may read messages just to have them dropped
 * by the communicator API.
 */
#define DEFAULT_MAX_QUEUE_LENGTH 8000

/**
 * Address prefix used by the communicator.
 */
#define COMMUNICATOR_ADDRESS_PREFIX "unix"

/**
 * Configuration section used by the communicator.
 */
#define COMMUNICATOR_CONFIG_SECTION "communicator-unix"

/**
 * Our MTU.
 */
#ifndef DARWIN
#define UNIX_MTU UINT16_MAX
#else
#define UNIX_MTU 2048
#endif

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
   * To whom are we talking to.
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
   * Message currently scheduled for transmission, non-NULL if and only
   * if this queue is in the #queue_head DLL.
   */
  struct UNIXMessage *msg;

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
  struct GNUNET_SCHEDULER_Task *timeout_task;
};

/**
 * My Peer Identity
 */
static struct GNUNET_PeerIdentity my_identity;

/**
 * ID of read task
 */
static struct GNUNET_SCHEDULER_Task *read_task;

/**
 * ID of write task
 */
static struct GNUNET_SCHEDULER_Task *write_task;

/**
 * Number of messages we currently have in our queues towards the transport service.
 */
static unsigned long long delivering_messages;

/**
 * Maximum queue length before we stop reading towards the transport service.
 */
static unsigned long long max_queue_length;

/**
 * For logging statistics.
 */
static struct GNUNET_STATISTICS_Handle *stats;

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
static struct Queue *queue_head;

/**
 * Tail of queue of messages to transmit.
 */
static struct Queue *queue_tail;

/**
 * socket that we transmit all data with
 */
static struct GNUNET_NETWORK_Handle *unix_sock;

/**
 * Handle to the operation that publishes our address.
 */
static struct GNUNET_TRANSPORT_AddressIdentifier *ai;


/**
 * Functions with this signature are called whenever we need
 * to close a queue due to a disconnect or failure to
 * establish a connection.
 *
 * @param queue queue to close down
 */
static void
queue_destroy (struct Queue *queue)
{
  struct GNUNET_MQ_Handle *mq;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Disconnecting queue for peer `%s'\n",
              GNUNET_i2s (&queue->target));
  if (0 != queue->bytes_in_queue)
  {
    GNUNET_CONTAINER_DLL_remove (queue_head, queue_tail, queue);
    queue->bytes_in_queue = 0;
  }
  if (NULL != (mq = queue->mq))
  {
    queue->mq = NULL;
    GNUNET_MQ_destroy (mq);
  }
  GNUNET_assert (
    GNUNET_YES ==
    GNUNET_CONTAINER_multipeermap_remove (queue_map, &queue->target, queue));
  GNUNET_STATISTICS_set (stats,
                         "# queues active",
                         GNUNET_CONTAINER_multipeermap_size (queue_map),
                         GNUNET_NO);
  if (NULL != queue->timeout_task)
  {
    GNUNET_SCHEDULER_cancel (queue->timeout_task);
    queue->timeout_task = NULL;
  }
  GNUNET_free (queue->address);
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
    queue->timeout_task =
      GNUNET_SCHEDULER_add_delayed (left, &queue_timeout, queue);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Queue %p was idle for %s, disconnecting\n",
              queue,
              GNUNET_STRINGS_relative_time_to_string (
                GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT,
                GNUNET_YES));
  queue_destroy (queue);
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
  queue->timeout =
    GNUNET_TIME_relative_to_absolute (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT);
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
unix_address_to_sockaddr (const char *unixpath, socklen_t *sock_len)
{
  struct sockaddr_un *un;
  size_t slen;

  GNUNET_assert (0 < strlen (unixpath));   /* sanity check */
  un = GNUNET_new (struct sockaddr_un);
  un->sun_family = AF_UNIX;
  slen = strlen (unixpath);
  if (slen >= sizeof(un->sun_path))
    slen = sizeof(un->sun_path) - 1;
  GNUNET_memcpy (un->sun_path, unixpath, slen);
  un->sun_path[slen] = '\0';
  slen = sizeof(struct sockaddr_un);
#if HAVE_SOCKADDR_UN_SUN_LEN
  un->sun_len = (u_char) slen;
#endif
  (*sock_len) = slen;
  if ('@' == un->sun_path[0])
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
  const struct sockaddr_un *un;

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
lookup_queue_it (void *cls, const struct GNUNET_PeerIdentity *key, void *value)
{
  struct LookupCtx *lctx = cls;
  struct Queue *queue = value;

  if ((queue->address_len == lctx->un_len) &&
      (0 == memcmp (lctx->un, queue->address, queue->address_len)))
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
              const struct sockaddr_un *un,
              socklen_t un_len)
{
  struct LookupCtx lctx;

  lctx.un = un;
  lctx.un_len = un_len;
  lctx.res = NULL;
  GNUNET_CONTAINER_multipeermap_get_multiple (queue_map,
                                              peer,
                                              &lookup_queue_it,
                                              &lctx);
  return lctx.res;
}


/**
 * We have been notified that our socket is ready to write.
 * Then reschedule this function to be called again once more is available.
 *
 * @param cls NULL
 */
static void
select_write_cb (void *cls)
{
  struct Queue *queue = queue_tail;
  const struct GNUNET_MessageHeader *msg = &queue->msg->header;
  size_t msg_size = ntohs (msg->size);
  ssize_t sent;

  /* take queue of the ready list */
  write_task = NULL;
resend:
  /* Send the data */
  sent = GNUNET_NETWORK_socket_sendto (unix_sock,
                                       msg,
                                       msg_size,
                                       (const struct sockaddr *) queue->address,
                                       queue->address_len);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "UNIX transmitted message to %s (%d/%u: %s)\n",
              GNUNET_i2s (&queue->target),
              (int) sent,
              (unsigned int) msg_size,
              (sent < 0) ? strerror (errno) : "ok");
  if (-1 != sent)
  {
    GNUNET_CONTAINER_DLL_remove (queue_head, queue_tail, queue);
    if (NULL != queue_head)
      write_task = GNUNET_SCHEDULER_add_write_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                                   unix_sock,
                                                   &select_write_cb,
                                                   NULL);

    /* send 'msg' */
    GNUNET_free (queue->msg);
    queue->msg = NULL;
    GNUNET_MQ_impl_send_continue (queue->mq);
    GNUNET_STATISTICS_update (stats,
                              "# bytes sent",
                              (long long) sent,
                              GNUNET_NO);
    reschedule_queue_timeout (queue);
    return;   /* all good */
  }
  GNUNET_STATISTICS_update (stats,
                            "# network transmission failures",
                            1,
                            GNUNET_NO);
  write_task = GNUNET_SCHEDULER_add_write_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                               unix_sock,
                                               &select_write_cb,
                                               NULL);
  switch (errno)
  {
  case EAGAIN:
  case ENOBUFS:
    /* We should retry later... */
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_DEBUG, "send");
    return;

  case EMSGSIZE: {
      socklen_t size = 0;
      socklen_t len = sizeof(size);

      GNUNET_NETWORK_socket_getsockopt (unix_sock,
                                        SOL_SOCKET,
                                        SO_SNDBUF,
                                        &size,
                                        &len);
      if (size > ntohs (msg->size))
      {
        /* Buffer is bigger than message:  error, no retry
         * This should never happen!*/
        GNUNET_break (0);
        return;
      }
      GNUNET_log (
        GNUNET_ERROR_TYPE_WARNING,
        "Trying to increase socket buffer size from %u to %u for message size %u\n",
        (unsigned int) size,
        (unsigned int) ((msg_size / 1000) + 2) * 1000,
        (unsigned int) msg_size);
      size = ((msg_size / 1000) + 2) * 1000;
      if (GNUNET_OK == GNUNET_NETWORK_socket_setsockopt (unix_sock,
                                                         SOL_SOCKET,
                                                         SO_SNDBUF,
                                                         &size,
                                                         sizeof(size)))
        goto resend; /* Increased buffer size, retry sending */
      /* Ok, then just try very modest increase */
      size = msg_size;
      if (GNUNET_OK == GNUNET_NETWORK_socket_setsockopt (unix_sock,
                                                         SOL_SOCKET,
                                                         SO_SNDBUF,
                                                         &size,
                                                         sizeof(size)))
        goto resend; /* Increased buffer size, retry sending */
      /* Could not increase buffer size: error, no retry */
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "setsockopt");
      return;
    }

  default:
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "send");
    return;
  }
}


/**
 * Signature of functions implementing the sending functionality of a
 * message queue.
 *
 * @param mq the message queue
 * @param msg the message to send
 * @param impl_state our `struct Queue`
 */
static void
mq_send (struct GNUNET_MQ_Handle *mq,
         const struct GNUNET_MessageHeader *msg,
         void *impl_state)
{
  struct Queue *queue = impl_state;
  size_t msize = ntohs (msg->size);

  GNUNET_assert (mq == queue->mq);
  GNUNET_assert (NULL == queue->msg);
  // Convert to UNIXMessage
  queue->msg = GNUNET_malloc (msize + sizeof (struct UNIXMessage));
  queue->msg->header.size = htons (msize + sizeof (struct UNIXMessage));
  queue->msg->sender = my_identity;
  memcpy (&queue->msg[1], msg, msize);
  GNUNET_CONTAINER_DLL_insert (queue_head, queue_tail, queue);
  GNUNET_assert (NULL != unix_sock);
  if (NULL == write_task)
    write_task = GNUNET_SCHEDULER_add_write_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                                 unix_sock,
                                                 &select_write_cb,
                                                 NULL);
}


/**
 * Signature of functions implementing the destruction of a message
 * queue.  Implementations must not free @a mq, but should take care
 * of @a impl_state.
 *
 * @param mq the message queue to destroy
 * @param impl_state our `struct Queue`
 */
static void
mq_destroy (struct GNUNET_MQ_Handle *mq, void *impl_state)
{
  struct Queue *queue = impl_state;

  if (mq == queue->mq)
  {
    queue->mq = NULL;
    queue_destroy (queue);
  }
}


/**
 * Implementation function that cancels the currently sent message.
 *
 * @param mq message queue
 * @param impl_state our `struct Queue`
 */
static void
mq_cancel (struct GNUNET_MQ_Handle *mq, void *impl_state)
{
  struct Queue *queue = impl_state;

  GNUNET_assert (NULL != queue->msg);
  queue->msg = NULL;
  GNUNET_CONTAINER_DLL_remove (queue_head, queue_tail, queue);
  GNUNET_assert (NULL != write_task);
  if (NULL == queue_head)
  {
    GNUNET_SCHEDULER_cancel (write_task);
    write_task = NULL;
  }
}


/**
 * Generic error handler, called with the appropriate
 * error code and the same closure specified at the creation of
 * the message queue.
 * Not every message queue implementation supports an error handler.
 *
 * @param cls our `struct Queue`
 * @param error error code
 */
static void
mq_error (void *cls, enum GNUNET_MQ_Error error)
{
  struct Queue *queue = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "UNIX MQ error in queue to %s: %d\n",
              GNUNET_i2s (&queue->target),
              (int) error);
  queue_destroy (queue);
}


/**
 * Creates a new outbound queue the transport service will use to send
 * data to another peer.
 *
 * @param peer the target peer
 * @param cs inbound or outbound queue
 * @param un the address
 * @param un_len number of bytes in @a un
 * @return the queue or NULL of max connections exceeded
 */
static struct Queue *
setup_queue (const struct GNUNET_PeerIdentity *target,
             enum GNUNET_TRANSPORT_ConnectionStatus cs,
             const struct sockaddr_un *un,
             socklen_t un_len)
{
  struct Queue *queue;

  queue = GNUNET_new (struct Queue);
  queue->target = *target;
  queue->address = GNUNET_memdup (un, un_len);
  queue->address_len = un_len;
  (void) GNUNET_CONTAINER_multipeermap_put (
    queue_map,
    &queue->target,
    queue,
    GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  GNUNET_STATISTICS_set (stats,
                         "# queues active",
                         GNUNET_CONTAINER_multipeermap_size (queue_map),
                         GNUNET_NO);
  queue->timeout =
    GNUNET_TIME_relative_to_absolute (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT);
  queue->timeout_task =
    GNUNET_SCHEDULER_add_delayed (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT,
                                  &queue_timeout,
                                  queue);
  queue->mq = GNUNET_MQ_queue_for_callbacks (&mq_send,
                                             &mq_destroy,
                                             &mq_cancel,
                                             queue,
                                             NULL,
                                             &mq_error,
                                             queue);
  {
    char *foreign_addr;

    if ('\0' == un->sun_path[0])
      GNUNET_asprintf (&foreign_addr,
                       "%s-@%s",
                       COMMUNICATOR_ADDRESS_PREFIX,
                       &un->sun_path[1]);
    else
      GNUNET_asprintf (&foreign_addr,
                       "%s-%s",
                       COMMUNICATOR_ADDRESS_PREFIX,
                       un->sun_path);
    queue->qh = GNUNET_TRANSPORT_communicator_mq_add (ch,
                                                      &queue->target,
                                                      foreign_addr,
                                                      UNIX_MTU - sizeof (struct UNIXMessage),
                                                      GNUNET_TRANSPORT_QUEUE_LENGTH_UNLIMITED,
                                                      0,
                                                      GNUNET_NT_LOOPBACK,
                                                      cs,
                                                      queue->mq);
    GNUNET_free (foreign_addr);
  }
  return queue;
}


/**
 * We have been notified that our socket has something to read. Do the
 * read and reschedule this function to be called again once more is
 * available.
 *
 * @param cls NULL
 */
static void
select_read_cb (void *cls);


/**
 * Function called when message was successfully passed to
 * transport service.  Continue read activity.
 *
 * @param cls NULL
 * @param success #GNUNET_OK on success
 */
static void
receive_complete_cb (void *cls, int success)
{
  (void) cls;
  delivering_messages--;
  if (GNUNET_OK != success)
    GNUNET_STATISTICS_update (stats,
                              "# transport transmission failures",
                              1,
                              GNUNET_NO);
  if ((NULL == read_task) && (delivering_messages < max_queue_length) &&
      (NULL != unix_sock))
    read_task = GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                               unix_sock,
                                               &select_read_cb,
                                               NULL);
}


/**
 * We have been notified that our socket has something to read. Do the
 * read and reschedule this function to be called again once more is
 * available.
 *
 * @param cls NULL
 */
static void
select_read_cb (void *cls)
{
  char buf[65536] GNUNET_ALIGN;
  struct Queue *queue;
  const struct UNIXMessage *msg;
  struct sockaddr_un un;
  socklen_t addrlen;
  ssize_t ret;
  uint16_t msize;

  GNUNET_assert (NULL != unix_sock);
  read_task = GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                             unix_sock,
                                             &select_read_cb,
                                             NULL);
  addrlen = sizeof(un);
  memset (&un, 0, sizeof(un));
  ret = GNUNET_NETWORK_socket_recvfrom (unix_sock,
                                        buf,
                                        sizeof(buf),
                                        (struct sockaddr *) &un,
                                        &addrlen);
  if ((-1 == ret) && ((EAGAIN == errno) || (ENOBUFS == errno)))
    return;
  if (-1 == ret)
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "recvfrom");
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Read %d bytes from socket %s\n",
              (int) ret,
              un.sun_path);
  GNUNET_assert (AF_UNIX == (un.sun_family));
  msg = (struct UNIXMessage *) buf;
  msize = ntohs (msg->header.size);
  if ((msize < sizeof(struct UNIXMessage)) || (msize > ret))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Wrong message size: %d bytes\n",
                msize);
    GNUNET_break_op (0);
    return;
  }
  queue = lookup_queue (&msg->sender, &un, addrlen);
  if (NULL == queue)
    queue =
      setup_queue (&msg->sender, GNUNET_TRANSPORT_CS_INBOUND, &un, addrlen);
  else
    reschedule_queue_timeout (queue);
  if (NULL == queue)
  {
    GNUNET_log (
      GNUNET_ERROR_TYPE_ERROR,
      _ (
        "Maximum number of UNIX connections exceeded, dropping incoming message\n"));
    return;
  }

  {
    uint16_t tsize = msize - sizeof(struct UNIXMessage);

    const struct GNUNET_MessageHeader *currhdr;
    struct GNUNET_MessageHeader al_hdr;

    currhdr = (const struct GNUNET_MessageHeader *) &msg[1];
    /* ensure aligned access */
    memcpy (&al_hdr, currhdr, sizeof(al_hdr));
    if ((tsize < sizeof(struct GNUNET_MessageHeader)) ||
        (tsize != ntohs(al_hdr.size)))
    {
      GNUNET_break_op (0);
      return;
    }
    ret = GNUNET_TRANSPORT_communicator_receive (ch,
                                                 &msg->sender,
                                                 currhdr,
                                                 GNUNET_TIME_UNIT_FOREVER_REL,
                                                 &receive_complete_cb,
                                                 NULL);
    if (GNUNET_SYSERR == ret)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Transport not up!\n");
      return;   /* transport not up */
    }
    if (GNUNET_NO == ret)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Error sending message to transport\n");
      return;
    }
    delivering_messages++;
  }
  if (delivering_messages >= max_queue_length)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Back pressure %llu\n", delivering_messages);

    /* we should try to apply 'back pressure' */
    GNUNET_SCHEDULER_cancel (read_task);
    read_task = NULL;
  }
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
mq_init (void *cls, const struct GNUNET_PeerIdentity *peer, const char *address)
{
  struct Queue *queue;
  const char *path;
  struct sockaddr_un *un;
  socklen_t un_len;

  (void) cls;
  if (0 != strncmp (address,
                    COMMUNICATOR_ADDRESS_PREFIX "-",
                    strlen (COMMUNICATOR_ADDRESS_PREFIX "-")))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  path = &address[strlen (COMMUNICATOR_ADDRESS_PREFIX "-")];
  un = unix_address_to_sockaddr (path, &un_len);
  queue = lookup_queue (peer, un, un_len);
  if (NULL != queue)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Address `%s' for %s ignored, queue exists\n",
                path,
                GNUNET_i2s (peer));
    GNUNET_free (un);
    return GNUNET_OK;
  }
  queue = setup_queue (peer, GNUNET_TRANSPORT_CS_OUTBOUND, un, un_len);
  GNUNET_free (un);
  if (NULL == queue)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Failed to setup queue to %s at `%s'\n",
                GNUNET_i2s (peer),
                path);
    return GNUNET_NO;
  }
  return GNUNET_OK;
}


/**
 * Iterator over all message queues to clean up.
 *
 * @param cls NULL
 * @param target unused
 * @param value the queue to destroy
 * @return #GNUNET_OK to continue to iterate
 */
static int
get_queue_delete_it (void *cls,
                     const struct GNUNET_PeerIdentity *target,
                     void *value)
{
  struct Queue *queue = value;

  (void) cls;
  (void) target;
  queue_destroy (queue);
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
    GNUNET_break (GNUNET_OK == GNUNET_NETWORK_socket_close (unix_sock));
    unix_sock = NULL;
  }
  GNUNET_CONTAINER_multipeermap_iterate (queue_map, &get_queue_delete_it, NULL);
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
  if (NULL != stats)
  {
    GNUNET_STATISTICS_destroy (stats, GNUNET_NO);
    stats = NULL;
  }
}


/**
 * Function called when the transport service has received an
 * acknowledgement for this communicator (!) via a different return
 * path.
 *
 * Not applicable for UNIX.
 *
 * @param cls closure
 * @param sender which peer sent the notification
 * @param msg payload
 */
static void
enc_notify_cb (void *cls,
               const struct GNUNET_PeerIdentity *sender,
               const struct GNUNET_MessageHeader *msg)
{
  (void) cls;
  (void) sender;
  (void) msg;
  GNUNET_break_op (0);
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
  struct sockaddr_un *un;
  socklen_t un_len;
  char *my_addr;
  struct GNUNET_CRYPTO_EddsaPrivateKey *my_private_key;

  (void) cls;
  delivering_messages = 0;

  my_private_key = GNUNET_CRYPTO_eddsa_key_create_from_configuration (cfg);
  if (NULL == my_private_key)
  {
    GNUNET_log (
      GNUNET_ERROR_TYPE_ERROR,
      _ (
        "UNIX communicator is lacking key configuration settings. Exiting.\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GNUNET_CRYPTO_eddsa_key_get_public (my_private_key, &my_identity.public_key);

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (cfg,
                                               COMMUNICATOR_CONFIG_SECTION,
                                               "UNIXPATH",
                                               &unix_socket_path))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
                               COMMUNICATOR_CONFIG_SECTION,
                               "UNIXPATH");
    return;
  }
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (cfg,
                                             COMMUNICATOR_CONFIG_SECTION,
                                             "MAX_QUEUE_LENGTH",
                                             &max_queue_length))
    max_queue_length = DEFAULT_MAX_QUEUE_LENGTH;

  un = unix_address_to_sockaddr (unix_socket_path, &un_len);
  if (NULL == un)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to setup UNIX domain socket address with path `%s'\n",
                unix_socket_path);
    GNUNET_free (unix_socket_path);
    return;
  }
  unix_sock = GNUNET_NETWORK_socket_create (AF_UNIX, SOCK_DGRAM, 0);
  if (NULL == unix_sock)
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "socket");
    GNUNET_free (un);
    GNUNET_free (unix_socket_path);
    return;
  }
  if (('\0' != un->sun_path[0]) &&
      (GNUNET_OK != GNUNET_DISK_directory_create_for_file (un->sun_path)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _ ("Cannot create path to `%s'\n"),
                un->sun_path);
    GNUNET_NETWORK_socket_close (unix_sock);
    unix_sock = NULL;
    GNUNET_free (un);
    GNUNET_free (unix_socket_path);
    return;
  }
  if (GNUNET_OK != GNUNET_NETWORK_socket_bind (unix_sock,
                                               (const struct sockaddr *) un,
                                               un_len))
  {
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR, "bind", un->sun_path);
    GNUNET_NETWORK_socket_close (unix_sock);
    unix_sock = NULL;
    GNUNET_free (un);
    GNUNET_free (unix_socket_path);
    return;
  }
  GNUNET_free (un);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Bound to `%s'\n", unix_socket_path);
  stats = GNUNET_STATISTICS_create ("C-UNIX", cfg);
  GNUNET_SCHEDULER_add_shutdown (&do_shutdown, NULL);
  read_task = GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                             unix_sock,
                                             &select_read_cb,
                                             NULL);
  queue_map = GNUNET_CONTAINER_multipeermap_create (10, GNUNET_NO);
  ch = GNUNET_TRANSPORT_communicator_connect (cfg,
                                              COMMUNICATOR_CONFIG_SECTION,
                                              COMMUNICATOR_ADDRESS_PREFIX,
                                              GNUNET_TRANSPORT_CC_RELIABLE,
                                              &mq_init,
                                              NULL,
                                              &enc_notify_cb,
                                              NULL);
  if (NULL == ch)
  {
    GNUNET_break (0);
    GNUNET_SCHEDULER_shutdown ();
    GNUNET_free (unix_socket_path);
    return;
  }
  GNUNET_asprintf (&my_addr,
                   "%s-%s",
                   COMMUNICATOR_ADDRESS_PREFIX,
                   unix_socket_path);
  GNUNET_free (unix_socket_path);
  ai = GNUNET_TRANSPORT_communicator_address_add (ch,
                                                  my_addr,
                                                  GNUNET_NT_LOOPBACK,
                                                  GNUNET_TIME_UNIT_FOREVER_REL);
  GNUNET_free (my_addr);
}


/**
 * The main function for the UNIX communicator.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  int ret;

  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;

  ret = (GNUNET_OK ==
         GNUNET_PROGRAM_run (argc,
                             argv,
                             "gnunet-communicator-unix",
                             _ ("GNUnet UNIX domain socket communicator"),
                             options,
                             &run,
                             NULL))
        ? 0
        : 1;
  GNUNET_free_nz ((void *) argv);
  return ret;
}


#if defined(__linux__) && defined(__GLIBC__)
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
