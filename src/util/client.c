/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2006, 2008, 2009 Christian Grothoff (and other contributing authors)

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
 * @file util/client.c
 * @brief code for access to services
 * @author Christian Grothoff
 *
 * Generic TCP code for reliable, record-oriented TCP
 * connections between clients and service providers.
 */

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_client_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_server_lib.h"
#include "gnunet_scheduler_lib.h"

#define DEBUG_CLIENT GNUNET_NO

/**
 * Struct to refer to a GNUnet TCP connection.
 * This is more than just a socket because if the server
 * drops the connection, the client automatically tries
 * to reconnect (and for that needs connection information).
 */
struct GNUNET_CLIENT_Connection
{

  /**
   * the socket handle, NULL if not live
   */
  struct GNUNET_CONNECTION_Handle *sock;

  /**
   * Our scheduler.
   */
  struct GNUNET_SCHEDULER_Handle *sched;

  /**
   * Name of the service we interact with.
   */
  char *service_name;

  /**
   * ID of task used for receiving.
   */
  GNUNET_SCHEDULER_TaskIdentifier receiver_task;

  /**
   * Handler for current receiver task.
   */
  GNUNET_CLIENT_MessageHandler receiver_handler;

  /**
   * Closure for receiver_handler.
   */
  void *receiver_handler_cls;

  /**
   * Handler for service test completion (NULL unless in service_test)
   */
  GNUNET_SCHEDULER_Task test_cb;

  /**
   * Closure for test_cb (NULL unless in service_test)
   */
  void *test_cb_cls;

  /**
   * Buffer for received message.
   */
  char *received_buf;

  /**
   * Timeout for receiving a response (absolute time).
   */
  struct GNUNET_TIME_Absolute receive_timeout;

  /**
   * Number of bytes in received_buf that are valid.
   */
  size_t received_pos;

  /**
   * Size of received_buf.
   */
  unsigned int received_size;

  /**
   * Do we have a complete response in received_buf?
   */
  int msg_complete;

};


/**
 * Get a connection with a service.
 *
 * @param sched scheduler to use
 * @param service_name name of the service
 * @param cfg configuration to use
 * @return NULL on error (service unknown to configuration)
 */
struct GNUNET_CLIENT_Connection *
GNUNET_CLIENT_connect (struct GNUNET_SCHEDULER_Handle *sched,
                       const char *service_name,
                       const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_CLIENT_Connection *ret;
  struct GNUNET_CONNECTION_Handle *sock;
  char *hostname;
  unsigned long long port;

  if ((GNUNET_OK !=
       GNUNET_CONFIGURATION_get_value_number (cfg,
                                              service_name,
                                              "PORT",
                                              &port)) ||
      (port > 65535) ||
      (GNUNET_OK !=
       GNUNET_CONFIGURATION_get_value_string (cfg,
                                              service_name,
                                              "HOSTNAME", &hostname)))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Could not determine valid hostname and port for service `%s' from configuration.\n",
                  service_name);
      return NULL;
    }
  sock = GNUNET_CONNECTION_create_from_connect (sched,
                                                    hostname,
                                                    port,
                                                    GNUNET_SERVER_MAX_MESSAGE_SIZE);
  GNUNET_free (hostname);
  if (sock == NULL)
    return NULL;
  ret = GNUNET_malloc (sizeof (struct GNUNET_CLIENT_Connection));
  ret->sock = sock;
  ret->sched = sched;
  ret->service_name = GNUNET_strdup (service_name);
  return ret;
}


/**
 * Receiver task has completed, free rest of client
 * data structures.
 */
static void
finish_cleanup (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_CLIENT_Connection *sock = cls;

  GNUNET_array_grow (sock->received_buf, sock->received_size, 0);
  GNUNET_free (sock->service_name);
  GNUNET_free (sock);
}


/**
 * Destroy connection with the service.
 */
void
GNUNET_CLIENT_disconnect (struct GNUNET_CLIENT_Connection *sock)
{
  GNUNET_assert (sock->sock != NULL);
  GNUNET_CONNECTION_destroy (sock->sock);
  sock->sock = NULL;
  sock->receiver_handler = NULL;
  GNUNET_SCHEDULER_add_after (sock->sched,
                              GNUNET_YES,
                              GNUNET_SCHEDULER_PRIORITY_KEEP,
                              sock->receiver_task, &finish_cleanup, sock);
}


/**
 * check if message is complete
 */
static void
check_complete (struct GNUNET_CLIENT_Connection *conn)
{
  if ((conn->received_pos >= sizeof (struct GNUNET_MessageHeader)) &&
      (conn->received_pos >=
       ntohs (((const struct GNUNET_MessageHeader *) conn->
               received_buf)->size)))
    conn->msg_complete = GNUNET_YES;
}


/**
 * Callback function for data received from the network.  Note that
 * both "available" and "errCode" would be 0 if the read simply timed out.
 *
 * @param cls closure
 * @param buf pointer to received data
 * @param available number of bytes availabe in "buf",
 *        possibly 0 (on errors)
 * @param addr address of the sender
 * @param addrlen size of addr
 * @param errCode value of errno (on errors receiving)
 */
static void
receive_helper (void *cls,
                const void *buf,
                size_t available,
                const struct sockaddr *addr, socklen_t addrlen, int errCode)
{
  struct GNUNET_CLIENT_Connection *conn = cls;
  struct GNUNET_TIME_Relative remaining;

  GNUNET_assert (conn->msg_complete == GNUNET_NO);
  conn->receiver_task = GNUNET_SCHEDULER_NO_TASK;

  if ((available == 0) || (conn->sock == NULL) || (errCode != 0))
    {
      /* signal timeout! */
      if (conn->receiver_handler != NULL)
        {
          conn->receiver_handler (conn->receiver_handler_cls, NULL);
          conn->receiver_handler = NULL;
        }
      return;
    }

  /* FIXME: optimize for common fast case where buf contains the
     entire message and we need no copying... */


  /* slow path: append to array */
  if (conn->received_size < conn->received_pos + available)
    GNUNET_array_grow (conn->received_buf,
                       conn->received_size, conn->received_pos + available);
  memcpy (&conn->received_buf[conn->received_pos], buf, available);
  conn->received_pos += available;
  check_complete (conn);
  /* check for timeout */
  remaining = GNUNET_TIME_absolute_get_remaining (conn->receive_timeout);
  if (remaining.value == 0)
    {
      /* signal timeout! */
      conn->receiver_handler (conn->receiver_handler_cls, NULL);
      return;
    }
  /* back to receive -- either for more data or to call callback! */
  GNUNET_CLIENT_receive (conn,
                         conn->receiver_handler,
                         conn->receiver_handler_cls, remaining);
}


/**
 * Continuation to call the receive callback.
 */
static void
receive_task (void *scls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_CLIENT_Connection *sock = scls;
  GNUNET_CLIENT_MessageHandler handler = sock->receiver_handler;
  const struct GNUNET_MessageHeader *cmsg = (const struct GNUNET_MessageHeader *) sock->received_buf;
  void *cls = sock->receiver_handler_cls;
  uint16_t msize = ntohs (cmsg->size);
  char mbuf[msize];
  struct GNUNET_MessageHeader *msg = (struct GNUNET_MessageHeader*) mbuf;

  GNUNET_assert (GNUNET_YES == sock->msg_complete);
  sock->receiver_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_assert (sock->received_pos >= msize);
  memcpy (msg, cmsg, msize);
  memmove (sock->received_buf,
	   &sock->received_buf[msize], sock->received_pos - msize);
  sock->received_pos -= msize;
  sock->msg_complete = GNUNET_NO;
  sock->receiver_handler = NULL;  
  check_complete (sock);
  if (handler != NULL)
    handler (cls, msg);
}


/**
 * Read from the service.
 *
 * @param sched scheduler to use
 * @param sock the service
 * @param handler function to call with the message
 * @param cls closure for handler
 * @param timeout how long to wait until timing out
 */
void
GNUNET_CLIENT_receive (struct GNUNET_CLIENT_Connection *sock,
                       GNUNET_CLIENT_MessageHandler handler,
                       void *cls, struct GNUNET_TIME_Relative timeout)
{
  if (sock->sock == NULL)
    {
      /* already disconnected, fail instantly! */
      GNUNET_break (0);         /* this should not happen in well-written code! */
      handler (cls, NULL);
      return;
    }
  GNUNET_assert (sock->receiver_task ==
                 GNUNET_SCHEDULER_NO_TASK);
  sock->receiver_handler = handler;
  sock->receiver_handler_cls = cls;
  sock->receive_timeout = GNUNET_TIME_relative_to_absolute (timeout);
  if (GNUNET_YES == sock->msg_complete)
    sock->receiver_task = GNUNET_SCHEDULER_add_after (sock->sched,
                                                      GNUNET_YES,
                                                      GNUNET_SCHEDULER_PRIORITY_KEEP,
                                                      GNUNET_SCHEDULER_NO_TASK,
                                                      &receive_task, sock);
  else
    sock->receiver_task = GNUNET_CONNECTION_receive (sock->sock,
                                                  GNUNET_SERVER_MAX_MESSAGE_SIZE,
                                                  timeout,
                                                  &receive_helper, sock);
}


static size_t
write_shutdown (void *cls, size_t size, void *buf)
{
  struct GNUNET_MessageHeader *msg;

  if (size < sizeof (struct GNUNET_MessageHeader))
    return 0;                   /* client disconnected */
  msg = (struct GNUNET_MessageHeader *) buf;
  msg->type = htons (GNUNET_MESSAGE_TYPE_SHUTDOWN);
  msg->size = htons (sizeof (struct GNUNET_MessageHeader));
  return sizeof (struct GNUNET_MessageHeader);
}


/**
 * Request that the service should shutdown.
 * Afterwards, the connection should be disconnected.
 *
 * @param sched scheduler to use
 * @param sock the socket connected to the service
 */
void
GNUNET_CLIENT_service_shutdown (struct GNUNET_CLIENT_Connection *sock)
{
  GNUNET_CONNECTION_notify_transmit_ready (sock->sock,
                                        sizeof (struct GNUNET_MessageHeader),
                                        GNUNET_TIME_UNIT_FOREVER_REL,
                                        &write_shutdown, NULL);
}


/**
 * Report service unavailable.
 */
static void
service_test_error (struct GNUNET_SCHEDULER_Handle *s,
                    GNUNET_SCHEDULER_Task task, void *task_cls)
{
  GNUNET_SCHEDULER_add_continuation (s,
                                     GNUNET_YES,
                                     task,
                                     task_cls,
                                     GNUNET_SCHEDULER_REASON_TIMEOUT);
}


/**
 * Receive confirmation from test, service is up.
 *
 * @param cls closure
 * @param msg message received, NULL on timeout or fatal error
 */
static void
confirm_handler (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_CLIENT_Connection *conn = cls;
  /* We may want to consider looking at the reply in more
     detail in the future, for example, is this the
     correct service? FIXME! */
  if (msg != NULL)
    {
#if DEBUG_CLIENT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Received confirmation that service is running.\n");
#endif
      GNUNET_SCHEDULER_add_continuation (conn->sched,
                                         GNUNET_YES,
                                         conn->test_cb,
                                         conn->test_cb_cls,
                                         GNUNET_SCHEDULER_REASON_PREREQ_DONE);
    }
  else
    {
      service_test_error (conn->sched, conn->test_cb, conn->test_cb_cls);
    }
  GNUNET_CLIENT_disconnect (conn);
}


static size_t
write_test (void *cls, size_t size, void *buf)
{
  struct GNUNET_MessageHeader *msg;

  if (size < sizeof (struct GNUNET_MessageHeader))
    {
#if DEBUG_CLIENT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  _("Failure to transmit TEST request.\n"));
#endif
      return 0;                 /* client disconnected */
    }
#if DEBUG_CLIENT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, _("Transmitting TEST request.\n"));
#endif
  msg = (struct GNUNET_MessageHeader *) buf;
  msg->type = htons (GNUNET_MESSAGE_TYPE_TEST);
  msg->size = htons (sizeof (struct GNUNET_MessageHeader));
  return sizeof (struct GNUNET_MessageHeader);
}


/**
 * Wait until the service is running.
 *
 * @param sched scheduler to use
 * @param service name of the service to wait for
 * @param cfg configuration to use
 * @param timeout how long to wait at most in ms
 * @param task task to run if service is running
 *        (reason will be "PREREQ_DONE" (service running)
 *         or "TIMEOUT" (service not known to be running))
 * @param task_cls closure for task
 */
void
GNUNET_CLIENT_service_test (struct GNUNET_SCHEDULER_Handle *sched,
                            const char *service,
                            const struct GNUNET_CONFIGURATION_Handle *cfg,
                            struct GNUNET_TIME_Relative timeout,
                            GNUNET_SCHEDULER_Task task, void *task_cls)
{
  struct GNUNET_CLIENT_Connection *conn;

#if DEBUG_CLIENT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Testing if service `%s' is running.\n", service);
#endif
  conn = GNUNET_CLIENT_connect (sched, service, cfg);
  if (conn == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  _
                  ("Could not connect to service `%s', must not be running.\n"),
                  service);
      service_test_error (sched, task, task_cls);
      return;
    }
  conn->test_cb = task;
  conn->test_cb_cls = task_cls;
  if (NULL ==
      GNUNET_CONNECTION_notify_transmit_ready (conn->sock,
                                            sizeof (struct
                                                    GNUNET_MessageHeader),
                                            timeout, &write_test, NULL))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _("Failure to transmit request to service `%s'\n"),
                  service);
      service_test_error (sched, task, task_cls);
      GNUNET_CLIENT_disconnect (conn);
      return;
    }
  GNUNET_CLIENT_receive (conn, &confirm_handler, conn, timeout);
}


/**
 * Ask the client to call us once the specified number of bytes
 * are free in the transmission buffer.  May call the notify
 * method immediately if enough space is available.
 *
 * @param client connection to the service
 * @param size number of bytes to send
 * @param timeout after how long should we give up (and call
 *        notify with buf NULL and size 0)?
 * @param notify function to call
 * @param notify_cls closure for notify
 * @return NULL if our buffer will never hold size bytes,
 *         a handle if the notify callback was queued (can be used to cancel)
 */
struct GNUNET_CONNECTION_TransmitHandle *
GNUNET_CLIENT_notify_transmit_ready (struct GNUNET_CLIENT_Connection *sock,
                                     size_t size,
                                     struct GNUNET_TIME_Relative timeout,
                                     GNUNET_CONNECTION_TransmitReadyNotify
                                     notify, void *notify_cls)
{
  return GNUNET_CONNECTION_notify_transmit_ready (sock->sock,
                                               size,
                                               timeout, notify, notify_cls);
}


/*  end of client.c */
