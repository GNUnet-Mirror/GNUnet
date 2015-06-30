/*
     This file is part of GNUnet.
     Copyright (C) 2001-2013 Christian Grothoff (and other contributing authors)

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
 * @file util/client.c
 * @brief code for access to services
 * @author Christian Grothoff
 *
 * Generic TCP code for reliable, record-oriented TCP
 * connections between clients and service providers.
 */
#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_util_lib.h"


/**
 * How often do we re-try tranmsitting requests before giving up?
 * Note that if we succeeded transmitting a request but failed to read
 * a response, we do NOT re-try.
 */
#define MAX_ATTEMPTS 50

#define LOG(kind,...) GNUNET_log_from (kind, "util",__VA_ARGS__)

/**
 * Handle for a transmission request.
 */
struct GNUNET_CLIENT_TransmitHandle
{
  /**
   * Connection state.
   */
  struct GNUNET_CLIENT_Connection *client;

  /**
   * Function to call to get the data for transmission.
   */
  GNUNET_CONNECTION_TransmitReadyNotify notify;

  /**
   * Closure for @e notify.
   */
  void *notify_cls;

  /**
   * Handle to the transmission with the underlying
   * connection.
   */
  struct GNUNET_CONNECTION_TransmitHandle *th;

  /**
   * If we are re-trying and are delaying to do so,
   * handle to the scheduled task managing the delay.
   */
  struct GNUNET_SCHEDULER_Task *reconnect_task;

  /**
   * Timeout for the operation overall.
   */
  struct GNUNET_TIME_Absolute timeout;

  /**
   * Number of bytes requested.
   */
  size_t size;

  /**
   * Are we allowed to re-try to connect without telling
   * the user (of this API) about the connection troubles?
   */
  int auto_retry;

  /**
   * Number of attempts left for transmitting the request.  We may
   * fail the first time (say because the service is not yet up), in
   * which case (if auto_retry is set) we wait a bit and re-try
   * (timeout permitting).
   */
  unsigned int attempts_left;

};


/**
 * Context for processing
 * "GNUNET_CLIENT_transmit_and_get_response" requests.
 */
struct TransmitGetResponseContext
{
  /**
   * Client handle.
   */
  struct GNUNET_CLIENT_Connection *client;

  /**
   * Message to transmit; do not free, allocated
   * right after this struct.
   */
  const struct GNUNET_MessageHeader *hdr;

  /**
   * Timeout to use.
   */
  struct GNUNET_TIME_Absolute timeout;

  /**
   * Function to call when done.
   */
  GNUNET_CLIENT_MessageHandler rn;

  /**
   * Closure for @e rn.
   */
  void *rn_cls;
};

/**
 * Struct to refer to a GNUnet TCP connection.
 * This is more than just a socket because if the server
 * drops the connection, the client automatically tries
 * to reconnect (and for that needs connection information).
 */
struct GNUNET_CLIENT_Connection
{

  /**
   * The connection handle, NULL if not live
   */
  struct GNUNET_CONNECTION_Handle *connection;

  /**
   * Our configuration.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Name of the service we interact with.
   */
  char *service_name;

  /**
   * Context of a transmit_and_get_response operation, NULL
   * if no such operation is pending.
   */
  struct TransmitGetResponseContext *tag;

  /**
   * Handler for current receiver task.
   */
  GNUNET_CLIENT_MessageHandler receiver_handler;

  /**
   * Closure for @e receiver_handler.
   */
  void *receiver_handler_cls;

  /**
   * Handle for a pending transmission request, NULL if there is
   * none pending.
   */
  struct GNUNET_CLIENT_TransmitHandle *th;

  /**
   * If we are re-trying and are delaying to do so,
   * handle to the scheduled task managing the delay.
   */
  struct GNUNET_SCHEDULER_Task * receive_task;

  /**
   * Buffer for received message.
   */
  char *received_buf;

  /**
   * Timeout for receiving a response (absolute time).
   */
  struct GNUNET_TIME_Absolute receive_timeout;

  /**
   * Current value for our incremental back-off (for
   * connect re-tries).
   */
  struct GNUNET_TIME_Relative back_off;

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

  /**
   * Are we currently busy doing receive-processing?
   * #GNUNET_YES if so, #GNUNET_NO if not. #GNUNET_SYSERR
   * if the connection has failed (but we may not have
   * closed the handle itself yet).
   */
  int in_receive;

  /**
   * Is this the first message we are sending to the service?
   */
  int first_message;

  /**
   * How often have we tried to connect?
   */
  unsigned int attempts;

};


/**
 * Try connecting to the server using UNIX domain sockets.
 *
 * @param service_name name of service to connect to
 * @param cfg configuration to use
 * @return NULL on error, connection to UNIX otherwise
 */
static struct GNUNET_CONNECTION_Handle *
try_unixpath (const char *service_name,
	      const struct GNUNET_CONFIGURATION_Handle *cfg)
{
#if AF_UNIX
  struct GNUNET_CONNECTION_Handle *connection;
  char *unixpath;
  struct sockaddr_un s_un;

  unixpath = NULL;
  if ((GNUNET_OK == GNUNET_CONFIGURATION_get_value_filename (cfg, service_name, "UNIXPATH", &unixpath)) &&
      (0 < strlen (unixpath)))
  {
    /* We have a non-NULL unixpath, need to validate it */
    if (strlen (unixpath) >= sizeof (s_un.sun_path))
    {
      LOG (GNUNET_ERROR_TYPE_WARNING,
	   _("UNIXPATH `%s' too long, maximum length is %llu\n"), unixpath,
	   (unsigned long long) sizeof (s_un.sun_path));
      unixpath = GNUNET_NETWORK_shorten_unixpath (unixpath);
      LOG (GNUNET_ERROR_TYPE_INFO,
	   _("Using `%s' instead\n"), unixpath);
      if (NULL == unixpath)
	return NULL;
    }
    connection = GNUNET_CONNECTION_create_from_connect_to_unixpath (cfg, unixpath);
    if (NULL != connection)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Connected to unixpath `%s'!\n",
	   unixpath);
      GNUNET_free (unixpath);
      return connection;
    }
  }
  GNUNET_free_non_null (unixpath);
#endif
  return NULL;
}


/**
 * Test whether the configuration has proper values for connection
 * (UNIXPATH || (PORT && HOSTNAME)).
 *
 * @param service_name name of service to connect to
 * @param cfg configuration to use
 * @return #GNUNET_OK if the configuration is valid, #GNUNET_SYSERR if not
 */
static int
test_service_configuration (const char *service_name,
			    const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  int ret = GNUNET_SYSERR;
  char *hostname = NULL;
  unsigned long long port;
#if AF_UNIX
  char *unixpath = NULL;

  if ((GNUNET_OK == GNUNET_CONFIGURATION_get_value_filename (cfg, service_name, "UNIXPATH", &unixpath)) &&
      (0 < strlen (unixpath)))
    ret = GNUNET_OK;
  GNUNET_free_non_null (unixpath);
#endif

  if ( (GNUNET_YES ==
	GNUNET_CONFIGURATION_have_value (cfg, service_name, "PORT")) &&
       (GNUNET_OK ==
	GNUNET_CONFIGURATION_get_value_number (cfg, service_name, "PORT", &port)) &&
       (port <= 65535) && (0 != port) &&
       (GNUNET_OK ==
	GNUNET_CONFIGURATION_get_value_string (cfg, service_name, "HOSTNAME",
					       &hostname)) &&
       (0 != strlen (hostname)) )
    ret = GNUNET_OK;
  GNUNET_free_non_null (hostname);
  return ret;
}


/**
 * Try to connect to the service.
 *
 * @param service_name name of service to connect to
 * @param cfg configuration to use
 * @param attempt counter used to alternate between IP and UNIX domain sockets
 * @return NULL on error
 */
static struct GNUNET_CONNECTION_Handle *
do_connect (const char *service_name,
            const struct GNUNET_CONFIGURATION_Handle *cfg,
	    unsigned int attempt)
{
  struct GNUNET_CONNECTION_Handle *connection;
  char *hostname;
  unsigned long long port;

  connection = NULL;
  if (0 == (attempt % 2))
  {
    /* on even rounds, try UNIX first */
    connection = try_unixpath (service_name, cfg);
    if (NULL != connection)
      return connection;
  }
  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_have_value (cfg, service_name, "PORT"))
  {
    if ((GNUNET_OK !=
	 GNUNET_CONFIGURATION_get_value_number (cfg, service_name, "PORT", &port))
	|| (port > 65535) ||
	(GNUNET_OK !=
	 GNUNET_CONFIGURATION_get_value_string (cfg, service_name, "HOSTNAME",
						&hostname)))
    {
      LOG (GNUNET_ERROR_TYPE_WARNING,
	   _
	   ("Could not determine valid hostname and port for service `%s' from configuration.\n"),
	   service_name);
      return NULL;
    }
    if (0 == strlen (hostname))
    {
      GNUNET_free (hostname);
      LOG (GNUNET_ERROR_TYPE_WARNING,
	   _("Need a non-empty hostname for service `%s'.\n"), service_name);
      return NULL;
    }
  }
  else
  {
    /* unspecified means 0 (disabled) */
    port = 0;
    hostname = NULL;
  }
  if (0 == port)
  {
    /* if port is 0, try UNIX */
    connection = try_unixpath (service_name, cfg);
    if (NULL != connection)
    {
      GNUNET_free_non_null (hostname);
      return connection;
    }
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Port is 0 for service `%s', UNIXPATH did not work, returning NULL!\n",
         service_name);
    GNUNET_free_non_null (hostname);
    return NULL;
  }
  connection = GNUNET_CONNECTION_create_from_connect (cfg, hostname, port);
  GNUNET_free (hostname);
  return connection;
}


/**
 * Get a connection with a service.
 *
 * @param service_name name of the service
 * @param cfg configuration to use
 * @return NULL on error (service unknown to configuration)
 */
struct GNUNET_CLIENT_Connection *
GNUNET_CLIENT_connect (const char *service_name,
                       const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_CLIENT_Connection *client;
  struct GNUNET_CONNECTION_Handle *connection;

  if (GNUNET_OK !=
      test_service_configuration (service_name,
				  cfg))
    return NULL;
  connection = do_connect (service_name, cfg, 0);
  client = GNUNET_new (struct GNUNET_CLIENT_Connection);
  client->first_message = GNUNET_YES;
  client->attempts = 1;
  client->connection = connection;
  client->service_name = GNUNET_strdup (service_name);
  client->cfg = cfg;
  client->back_off = GNUNET_TIME_UNIT_MILLISECONDS;
  return client;
}


/**
 * Destroy connection with the service.  This will automatically
 * cancel any pending "receive" request (however, the handler will
 * *NOT* be called, not even with a NULL message).  Any pending
 * transmission request will also be cancelled UNLESS the callback for
 * the transmission request has already been called, in which case the
 * transmission 'finish_pending_write' argument determines whether or
 * not the write is guaranteed to complete before the socket is fully
 * destroyed (unless, of course, there is an error with the server in
 * which case the message may still be lost).
 *
 * @param client handle to the service connection
 */
void
GNUNET_CLIENT_disconnect (struct GNUNET_CLIENT_Connection *client)
{
  if (GNUNET_YES == client->in_receive)
  {
    GNUNET_CONNECTION_receive_cancel (client->connection);
    client->in_receive = GNUNET_NO;
  }
  if (NULL != client->th)
  {
    GNUNET_CLIENT_notify_transmit_ready_cancel (client->th);
    client->th = NULL;
  }
  if (NULL != client->connection)
  {
    GNUNET_CONNECTION_destroy (client->connection);
    client->connection = NULL;
  }
  if (NULL != client->receive_task)
  {
    GNUNET_SCHEDULER_cancel (client->receive_task);
    client->receive_task = NULL;
  }
  if (NULL != client->tag)
  {
    GNUNET_free (client->tag);
    client->tag = NULL;
  }
  client->receiver_handler = NULL;
  GNUNET_array_grow (client->received_buf, client->received_size, 0);
  GNUNET_free (client->service_name);
  GNUNET_free (client);
}


/**
 * Check if message is complete.  Sets the "msg_complete" member
 * in the client struct.
 *
 * @param client connection with the buffer to check
 */
static void
check_complete (struct GNUNET_CLIENT_Connection *client)
{
  if ((client->received_pos >= sizeof (struct GNUNET_MessageHeader)) &&
      (client->received_pos >=
       ntohs (((const struct GNUNET_MessageHeader *) client->received_buf)->
              size)))
    client->msg_complete = GNUNET_YES;
}


/**
 * Callback function for data received from the network.  Note that
 * both @a available and @a errCode would be 0 if the read simply timed out.
 *
 * @param cls closure
 * @param buf pointer to received data
 * @param available number of bytes availabe in @a buf,
 *        possibly 0 (on errors)
 * @param addr address of the sender
 * @param addrlen size of @a addr
 * @param errCode value of errno (on errors receiving)
 */
static void
receive_helper (void *cls,
                const void *buf,
                size_t available,
                const struct sockaddr *addr,
                socklen_t addrlen,
                int errCode)
{
  struct GNUNET_CLIENT_Connection *client = cls;
  struct GNUNET_TIME_Relative remaining;
  GNUNET_CLIENT_MessageHandler receive_handler;
  void *receive_handler_cls;

  GNUNET_assert (GNUNET_NO == client->msg_complete);
  GNUNET_assert (GNUNET_YES == client->in_receive);
  client->in_receive = GNUNET_NO;
  if ( (0 == available) ||
       (NULL == client->connection) ||
       (0 != errCode) )
  {
    /* signal timeout! */
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Timeout in receive_helper, available %u, client->connection %s, errCode `%s'\n",
         (unsigned int) available,
         NULL == client->connection ? "NULL" : "non-NULL",
         STRERROR (errCode));
    /* remember failure */
    client->in_receive = GNUNET_SYSERR;
    if (NULL != (receive_handler = client->receiver_handler))
    {
      receive_handler_cls = client->receiver_handler_cls;
      client->receiver_handler = NULL;
      receive_handler (receive_handler_cls,
                       NULL);
    }
    return;
  }
  /* FIXME: optimize for common fast case where buf contains the
   * entire message and we need no copying... */

  /* slow path: append to array */
  if (client->received_size < client->received_pos + available)
    GNUNET_array_grow (client->received_buf, client->received_size,
                       client->received_pos + available);
  memcpy (&client->received_buf[client->received_pos], buf, available);
  client->received_pos += available;
  check_complete (client);
  /* check for timeout */
  remaining = GNUNET_TIME_absolute_get_remaining (client->receive_timeout);
  if (0 == remaining.rel_value_us)
  {
    /* signal timeout! */
    if (NULL != (receive_handler = client->receiver_handler))
    {
      client->receiver_handler = NULL;
      receive_handler (client->receiver_handler_cls, NULL);
    }
    return;
  }
  /* back to receive -- either for more data or to call callback! */
  GNUNET_CLIENT_receive (client, client->receiver_handler,
                         client->receiver_handler_cls, remaining);
}


/**
 * Continuation to call the receive callback.
 *
 * @param cls  our handle to the client connection
 * @param tc scheduler context
 */
static void
receive_task (void *cls,
              const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_CLIENT_Connection *client = cls;
  GNUNET_CLIENT_MessageHandler handler = client->receiver_handler;
  const struct GNUNET_MessageHeader *cmsg =
      (const struct GNUNET_MessageHeader *) client->received_buf;
  void *handler_cls = client->receiver_handler_cls;
  uint16_t msize = ntohs (cmsg->size);
  char mbuf[msize] GNUNET_ALIGN;
  struct GNUNET_MessageHeader *msg = (struct GNUNET_MessageHeader *) mbuf;

  client->receive_task = NULL;
  if ( (GNUNET_SYSERR == client->in_receive) &&
       (GNUNET_YES != client->msg_complete) )
  {
    /* Connection failure, signal to caller! */
    client->receiver_handler = NULL;
    if (NULL != handler)
      handler (handler_cls,
               NULL);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received message of type %u and size %u from %s service.\n",
       ntohs (cmsg->type),
       msize,
       client->service_name);
  GNUNET_assert (GNUNET_YES == client->msg_complete);
  GNUNET_assert (client->received_pos >= msize);
  memcpy (msg, cmsg, msize);
  memmove (client->received_buf, &client->received_buf[msize],
           client->received_pos - msize);
  client->received_pos -= msize;
  client->msg_complete = GNUNET_NO;
  client->receiver_handler = NULL;
  check_complete (client);
  if (NULL != handler)
    handler (handler_cls, msg);
}


/**
 * Read from the service.
 *
 * @param client the service
 * @param handler function to call with the message
 * @param handler_cls closure for @a handler
 * @param timeout how long to wait until timing out
 */
void
GNUNET_CLIENT_receive (struct GNUNET_CLIENT_Connection *client,
                       GNUNET_CLIENT_MessageHandler handler,
		       void *handler_cls,
                       struct GNUNET_TIME_Relative timeout)
{
  if (NULL == client->connection)
  {
    /* already disconnected, fail instantly! */
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		"Client API violation for service `%s'\n",
		client->service_name);
    GNUNET_break (0);           /* this should not happen in well-written code! */
    if (NULL != handler)
      handler (handler_cls,
               NULL);
    return;
  }
  client->receiver_handler = handler;
  client->receiver_handler_cls = handler_cls;
  client->receive_timeout = GNUNET_TIME_relative_to_absolute (timeout);
  if ( (GNUNET_YES == client->msg_complete) ||
       (GNUNET_SYSERR == client->in_receive) )
  {
    GNUNET_assert (NULL == client->receive_task);
    client->receive_task = GNUNET_SCHEDULER_add_now (&receive_task, client);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "calling GNUNET_CONNECTION_receive\n");
  GNUNET_assert (GNUNET_NO == client->in_receive);
  client->in_receive = GNUNET_YES;
  GNUNET_CONNECTION_receive (client->connection,
                             GNUNET_SERVER_MAX_MESSAGE_SIZE - 1,
                             timeout,
                             &receive_helper,
                             client);
}


/**
 * Handle for a test to check if a service is running.
 */
struct GNUNET_CLIENT_TestHandle
{
  /**
   * Function to call with the result of the test.
   */
  GNUNET_CLIENT_TestResultCallback cb;

  /**
   * Closure for @e cb.
   */
  void *cb_cls;

  /**
   * Client connection we are using for the test, if any.
   */
  struct GNUNET_CLIENT_Connection *client;

  /**
   * Handle for the transmission request, if any.
   */
  struct GNUNET_CLIENT_TransmitHandle *th;

  /**
   * Deadline for calling @e cb.
   */
  struct GNUNET_TIME_Absolute test_deadline;

  /**
   * ID of task used for asynchronous operations.
   */
  struct GNUNET_SCHEDULER_Task * task;

  /**
   * Final result to report back (once known).
   */
  int result;
};


/**
 * Abort testing for service.
 *
 * @param th test handle
 */
void
GNUNET_CLIENT_service_test_cancel (struct GNUNET_CLIENT_TestHandle *th)
{
  if (NULL != th->th)
  {
    GNUNET_CLIENT_notify_transmit_ready_cancel (th->th);
    th->th = NULL;
  }
  if (NULL != th->client)
  {
    GNUNET_CLIENT_disconnect (th->client);
    th->client = NULL;
  }
  if (NULL != th->task)
  {
    GNUNET_SCHEDULER_cancel (th->task);
    th->task = NULL;
  }
  GNUNET_free (th);
}


/**
 * Task that reports back the result by calling the callback
 * and then cleans up.
 *
 * @param cls the `struct GNUNET_CLIENT_TestHandle`
 * @param tc scheduler context
 */
static void
report_result (void *cls,
	       const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_CLIENT_TestHandle *th = cls;

  th->task = NULL;
  th->cb (th->cb_cls, th->result);
  GNUNET_CLIENT_service_test_cancel (th);
}


/**
 * Report service test result asynchronously back to callback.
 *
 * @param th test handle with the result and the callback
 * @param result result to report
 */
static void
service_test_report (struct GNUNET_CLIENT_TestHandle *th,
		     int result)
{
  th->result = result;
  th->task = GNUNET_SCHEDULER_add_now (&report_result,
				       th);
}


/**
 * Receive confirmation from test, service is up.
 *
 * @param cls closure with the `struct GNUNET_CLIENT_TestHandle`
 * @param msg message received, NULL on timeout or fatal error
 */
static void
confirm_handler (void *cls,
                 const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_CLIENT_TestHandle *th = cls;

  /* We may want to consider looking at the reply in more
   * detail in the future, for example, is this the
   * correct service? FIXME! */
  if (NULL != msg)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Received confirmation that service is running.\n");
    service_test_report (th, GNUNET_YES);
  }
  else
  {
    service_test_report (th, GNUNET_NO);
  }
}


/**
 * Send the 'TEST' message to the service.  If successful, prepare to
 * receive the reply.
 *
 * @param cls the `struct GNUNET_CLIENT_TestHandle` of the test
 * @param size number of bytes available in @a buf
 * @param buf where to write the message
 * @return number of bytes written to @a buf
 */
static size_t
write_test (void *cls, size_t size, void *buf)
{
  struct GNUNET_CLIENT_TestHandle *th = cls;
  struct GNUNET_MessageHeader *msg;

  th->th = NULL;
  if (size < sizeof (struct GNUNET_MessageHeader))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
	 "Failed to transmit TEST request.\n");
    service_test_report (th, GNUNET_NO);
    return 0;                   /* client disconnected */
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Transmitting `%s' request.\n",
       "TEST");
  msg = (struct GNUNET_MessageHeader *) buf;
  msg->type = htons (GNUNET_MESSAGE_TYPE_TEST);
  msg->size = htons (sizeof (struct GNUNET_MessageHeader));
  GNUNET_CLIENT_receive (th->client,
			 &confirm_handler, th,
                         GNUNET_TIME_absolute_get_remaining
                         (th->test_deadline));
  return sizeof (struct GNUNET_MessageHeader);
}


/**
 * Test if the service is running.  If we are given a UNIXPATH or a
 * local address, we do this NOT by trying to connect to the service,
 * but by trying to BIND to the same port.  If the BIND fails, we know
 * the service is running.
 *
 * @param service name of the service to wait for
 * @param cfg configuration to use
 * @param timeout how long to wait at most
 * @param cb function to call with the result
 * @param cb_cls closure for @a cb
 * @return handle to cancel the test
 */
struct GNUNET_CLIENT_TestHandle *
GNUNET_CLIENT_service_test (const char *service,
                            const struct GNUNET_CONFIGURATION_Handle *cfg,
                            struct GNUNET_TIME_Relative timeout,
                            GNUNET_CLIENT_TestResultCallback cb,
			    void *cb_cls)
{
  struct GNUNET_CLIENT_TestHandle *th;
  char *hostname;
  unsigned long long port;
  struct GNUNET_NETWORK_Handle *sock;

  th = GNUNET_new (struct GNUNET_CLIENT_TestHandle);
  th->cb = cb;
  th->cb_cls = cb_cls;
  th->test_deadline = GNUNET_TIME_relative_to_absolute (timeout);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Testing if service `%s' is running.\n",
       service);
#ifdef AF_UNIX
  {
    /* probe UNIX support */
    struct sockaddr_un s_un;
    char *unixpath;
    int abstract;

    unixpath = NULL;
    if ((GNUNET_OK ==
	 GNUNET_CONFIGURATION_get_value_filename (cfg,
						  service,
						  "UNIXPATH",
						  &unixpath)) &&
	(0 < strlen (unixpath)))  /* We have a non-NULL unixpath, does that mean it's valid? */
    {
      if (strlen (unixpath) >= sizeof (s_un.sun_path))
      {
        LOG (GNUNET_ERROR_TYPE_WARNING,
             _("UNIXPATH `%s' too long, maximum length is %llu\n"),
	     unixpath,
             (unsigned long long) sizeof (s_un.sun_path));
	unixpath = GNUNET_NETWORK_shorten_unixpath (unixpath);
        LOG (GNUNET_ERROR_TYPE_INFO,
             _("Using `%s' instead\n"), unixpath);
      }
    }
#ifdef LINUX
    abstract = GNUNET_CONFIGURATION_get_value_yesno (cfg,
                                                     "TESTING",
                                                     "USE_ABSTRACT_SOCKETS");
#else
    abstract = GNUNET_NO;
#endif
    if ((NULL != unixpath) && (GNUNET_YES != abstract))
    {
      if (GNUNET_SYSERR == GNUNET_DISK_directory_create_for_file (unixpath))
        GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING,
                                  "mkdir", unixpath);
    }
    if (NULL != unixpath)
    {
      sock = GNUNET_NETWORK_socket_create (PF_UNIX, SOCK_STREAM, 0);
      if (NULL != sock)
      {
	memset (&s_un, 0, sizeof (s_un));
	s_un.sun_family = AF_UNIX;
        strncpy (s_un.sun_path, unixpath, sizeof (s_un.sun_path) - 1);
        if (GNUNET_YES == abstract)
          s_un.sun_path[0] = '\0';
#if HAVE_SOCKADDR_IN_SIN_LEN
        s_un.sun_len = (u_char) sizeof (struct sockaddr_un);
#endif
	if (GNUNET_OK !=
	    GNUNET_NETWORK_socket_bind (sock, (const struct sockaddr *) &s_un,
					sizeof (struct sockaddr_un)))
        {
	  /* failed to bind => service must be running */
	  GNUNET_free (unixpath);
	  (void) GNUNET_NETWORK_socket_close (sock);
	  service_test_report (th, GNUNET_YES);
	  return th;
	}
	(void) GNUNET_NETWORK_socket_close (sock);
        /* let's try IP */
      }
    }
    GNUNET_free_non_null (unixpath);
  }
#endif

  hostname = NULL;
  if ((GNUNET_OK !=
       GNUNET_CONFIGURATION_get_value_number (cfg, service, "PORT", &port)) ||
      (port > 65535) ||
      (GNUNET_OK !=
       GNUNET_CONFIGURATION_get_value_string (cfg, service, "HOSTNAME",
                                              &hostname)))
  {
    /* UNIXPATH failed (if possible) AND IP failed => error */
    service_test_report (th, GNUNET_SYSERR);
    return th;
  }

  if (0 == strcmp ("localhost", hostname)
#if !LINUX
      && 0
#endif
      )
  {
    /* can test using 'bind' */
    struct sockaddr_in s_in;

    memset (&s_in, 0, sizeof (s_in));
#if HAVE_SOCKADDR_IN_SIN_LEN
    s_in.sin_len = sizeof (struct sockaddr_in);
#endif
    s_in.sin_family = AF_INET;
    s_in.sin_port = htons (port);

    sock = GNUNET_NETWORK_socket_create (AF_INET, SOCK_STREAM, 0);
    if (NULL != sock)
    {
      if (GNUNET_OK !=
          GNUNET_NETWORK_socket_bind (sock, (const struct sockaddr *) &s_in,
                                      sizeof (s_in)))
      {
        /* failed to bind => service must be running */
        GNUNET_free (hostname);
        (void) GNUNET_NETWORK_socket_close (sock);
        service_test_report (th, GNUNET_YES);
        return th;
      }
      (void) GNUNET_NETWORK_socket_close (sock);
    }
  }

  if (0 == strcmp ("ip6-localhost", hostname)
#if !LINUX
      && 0
#endif
      )
  {
    /* can test using 'bind' */
    struct sockaddr_in6 s_in6;

    memset (&s_in6, 0, sizeof (s_in6));
#if HAVE_SOCKADDR_IN_SIN_LEN
    s_in6.sin6_len = sizeof (struct sockaddr_in6);
#endif
    s_in6.sin6_family = AF_INET6;
    s_in6.sin6_port = htons (port);

    sock = GNUNET_NETWORK_socket_create (AF_INET6, SOCK_STREAM, 0);
    if (NULL != sock)
    {
      if (GNUNET_OK !=
          GNUNET_NETWORK_socket_bind (sock, (const struct sockaddr *) &s_in6,
                                      sizeof (s_in6)))
      {
        /* failed to bind => service must be running */
        GNUNET_free (hostname);
        (void) GNUNET_NETWORK_socket_close (sock);
        service_test_report (th, GNUNET_YES);
        return th;
      }
      (void) GNUNET_NETWORK_socket_close (sock);
    }
  }

  if (((0 == strcmp ("localhost", hostname)) ||
       (0 == strcmp ("ip6-localhost", hostname)))
#if !LINUX
      && 0
#endif
      )
  {
    /* all binds succeeded => claim service not running right now */
    GNUNET_free_non_null (hostname);
    service_test_report (th, GNUNET_NO);
    return th;
  }
  GNUNET_free_non_null (hostname);

  /* non-localhost, try 'connect' method */
  th->client = GNUNET_CLIENT_connect (service, cfg);
  if (NULL == th->client)
  {
    LOG (GNUNET_ERROR_TYPE_INFO,
         _("Could not connect to service `%s', configuration broken.\n"),
         service);
    service_test_report (th, GNUNET_SYSERR);
    return th;
  }
  th->th = GNUNET_CLIENT_notify_transmit_ready (th->client,
						sizeof (struct GNUNET_MessageHeader),
						timeout, GNUNET_YES,
						&write_test, th);
  if (NULL == th->th)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         _("Failure to transmit request to service `%s'\n"), service);
    service_test_report (th, GNUNET_SYSERR);
    return th;
  }
  return th;
}


/**
 * Connection notifies us about failure or success of
 * a transmission request.  Either pass it on to our
 * user or, if possible, retry.
 *
 * @param cls our `struct GNUNET_CLIENT_TransmissionHandle`
 * @param size number of bytes available for transmission
 * @param buf where to write them
 * @return number of bytes written to @a buf
 */
static size_t
client_notify (void *cls, size_t size, void *buf);


/**
 * This task is run if we should re-try connection to the
 * service after a while.
 *
 * @param cls our `struct GNUNET_CLIENT_TransmitHandle` of the request
 * @param tc unused
 */
static void
client_delayed_retry (void *cls,
		      const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_CLIENT_TransmitHandle *th = cls;
  struct GNUNET_TIME_Relative delay;

  th->reconnect_task = NULL;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
  {
    /* give up, was shutdown */
    th->client->th = NULL;
    th->notify (th->notify_cls, 0, NULL);
    GNUNET_free (th);
    return;
  }
  th->client->connection =
    do_connect (th->client->service_name,
		th->client->cfg,
		th->client->attempts++);
  th->client->first_message = GNUNET_YES;
  if (NULL == th->client->connection)
  {
    /* could happen if we're out of sockets */
    delay = GNUNET_TIME_relative_min (GNUNET_TIME_absolute_get_remaining (th->timeout),
                                      th->client->back_off);
    th->client->back_off = GNUNET_TIME_STD_BACKOFF (th->client->back_off);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Transmission failed %u times, trying again in %s.\n",
         MAX_ATTEMPTS - th->attempts_left,
         GNUNET_STRINGS_relative_time_to_string (delay, GNUNET_YES));
    GNUNET_assert (NULL == th->th);
    GNUNET_assert (NULL == th->reconnect_task);
    th->reconnect_task =
        GNUNET_SCHEDULER_add_delayed (delay, &client_delayed_retry, th);
    return;
  }
  th->th =
      GNUNET_CONNECTION_notify_transmit_ready (th->client->connection, th->size,
                                               GNUNET_TIME_absolute_get_remaining
                                               (th->timeout), &client_notify,
                                               th);
  if (NULL == th->th)
  {
    GNUNET_break (0);
    th->client->th = NULL;
    th->notify (th->notify_cls, 0, NULL);
    GNUNET_free (th);
    return;
  }
}


/**
 * Connection notifies us about failure or success of a transmission
 * request.  Either pass it on to our user or, if possible, retry.
 *
 * @param cls our `struct GNUNET_CLIENT_TransmissionHandle`
 * @param size number of bytes available for transmission
 * @param buf where to write them
 * @return number of bytes written to @a buf
 */
static size_t
client_notify (void *cls,
               size_t size,
               void *buf)
{
  struct GNUNET_CLIENT_TransmitHandle *th = cls;
  struct GNUNET_CLIENT_Connection *client = th->client;
  size_t ret;
  struct GNUNET_TIME_Relative delay;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "client_notify is running\n");
  th->th = NULL;
  client->th = NULL;
  if (NULL == buf)
  {
    delay = GNUNET_TIME_absolute_get_remaining (th->timeout);
    delay.rel_value_us /= 2;
    if ( (GNUNET_YES != th->auto_retry) ||
         (0 == --th->attempts_left) ||
         (delay.rel_value_us < 1)||
         (0 != (GNUNET_SCHEDULER_get_reason() & GNUNET_SCHEDULER_REASON_SHUTDOWN)))
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Transmission failed %u times, giving up.\n",
           MAX_ATTEMPTS - th->attempts_left);
      GNUNET_break (0 ==
                    th->notify (th->notify_cls, 0, NULL));
      GNUNET_free (th);
      return 0;
    }
    /* auto-retry */
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Failed to connect to `%s', automatically trying again.\n",
         client->service_name);
    if (GNUNET_YES == client->in_receive)
    {
      GNUNET_CONNECTION_receive_cancel (client->connection);
      client->in_receive = GNUNET_NO;
    }
    GNUNET_CONNECTION_destroy (client->connection);
    client->connection = NULL;
    delay = GNUNET_TIME_relative_min (delay, client->back_off);
    client->back_off =
        GNUNET_TIME_relative_min (GNUNET_TIME_relative_multiply
                                  (client->back_off, 2),
                                  GNUNET_TIME_UNIT_SECONDS);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Transmission failed %u times, trying again in %s.\n",
         MAX_ATTEMPTS - th->attempts_left,
         GNUNET_STRINGS_relative_time_to_string (delay, GNUNET_YES));
    client->th = th;
    GNUNET_assert (NULL == th->reconnect_task);
    GNUNET_assert (NULL == th->th);
    th->reconnect_task =
        GNUNET_SCHEDULER_add_delayed (delay, &client_delayed_retry, th);
    return 0;
  }
  GNUNET_assert (size >= th->size);
  ret = th->notify (th->notify_cls, size, buf);
  GNUNET_free (th);
  if (sizeof (struct GNUNET_MessageHeader) <= ret)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Transmitting message of type %u and size %u to %s service.\n",
         ntohs (((struct GNUNET_MessageHeader *) buf)->type),
         ntohs (((struct GNUNET_MessageHeader *) buf)->size),
         client->service_name);
  }
  return ret;
}


/**
 * Ask the client to call us once the specified number of bytes
 * are free in the transmission buffer.  Will never call the @a notify
 * callback in this task, but always first go into the scheduler.
 *
 * @param client connection to the service
 * @param size number of bytes to send
 * @param timeout after how long should we give up (and call
 *        notify with buf NULL and size 0)?
 * @param auto_retry if the connection to the service dies, should we
 *        automatically re-connect and retry (within the timeout period)
 *        or should we immediately fail in this case?  Pass GNUNET_YES
 *        if the caller does not care about temporary connection errors,
 *        for example because the protocol is stateless
 * @param notify function to call
 * @param notify_cls closure for @a notify
 * @return NULL if our buffer will never hold size bytes,
 *         a handle if the notify callback was queued (can be used to cancel)
 */
struct GNUNET_CLIENT_TransmitHandle *
GNUNET_CLIENT_notify_transmit_ready (struct GNUNET_CLIENT_Connection *client,
                                     size_t size,
                                     struct GNUNET_TIME_Relative timeout,
                                     int auto_retry,
                                     GNUNET_CONNECTION_TransmitReadyNotify notify,
				     void *notify_cls)
{
  struct GNUNET_CLIENT_TransmitHandle *th;

  if (NULL != client->th)
  {
    /* If this breaks, you most likley called this function twice without waiting
     * for completion or canceling the request */
    GNUNET_assert (0);
    return NULL;
  }
  th = GNUNET_new (struct GNUNET_CLIENT_TransmitHandle);
  th->client = client;
  th->size = size;
  th->timeout = GNUNET_TIME_relative_to_absolute (timeout);
  /* always auto-retry on first message to service */
  th->auto_retry = (GNUNET_YES == client->first_message) ? GNUNET_YES : auto_retry;
  client->first_message = GNUNET_NO;
  th->notify = notify;
  th->notify_cls = notify_cls;
  th->attempts_left = MAX_ATTEMPTS;
  client->th = th;
  if (NULL == client->connection)
  {
    GNUNET_assert (NULL == th->th);
    GNUNET_assert (NULL == th->reconnect_task);
    th->reconnect_task =
        GNUNET_SCHEDULER_add_delayed (client->back_off,
                                      &client_delayed_retry,
                                      th);
  }
  else
  {
    th->th = GNUNET_CONNECTION_notify_transmit_ready (client->connection,
                                                      size,
                                                      timeout,
                                                      &client_notify,
                                                      th);
    if (NULL == th->th)
    {
      GNUNET_break (0);
      GNUNET_free (th);
      client->th = NULL;
      return NULL;
    }
  }
  return th;
}


/**
 * Cancel a request for notification.
 *
 * @param th handle from the original request.
 */
void
GNUNET_CLIENT_notify_transmit_ready_cancel (struct GNUNET_CLIENT_TransmitHandle *th)
{
  if (NULL != th->reconnect_task)
  {
    GNUNET_assert (NULL == th->th);
    GNUNET_SCHEDULER_cancel (th->reconnect_task);
    th->reconnect_task = NULL;
  }
  else
  {
    GNUNET_assert (NULL != th->th);
    GNUNET_CONNECTION_notify_transmit_ready_cancel (th->th);
  }
  th->client->th = NULL;
  GNUNET_free (th);
}


/**
 * Function called to notify a client about the socket
 * begin ready to queue the message.  @a buf will be
 * NULL and @a size zero if the socket was closed for
 * writing in the meantime.
 *
 * @param cls closure of type `struct TransmitGetResponseContext *`
 * @param size number of bytes available in @a buf
 * @param buf where the callee should write the message
 * @return number of bytes written to @a buf
 */
static size_t
transmit_for_response (void *cls,
		       size_t size,
		       void *buf)
{
  struct TransmitGetResponseContext *tc = cls;
  uint16_t msize;

  tc->client->tag = NULL;
  msize = ntohs (tc->hdr->size);
  if (NULL == buf)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Could not submit request, not expecting to receive a response.\n");
    if (NULL != tc->rn)
      tc->rn (tc->rn_cls, NULL);
    GNUNET_free (tc);
    return 0;
  }
  GNUNET_assert (size >= msize);
  memcpy (buf, tc->hdr, msize);
  GNUNET_CLIENT_receive (tc->client,
                         tc->rn,
                         tc->rn_cls,
                         GNUNET_TIME_absolute_get_remaining (tc->timeout));
  GNUNET_free (tc);
  return msize;
}


/**
 * Convenience API that combines sending a request
 * to the service and waiting for a response.
 * If either operation times out, the callback
 * will be called with a "NULL" response (in which
 * case the connection should probably be destroyed).
 *
 * @param client connection to use
 * @param hdr message to transmit
 * @param timeout when to give up (for both transmission
 *         and for waiting for a response)
 * @param auto_retry if the connection to the service dies, should we
 *        automatically re-connect and retry (within the timeout period)
 *        or should we immediately fail in this case?  Pass GNUNET_YES
 *        if the caller does not care about temporary connection errors,
 *        for example because the protocol is stateless
 * @param rn function to call with the response
 * @param rn_cls closure for @a rn
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if a request
 *         is already pending
 */
int
GNUNET_CLIENT_transmit_and_get_response (struct GNUNET_CLIENT_Connection *client,
                                         const struct GNUNET_MessageHeader *hdr,
                                         struct GNUNET_TIME_Relative timeout,
                                         int auto_retry,
                                         GNUNET_CLIENT_MessageHandler rn,
                                         void *rn_cls)
{
  struct TransmitGetResponseContext *tc;
  uint16_t msize;

  if (NULL != client->th)
    return GNUNET_SYSERR;
  GNUNET_assert (NULL == client->tag);
  msize = ntohs (hdr->size);
  tc = GNUNET_malloc (sizeof (struct TransmitGetResponseContext) + msize);
  tc->client = client;
  tc->hdr = (const struct GNUNET_MessageHeader *) &tc[1];
  memcpy (&tc[1], hdr, msize);
  tc->timeout = GNUNET_TIME_relative_to_absolute (timeout);
  tc->rn = rn;
  tc->rn_cls = rn_cls;
  if (NULL ==
      GNUNET_CLIENT_notify_transmit_ready (client, msize, timeout, auto_retry,
                                           &transmit_for_response, tc))
  {
    GNUNET_break (0);
    GNUNET_free (tc);
    return GNUNET_SYSERR;
  }
  client->tag = tc;
  return GNUNET_OK;
}


/*  end of client.c */
