/*
     This file is part of GNUnet.
     (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @file lockmanager/lockmanager_api.c
 * @brief API implementation of gnunet_lockmanager_service.h
 * @author Sree Harsha Totakura
 */

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_protocols.h"
#include "gnunet_client_lib.h"
#include "gnunet_lockmanager_service.h"

#include "lockmanager.h"

#define LOG(kind,...) \
  GNUNET_log_from (kind, "lockmanager-api",__VA_ARGS__)

#define TIME_REL_MINS(min) \
  GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, min)

#define TIMEOUT TIME_REL_MINS(3)

/**
 * Handler for the lockmanager service
 */
struct GNUNET_LOCKMANAGER_Handle
{
  /**
   * The client connection to the service
   */
  struct GNUNET_CLIENT_Connection *conn;
};


/**
 * Structure for Locking Request
 */
struct GNUNET_LOCKMANAGER_LockingRequest
{
  /**
   * The handle associated with this request
   */
  struct GNUNET_LOCKMANAGER_Handle *handle;

  /**
   * The status callback
   */
  GNUNET_LOCKMANAGER_StatusCallback status_cb;

  /**
   * Closure for the status callback
   */
  void *status_cb_cls;

  /**
   * The pending transmit handle for the ACQUIRE message
   */
  struct GNUNET_CLIENT_TransmitHandle *transmit_handle;

  /**
   * The locking domain of this request
   */
  char *domain;
  
  /**
   * The lock
   */
  uint32_t lock;

  /**
   * The status of the lock
   */
  enum GNUNET_LOCKMANAGER_Status status;

  /**
   * The length of the locking domain string including the trailing NULL
   */
  uint16_t domain_name_length;
};


/**
 * Message handler for SUCCESS messages
 *
 * @param cls the LOCKMANAGER_Handle
 * @param msg message received, NULL on timeout or fatal error
 */
static void 
handle_success (void *cls,
                const struct GNUNET_MessageHeader *msg)
{
  if (NULL == msg)
    return;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received SUCCESS message\n");
}


/**
 * We wait for DUMMY message which will never be sent by the server. However,
 * in case the server shuts-down/crashes/restarts we are notified by this call
 * back with a NULL for msg.
 *
 * @param cls closure
 * @param msg message received, NULL on timeout or fatal error
 */
static void
handle_server_crash (void *cls,
                     const struct GNUNET_MessageHeader *msg)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Lockmanager service not available or went down\n");

}


/**
 * Transmit notify for sending message to server
 *
 * @param cls the message to send
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t 
transmit_notify (void *cls, size_t size, void *buf)
{
  struct GNUNET_LOCKMANAGER_Message *msg = cls;
  uint16_t msg_size;

  if ((0 == size) || (NULL == buf))
    {
      /* FIXME: Timed out -- requeue? */
      return 0;
    }
  msg_size = ntohs (msg->header.size);
  GNUNET_assert (size >= msg_size);
  memcpy (buf, msg, msg_size);
  GNUNET_free (msg);
  return msg_size;
}



/*******************/
/* API Definitions */
/*******************/

/**
 * Connect to the lockmanager service
 *
 * @param cfg the configuration to use
 *
 * @return upon success the handle to the service; NULL upon error
 */
struct GNUNET_LOCKMANAGER_Handle *
GNUNET_LOCKMANAGER_connect (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_LOCKMANAGER_Handle *h;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "%s()\n", __func__);
  h = GNUNET_malloc (sizeof (struct GNUNET_LOCKMANAGER_Handle));
  h->conn = GNUNET_CLIENT_connect ("lockmanager", cfg);
  if (NULL == h->conn)
    {
      GNUNET_free (h);
      LOG (GNUNET_ERROR_TYPE_DEBUG, "%s() END\n", __func__);
      return NULL;
    }
  
  GNUNET_CLIENT_receive (h->conn,
                         &handle_server_crash,
                         NULL,
                         GNUNET_TIME_UNIT_FOREVER_REL);
  
  /* FIXME: Assertions fail in client.c if trying to receive multiple messages */
  /* GNUNET_CLIENT_receive (h->conn, */
  /*                        &handle_success, */
  /*                        h, */
  /*                        GNUNET_TIME_UNIT_FOREVER_REL); */

  LOG (GNUNET_ERROR_TYPE_DEBUG, "%s() END\n", __func__);
  return h;
}


/**
 * Disconnect from the lockmanager service
 *
 * @param handle the handle to the lockmanager service
 */
void
GNUNET_LOCKMANAGER_disconnect (struct GNUNET_LOCKMANAGER_Handle *handle)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG, "%s()\n", __func__);
  GNUNET_CLIENT_disconnect (handle->conn);
  GNUNET_free (handle);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "%s() END\n", __func__);
}


/**
 * Tries to acquire the given lock(even if the lock has been lost) until the
 * request is called. If the lock is available the status_cb will be
 * called. If the lock is busy then the request is queued and status_cb
 * will be called when the lock has been made available and acquired by us.
 *
 * @param handle the handle to the lockmanager service
 *
 * @param domain_name name of the locking domain. Clients who want to share
 *          locks must use the same name for the locking domain. Also the
 *          domain_name should be selected with the prefix
 *          "GNUNET_<PROGRAM_NAME>_" to avoid domain name collisions.
 *
 *
 * @param lock which lock to lock
 *
 * @param status_cb the callback for signalling when the lock is acquired and
 *          when it is lost
 *
 * @param status_cb_cls the closure to the above callback
 *
 * @return the locking request handle for this request. It will be invalidated
 *           when status_cb is called.
 */
struct GNUNET_LOCKMANAGER_LockingRequest *
GNUNET_LOCKMANAGER_acquire_lock (struct GNUNET_LOCKMANAGER_Handle *handle,
                                 const char *domain_name,
                                 uint32_t lock,
                                 GNUNET_LOCKMANAGER_StatusCallback
                                 status_cb,
                                 void *status_cb_cls)
{
  struct GNUNET_LOCKMANAGER_LockingRequest *r;
  struct GNUNET_LOCKMANAGER_Message *msg;
  uint16_t msg_size;
  
  LOG (GNUNET_ERROR_TYPE_DEBUG, "%s()\n", __func__);
  r = GNUNET_malloc (sizeof (struct GNUNET_LOCKMANAGER_LockingRequest));
  r->domain_name_length = strlen (domain_name) + 1;
  r->handle = handle;
  r->lock = lock;
  r->domain = GNUNET_malloc (r->domain_name_length);
  memcpy (r->domain, domain_name, r->domain_name_length);
  
  msg_size = sizeof (struct GNUNET_LOCKMANAGER_Message) + r->domain_name_length;
  msg = GNUNET_malloc (msg_size);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_LOCKMANAGER_ACQUIRE);
  msg->header.size = htons (msg_size);
  msg->lock = htonl (lock);
  memcpy (&msg[1], r->domain, r->domain_name_length);
  
  r->transmit_handle =
    GNUNET_CLIENT_notify_transmit_ready (r->handle->conn,
                                         msg_size,
                                         TIMEOUT,
                                         GNUNET_NO,
                                         *transmit_notify,
                                         msg);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "%s() END\n", __func__);
  return r;
}



/**
 * Function to cancel the locking request generated by
 * GNUNET_LOCKMANAGER_acquire_lock. If the lock is acquired us then the lock is
 * released. GNUNET_LOCKMANAGER_StatusCallback will not be called upon any
 * status changes resulting due to this call.
 *
 * @param request the LockingRequest to cancel
 */
void
GNUNET_LOCKMANAGER_cancel_request (struct GNUNET_LOCKMANAGER_LockingRequest
                                   *request)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG, "%s()\n", __func__);
  /* FIXME: Stop ACQUIRE retransmissions */
  if (GNUNET_LOCKMANAGER_SUCCESS == request->status)
    {
      struct GNUNET_LOCKMANAGER_Message *msg;
      uint16_t msg_size;

      msg_size = sizeof (struct GNUNET_LOCKMANAGER_Message) 
        + request->domain_name_length;
      msg = GNUNET_malloc (msg_size);
      msg->header.type = htons (GNUNET_MESSAGE_TYPE_LOCKMANAGER_RELEASE);
      msg->header.size = htons (msg_size);
      msg->lock = htonl (request->lock);
      memcpy (&msg[1], request->domain, request->domain_name_length);
      
      GNUNET_CLIENT_notify_transmit_ready (request->handle->conn,
                                           msg_size,
                                           TIMEOUT, /* What if this fails */
                                           GNUNET_NO,
                                           &transmit_notify,
                                           msg);
    }
    LOG (GNUNET_ERROR_TYPE_DEBUG, "%s() END\n", __func__);
  GNUNET_free (request);
}
