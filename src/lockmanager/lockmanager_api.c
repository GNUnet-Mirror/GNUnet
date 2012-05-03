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
#include "gnunet_container_lib.h"
#include "gnunet_client_lib.h"
#include "gnunet_crypto_lib.h"
#include "gnunet_lockmanager_service.h"
#include "gnunet_protocols.h"

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

  /**
   * Hashmap handle
   */
  struct GNUNET_CONTAINER_MultiHashMap *hashmap;
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
 * Generate hash with domain name and the lock
 *
 * @param domain NULL terminated domain name
 *
 * @param domain_length the length of the domain name including the terminating
 *          NULL if already known; 0 to calculate
 *
 * @param lock the lock number
 * @param ret where to write the generated hash
 */
static void
hash_domain_and_lock (const char *domain,
                      uint16_t domain_length,
                      uint32_t lock,
                      GNUNET_HashCode *ret)
{
  unsigned int str_len;
  uint32_t *block;
  size_t block_size;

  str_len = (0 == domain_length) ? strlen (domain) : domain_length - 1;
  block_size = sizeof (uint32_t) + str_len;
  block = GNUNET_malloc (block_size);
  /* Copy data */
  *block = lock;
  memcpy (&block[1], domain, str_len);
  
  GNUNET_CRYPTO_hash (block, block_size, ret);
  GNUNET_free (block);
}


/**
 * Task for calling status change callback for a lock
 *
 * @param cls the LockingRequest associated with this lock
 * @param tc the TaskScheduler context
 */
static void
call_status_cb_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  const struct GNUNET_LOCKMANAGER_LockingRequest *r = cls;

  if (NULL != r->status_cb)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Calling status change callback for lock: %d in domain: %s\n",
           r->lock, r->domain);
      r->status_cb (r->status_cb_cls,
                    r->domain,
                    r->lock,
                    r->status);
    }
}


/**
 * Handler for server replies
 *
 * @param cls the LOCKMANAGER_Handle
 * @param msg received message, NULL on timeout or fatal error
 */
static void 
handle_replies (void *cls,
                const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_LOCKMANAGER_Handle *handle = cls;

  if (NULL == msg)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Lockmanager service not available or went down\n");
      return;
    }

  switch (ntohs (msg->type))
    {
    case GNUNET_MESSAGE_TYPE_LOCKMANAGER_SUCCESS:
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Received SUCCESS message\n");

      const struct GNUNET_LOCKMANAGER_Message *m;
      const char *domain;
      struct GNUNET_HashCode hash;
      uint32_t lock;
      int match_found;

      m = (struct GNUNET_LOCKMANAGER_Message *) msg;
      domain = (char *) &m[1];
      lock = ntohl (m->lock);
      hash_domain_and_lock (domain, 0, lock, &hash);
      
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "\t on lock: %d in domain %s\n",
           lock, domain);

      int match_iterator(void *cls, const GNUNET_HashCode *key, void *value)
      {
        struct GNUNET_LOCKMANAGER_LockingRequest *r = value;
        
        if ( !((0 == strcmp (domain, r->domain))
               && (lock == r->lock)))
          return GNUNET_YES;
        
        match_found = GNUNET_YES;
        if (GNUNET_LOCKMANAGER_SUCCESS != r->status)
          {
            LOG (GNUNET_ERROR_TYPE_DEBUG,
                 "Changing status for lock: %d in domain: %s to SUCCESS\n",
                 r->lock, r->domain);
            r->status = GNUNET_LOCKMANAGER_SUCCESS;
            GNUNET_SCHEDULER_add_continuation (&call_status_cb_task,
                                               r,
                                               GNUNET_SCHEDULER_REASON_PREREQ_DONE);
          }
        return GNUNET_NO;
      }
      
      match_found = GNUNET_NO;
      GNUNET_CONTAINER_multihashmap_get_multiple (handle->hashmap,
                                                  &hash,
                                                  &match_iterator,
                                                  NULL);
      GNUNET_assert (GNUNET_YES == match_found);
      break;
    default:
      GNUNET_break(0);
    }
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
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Message of size %u sent\n", msg_size);
  return msg_size;
}


/**
 * Iterator to free hash map entries.
 *
 * @param cls NULL
 * @param key current key code
 * @param value the Locking request
 * @return GNUNET_YES if we should continue to
 *         iterate,
 *         GNUNET_NO if not.
 */
static int
free_iterator(void *cls,
              const GNUNET_HashCode * key,
              void *value)
{
  struct GNUNET_LOCKMANAGER_LockingRequest *r = value;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Clearing locking request\n");
  GNUNET_free (r->domain);
  GNUNET_free (r);
  return GNUNET_YES;
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
  
  h->hashmap = GNUNET_CONTAINER_multihashmap_create (15);
  GNUNET_assert (NULL != h->hashmap);

  GNUNET_CLIENT_receive (h->conn,
                         &handle_replies,
                         h,
                         GNUNET_TIME_UNIT_FOREVER_REL);
  
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
  
  if (0 != GNUNET_CONTAINER_multihashmap_size (handle->hashmap))
    {
      LOG (GNUNET_ERROR_TYPE_WARNING,
           "Some locking requests are still present. Cancel them before "
           "calling %s\n", __func__);
      GNUNET_CONTAINER_multihashmap_iterate (handle->hashmap,
                                             &free_iterator,
                                             NULL);
    }
  GNUNET_CONTAINER_multihashmap_destroy (handle->hashmap);

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
  struct GNUNET_HashCode hash;
  uint16_t msg_size;
  
  LOG (GNUNET_ERROR_TYPE_DEBUG, "%s()\n", __func__);
  r = GNUNET_malloc (sizeof (struct GNUNET_LOCKMANAGER_LockingRequest));
  r->domain_name_length = strlen (domain_name) + 1;
  r->handle = handle;
  r->lock = lock;
  r->domain = GNUNET_malloc (r->domain_name_length);
  r->status = GNUNET_LOCKMANAGER_RELEASE;
  r->status_cb = status_cb;
  r->status_cb_cls = status_cb_cls;
  memcpy (r->domain, domain_name, r->domain_name_length);
  
  msg_size = sizeof (struct GNUNET_LOCKMANAGER_Message) + r->domain_name_length;
  msg = GNUNET_malloc (msg_size);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_LOCKMANAGER_ACQUIRE);
  msg->header.size = htons (msg_size);
  msg->lock = htonl (lock);
  memcpy (&msg[1], r->domain, r->domain_name_length);
  
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Queueing ACQUIRE message\n");
  r->transmit_handle =
    GNUNET_CLIENT_notify_transmit_ready (r->handle->conn,
                                         msg_size,
                                         TIMEOUT,
                                         GNUNET_YES,
                                         &transmit_notify,
                                         msg);
  hash_domain_and_lock (r->domain,
                        r->domain_name_length,
                        r->lock,
                        &hash);
  GNUNET_CONTAINER_multihashmap_put (r->handle->hashmap,
                                     &hash,
                                     r,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);

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
  struct GNUNET_HashCode hash;

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
    
  hash_domain_and_lock (request->domain,
                        request->domain_name_length,
                        request->lock,
                        &hash);

  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap_remove
                 (request->handle->hashmap, &hash, request));

  GNUNET_free (request->domain);
  GNUNET_free (request);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "%s() END\n", __func__);
}
