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

/**
 * To be fixed:
 *  Should the handle be freed when the connection to service is lost?
 *  Should cancel_request have a call back (else simultaneous calls break)
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
 * The message queue
 */
struct MessageQueue
{
  /**
   * The next pointer for doubly linked list
   */
  struct MessageQueue *next;

  /**
   * The prev pointer for doubly linked list
   */
  struct MessageQueue *prev;
  
  /**
   * The LOCKMANAGER Message
   */
  struct GNUNET_LOCKMANAGER_Message *msg;
};


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
   * The transmit handle for transmissions using conn
   */
  struct GNUNET_CLIENT_TransmitHandle *transmit_handle;

  /**
   * Hashmap handle
   */
  struct GNUNET_CONTAINER_MultiHashMap *hashmap;

  /**
   * Double linked list head for message queue
   */
  struct MessageQueue *mq_head;

  /**
   * Double linked list tail for message queue
   */
  struct MessageQueue *mq_tail;
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
};


/**
 * Structure for matching a lock
 */
struct LockingRequestMatch
{
  /**
   * The matched LockingRequest entry; Should be NULL if no entry is found
   */
  struct GNUNET_LOCKMANAGER_LockingRequest *matched_entry;

  /**
   * The locking domain name of the lock
   */
  const char *domain;

  /**
   * The lock number
   */
  uint32_t lock;
};


/**
 * Transmit notify for sending message to server
 *
 * @param cls the lockmanager handle
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t 
transmit_notify (void *cls, size_t size, void *buf)
{
  struct GNUNET_LOCKMANAGER_Handle *handle = cls;
  struct MessageQueue *queue_entity;
  uint16_t msg_size;

  handle->transmit_handle = NULL;
  if ((0 == size) || (NULL == buf))
  {
    /* FIXME: Timed out -- requeue? */
    return 0;
  }
  queue_entity = handle->mq_head;
  GNUNET_assert (NULL != queue_entity);
  msg_size = ntohs (queue_entity->msg->header.size);
  GNUNET_assert (size >= msg_size);
  memcpy (buf, queue_entity->msg, msg_size);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Message of size %u sent\n", msg_size);
  GNUNET_free (queue_entity->msg);
  GNUNET_CONTAINER_DLL_remove (handle->mq_head,
                               handle->mq_tail,
                               queue_entity);
  GNUNET_free (queue_entity);
  queue_entity = handle->mq_head;
  if (NULL != queue_entity)
  {
    handle->transmit_handle =
      GNUNET_CLIENT_notify_transmit_ready (handle->conn,
                                           ntohs
                                           (queue_entity->msg->header.size),
                                           TIMEOUT,
                                           GNUNET_YES,
                                           &transmit_notify,
                                           handle);
  }
  return msg_size;
}


/**
 * Queues a message into handle's send message queue
 *
 * @param handle the lockmanager handle whose queue will be used
 * @param msg the message to be queued
 */
static void
queue_message (struct GNUNET_LOCKMANAGER_Handle *handle,
               struct GNUNET_LOCKMANAGER_Message *msg)
{
  struct MessageQueue *queue_entity;

  GNUNET_assert (NULL != msg);
  queue_entity = GNUNET_malloc (sizeof (struct MessageQueue));
  queue_entity->msg = msg;
  GNUNET_CONTAINER_DLL_insert_tail (handle->mq_head,
                                    handle->mq_tail,
                                    queue_entity);
  if (NULL == handle->transmit_handle)
  {
    handle->transmit_handle =
      GNUNET_CLIENT_notify_transmit_ready (handle->conn,
                                           ntohs (msg->header.size),
                                           TIMEOUT,
                                           GNUNET_YES,
                                           &transmit_notify,
                                           handle);
  }
}


/**
 * Get the key for the given lock in the 'lock_map'.
 *
 * @param domain_name
 * @param lock_number
 * @param key set to the key
 */
static void
get_key (const char *domain_name,
	 uint32_t lock_number,
	 struct GNUNET_HashCode *key)
{
  uint32_t *last_32;

  GNUNET_CRYPTO_hash (domain_name,
		      strlen (domain_name),
		      key);
  last_32 = (uint32_t *) key;
  *last_32 ^= lock_number;
}


/**
 * Hashmap iterator for matching a LockingRequest
 *
 * @param cls the LockingRequestMatch structure
 * @param key current key code
 * @param value value in the hash map (struct GNUNET_LOCKMANAGER_LockingRequest)
 * @return GNUNET_YES if we should continue to
 *         iterate,
 *         GNUNET_NO if not. 
 */
static int
match_iterator (void *cls, const GNUNET_HashCode *key, void *value)
{
  struct LockingRequestMatch *match = cls;
  struct GNUNET_LOCKMANAGER_LockingRequest *lr = value;

  if ( (match->lock == lr->lock) && (0 == strcmp (match->domain, lr->domain)) )
  {
    match->matched_entry = lr;    
    return GNUNET_NO;
  }
  return GNUNET_YES;
}


/**
 * Function to find a LockingRequest associated with the given domain and lock
 * attributes in the map
 *
 * @param map the map where the LockingRequests are stored
 * @param domain the locking domain name
 * @param lock the lock number
 * @return the found LockingRequest; NULL if a matching LockingRequest wasn't
 *           found 
 */
static struct GNUNET_LOCKMANAGER_LockingRequest *
hashmap_find_lockingrequest (const struct GNUNET_CONTAINER_MultiHashMap *map,
                             const char *domain,
                             uint32_t lock)
{
  struct GNUNET_HashCode hash;
  struct LockingRequestMatch lock_match;

  lock_match.matched_entry = NULL;
  lock_match.domain = domain;
  lock_match.lock = lock;
  get_key (domain, lock, &hash);
  GNUNET_CONTAINER_multihashmap_get_multiple (map,
                                              &hash,
                                              &match_iterator,
                                              &lock_match);
  return lock_match.matched_entry;
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
         "Calling status change for SUCCESS on lock num: %d, domain: %s\n",
         r->lock, r->domain);
    r->status_cb (r->status_cb_cls,
                  r->domain,
                  r->lock,
                  r->status);
  }
}


/**
 * Iterator to call relase and free all LockingRequest entries
 *
 * @param cls the lockmanager handle
 * @param key current key code
 * @param value the Locking request
 * @return GNUNET_YES if we should continue to
 *         iterate,
 *         GNUNET_NO if not.
 */
static int
release_iterator(void *cls,
                 const GNUNET_HashCode * key,
                 void *value)
{
  struct GNUNET_LOCKMANAGER_Handle *h = cls;
  struct GNUNET_LOCKMANAGER_LockingRequest *r = value;

  if (NULL != r->status_cb)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Calling status change for RELEASE on lock num: %d, domain: %s\n",
         r->lock, r->domain);
    r->status_cb (r->status_cb_cls,
                  r->domain,
                  r->lock,
                  GNUNET_LOCKMANAGER_RELEASE);
  }
  GNUNET_assert (GNUNET_YES == 
                 GNUNET_CONTAINER_multihashmap_remove (h->hashmap,
                                                       key,
                                                       value));
  GNUNET_free (r->domain);
  GNUNET_free (r);
  return GNUNET_YES;
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
  const struct GNUNET_LOCKMANAGER_Message *m;
  struct GNUNET_LOCKMANAGER_LockingRequest *lr;
  const char *domain;
  struct GNUNET_HashCode hash;
  uint32_t lock;
  uint16_t msize;
  
  if (NULL == msg)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Lockmanager service not available or went down\n");
    /* Should release all locks and free its locking requests */
    GNUNET_CONTAINER_multihashmap_iterate (handle->hashmap,
                                           &release_iterator,
                                           handle);
    return;
  }
  GNUNET_CLIENT_receive (handle->conn,
                         &handle_replies,
                         handle,
                         GNUNET_TIME_UNIT_FOREVER_REL);
  if (GNUNET_MESSAGE_TYPE_LOCKMANAGER_SUCCESS != ntohs(msg->type))
  {
    GNUNET_break (0);
    return;
  }
  msize = ntohs (msg->size);
  if (msize <= sizeof (struct GNUNET_LOCKMANAGER_Message))
  {
    GNUNET_break (0);
    return;
  }
  m = (const struct GNUNET_LOCKMANAGER_Message *) msg;
  domain = (const char *) &m[1];
  msize -= sizeof (struct GNUNET_LOCKMANAGER_Message);
  if ('\0' != domain[msize-1])
  {
    GNUNET_break (0);
    return;
  }

  lock = ntohl (m->lock);
  get_key (domain, lock, &hash);      
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received SUCCESS message for lock: %d, domain %s\n",
       lock, domain);
  if (NULL == (lr = hashmap_find_lockingrequest (handle->hashmap,
                                                 domain,
                                                 lock)))
  {
    GNUNET_break (0);
    return;
  }
  if (GNUNET_LOCKMANAGER_SUCCESS == lr->status)
  {
    GNUNET_break (0);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Changing status for lock: %d in domain: %s to SUCCESS\n",
       lr->lock, lr->domain);
  lr->status = GNUNET_LOCKMANAGER_SUCCESS;
  GNUNET_SCHEDULER_add_continuation (&call_status_cb_task,
                                     lr,
                                     GNUNET_SCHEDULER_REASON_PREREQ_DONE);
}


/**
 * Iterator to free hash map entries.
 *
 * @param cls the lockmanger handle
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
  struct GNUNET_LOCKMANAGER_Handle *h = cls;
  struct GNUNET_LOCKMANAGER_LockingRequest *r = value;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Clearing locking request\n");
  GNUNET_assert (GNUNET_YES == 
                 GNUNET_CONTAINER_multihashmap_remove (h->hashmap,
                                                       key,
                                                       value));
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
  struct MessageQueue *head;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "%s()\n", __func__);
  if (0 != GNUNET_CONTAINER_multihashmap_size (handle->hashmap))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Some locking requests are still present. Cancel them before "
         "calling %s\n", __func__);
    GNUNET_CONTAINER_multihashmap_iterate (handle->hashmap,
                                           &free_iterator,
                                           handle);
  }
  GNUNET_CONTAINER_multihashmap_destroy (handle->hashmap);
  /* Clear the message queue */
  if (NULL != handle->transmit_handle)
  {
    GNUNET_CLIENT_notify_transmit_ready_cancel (handle->transmit_handle);
  }
  head = handle->mq_head;
  while (NULL != head)
  {
    GNUNET_CONTAINER_DLL_remove (handle->mq_head,
                                 handle->mq_tail,
                                 head);
    GNUNET_free (head->msg);
    GNUNET_free (head);
    head = handle->mq_head;
  }
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
 * @return the locking request handle for this request
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
  size_t domain_name_length;
  
  LOG (GNUNET_ERROR_TYPE_DEBUG, "%s()\n", __func__);
  r = GNUNET_malloc (sizeof (struct GNUNET_LOCKMANAGER_LockingRequest));
  domain_name_length = strlen (domain_name) + 1;
  r->handle = handle;
  r->lock = lock;
  r->domain = GNUNET_malloc (domain_name_length);
  r->status = GNUNET_LOCKMANAGER_RELEASE;
  r->status_cb = status_cb;
  r->status_cb_cls = status_cb_cls;
  memcpy (r->domain, domain_name, domain_name_length);
  msg_size = sizeof (struct GNUNET_LOCKMANAGER_Message) + domain_name_length;
  msg = GNUNET_malloc (msg_size);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_LOCKMANAGER_ACQUIRE);
  msg->header.size = htons (msg_size);
  msg->lock = htonl (lock);
  memcpy (&msg[1], r->domain, domain_name_length);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Queueing ACQUIRE message\n");
  queue_message (handle, msg);
  get_key (r->domain, r->lock, &hash);
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
  struct GNUNET_LOCKMANAGER_Message *msg;
  struct GNUNET_HashCode hash;
  uint16_t msg_size;
  size_t domain_name_length;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "%s()\n", __func__);
  /* FIXME: Stop ACQUIRE retransmissions */
  if (GNUNET_LOCKMANAGER_SUCCESS == request->status)
  {
    domain_name_length = strlen (request->domain) + 1;
    msg_size = sizeof (struct GNUNET_LOCKMANAGER_Message) 
      + domain_name_length;
    msg = GNUNET_malloc (msg_size);
    msg->header.type = htons (GNUNET_MESSAGE_TYPE_LOCKMANAGER_RELEASE);
    msg->header.size = htons (msg_size);
    msg->lock = htonl (request->lock);
    memcpy (&msg[1], request->domain, domain_name_length);
    queue_message (request->handle, msg);
  }
  get_key (request->domain, request->lock, &hash);
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap_remove
                 (request->handle->hashmap, &hash, request));
  GNUNET_free (request->domain);
  GNUNET_free (request);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "%s() END\n", __func__);
}
