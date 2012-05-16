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
 * @file lockmanager/gnunet-service-lockmanager.c
 * @brief implementation of the LOCKMANAGER service
 * @author Sree Harsha Totakura
 */

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_container_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_service_lib.h"
#include "gnunet_server_lib.h"

#include "lockmanager.h"


#define LOG(kind,...)                           \
  GNUNET_log (kind, __VA_ARGS__)

#define TIME_REL_MINS(min)                                      \
  GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, min)

#define TIMEOUT TIME_REL_MINS(3)


/**
 * Doubly linked list of clients having connections to us
 */
struct ClientList;


/**
 * Doubly linked list of clients waiting for a lock
 */
struct WaitList
{
  /**
   * The next client structure
   */
  struct WaitList *next;
  
  /**
   * The prev client structure
   */
  struct WaitList *prev;

  /**
   * Pointer to the client
   */
  struct ClientList *cl_entry;
};


/**
 * Structure representing a Lock
 */
struct Lock
{
  /**
   * List head of clients waiting for this lock
   */
  struct WaitList *wl_head;

  /**
   * List tail of clients waiting for this lock
   */
  struct WaitList *wl_tail;

  /**
   * The client which is currently holding this lock
   */
  struct ClientList *cl_entry;

  /**
   * The name of the locking domain this lock belongs to
   */
  char *domain_name;

  /**
   * The number of this lock
   */
  uint32_t lock_num;
};


/**
 * A Lock element for a doubly linked list
 */
struct LockList
{
  /**
   * The next element pointer
   */
  struct LockList *next;

  /**
   * Pointer to the previous element
   */
  struct LockList *prev;

  /**
   * Pointer to the Lock
   */
  struct Lock *lock;
};


/**
 * Doubly linked list of clients having connections to us
 */
struct ClientList
{

  /**
   * The next client structure
   */
  struct ClientList *next;

  /**
   * The previous client structure
   */
  struct ClientList *prev;

  /**
   * Head of the doubly linked list of the currently held locks by this client
   */
  struct LockList *ll_head;

  /**
   * Tail of the doubly linked list of the currently held locks by this client
   */
  struct LockList *ll_tail;

  /**
   * Pointer to the client
   */
  struct GNUNET_SERVER_Client *client;
};


/**
 * Structure for matching a lock
 */
struct LockMatch
{
  /**
   * The matched LockingRequest entry; Should be NULL if no entry is found
   */
  struct Lock *matched_entry;

  /**
   * The locking domain name of the lock
   */
  const char *domain_name;

  /**
   * The lock number
   */
  uint32_t lock_num;
};


/**
 * Map of lock-keys to the 'struct LockList' entry for the key.
 */
static struct GNUNET_CONTAINER_MultiHashMap *lock_map;

/**
 * Head of the doubly linked list of clients currently connected
 */
static struct ClientList *cl_head;

/**
 * Tail of the doubly linked list of clients currently connected
 */
static struct ClientList *cl_tail;


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
 * Hashmap iterator for matching a lock
 *
 * @param cls the LockMatch structure
 * @param key current key code
 * @param value value in the hash map (struct Lock)
 * @return GNUNET_YES if we should continue to
 *         iterate,
 *         GNUNET_NO if not. 
 */
static int
match_iterator (void *cls, const GNUNET_HashCode *key, void *value)
{
  struct LockMatch *match = cls;
  struct Lock *lock = value;

  if ( (match->lock_num == lock->lock_num) 
       && (0 == strcmp (match->domain_name, lock->domain_name)) )
  {
    match->matched_entry = lock;    
    return GNUNET_NO;
  }
  return GNUNET_YES;
}


/**
 * Function to search for a lock in the global lock hashmap
 *
 * @param domain_name the name of the locking domain
 * @param lock_num the number of the lock
 * @return the lock if found; NULL if not
 */
static struct Lock *
find_lock (const char *domain_name,
           const uint32_t lock_num)
              
{
  struct LockMatch match;
  struct GNUNET_HashCode key;

  match.lock_num = lock_num;
  match.domain_name = domain_name;
  match.matched_entry = NULL;
  get_key (domain_name, lock_num, &key);
  GNUNET_CONTAINER_multihashmap_get_multiple (lock_map,
                                              &key,
                                              &match_iterator,
                                              &match);
  return match.matched_entry;
}


/**
 * Adds a lock to the global lock hashmap
 *
 * @param domain_name the name of the lock's locking domain
 * @param lock_num the lock number
 * @return pointer to the lock structure which is added to lock map
 */
static struct Lock *
add_lock (const char *domain_name, 
          uint32_t lock_num)
{
  struct Lock *lock;
  struct GNUNET_HashCode key;
  size_t domain_name_len;

  lock = GNUNET_malloc (sizeof (struct Lock));
  domain_name_len = strlen (domain_name) + 1;
  lock->domain_name = GNUNET_malloc (domain_name_len);
  strncpy (lock->domain_name, domain_name, domain_name_len);
  lock->lock_num = lock_num;
  get_key (domain_name, lock_num, &key);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Adding a lock with num: %d and domain: %s to the lock map\n",
       lock->lock_num, lock->domain_name);
  GNUNET_CONTAINER_multihashmap_put (lock_map,
                                     &key,
                                     lock,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  return lock;
}


/**
 * Removes a lock from the lock map. The WaitList of the lock should be empty
 *
 * @param lock the lock to remove
 */
static void
remove_lock (struct Lock *lock)
{
  struct GNUNET_HashCode key;
  
  GNUNET_assert (NULL == lock->wl_head);
  get_key (lock->domain_name,
           lock->lock_num,
           &key);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Removing lock with num: %u, domain: %s from lock map\n",
       lock->lock_num, lock->domain_name);
  GNUNET_assert (GNUNET_YES == GNUNET_CONTAINER_multihashmap_remove
                 (lock_map, &key, lock));
  GNUNET_free (lock->domain_name);
  GNUNET_free (lock);
}


/**
 * Find the LockList entry corresponding to the given Lock in a ClientList
 * entry
 *
 * @param cl_entry the ClientList entry whose lock list has to be searched
 * @param lock the lock which has to be matched
 * @return the matching LockList entry; NULL if no match is found
 */
static struct LockList *
cl_ll_find_lock (struct ClientList *cl_entry,
                 const struct Lock *lock)
{
  struct LockList *ll_entry;

  for (ll_entry = cl_entry->ll_head;
       NULL != ll_entry; ll_entry = ll_entry->next)
  {
    if (lock == ll_entry->lock)
      return ll_entry;
  }
  return NULL;
}


/**
 * Function to append a lock to the lock list of a ClientList entry
 *
 * @param cl_entry the client which currently owns this lock
 * @param lock the lock to be added to the cl_entry's lock list
 */
static void
cl_ll_add_lock (struct ClientList *cl_entry,
                struct Lock *lock)
{
  struct LockList *ll_entry;

  ll_entry = GNUNET_malloc (sizeof (struct LockList));
  ll_entry->lock = lock;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Adding a lock with num: %u and domain: %s to lock list\n",
       lock->lock_num, lock->domain_name);
  GNUNET_CONTAINER_DLL_insert_tail (cl_entry->ll_head,
                                    cl_entry->ll_tail,
                                    ll_entry);
}


/**
 * Function to delete a lock from the lock list of the given ClientList entry
 *
 * @param cl_entry the ClientList entry
 * @param ll_entry the LockList entry to be deleted
 */
static void
cl_ll_remove_lock (struct ClientList *cl_entry,
                   struct LockList *ll_entry)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Removing lock with num: %u, domain: %s from lock list of a client\n",
       ll_entry->lock->lock_num,
       ll_entry->lock->domain_name);
  GNUNET_assert (NULL != cl_entry->ll_head);
  GNUNET_CONTAINER_DLL_remove (cl_entry->ll_head,
                               cl_entry->ll_tail,
                               ll_entry);
  GNUNET_free (ll_entry);
}


/**
 * Find a WaitList entry in the waiting list of a lock
 *
 * @param lock the lock whose wait list has to be searched
 * @param cl_entry the ClientList entry to be searched
 * @return the WaitList entry matching the given cl_entry; NULL if not match
 *           was found
 */
static struct WaitList *
lock_wl_find (const struct Lock *lock,
              const struct ClientList *cl_entry)
{
  struct WaitList *wl_entry;

  for (wl_entry = lock->wl_head;
       NULL != wl_entry; 
       wl_entry = wl_entry->next)
  {
    if (cl_entry == wl_entry->cl_entry)
      return wl_entry;
  }
  return NULL;
}


/**
 * Add a client to the wait list of given lock
 *
 * @param lock the lock list entry of a lock
 * @param cl_entry the client to queue for the lock's wait list
 */
static void
lock_wl_add_client (struct Lock *lock,
                    struct ClientList *cl_entry)
{
  struct WaitList *wl_entry;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Adding a client to lock's wait list (lock num: %u, domain: %s)\n",
       lock->lock_num,
       lock->domain_name);
  wl_entry = GNUNET_malloc (sizeof (struct WaitList));
  wl_entry->cl_entry = cl_entry;
  GNUNET_CONTAINER_DLL_insert_tail (lock->wl_head,
                                    lock->wl_tail,
                                    wl_entry);
}


/**
 * Remove an entry from the wait list of the given lock
 *
 * @param lock the lock
 * @param wl_entry the wait list entry to be removed
 */
static void
lock_wl_remove (struct Lock *lock,
                struct WaitList *wl_entry)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Removing client from wait list of lock with num: %u, domain: %s\n",
       lock->lock_num, lock->domain_name);
  GNUNET_CONTAINER_DLL_remove (lock->wl_head,
                               lock->wl_tail,
                               wl_entry);
  GNUNET_free (wl_entry);
}


/**
 * Search for a client in the client list
 *
 * @param client the client to be searched for
 * @return the ClientList entry; NULL if the client is not found
 */
static struct ClientList *
cl_find_client (const struct GNUNET_SERVER_Client *client)                
{
  struct ClientList *current;

  for (current = cl_head; NULL != current; current = current->next)
    if (client == current->client)
      return current;
  return NULL;
}


/**
 * Append a client to the client list
 *
 * @param client the client to be appended to the list
 * @return the client list entry which is added to the client list
 */
static struct ClientList *
cl_add_client (struct GNUNET_SERVER_Client *client)
{
  struct ClientList *new_client;
  
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Adding a client to the client list\n");
  new_client = GNUNET_malloc (sizeof (struct ClientList));
  GNUNET_SERVER_client_keep (client);
  new_client->client = client;
  GNUNET_CONTAINER_DLL_insert_tail (cl_head,
                                    cl_tail,
                                    new_client);
  return new_client;
}


/**
 * Delete the given client from the client list. The LockList should be empty
 *
 * @param cl_entry the client list entry to delete
 */
static void
cl_remove_client (struct ClientList *cl_entry)
{
  GNUNET_assert (NULL == cl_entry->ll_head);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Removing a client from the client list\n");
  GNUNET_SERVER_client_drop (cl_entry->client);
  GNUNET_CONTAINER_DLL_remove (cl_head,
                               cl_tail,
                               cl_entry);
  GNUNET_free (cl_entry);
}


/**
 * Transmit notify for sending message to client
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
 * Send SUCCESS message to the client
 *
 * @param client the client to which the message has to be sent
 * @param domain_name the locking domain of the successfully acquried lock
 * @param lock_num the number of the successfully acquired lock
 */
static void
send_success_msg (struct GNUNET_SERVER_Client *client,
                  const char *domain_name,
                  int lock_num)
{
  struct GNUNET_LOCKMANAGER_Message *reply;
  size_t domain_name_len;
  uint16_t reply_size;

  domain_name_len = strlen (domain_name) + 1;
  reply_size = sizeof (struct GNUNET_LOCKMANAGER_Message) + domain_name_len;
  reply = GNUNET_malloc (reply_size);
  reply->header.size = htons (reply_size);
  reply->header.type = htons (GNUNET_MESSAGE_TYPE_LOCKMANAGER_SUCCESS);
  reply->lock = htonl (lock_num);
  strncpy ((char *) &reply[1], domain_name, domain_name_len);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Sending SUCCESS message for lock with num: %u, domain: %s\n",
       lock_num, domain_name);
  GNUNET_SERVER_notify_transmit_ready (client,
                                       reply_size,
                                       TIMEOUT,
                                       &transmit_notify,
                                       reply);
}


/**
 * Handler for GNUNET_MESSAGE_TYPE_LOCKMANAGER_ACQUIRE
 *
 * @param cls NULL
 * @param client the client sending this message
 * @param message GNUNET_MESSAGE_TYPE_LOCKMANAGER_ACQUIRE message
 */
static void
handle_acquire (void *cls,
                struct GNUNET_SERVER_Client *client,
                const struct GNUNET_MessageHeader *message)
{
  const struct GNUNET_LOCKMANAGER_Message *request;
  const char *domain_name;
  struct Lock *lock;
  struct ClientList *cl_entry;
  uint32_t lock_num;
  uint16_t msize;

  msize = htons (message->size);
  if (msize <= sizeof (struct GNUNET_LOCKMANAGER_Message))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  request = (struct GNUNET_LOCKMANAGER_Message *) message;
  domain_name = (const char *) &request[1];
  msize -= sizeof (struct GNUNET_LOCKMANAGER_Message);
  if ('\0' != domain_name[msize])
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  lock_num = ntohl (request->lock);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received an ACQUIRE message for lock num: %u domain: %s\n",
       lock_num, domain_name);
  if (NULL == (cl_entry = cl_find_client (client))) 
    cl_entry = cl_add_client (client); /* Add client if not in client list */
  if (NULL != (lock = find_lock (domain_name,lock_num)))
  {
    if (lock->cl_entry == cl_entry)
    {                         /* Client is requesting a lock it already owns */
      GNUNET_break (0);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }
    lock_wl_add_client (lock, cl_entry);
    cl_ll_add_lock (cl_entry, lock);
  }
  else                          /* Lock not present */
  {
    lock = add_lock (domain_name, lock_num);
    lock->cl_entry = cl_entry;
    cl_ll_add_lock (cl_entry, lock);
    send_success_msg (cl_entry->client, domain_name, lock_num);
  }
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * This function gives the lock to the first client in the wait list of the
 * lock. If no clients are currently waiting for this lock, the lock is then
 * destroyed.
 *
 * @param lock the lock which has to be processed for release
 */
static void
process_lock_release (struct Lock *lock)
{
  struct WaitList *wl_entry;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Processing lock release for lock with num: %u, domain: %s\n",
       lock->lock_num, lock->domain_name);
  wl_entry = lock->wl_head;
  if (NULL == wl_entry)
  {
    remove_lock (lock);   /* No clients waiting for this lock - delete */
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Giving lock to a client from wait list\n");
  lock->cl_entry = wl_entry->cl_entry;
  lock_wl_remove(lock, wl_entry);
  send_success_msg (lock->cl_entry->client,
                    lock->domain_name,
                    lock->lock_num);
  return;
}


/**
 * Handle for GNUNET_MESSAGE_TYPE_LOCKMANAGER_RELEASE
 *
 * @param cls NULL
 * @param client the client sending this message
 * @param message the LOCKMANAGER_RELEASE message
 */
static void
handle_release (void *cls,
                struct GNUNET_SERVER_Client *client,
                const struct GNUNET_MessageHeader *message)
{
  const struct GNUNET_LOCKMANAGER_Message *request;
  struct ClientList *cl_entry;
  struct WaitList *wl_entry;
  struct LockList *ll_entry;
  const char *domain_name;
  struct Lock *lock;
  uint32_t lock_num;
  uint16_t msize;

  msize = ntohs (message->size);
  if (msize <= sizeof (struct GNUNET_LOCKMANAGER_Message))
  { 
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  request = (const struct GNUNET_LOCKMANAGER_Message *) message;
  domain_name = (const char *) &request[1];
  msize -= sizeof (struct GNUNET_LOCKMANAGER_Message);
  if ('\0' != domain_name[msize-1])
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  

  }
  lock_num = ntohl (request->lock);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received RELEASE message for lock with num: %d, domain: %s\n",
       lock_num, domain_name);
  if (NULL == (cl_entry = cl_find_client (client)))
  {
    GNUNET_break(0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  lock = find_lock (domain_name, lock_num);
  if(NULL == lock)
  {    
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  if (NULL == (ll_entry = cl_ll_find_lock (cl_entry, lock)))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  cl_ll_remove_lock (cl_entry, ll_entry);
  if (cl_entry == lock->cl_entry)
  {
    process_lock_release (lock);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  /* remove 'client' from wait list (check that it is not there...) */
  if (NULL != (wl_entry = lock_wl_find (lock, cl_entry)))
  {
    lock_wl_remove (lock, wl_entry);
  }
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Callback for client disconnect
 *
 * @param cls NULL
 * @param client the client which has disconnected
 */
static void
client_disconnect_cb (void *cls, struct GNUNET_SERVER_Client *client)
{
  struct ClientList *cl_entry;
  struct LockList *ll_entry;
  struct Lock *lock;

  if (NULL == client)
    return;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "A client has been disconnected -- freeing its locks and resources\n"); 
  cl_entry = cl_find_client (client);
  if (NULL == cl_entry)
    return;
  while (NULL != (ll_entry = cl_entry->ll_head))
  {
    lock = ll_entry->lock;
    cl_ll_remove_lock (cl_entry, ll_entry);
    process_lock_release (lock);
  }
  cl_remove_client (cl_entry);
}


/**
 * Hashmap Iterator to delete lock entries in hash map
 *
 * @param cls NULL
 * @param key current key code
 * @param value value in the hash map
 * @return GNUNET_YES if we should continue to
 *         iterate,
 *         GNUNET_NO if not.
 */
static int 
lock_delete_iterator (void *cls,
                      const GNUNET_HashCode * key,
                      void *value)
{
  struct Lock *lock = value;

  GNUNET_assert (NULL != lock);
  while (NULL != lock->wl_head)
  {
    lock_wl_remove (lock, lock->wl_head);
  }
  GNUNET_assert (GNUNET_YES == 
                 GNUNET_CONTAINER_multihashmap_remove(lock_map,
                                                      key,
                                                      lock));
  GNUNET_free (lock->domain_name);
  GNUNET_free (lock);
  return GNUNET_YES;
}


/**
 * Task to clean up and shutdown nicely
 *
 * @param cls NULL
 * @param tc the TaskContext from scheduler
 */
static void
shutdown_task (void *cls,
               const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Shutting down lock manager\n");
  /* Clean the global ClientList */
  while (NULL != cl_head)
  {
    while (NULL != cl_head->ll_head) /* Clear the LockList */
    {
      cl_ll_remove_lock (cl_head, cl_head->ll_head);
    }
    cl_remove_client (cl_head);
  }
  /* Clean the global hash table */
  GNUNET_CONTAINER_multihashmap_iterate (lock_map,
                                         &lock_delete_iterator,
                                         NULL);
  GNUNET_assert (0 == GNUNET_CONTAINER_multihashmap_size (lock_map));
  GNUNET_CONTAINER_multihashmap_destroy (lock_map);
}


/**
 * Lock manager setup
 *
 * @param cls closure
 * @param server the initialized server
 * @param cfg configuration to use
 */
static void 
lockmanager_run (void *cls,
                 struct GNUNET_SERVER_Handle * server,
                 const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  static const struct GNUNET_SERVER_MessageHandler message_handlers[] =
    {
      {&handle_acquire, NULL, GNUNET_MESSAGE_TYPE_LOCKMANAGER_ACQUIRE, 0},
      {&handle_release, NULL, GNUNET_MESSAGE_TYPE_LOCKMANAGER_RELEASE, 0},
      {NULL}
    };
  GNUNET_SERVER_add_handlers (server,
                              message_handlers);
  GNUNET_SERVER_disconnect_notify (server,
                                   &client_disconnect_cb,
                                   NULL);
  lock_map = GNUNET_CONTAINER_multihashmap_create (30);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
                                &shutdown_task,
                                NULL);
}


/**
 * The starting point of execution
 */
int main (int argc, char *const *argv)
{
  return
    (GNUNET_OK ==
     GNUNET_SERVICE_run (argc,
                         argv,
                         "lockmanager",
                         GNUNET_SERVICE_OPTION_NONE,
                         &lockmanager_run,
                         NULL)) ? 0 : 1;
}
