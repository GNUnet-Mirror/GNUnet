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

#define VERBOSE GNUNET_YES

#define LOG(kind,...) \
  GNUNET_log (kind, __VA_ARGS__)

#define TIME_REL_MINS(min) \
  GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, min)

#define TIMEOUT TIME_REL_MINS(3)


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
  struct GNUNET_SERVER_Client *client;
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
   * List head of clients waiting for this lock
   */
  struct WaitList *wait_list_head;

  /**
   * List tail of clients waiting for this lock
   */
  struct WaitList *wait_list_tail;

  /**
   * The client which is currently holding this lock
   */
  struct GNUNET_SERVER_Client *client;

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
   * Pointer to the client
   */
  struct GNUNET_SERVER_Client *client;
};


/**
 * Head of the doubly linked list of the currently held locks
 */
static struct LockList *ll_head;

/**
 * Tail of the doubly linked list of the currently held locks
 */
static struct LockList *ll_tail;

/**
 * Head of the doubly linked list of clients currently connected
 */
static struct ClientList *cl_head;

/**
 * Tail of the doubly linked list of clients currently connected
 */
static struct ClientList *cl_tail;


/**
 * Function to search for a lock in lock_list matching the given domain_name and
 * lock number
 *
 * @param domain_name the name of the locking domain
 * @param lock_num the number of the lock
 * @param ret this will be the pointer to the corresponding Lock if found; else
 *         it will be the last element in the locks list
 * @return GNUNET_YES if a matching lock is present in lock_list; GNUNET_NO if not
 */
static int
ll_find_lock (const char *domain_name,
              const uint32_t lock_num,
              struct LockList **ret)
{
  struct LockList *current_lock;

  current_lock = ll_head;
  
  while (NULL != current_lock)
    {
      if ( (0 == strcmp (domain_name, current_lock->domain_name))
           && (lock_num == current_lock->lock_num))
        {
          if (NULL != ret)
            *ret = current_lock;
          return GNUNET_YES;
        }

      current_lock = current_lock->next;
    }
  if (NULL != ret)
    *ret = current_lock;
  return GNUNET_NO;
}


/**
 * Function to search for a lock in lock_list matching the given domain_name and
 * lock number
 *
 * @param client the client owning this lock currently
 * @param ret this will be the pointer to the corresponding Lock if found; else
 *         it will be the last element in the locks list
 * @return GNUNET_YES if a matching lock is present in lock_list; GNUNET_NO if not
 */
static int
ll_find_lock_by_owner (const struct GNUNET_SERVER_Client *client,
                       struct LockList **ret)
{
  struct LockList *current_lock;

  current_lock = ll_head;
  
  while (NULL != current_lock)
    {
      if (client == current_lock->client)
        {
          if (NULL != ret)
            *ret = current_lock;
          return GNUNET_YES;
        }

      current_lock = current_lock->next;
    }
  if (NULL != ret)
    *ret = current_lock;
  return GNUNET_NO;
}


/**
 * Function to append a lock to the global lock list
 *
 * @param client the client which currently owns this lock
 * @param domain_name the name of the locking domain
 * @param lock_num the number of the lock
 * @param tail the pointer to the tail of the global lock list
 */
static void
ll_add_lock (struct GNUNET_SERVER_Client *client,
             const char *domain_name,
             const uint32_t lock_num)
{
  struct LockList *lock;
  size_t domain_name_len;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Adding a lock with num: %u and domain: %s to lock list\n",
       lock_num, domain_name);

  lock = GNUNET_malloc (sizeof (struct LockList));
  domain_name_len = strlen (domain_name) + 1;
  lock->domain_name = GNUNET_malloc (domain_name_len);
  strncpy (lock->domain_name, domain_name, domain_name_len);
  lock->lock_num = lock_num;
  lock->client = client;
  
  GNUNET_CONTAINER_DLL_insert_tail (ll_head,
                                    ll_tail,
                                    lock);
}


/**
 * Function to delete a lock from the lock list
 *
 * @param lock the lock to be deleted
 */
static void
ll_remove_lock (struct LockList *lock)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Removing lock with num: %u, domain: %s\n",
       lock->lock_num, lock->domain_name);
  GNUNET_assert (NULL != ll_head);
  GNUNET_CONTAINER_DLL_remove (ll_head,
                               ll_tail,
                               lock);
  GNUNET_free (lock->domain_name);
  GNUNET_free (lock);
}


/**
 * Find a client in the waiting list of a lock
 *
 * @param lock the LockList entry of a lock
 * @param client the client to look for
 * @param ret where to store the matched wait list entry
 * @return GNUNET_YES if a match is found; GNUNET_NO if not
 */
static int
ll_wl_find_client (struct LockList *lock,
                   const struct GNUNET_SERVER_Client *client,
                   struct WaitList **ret)
{
  struct WaitList *current_wl_entry;

  current_wl_entry = lock->wait_list_head;

  while (NULL != current_wl_entry)
    {
      if (client == current_wl_entry->client)
        {
          if (NULL != ret)
            *ret = current_wl_entry;
          return GNUNET_YES;
        }
      current_wl_entry = current_wl_entry->next;
    }
  if (NULL != ret)
    *ret = current_wl_entry;
  return GNUNET_NO;
}


/**
 * Add a client to the wait list of given lock
 *
 * @param lock the lock list entry of a lock
 * @param client the client to queue for the lock's wait list
 */
static void
ll_wl_add_client (struct LockList *lock,
                  struct GNUNET_SERVER_Client *client)
{
  struct WaitList *wl_entry;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Adding a client to lock's wait list\n"
       "\t lock num: %u, domain: %s\n",
       lock->lock_num,
       lock->domain_name);

  wl_entry = GNUNET_malloc (sizeof (struct WaitList));
  wl_entry->client = client;
  GNUNET_CONTAINER_DLL_insert_tail (lock->wait_list_head,
                                    lock->wait_list_tail,
                                    wl_entry);
}


/**
 * Remove a client from the wait list of the given lock
 *
 * @param lock the lock list entry of the lock
 * @param wl_client the wait list entry to be removed
 */
static void
ll_wl_remove_client (struct LockList *lock,
                     struct WaitList *wl_client)
{
  GNUNET_CONTAINER_DLL_remove (lock->wait_list_head,
                               lock->wait_list_tail,
                               wl_client);

  GNUNET_free (wl_client);
}


/**
 * Search for a client in the client list
 *
 * @param client the client to be searched for
 * @param ret will be pointing to the matched list entry (if there is a match);
 *          else to the tail of the client list
 * @return GNUNET_YES if the client is present; GNUNET_NO if not
 */
static int
cl_find_client (const struct GNUNET_SERVER_Client *client,
                struct ClientList **ret)
{
  struct ClientList *current;

  current = cl_head;

  while (NULL != current)
    {
      if (client == current->client)
        {
          if (NULL != ret) 
            *ret = current;
          return GNUNET_YES;
        }

      current = current->next;
    }
  
  if (NULL != ret)
    *ret = current;
  return GNUNET_NO;
}


/**
 * Append a client to the client list
 *
 * @param client the client to be appended to the list
 */
static void
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
}


/**
 * Delete the given client from the client list
 *
 * @param client the client list entry to delete
 */
static void
cl_remove_client (struct ClientList *client)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Removing a client from the client list\n");
  GNUNET_SERVER_client_drop (client->client);
  GNUNET_CONTAINER_DLL_remove (cl_head,
                               cl_tail,
                               client);
  GNUNET_free (client);
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
  struct LockList *ll_entry;
  uint32_t lock_num;
  

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received an ACQUIRE message\n");


  /* Check if the client is in client list */
  if (GNUNET_NO == cl_find_client (client, NULL))
    {
      cl_add_client (client);
    }
  
  request = (struct GNUNET_LOCKMANAGER_Message *) message;
  lock_num = ntohl (request->lock);
  domain_name = (char *) &request[1];
  if (GNUNET_YES == ll_find_lock (domain_name,
                                  lock_num,
                                  &ll_entry))
    {/* Add client to the lock's wait list */
      ll_wl_add_client (ll_entry, client);
    }
  else
    {
      ll_add_lock (client, domain_name, lock_num);
      send_success_msg (client, domain_name, lock_num);
    }
  
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
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
  const char *domain_name;
  struct LockList *ll_entry;
  uint32_t lock_num;

  request = (struct GNUNET_LOCKMANAGER_Message *) message;
  lock_num = ntohl (request->lock);
  domain_name = (char *) &request[1];
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received a RELEASE message on lock with num: %d, domain: %s\n",
       lock_num, domain_name);
  if (GNUNET_YES == ll_find_lock (domain_name, lock_num, &ll_entry))
    {
      if (NULL == ll_entry->wait_list_head)
        {
          ll_remove_lock (ll_entry);
        }
      else
        {
          /* Do furthur processing on lock's wait list here */
        }
    }
  else
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "\t give lock doesn't exist\n");
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

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "A client has been disconnected -- freeing its locks and resources\n");
  
  if (GNUNET_YES == cl_find_client (client, &cl_entry))
    {
      struct LockList *lock;
      
      cl_remove_client (cl_entry);
      while (GNUNET_YES == ll_find_lock_by_owner (client, &lock))
        {
          if (NULL == lock->wait_list_head)
            {
              ll_remove_lock (lock);
            }
          else
            {
              /* Do furthur processing on lock's wait list here */
            }
        }
    }
  else GNUNET_break (0);
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
  
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Starting lockmanager\n");
  GNUNET_SERVER_add_handlers (server,
                              message_handlers);
  GNUNET_SERVER_disconnect_notify (server,
                                   &client_disconnect_cb,
                                   NULL);
                                   
  
}

/**
 * The starting point of execution
 */
int main (int argc, char *const *argv)
{
  int ret;
  
  GNUNET_log_setup ("lockmanager",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);

  LOG (GNUNET_ERROR_TYPE_DEBUG, "main()\n");
  ret = 
    (GNUNET_OK ==
     GNUNET_SERVICE_run (argc,
                         argv,
                         "lockmanager",
                         GNUNET_SERVICE_OPTION_NONE,
                         &lockmanager_run,
                         NULL)) ? 0 : 1;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "main() END\n");
  return ret;
}
