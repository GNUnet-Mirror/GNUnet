/*
     This file is part of GNUnet
     (C) 2004, 2005, 2006, 2007, 2009 Christian Grothoff (and other contributing authors)

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
 * @file datastore/datastore_api.c
 * @brief Management for the datastore for files stored on a GNUnet node
 * @author Christian Grothoff
 *
 * TODO:
 * 1) clarify API (wrt. efficient UPDATE of priority/expiration after GET)
 * 2) implement INIT
 * 3) implement SIZE handling (=> API impact?)
 * 4) implement DROP
 * 5) implement PUT
 * 6) implement GET
 * 7) implement GET_RANDOM
 * 8) implement REMOVE
 */

#include "platform.h"
#include "gnunet_datastore_service.h"
#include "datastore.h"


struct MessageQueue
{
  /**
   * This is a linked list.
   */
  struct MessageQueue *next;

  /**
   * Message we will transmit (allocated at the end
   * of this struct; do not free!).
   */
  struct GNUNET_MessageHeader *msg;

  /**
   * Function to call on the response.
   */
  GNUNET_CLIENT_MessageHandler response_processor;
  
  /**
   * Closure for response_processor.
   */
  void *response_processor_cls;

};


/**
 * Handle to the datastore service.
 */
struct GNUNET_DATASTORE_Handle
{

  /**
   * Current connection to the datastore service.
   */
  struct GNUNET_CLIENT_Connection *client;
  
  /**
   * Linked list of messages waiting to be transmitted.
   */
  struct MessageQueue *messages;

  /**
   * Current response processor (NULL if we are not waiting
   * for a response).  Largely used only to know if we have
   * a 'receive' request pending.
   */
  GNUNET_CLIENT_MessageHandler response_proc;
  
  /**
   * Closure for response_proc.
   */
  void *response_proc_cls;

  /**
   * Current size of the datastore (cached).
   */ 
  unsigned long long size;

  /**
   * Set to GNUNET_YES if we have received the size
   * from the datastore.
   */
  int ready;

};


/**
 * Connect to the datastore service.
 *
 * @param cfg configuration to use
 * @param sched scheduler to use
 * @return handle to use to access the service
 */
struct GNUNET_DATASTORE_Handle *GNUNET_DATASTORE_connect (struct
                                                          GNUNET_CONFIGURATION_Handle
                                                          *cfg,
                                                          struct
                                                          GNUNET_SCHEDULER_Handle
                                                          *sched)
{
  struct GNUNET_CLIENT_Connection *c;
  struct GNUNET_DATASTORE_Handle *h;
  
  c = GNUNET_CLIENT_connect (sched, "datastore", cfg);
  if (c == NULL)
    return NULL; /* oops */
  h = GNUNET_malloc (sizeof(struct GNUNET_DATASTORE_Handle));
  h->client = c;
  /* FIXME: send 'join' request */
  return h;
}


/**
 * Disconnect from the datastore service (and free
 * associated resources).
 *
 * @param h handle to the datastore
 * @param drop set to GNUNET_YES to delete all data in datastore (!)
 */
void GNUNET_DATASTORE_disconnect (struct GNUNET_DATASTORE_Handle *h,
				  int drop)
{
  if (GNUNET_YES == drop)
    {
      /* FIXME: send 'drop' request */
    }
  GNUNET_CLIENT_disconnect (h->client);
  GNUNET_free (h);
}


/**
 * Get the current on-disk size of the datastore.
 * @param h handle to the datastore
 * @return size estimate, -1 if datastore is not available (yet)
 */
unsigned long long GNUNET_DATASTORE_size (struct GNUNET_DATASTORE_Handle *h)
{
  if (GNUNET_YES != h->ready)
    return (unsigned long long) -1LL;
  return h->size;
}


/**
 * Store an item in the datastore.  If the item is already present,
 * the priorities are summed up and the higher expiration time and
 * lower anonymity level is used.
 *
 * @param h handle to the datastore
 * @param key key for the value
 * @param size number of bytes in data
 * @param data content stored
 * @param type type of the content
 * @param priority priority of the content
 * @param anonymity anonymity-level for the content
 * @param expiration expiration time for the content
 */
void
GNUNET_DATASTORE_put (struct GNUNET_DATASTORE_Handle *h,
                      const GNUNET_HashCode * key,
                      uint32_t size,
                      const void *data,
                      uint32_t type,
                      uint32_t priority,
                      uint32_t anonymity,
                      struct GNUNET_TIME_Absolute expiration)
{
}


/**
 * Iterate over the results for a particular key
 * in the datastore.
 *
 * @param h handle to the datastore
 * @param key maybe NULL (to match all entries)
 * @param type desired type, 0 for any
 * @param iter function to call on each matching value;
 *        will be called once with a NULL value at the end
 * @param iter_cls closure for iter
 */
void
GNUNET_DATASTORE_get (struct GNUNET_DATASTORE_Handle *h,
                      const GNUNET_HashCode * key,
                      uint32_t type,
                      GNUNET_DATASTORE_Iterator iter, void *iter_cls)
{
}


/**
 * Get a random value from the datastore.
 *
 * @param h handle to the datastore
 * @param iter function to call on a random value; it
 *        will be called exactly once; if no values
 *        are available, the value will be NULL.
 * @param iter_cls closure for iter
 */
void
GNUNET_DATASTORE_get_random (struct GNUNET_DATASTORE_Handle *h,
                             GNUNET_DATASTORE_Iterator iter, void *iter_cls)
{
  static struct GNUNET_TIME_Absolute zero;
  
  iter (iter_cls,
	NULL, 0, NULL, 0, 0, 0, zero, 0);
}


/**
 * Explicitly remove some content from the database.
 *
 * @param h handle to the datastore
 * @param key key for the value
 * @param size number of bytes in data
 * @param data content stored
 */
void
GNUNET_DATASTORE_remove (struct GNUNET_DATASTORE_Handle *h,
                         const GNUNET_HashCode * key,
                         uint32_t size, const void *data)
{
}


/* end of datastore_api.c */
