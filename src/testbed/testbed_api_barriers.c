/*
  This file is part of GNUnet.
  (C) 2008--2013 Christian Grothoff (and other contributing authors)

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
  Free Software Foundation, Inc., 59 Temple Place - Suite 330,
  Boston, MA 02111-1307, USA.
*/

/**
 * @file testbed/testbed_api_barriers.c
 * @brief API implementation for testbed barriers
 * @author Sree Harsha Totakura <sreeharsha@totakura.in> 
 */

#include "platform.h"
#include "gnunet_testbed_service.h"
#include "testbed_api.h"

/**
 * Handle for barrier
 */
struct GNUNET_TESTBED_Barrier
{
  /**
   * hashcode identifying this barrier in the hashmap
   */
  struct GNUNET_HashCode key;

  /**
   * The controller handle given while initiliasing this barrier
   */
  struct GNUNET_TESTBED_Controller *c;
  
  /**
   * The name of the barrier
   */
  char *name;

  /**
   * The continuation callback to call when we have a status update on this
   */
  GNUNET_TESTBED_barrier_status_cb cb;

  /**
   * the closure for the above callback
   */
  void *cls;
 
};


/**
 * handle for hashtable of barrier handles
 */
static struct GNUNET_CONTAINER_MultiHashMap *barrier_map;


/**
 * Remove a barrier and it was the last one in the barrier hash map, destroy the
 * hash map
 *
 * @param barrier the barrier to remove
 */
static void
barrier_remove (struct GNUNET_TESTBED_Barrier *barrier)
{
  GNUNET_assert (NULL != barrier_map); /* No barriers present */
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multihashmap_remove (barrier_map,
                                                       &barrier->key,
                                                       barrier));
  GNUNET_free (barrier->name);
  GNUNET_free (barrier);
  if (0 == GNUNET_CONTAINER_multihashmap_size (barrier_map))
  {
    GNUNET_CONTAINER_multihashmap_destroy (barrier_map);
    barrier_map = NULL;
  }
}


/**
 * Handler for GNUNET_MESSAGE_TYPE_TESTBED_BARRIER_STATUS messages
 *
 * @param c the controller handle to determine the connection this message
 *   belongs to
 * @param msg the barrier status message
 * @return GNUNET_OK to keep the connection active; GNUNET_SYSERR to tear it
 *   down signalling an error
 */
int
GNUNET_TESTBED_handle_barrier_status_ (struct GNUNET_TESTBED_Controller *c,
                                       const struct GNUNET_TESTBED_BarrierStatus
                                       *msg)
{
  struct GNUNET_TESTBED_Barrier *barrier;
  char *emsg;
  const char *name;
  struct GNUNET_HashCode key;  
  size_t emsg_len;
  int status;
  uint16_t msize;
  uint16_t name_len;
  
  emsg = NULL;
  barrier = NULL;
  msize = ntohs (msg->header.size);  
  name = msg->data;
  name_len = ntohs (msg->name_len);
  if (  (sizeof (struct GNUNET_TESTBED_BarrierStatus) + name_len + 1 > msize)
        || ('\0' != name[name_len])  )
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  status = ntohs (msg->status);
  if (0 != status)
  {
    status = -1;
    emsg_len = msize - (sizeof (struct GNUNET_TESTBED_BarrierStatus) + name_len
                        + 1);
    if (0 == emsg_len)
    {
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
    emsg_len++;
    emsg = GNUNET_malloc (emsg_len);
    emsg_len--;
    emsg[emsg_len] = '\0';
    (void) memcpy (emsg, msg->data + name_len + 1, emsg_len);
  }
  if (NULL == barrier_map)
    goto cleanup;
  GNUNET_CRYPTO_hash (name, name_len, &key);
  barrier = GNUNET_CONTAINER_multihashmap_get (barrier_map, &key);
  if (NULL == barrier)
    goto cleanup;
  GNUNET_assert (NULL != barrier->cb);
  barrier->cb (barrier->cls, name, barrier, status, emsg);

 cleanup:
  GNUNET_free_non_null (emsg);
  if (NULL != barrier)
    barrier_remove (barrier);
  return GNUNET_OK;
}


/**
 * Initialise a barrier and call the given callback when the required percentage
 * of peers (quorum) reach the barrier OR upon error.
 *
 * @param controller the handle to the controller
 * @param name identification name of the barrier
 * @param quorum the percentage of peers that is required to reach the barrier.
 *   Peers signal reaching a barrier by calling
 *   GNUNET_TESTBED_barrier_reached().
 * @param cb the callback to call when the barrier is reached or upon error.
 *   Cannot be NULL.
 * @param cls closure for the above callback
 * @return barrier handle; NULL upon error
 */
struct GNUNET_TESTBED_Barrier *
GNUNET_TESTBED_barrier_init (struct GNUNET_TESTBED_Controller *controller,
                             const char *name,
                             unsigned int quorum,
                             GNUNET_TESTBED_barrier_status_cb cb, void *cls)
{
  struct GNUNET_TESTBED_Barrier *barrier;
  struct GNUNET_HashCode key;
  size_t name_len;
  
  GNUNET_assert (quorum <= 100);
  GNUNET_assert (NULL != cb);
  name_len = strlen (name);
  GNUNET_assert (0 < name_len);
  GNUNET_CRYPTO_hash (name, name_len, &key);
  if (NULL == barrier_map)
    barrier_map = GNUNET_CONTAINER_multihashmap_create (3, GNUNET_YES);
  if (GNUNET_YES ==
      GNUNET_CONTAINER_multihashmap_contains (barrier_map, &key))
  {
    GNUNET_break (0);
    return NULL;
  }
  barrier = GNUNET_malloc (sizeof (struct GNUNET_TESTBED_Barrier));
  barrier->name = GNUNET_strdup (name);
  barrier->cb = cb;
  barrier->cls = cls;
  (void) memcpy (&barrier->key, &key, sizeof (struct GNUNET_HashCode));
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multihashmap_put (barrier_map, &barrier->key,
                                                    barrier,
                                                    GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST));
  return barrier;
}


/**
 * Cancel a barrier.
 *
 * @param barrier the barrier handle
 */
void
GNUNET_TESTBED_barrier_cancel (struct GNUNET_TESTBED_Barrier *barrier)
{
  barrier_remove (barrier);
}
