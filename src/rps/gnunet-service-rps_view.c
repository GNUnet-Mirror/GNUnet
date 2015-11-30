/*
     This file is part of GNUnet.
     Copyright (C)

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
 * @file rps/gnunet-service-rps_view.c
 * @brief wrapper around the "local view"
 * @author Julius Bünger
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet-service-rps_view.h"
#include <inttypes.h>


/**
 * Array containing the peers
 */
static struct GNUNET_PeerIdentity *array;

/**
 * (Maximum) length of the view
 */
static uint32_t length;

/**
 * Multipeermap containing the peers
 */
static struct GNUNET_CONTAINER_MultiPeerMap *mpm;


/**
 * Create an empty view.
 *
 * @param len the maximum length for the view
 */
void
View_create (uint32_t len)
{
  length = len;
  array = GNUNET_new_array (len, struct GNUNET_PeerIdentity);
  mpm = GNUNET_CONTAINER_multipeermap_create (len, GNUNET_NO); /* might even be
                                                                * set to _YES */
}

/**
 * Change length of view
 *
 * @param len the (maximum) length for the view
 */
void
View_change_len (uint32_t len)
{
  uint32_t i;
  uint32_t *index;

  if (GNUNET_CONTAINER_multipeermap_size (mpm) < len)
  { /* Simply shrink */
    /* We might simply clear and free the left over space */
    GNUNET_array_grow (array, length, len);
  }
  else /* We have to remove elements */
  {
    /* TODO find a way to preserve indices */
    for (i = 0; i < len; i++)
    {
      index = GNUNET_CONTAINER_multipeermap_get (mpm, &array[i]);
      GNUNET_assert (NULL != index);
      GNUNET_free (index);
    }
    GNUNET_array_grow (array, length, len);
    GNUNET_CONTAINER_multipeermap_destroy (mpm);
    mpm = GNUNET_CONTAINER_multipeermap_create (len, GNUNET_NO);
    for (i = 0; i < len; i++)
    {
      index = GNUNET_new (uint32_t);
      *index = i;
      GNUNET_CONTAINER_multipeermap_put (mpm, &array[i], index,
          GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
    }
  }
  GNUNET_assert (length == len);
}

/**
 * Get the view as an array
 *
 * @return the view in array representation
 */
const struct GNUNET_PeerIdentity *
View_get_as_array ()
{
  return array;
}

/**
 * Get the size of the view
 *
 * @return current number of actually contained peers
 */
unsigned int
View_size ()
{
  return GNUNET_CONTAINER_multipeermap_size (mpm);
}

/**
 * Insert peer into the view
 *
 * @param peer the peer to insert
 *
 * @return GNUNET_OK if peer was actually inserted
 *         GNUNET_NO if peer was not inserted
 */
int
View_put (const struct GNUNET_PeerIdentity *peer)
{
  uint32_t *index;

  if ((length <= View_size ()) || /* If array is 'full' */
      (GNUNET_YES == View_contains_peer (peer)))
  {
    return GNUNET_NO;
  }
  else
  {
    index = GNUNET_new (uint32_t);
    *index = (uint32_t) View_size ();
    array[*index] = *peer;
    GNUNET_CONTAINER_multipeermap_put (mpm, peer, index,
        GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
    return GNUNET_OK;
  }
}

/**
 * Check whether view contains a peer
 *
 * @param peer the peer to check for
 *
 * @return GNUNET_OK if view contains peer
 *         GNUNET_NO otherwise
 */
int
View_contains_peer (const struct GNUNET_PeerIdentity *peer)
{
  return GNUNET_CONTAINER_multipeermap_contains (mpm, peer);
}

/**
 * Remove peer from view
 *
 * @param peer the peer to remove
 *
 * @return GNUNET_OK if view contained peer and removed it successfully
 *         GNUNET_NO if view does not contain peer
 */
int
View_remove_peer (const struct GNUNET_PeerIdentity *peer)
{
  uint32_t *index;
  uint32_t *index_swap;

  if (GNUNET_NO == View_contains_peer (peer))
  {
    return GNUNET_NO;
  }
  index = GNUNET_CONTAINER_multipeermap_get (mpm, peer);
  GNUNET_assert (NULL != index);
  if (*index < (View_size () - 1) )
  { /* Fill the 'gap' in the array with the last peer */
    array[*index] = array[(View_size () - 1)];
    index_swap = GNUNET_CONTAINER_multipeermap_get (mpm, &array[View_size ()]);
    *index_swap = *index;
    GNUNET_free (index);
  }
  GNUNET_CONTAINER_multipeermap_remove_all (mpm, peer);
  return GNUNET_OK;
}

/**
 * Get a peer by index
 *
 * @param index the index of the peer to get
 *
 * @return peer to the corresponding index.
 *         NULL if this index is not known
 */
const struct GNUNET_PeerIdentity *
View_get_peer_by_index (uint32_t index)
{
  if (index < GNUNET_CONTAINER_multipeermap_size (mpm))
  {
    return &array[index];
  }
  else
  {
    return NULL;
  }
}

/**
 * Clear the custom peer map
 *
 * @param c_peer_map the custom peer map to look in
 *
 * @return size of the map
 */
void
View_clear ()
{
  uint32_t i;
  uint32_t *index;

  for (i = 0; 0 < View_size (); i++)
  { /* Need to free indices stored at peers */
    GNUNET_assert (GNUNET_YES ==
        GNUNET_CONTAINER_multipeermap_contains (mpm, &array[i]));
    index = GNUNET_CONTAINER_multipeermap_get (mpm, &array[i]);
    GNUNET_assert (NULL != index);
    GNUNET_free (index);
    GNUNET_CONTAINER_multipeermap_remove_all (mpm, &array[i]);
  }
  GNUNET_assert (0 == View_size ());
}

/**
 * Destroy peermap.
 *
 * @param c_peer_map the map to destroy
 */
void
View_destroy ()
{
  View_clear ();
  GNUNET_free (array);
  GNUNET_CONTAINER_multipeermap_destroy (mpm);
}

/* end of gnunet-service-rps_view.c */
