/*
     This file is part of GNUnet.
     Copyright (C)

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
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

struct View
{
  /**
   * Array containing the peers
   */
  struct GNUNET_PeerIdentity *array;

  /**
   * (Maximum) length of the view
   */
  uint32_t length;

  /**
   * Multipeermap containing the peers
   */
  struct GNUNET_CONTAINER_MultiPeerMap *mpm;
};


/**
 * Create an empty view.
 *
 * @param len the maximum length for the view
 * @return The newly created view
 */
struct View *
View_create (uint32_t len)
{
  struct View *view;

  view = GNUNET_new (struct View);
  view->length = len;
  view->array = GNUNET_new_array (len, struct GNUNET_PeerIdentity);
  view->mpm =
    GNUNET_CONTAINER_multipeermap_create (len, GNUNET_NO);  /* might even be
                                                           * set to _YES */
  return view;
}


/**
 * Change length of view
 *
 * If size is decreased, peers with higher indices are removed.
 *
 * @param view The view that is changed
 * @param len the (maximum) length for the view
 */
void
View_change_len (struct View *view,
                 uint32_t len)
{
  uint32_t i;
  uint32_t *index;

  if (GNUNET_CONTAINER_multipeermap_size (view->mpm) < len)
  {   /* Simply shrink */
      /* We might simply clear and free the left over space */
    GNUNET_array_grow (view->array, view->length, len);
  }
  else /* We have to remove elements */
  {
    /* TODO find a way to preserve indices */
    for (i = 0; i < len; i++)
    {
      index = GNUNET_CONTAINER_multipeermap_get (view->mpm, &view->array[i]);
      GNUNET_assert (NULL != index);
      GNUNET_free (index);
    }
    GNUNET_array_grow (view->array, view->length, len);
    GNUNET_CONTAINER_multipeermap_destroy (view->mpm);
    view->mpm = GNUNET_CONTAINER_multipeermap_create (len, GNUNET_NO);
    for (i = 0; i < len; i++)
    {
      index = GNUNET_new (uint32_t);
      *index = i;
      GNUNET_CONTAINER_multipeermap_put (view->mpm, &view->array[i], index,
                                         GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
    }
  }
  GNUNET_assert (view->length == len);
}


/**
 * Get the view as an array
 *
 * @param view The view of which the array representation is of interest
 * @return the view in array representation
 */
const struct GNUNET_PeerIdentity *
View_get_as_array (const struct View *view)
{
  return view->array;
}


/**
 * Get the size of the view
 *
 * @param view The view of which the size should be returned
 * @return current number of actually contained peers
 */
unsigned int
View_size (const struct View *view)
{
  return GNUNET_CONTAINER_multipeermap_size (view->mpm);
}


/**
 * Insert peer into the view
 *
 * @param view The view to put the peer into
 * @param peer the peer to insert
 *
 * @return GNUNET_OK if peer was actually inserted
 *         GNUNET_NO if peer was not inserted
 */
int
View_put (struct View *view,
          const struct GNUNET_PeerIdentity *peer)
{
  uint32_t *index;

  if ((view->length <= View_size (view)) ||  /* If array is 'full' */
      (GNUNET_YES == View_contains_peer (view, peer)))
  {
    return GNUNET_NO;
  }
  else
  {
    index = GNUNET_new (uint32_t);
    *index = (uint32_t) View_size (view);
    view->array[*index] = *peer;
    GNUNET_CONTAINER_multipeermap_put (view->mpm, peer, index,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
    return GNUNET_OK;
  }
}


/**
 * Check whether view contains a peer
 *
 * @param view The which is checked for a peer
 * @param peer the peer to check for
 *
 * @return GNUNET_OK if view contains peer
 *         GNUNET_NO otherwise
 */
int
View_contains_peer (const struct View *view,
                    const struct GNUNET_PeerIdentity *peer)
{
  return GNUNET_CONTAINER_multipeermap_contains (view->mpm, peer);
}


/**
 * Remove peer from view
 *
 * @param view The view of which to remove the peer
 * @param peer the peer to remove
 *
 * @return GNUNET_OK if view contained peer and removed it successfully
 *         GNUNET_NO if view does not contain peer
 */
int
View_remove_peer (struct View *view,
                  const struct GNUNET_PeerIdentity *peer)
{
  uint32_t *index;
  uint32_t *swap_index;
  uint32_t last_index;

  if (GNUNET_NO == View_contains_peer (view, peer))
  {
    return GNUNET_NO;
  }
  index = GNUNET_CONTAINER_multipeermap_get (view->mpm, peer);
  GNUNET_assert (NULL != index);
  last_index = View_size (view) - 1;
  if (*index < last_index)
  {   /* Fill the 'gap' in the array with the last peer */
    view->array[*index] = view->array[last_index];
    GNUNET_assert (GNUNET_YES == View_contains_peer (view,
                                                     &view->array[last_index]));
    swap_index = GNUNET_CONTAINER_multipeermap_get (view->mpm,
                                                    &view->array[last_index]);
    GNUNET_assert (NULL != swap_index);
    *swap_index = *index;
    GNUNET_free (index);
  }
  GNUNET_CONTAINER_multipeermap_remove_all (view->mpm, peer);
  return GNUNET_OK;
}


/**
 * Get a peer by index
 *
 * @param view the view of which to get the peer
 * @param index the index of the peer to get
 *
 * @return peer to the corresponding index.
 *         NULL if this index is not known
 */
const struct GNUNET_PeerIdentity *
View_get_peer_by_index (const struct View *view,
                        uint32_t index)
{
  if (index < GNUNET_CONTAINER_multipeermap_size (view->mpm))
  {
    return &view->array[index];
  }
  else
  {
    return NULL;
  }
}


/**
 * Clear the view
 *
 * @param view The view to clear
 */
void
View_clear (struct View *view)
{
  for (uint32_t i = 0; 0 < View_size (view); i++)
  {   /* Need to free indices stored at peers */
    uint32_t *index;

    GNUNET_assert (GNUNET_YES ==
                   GNUNET_CONTAINER_multipeermap_contains (view->mpm,
                                                           &view->array[i]));
    index = GNUNET_CONTAINER_multipeermap_get (view->mpm, &view->array[i]);
    GNUNET_assert (NULL != index);
    GNUNET_free (index);
    GNUNET_CONTAINER_multipeermap_remove_all (view->mpm, &view->array[i]);
  }
  GNUNET_assert (0 == View_size (view));
}


/**
 * Destroy view.
 *
 * @param view the view to destroy
 */
void
View_destroy (struct View *view)
{
  View_clear (view);
  GNUNET_free (view->array);
  view->array = NULL;
  GNUNET_CONTAINER_multipeermap_destroy (view->mpm);
  GNUNET_free (view);
}


/* end of gnunet-service-rps_view.c */
