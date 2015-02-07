/*
  This file is part of GNUnet.
  Copyright (C) 2008--2013 Christian Grothoff (and other contributing authors)

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
 * @file testbed/testbed_api_underlay.c
 * @brief testbed underlay API implementation
 * @author Sree Harsha Totakura <sreeharsha@totakura.in>
 */

#include "testbed_api_peers.h"


/**
 * An underlay link
 */
struct LinkProperty
{
  /**
   * next pointer for list
   */
  struct LinkProperty *next;

  /**
   * the peer whose link is defined by these properties
   */
  struct GNUNET_TESTBED_Peer *peer;

  /**
   * latency of the link in microseconds
   */
  uint32_t latency;

  /**
   * data loss on the link expressed as percentage
   */
  uint32_t loss;

  /**
   * bandwidth of the link in kilobytes per second
   */
  uint32_t bandwidth;
};


/**
 * Container for holding a peer in whitelist/blacklist
 */
struct ListEntry
{
  /**
   * the next pointer
   */
  struct ListEntry *next;

  /**
   * the peer
   */
  struct GNUNET_TESTBED_Peer *peer;
};


/**
 * Model for configuring underlay links of a peer
 * @ingroup underlay
 */
struct GNUNET_TESTBED_UnderlayLinkModel
{
  /**
   * The peer associated with this model
   */
  struct GNUNET_TESTBED_Peer *peer;

  /**
   * List of peers in the list
   */
  struct ListEntry *entries;

  /**
   * list of link properties
   */
  struct LinkProperty *props;

  /**
   * the type of this model
   */
  enum GNUNET_TESTBED_UnderlayLinkModelType type;
}


/**
 * Function to free resources of list entries
 *
 * @param model the model
 */
static void
free_entries (struct GNUNET_TESTBED_UnderlayLinkModel *model)
{
  struct ListEntry *e;

  while (NULL != (e = model->entries))
  {
    model->entries = e->next;
    GNUNET_free (e);
  }
}


/**
 * Function to free resources of link properties added to the given model
 *
 * @param model the model
 */
static void
free_link_properties (struct GNUNET_TESTBED_UnderlayLinkModel *model)
{
  struct LinkProperty *p;

  while (NULL != (p = model->props))
  {
    model->props = p->next;
    GNUNET_free (p);
  }
}


/**
 * Create a GNUNET_TESTBED_UnderlayLinkModel for the given peer.  A peer can
 * have ONLY ONE model and it can be either a blacklist or whitelist based one.
 *
 * @ingroup underlay
 * @param peer the peer for which the model has to be created
 * @param type the type of the model
 * @return the model
 */
struct GNUNET_TESTBED_UnderlayLinkModel *
GNUNET_TESTBED_underlaylinkmodel_create (struct GNUNET_TESTBED_Peer *peer,
                                         enum GNUNET_TESTBED_UnderlayLinkModelType type)
{
  struct GNUNET_TESTBED_UnderlayLinkModel *m;

  GNUNET_assert (0 == peer->underlay_model_exists);
  m = GNUNET_new (struct GNUNET_TESTBED_UnderlayLinkModel);
  peer->underlay_model_exists = 1;
  m->type = type;
  return m;
}


/**
 * Add a peer to the given model.  Underlay connections to the given peer will
 * be permitted if the model is whitelist based; otherwise they will not be
 * permitted.
 *
 * @ingroup underlay
 * @param model the model
 * @param peer the peer to add
 */
void
GNUNET_TESTBED_underlaylinkmodel_add_peer (struct GNUNET_TESTBED_UnderlayLinkModel *model,
                                           struct GNUNET_TESTBED_Peer *peer)
{
  struct ListEntry *entry;

  entry = GNUNET_new (struct ListEntry);
  entry->peer = peer;
  entry->next = model->entries;
  model->entries = entry;
}


/**
 * Set the metrics for a link to the given peer in the underlay model.  The link
 * SHOULD be permittable according to the given model.
 *
 * @ingroup underlay
 * @param model the model
 * @param peer the other end peer of the link
 * @param latency latency of the link in microseconds
 * @param loss data loss of the link expressed as a percentage
 * @param bandwidth bandwidth of the link in kilobytes per second [kB/s]
 */
void
GNUNET_TESTBED_underlaylinkmodel_set_link (struct GNUNET_TESTBED_UnderlayLinkModel *model,
                                           struct GNUNET_TESTBED_Peer *peer,
                                           uint32_t latency,
                                           uint32_t loss,
                                           uint32_t bandwidth)
{
  struct LinkProperty *prop;

  prop = GNUNET_new (struct LinkProperty);
  prop->peer = peer;
  prop->latency = latency;
  prop->loss = loss;
  prop->bandwidth = bandwidth;
  prop->next = model->props;
  model->props = prop;
}


/**
 * Free the resources of the model.  Use this function only if the model has not
 * be committed and has to be unallocated.  The peer can then have another model
 * created.
 *
 * @ingroup underlay
 * @param model the model to unallocate
 */
void
GNUNET_TESTBED_underlaylinkmodel_free (struct GNUNET_TESTBED_UnderlayLinkModel *model)
{
  model->peer->underlay_model_exists = 0;
  free_entries (model);
  free_link_properties (model);
  gnunet_free (model);
}


/**
 * Commit the model.  The model is freed in this function(!).
 *
 * @ingroup underlay
 * @param model the model to commit
 */
void
GNUNET_TESTBED_underlaylinkmodel_commit (struct GNUNET_TESTBED_UnderlayLinkModel *model)
{
  /* FIXME: Marshal the model into a message */
  GNUNET_break (0);
  /* do not reset the value of model->peer->underlay_model_exists */
  free_entries (model);
  free_link_properties (model);
  GNUNET_free (model);
}
