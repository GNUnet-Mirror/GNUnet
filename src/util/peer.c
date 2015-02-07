/*
      This file is part of GNUnet
     Copyright (C) 2006, 2008, 2009 Christian Grothoff (and other contributing authors)

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
 * @file util/peer.c
 * @brief peer-ID table that assigns integer IDs to peer-IDs to save memory
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_peer_lib.h"

#define LOG(kind,...) GNUNET_log_from (kind, "util", __VA_ARGS__)


struct PeerEntry
{
  /**
   * The identifier itself
   */
  struct GNUNET_PeerIdentity id;

  /**
   * Short version of the identifier; if the RC==0, then index of next
   * free slot in table, otherwise equal to this slot in the table.
   */
  GNUNET_PEER_Id pid;

  /**
   * Reference counter, 0 if this slot is not used.
   */
  unsigned int rc;
};


/**
 * Table with our interned peer IDs.
 */
static struct PeerEntry **table;

/**
 * Peermap of PeerIdentities to "struct PeerEntry"
 * (for fast lookup).  NULL until the library
 * is actually being used.
 */
static struct GNUNET_CONTAINER_MultiPeerMap *map;

/**
 * Size of the "table".
 */
static unsigned int size;

/**
 * Index of the beginning of the free list in the table; set to "size"
 * if no slots are free in the table.
 */
static unsigned int free_list_start;


/**
 * Search for a peer identity. The reference counter is not changed.
 *
 * @param pid identity to find
 * @return the interned identity or 0.
 */
GNUNET_PEER_Id
GNUNET_PEER_search (const struct GNUNET_PeerIdentity *pid)
{
  struct PeerEntry *e;

  if (NULL == pid)
    return 0;
  if (NULL == map)
    return 0;
  e = GNUNET_CONTAINER_multipeermap_get (map, pid);
  if (NULL == e)
    return 0;
  GNUNET_assert (e->rc > 0);
  return e->pid;
}


/**
 * Intern an peer identity.  If the identity is already known, its
 * reference counter will be increased by one.
 *
 * @param pid identity to intern
 * @return the interned identity.
 */
GNUNET_PEER_Id
GNUNET_PEER_intern (const struct GNUNET_PeerIdentity *pid)
{
  GNUNET_PEER_Id ret;
  struct PeerEntry *e;
  unsigned int i;

  if (NULL == pid)
    return 0;
  if (NULL == map)
    map = GNUNET_CONTAINER_multipeermap_create (32, GNUNET_YES);
  e = GNUNET_CONTAINER_multipeermap_get (map, pid);
  if (NULL != e)
  {
    GNUNET_assert (e->rc > 0);
    e->rc++;
    return e->pid;
  }
  ret = free_list_start;
  if (ret == size)
  {
    GNUNET_array_grow (table, size, size + 16);
    for (i = ret; i < size; i++)
    {
      table[i] = GNUNET_new (struct PeerEntry);
      table[i]->pid = i + 1;
    }
  }
  if (0 == ret)
  {
    table[0]->pid = 0;
    table[0]->rc = 1;
    ret = 1;
  }
  GNUNET_assert (ret < size);
  GNUNET_assert (0 == table[ret]->rc);
  free_list_start = table[ret]->pid;
  table[ret]->id = *pid;
  table[ret]->rc = 1;
  table[ret]->pid = ret;
  GNUNET_break (GNUNET_OK ==
                GNUNET_CONTAINER_multipeermap_put (map,
						   &table[ret]->id,
                                                   table[ret],
                                                   GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  return ret;
}


/**
 * Decrement multiple RCs of peer identities by one.
 *
 * @param ids array of PIDs to decrement the RCs of
 * @param count size of the ids array
 */
void
GNUNET_PEER_decrement_rcs (const GNUNET_PEER_Id *ids, unsigned int count)
{
  int i;
  GNUNET_PEER_Id id;

  if (0 == count)
    return;
  for (i = count - 1; i >= 0; i--)
  {
    id = ids[i];
    if (0 == id)
      continue;
    GNUNET_assert (id < size);
    GNUNET_assert (table[id]->rc > 0);
    table[id]->rc--;
    if (0 == table[id]->rc)
    {
      GNUNET_break (GNUNET_OK ==
                    GNUNET_CONTAINER_multipeermap_remove (map,
                                                          &table[id]->id,
                                                          table[id]));
      table[id]->pid = free_list_start;
      free_list_start = id;
    }
  }
}


/**
 * Change the reference counter of an interned PID.
 *
 * @param id identity to change the RC of
 * @param delta how much to change the RC
 */
void
GNUNET_PEER_change_rc (GNUNET_PEER_Id id, int delta)
{
  if (0 == id)
    return;
  GNUNET_assert (id < size);
  GNUNET_assert (table[id]->rc > 0);
  GNUNET_assert ((delta >= 0) || (table[id]->rc >= -delta));
  table[id]->rc += delta;
  if (0 == table[id]->rc)
  {
    GNUNET_break (GNUNET_OK ==
                  GNUNET_CONTAINER_multipeermap_remove (map,
                                                        &table[id]->id,
                                                        table[id]));
    table[id]->pid = free_list_start;
    free_list_start = id;
  }
}


/**
 * Convert an interned PID to a normal peer identity.
 *
 * @param id interned PID to convert
 * @param pid where to write the normal peer identity
 */
void
GNUNET_PEER_resolve (GNUNET_PEER_Id id, struct GNUNET_PeerIdentity *pid)
{
  if (0 == id)
  {
    memset (pid, 0, sizeof (struct GNUNET_PeerIdentity));
    return;
  }
  GNUNET_assert (id < size);
  GNUNET_assert (table[id]->rc > 0);
  *pid = table[id]->id;
}


/**
 * Convert an interned PID to a normal peer identity.
 *
 * @param id interned PID to convert
 * @return pointer to peer identity, valid as long 'id' is valid
 */
const struct GNUNET_PeerIdentity *
GNUNET_PEER_resolve2 (GNUNET_PEER_Id id)
{
  return &table[id]->id;
}



/* end of peer.c */
