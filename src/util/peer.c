/*
      This file is part of GNUnet
     (C) 2006, 2008, 2009 Christian Grothoff (and other contributing authors)

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
static struct PeerEntry *table;

/**
 * Hashmap of PeerIdentities to "struct PeerEntry"
 * (for fast lookup).  NULL until the library
 * is actually being used.
 */
static struct GNUNET_CONTAINER_MultiHashMap *map;

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
  long off;

  if (pid == NULL)
    return 0;
  if (NULL == map)
    return 0;
  off = (long) GNUNET_CONTAINER_multihashmap_get (map, &pid->hashPubKey);
  e = (off == 0) ? NULL : &table[off];
  if (e == NULL)
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
  long off;

  if (pid == NULL)
    return 0;
  if (NULL == map)
    map = GNUNET_CONTAINER_multihashmap_create (32);
  off = (long) GNUNET_CONTAINER_multihashmap_get (map, &pid->hashPubKey);
  e = (off == 0) ? NULL : &table[off];
  if (e != NULL)
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
      table[i].pid = i + 1;
  }
  if (ret == 0)
  {
    table[0].pid = 0;
    table[0].rc = 1;
    ret = 1;
  }
  GNUNET_assert (ret < size);
  GNUNET_assert (table[ret].rc == 0);
  free_list_start = table[ret].pid;
  table[ret].id = *pid;
  table[ret].rc = 1;
  table[ret].pid = ret;
  GNUNET_break (GNUNET_OK ==
                GNUNET_CONTAINER_multihashmap_put (map, &pid->hashPubKey,
                                                   (void *) (long) ret,
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

  if (count == 0)
    return;
  for (i = count - 1; i >= 0; i--)
  {
    id = ids[i];
    if (id == 0)
      continue;
    GNUNET_assert (id < size);
    GNUNET_assert (table[id].rc > 0);
    table[id].rc--;
    if (table[id].rc == 0)
    {
      GNUNET_break (GNUNET_OK ==
                    GNUNET_CONTAINER_multihashmap_remove (map,
                                                          &table[id].
                                                          id.hashPubKey,
                                                          (void *) (long) id));
      table[id].pid = free_list_start;
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
  if (id == 0)
    return;
  GNUNET_assert (id < size);
  GNUNET_assert (table[id].rc > 0);
  GNUNET_assert ((delta >= 0) || (table[id].rc >= -delta));
  table[id].rc += delta;
  if (table[id].rc == 0)
  {
    GNUNET_break (GNUNET_OK ==
                  GNUNET_CONTAINER_multihashmap_remove (map,
                                                        &table[id].
                                                        id.hashPubKey,
                                                        (void *) (long) id));
    table[id].pid = free_list_start;
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
  if (id == 0)
  {
    memset (pid, 0, sizeof (struct GNUNET_PeerIdentity));
    GNUNET_break (0);
    return;
  }
  GNUNET_assert (id < size);
  GNUNET_assert (table[id].rc > 0);
  *pid = table[id].id;
}


/* end of peer.c */
