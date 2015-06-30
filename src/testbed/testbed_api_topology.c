/*
      This file is part of GNUnet
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
      Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
      Boston, MA 02110-1301, USA.
 */

/**
 * @file testbed/testbed_api_topology.c
 * @brief topology-generation functions
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_testbed_service.h"
#include "testbed_api.h"
#include "testbed_api_peers.h"
#include "testbed_api_operations.h"
#include "testbed_api_topology.h"

/**
 * Generic loggins shorthand
 */
#define LOG(kind,...)                                           \
  GNUNET_log_from (kind, "testbed-api-topology", __VA_ARGS__)


/**
 * Default number of retires
 */
#define DEFAULT_RETRY_CNT 3


/**
 * Context information for topology operations
 */
struct TopologyContext;


/**
 * Representation of an overlay link
 */
struct OverlayLink
{

  /**
   * An operation corresponding to this link
   */
  struct GNUNET_TESTBED_Operation *op;

  /**
   * The topology context this link is a part of
   */
  struct TopologyContext *tc;

  /**
   * position of peer A's handle in peers array
   */
  uint32_t A;

  /**
   * position of peer B's handle in peers array
   */
  uint32_t B;

};


/**
 * Representation of an underlay link
 */
struct UnderlayLink
{
  /**
   * position of peer A's handle in peers array
   */
  uint32_t A;

  /**
   * position of peer B's handle in peers array
   */
  uint32_t B;

  /**
   * Bandwidth of the link in bytes per second
   */
  uint32_t bandwidth;

  /**
   * Latency of the link in milliseconds
   */
  uint32_t latency;

  /**
   * Loss in the link in percentage of message dropped
   */
  uint32_t loss;
};


struct RetryListEntry
{
  /**
   * the next pointer for the DLL
   */
  struct RetryListEntry *next;

  /**
   * the prev pointer for the DLL
   */
  struct RetryListEntry *prev;

  /**
   * The link to be retired
   */
  struct OverlayLink *link;
};


/**
 * Context information for overlay topologies
 */
struct TopologyContextOverlay
{
  /**
   * The array of peers
   */
  struct GNUNET_TESTBED_Peer **peers;

  /**
   * An array of links; this array is of size link_array_size
   */
  struct OverlayLink *link_array;

  /**
   * The operation closure
   */
  void *op_cls;

  /**
   * topology generation completion callback
   */
  GNUNET_TESTBED_TopologyCompletionCallback comp_cb;

  /**
   * The closure for the above callback
   */
  void *comp_cb_cls;

  /**
   * DLL head for retry list
   */
  struct RetryListEntry *rl_head;

  /**
   * DLL tail for retry list
   */
  struct RetryListEntry *rl_tail;

  /**
   * How many retries to do before we give up
   */
  unsigned int retry_cnt;

  /**
   * Number of links to try
   */
  unsigned int nlinks;

  /**
   * How many links have been completed
   */
  unsigned int ncompleted;

  /**
   * Total successfully established overlay connections
   */
  unsigned int nsuccess;

  /**
   * Total failed overlay connections
   */
  unsigned int nfailures;
};


/**
 * Topology context information for underlay topologies
 */
struct TopologyContextUnderlay
{
  /**
   * The link array
   */
  struct UnderlayLink *link_array;
};


/**
 * Context information for topology operations
 */
struct TopologyContext
{
  /**
   * The type of this context
   */
  enum {
    
    /**
     * Type for underlay topology
     */
    TOPOLOGYCONTEXT_TYPE_UNDERLAY = 0,
    
    /**
     * Type for overlay topology
     */
    TOPOLOGYCONTEXT_TYPE_OVERLAY

  } type;

  union {

    /**
     * Topology context information for overlay topology
     */
    struct TopologyContextOverlay overlay;

    /**
     * Topology context information for underlay topology
     */
    struct TopologyContextUnderlay underlay;
  } u;

  /**
   * The number of peers
   */
  unsigned int num_peers;

  /**
   * The size of the link array
   */
  unsigned int link_array_size;

};


/**
 * A array of names representing topologies. Should be in sync with enum
 * GNUNET_TESTBED_TopologyOption
 */
const char *topology_strings[] = {

    /**
     * A clique (everyone connected to everyone else).  No options. If there are N
     * peers this topology results in (N * (N -1)) connections.
     */
  "CLIQUE",

    /**
     * Small-world network (2d torus plus random links).  Followed
     * by the number of random links to add (unsigned int).
     */
  "SMALL_WORLD",

    /**
     * Small-world network (ring plus random links).  Followed
     * by the number of random links to add (unsigned int).
     */
  "SMALL_WORLD_RING",

    /**
     * Ring topology.  No options.
     */
  "RING",

    /**
     * 2-d torus.  No options.
     */
  "2D_TORUS",

    /**
     * Random graph.  Followed by the number of random links to be established
     * (unsigned int)
     */
  "RANDOM",                     // GNUNET_TESTBED_TOPOLOGY_ERDOS_RENYI

    /**
     * Certain percentage of peers are unable to communicate directly
     * replicating NAT conditions.  Followed by the fraction of
     * NAT'ed peers (float).
     */
  "INTERNAT",

    /**
     * Scale free topology. Followed by the maximum number of links a node can
     * have (unsigned int); and the number of links a new node should have when
     * it is added to the network (unsigned int)
     */
  "SCALE_FREE",

    /**
     * Straight line topology.  No options.
     */
  "LINE",

    /**
     * Read a topology from a given file.  Followed by the name of the file (const char *).
     */
  "FROM_FILE",

    /**
     * All peers are disconnected.  No options.
     */
  "NONE",

    /**
     * End of strings
     */
  NULL
};


/**
 * Callback to be called when an overlay_link operation complete
 *
 * @param cls element of the link_op array which points to the corresponding operation
 * @param op the operation that has been finished
 * @param emsg error message in case the operation has failed; will be NULL if
 *          operation has executed successfully.
 */
static void
overlay_link_completed (void *cls, struct GNUNET_TESTBED_Operation *op,
                        const char *emsg)
{
  struct OverlayLink *link = cls;
  struct TopologyContext *tc;
  struct TopologyContextOverlay *overlay;
  struct RetryListEntry *retry_entry;

  GNUNET_assert (op == link->op);
  GNUNET_TESTBED_operation_done (op);
  link->op = NULL;
  tc = link->tc;
  GNUNET_assert (TOPOLOGYCONTEXT_TYPE_OVERLAY == tc->type);
  overlay = &tc->u.overlay;
  if (NULL != emsg)
  {
    overlay->nfailures++;
    if (0 != overlay->retry_cnt)
    {
      LOG (GNUNET_ERROR_TYPE_WARNING,
           "Error while establishing a link: %s -- Retrying\n", emsg);
      retry_entry = GNUNET_new (struct RetryListEntry);
      retry_entry->link = link;
      GNUNET_CONTAINER_DLL_insert_tail (overlay->rl_head, overlay->rl_tail, retry_entry);
    }
  }
  else
    overlay->nsuccess++;
  overlay->ncompleted++;
  if (overlay->ncompleted < overlay->nlinks)
    return;
  if ((0 != overlay->retry_cnt) && (NULL != overlay->rl_head))
  {
    overlay->retry_cnt--;
    overlay->ncompleted = 0;
    overlay->nlinks = 0;
    while (NULL != (retry_entry = overlay->rl_head))
    {
      link = retry_entry->link;
      link->op =
          GNUNET_TESTBED_overlay_connect (overlay->op_cls, &overlay_link_completed,
                                          link, overlay->peers[link->A],
                                          overlay->peers[link->B]);
      overlay->nlinks++;
      GNUNET_CONTAINER_DLL_remove (overlay->rl_head, overlay->rl_tail, retry_entry);
      GNUNET_free (retry_entry);
    }
    return;
  }
  if (NULL != overlay->comp_cb)
  {
    overlay->comp_cb (overlay->comp_cb_cls, overlay->nsuccess, overlay->nfailures);
  }
}



/**
 * Function called when a overlay connect operation is ready
 *
 * @param cls the Topology context
 */
static void
opstart_overlay_configure_topology (void *cls)
{
  struct TopologyContext *tc = cls;
  struct TopologyContextOverlay *overlay;
  unsigned int p;

  GNUNET_assert (TOPOLOGYCONTEXT_TYPE_OVERLAY == tc->type);
  overlay = &tc->u.overlay;
  overlay->nlinks = tc->link_array_size;
  for (p = 0; p < tc->link_array_size; p++)
  {
    overlay->link_array[p].op =
        GNUNET_TESTBED_overlay_connect (overlay->op_cls, &overlay_link_completed,
                                        &overlay->link_array[p],
                                        overlay->peers[overlay->link_array[p].A],
                                        overlay->peers[overlay->link_array[p].B]);
  }
}


/**
 * Callback which will be called when overlay connect operation is released
 *
 * @param cls the Topology context
 */
static void
oprelease_overlay_configure_topology (void *cls)
{
  struct TopologyContext *tc = cls;
  struct TopologyContextOverlay *overlay;
  struct RetryListEntry *retry_entry;
  unsigned int p;

  GNUNET_assert (TOPOLOGYCONTEXT_TYPE_OVERLAY == tc->type);
  overlay = &tc->u.overlay;
  while (NULL != (retry_entry = overlay->rl_head))
  {
    GNUNET_CONTAINER_DLL_remove (overlay->rl_head, overlay->rl_tail, retry_entry);
    GNUNET_free (retry_entry);
  }
  if (NULL != overlay->link_array)
  {
    for (p = 0; p < tc->link_array_size; p++)
      if (NULL != overlay->link_array[p].op)
        GNUNET_TESTBED_operation_done (overlay->link_array[p].op);
    GNUNET_free (overlay->link_array);
  }
  GNUNET_free (tc);
}


/**
 * Populates the OverlayLink structure.
 *
 * @param offset the offset of the link array to use
 * @param A the peer A. Should be different from B
 * @param B the peer B. Should be different from A
 * @param tc the TopologyContext
 * @return
 */
static void
make_link (unsigned int offset, uint32_t A, uint32_t B,
           struct TopologyContext *tc)
{
  GNUNET_assert (A != B);
  switch (tc->type)
  {
  case TOPOLOGYCONTEXT_TYPE_OVERLAY:
    {
      struct TopologyContextOverlay *overlay;
      struct OverlayLink *olink;
      
      overlay = &tc->u.overlay;
      GNUNET_assert (offset < tc->link_array_size);
      olink = &overlay->link_array[offset];
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Connecting peer %u to %u\n", B, A);
      olink->A = A;
      olink->B = B;
      olink->op = NULL;
      olink->tc = tc;
    }
    break;
  case TOPOLOGYCONTEXT_TYPE_UNDERLAY:
    {
      struct TopologyContextUnderlay *underlay;
      struct UnderlayLink *ulink;
      
      underlay = &tc->u.underlay;
      GNUNET_assert (offset < tc->link_array_size);
      ulink = &underlay->link_array[offset];
      ulink->A = A;
      ulink->B = B;
    }
    break;
  }
}


/**
 * Generates line topology
 *
 * @param tc the topology context
 */
static void
gen_topo_line (struct TopologyContext *tc)
{
  unsigned int cnt;

  tc->link_array_size = tc->num_peers - 1;
  switch (tc->type)
  {
  case TOPOLOGYCONTEXT_TYPE_OVERLAY:
    {
      struct TopologyContextOverlay *overlay;
      
      overlay = &tc->u.overlay;
      overlay->link_array =
          GNUNET_malloc (sizeof (struct OverlayLink) * tc->link_array_size);
    }
    break;
  case TOPOLOGYCONTEXT_TYPE_UNDERLAY:
    {
      struct TopologyContextUnderlay *underlay;
      
      underlay = &tc->u.underlay;
      underlay->link_array =
          GNUNET_malloc (sizeof (struct UnderlayLink) * tc->link_array_size);
    }
    break;
  }
  for (cnt = 0; cnt < (tc->link_array_size); cnt++)
    make_link (cnt, cnt, cnt + 1, tc);
}


/**
 * Generates ring topology
 *
 * @param tc the topology context
 */
static void
gen_topo_ring (struct TopologyContext *tc)
{
  gen_topo_line (tc);
  tc->link_array_size++;
  switch (tc->type)
  {
  case TOPOLOGYCONTEXT_TYPE_OVERLAY:
    {
      struct TopologyContextOverlay *overlay;

      overlay = &tc->u.overlay;
      overlay->link_array =
          GNUNET_realloc (overlay->link_array, sizeof (struct OverlayLink) *
                          tc->link_array_size);
    }
    break;
  case TOPOLOGYCONTEXT_TYPE_UNDERLAY:
    {
      struct TopologyContextUnderlay *underlay;
      
      underlay = &tc->u.underlay;
      underlay->link_array =
          GNUNET_realloc (underlay->link_array, sizeof (struct UnderlayLink) *
      tc->link_array_size);
    }
    break;
  }
  make_link (tc->link_array_size - 1, tc->num_peers - 1, 0, tc);
}


/**
 * Returns the number of links that are required to generate a 2d torus for the
 * given number of peers. Also returns the arrangment (number of rows and the
 * length of each row)
 *
 * @param num_peers number of peers
 * @param rows number of rows in the 2d torus. Can be NULL
 * @param rows_len the length of each row. This array will be allocated
 *          fresh. The caller should free it. Can be NULL
 * @return the number of links that are required to generate a 2d torus for the
 *           given number of peers
 */
unsigned int
GNUNET_TESTBED_2dtorus_calc_links (unsigned int num_peers, unsigned int *rows,
                                   unsigned int **rows_len)
{
  double sq;
  unsigned int sq_floor;
  unsigned int _rows;
  unsigned int *_rows_len;
  unsigned int x;
  unsigned int y;
  unsigned int _num_peers;
  unsigned int cnt;

  sq = sqrt (num_peers);
  sq = floor (sq);
  sq_floor = (unsigned int) sq;
  _rows = (sq_floor + 1);
  _rows_len = GNUNET_malloc (sizeof (unsigned int) * _rows);
  for (y = 0; y < _rows - 1; y++)
    _rows_len[y] = sq_floor;
  _num_peers = sq_floor * sq_floor;
  cnt = (_num_peers < 2) ? _num_peers : 2 * _num_peers;
  x = 0;
  y = 0;
  while (_num_peers < num_peers)
  {
    if (x < y)
      _rows_len[_rows - 1] = ++x;
    else
      _rows_len[y++]++;
    _num_peers++;
  }
  cnt += (x < 2) ? x : 2 * x;
  cnt += (y < 2) ? y : 2 * y;
  if (0 == _rows_len[_rows - 1])
    _rows--;
  if (NULL != rows)
    *rows = _rows;
  if (NULL != rows_len)
    *rows_len = _rows_len;
  else
    GNUNET_free (_rows_len);
  return cnt;
}


/**
 * Generates ring topology
 *
 * @param tc the topology context
 */
static void
gen_topo_2dtorus (struct TopologyContext *tc)
{
  unsigned int rows;
  unsigned int *rows_len;
  unsigned int x;
  unsigned int y;
  unsigned int cnt;
  unsigned int offset;

  tc->link_array_size =
      GNUNET_TESTBED_2dtorus_calc_links (tc->num_peers, &rows, &rows_len);
  switch (tc->type)
  {
  case TOPOLOGYCONTEXT_TYPE_OVERLAY:
    {
      struct TopologyContextOverlay *overlay;
      
      overlay = &tc->u.overlay;
      overlay->link_array =
          GNUNET_malloc (sizeof (struct OverlayLink) * tc->link_array_size);
    }
    break;
  case TOPOLOGYCONTEXT_TYPE_UNDERLAY:
    {
      struct TopologyContextUnderlay *underlay;

      underlay = &tc->u.underlay;
      underlay->link_array =
          GNUNET_malloc (sizeof (struct UnderlayLink) * tc->link_array_size);
      break;
    }
  }
  cnt = 0;
  offset = 0;
  for (y = 0; y < rows; y++)
  {
    for (x = 0; x < rows_len[y] - 1; x++)
    {
      make_link (cnt, offset + x, offset + x + 1, tc);
      cnt++;
    }
    if (0 == x)
      break;
    make_link (cnt, offset + x, offset, tc);
    cnt++;
    offset += rows_len[y];
  }
  for (x = 0; x < rows_len[0]; x++)
  {
    offset = 0;
    for (y = 0; y < rows - 1; y++)
    {
      if (x >= rows_len[y + 1])
        break;
      GNUNET_assert (x < rows_len[y + 1]);
      make_link (cnt, offset + x, offset + rows_len[y] + x, tc);
      offset += rows_len[y];
      cnt++;
    }
    if (0 == offset)
      break;
    make_link (cnt, offset + x, x, tc);
    cnt++;
  }
  GNUNET_assert (cnt == tc->link_array_size);
  GNUNET_free (rows_len);
}


/**
 * Generates ring topology
 *
 * @param tc the topology context
 * @param links the number of random links to establish
 * @param append GNUNET_YES to add links to existing link array; GNUNET_NO to
 *          create a new link array
 */
static void
gen_topo_random (struct TopologyContext *tc, unsigned int links, int append)
{
  unsigned int cnt;
  unsigned int index;
  uint32_t A_rand;
  uint32_t B_rand;

  if (1 == tc->num_peers)
    return;
  if (GNUNET_YES == append)
  {
    index = tc->link_array_size;
    tc->link_array_size += links;
  }
  else
  {
    index = 0;
    tc->link_array_size = links;
  }
  switch (tc->type)
  {
  case TOPOLOGYCONTEXT_TYPE_OVERLAY:
    {
      struct TopologyContextOverlay *overlay;

      overlay = &tc->u.overlay;
      if (GNUNET_YES != append)
      {
        GNUNET_assert (NULL == overlay->link_array);
        overlay->link_array =
            GNUNET_malloc (sizeof (struct OverlayLink) * tc->link_array_size);
        break;
      }
      GNUNET_assert ((0 < tc->link_array_size) && (NULL != overlay->link_array));
      overlay->link_array =
          GNUNET_realloc (overlay->link_array,
                          sizeof (struct OverlayLink) * tc->link_array_size);
      break;
    }
  case TOPOLOGYCONTEXT_TYPE_UNDERLAY:
    {
      struct TopologyContextUnderlay *underlay;

      underlay = &tc->u.underlay;
      if (GNUNET_YES != append)
      {
        GNUNET_assert (NULL == underlay->link_array);
        underlay->link_array =
            GNUNET_malloc (sizeof (struct UnderlayLink) * tc->link_array_size);
        break;
      }
      GNUNET_assert ((0 < tc->link_array_size) && (NULL != underlay->link_array));
      underlay->link_array =
          GNUNET_realloc (underlay->link_array,
                          sizeof (struct UnderlayLink) * tc->link_array_size);
      break;
    }
  }
  for (cnt = 0; cnt < links; cnt++)
  {
    do
    {
      A_rand =
          GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, tc->num_peers);
      B_rand =
          GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, tc->num_peers);
    }
    while (A_rand == B_rand);
    make_link (index+cnt, A_rand, B_rand, tc);
  }
}


/**
 * Generates scale free network. Its construction is described in:
 *
 * "Emergence of Scaling in Random Networks." Science 286, 509-512, 1999.
 *
 * @param tc the topology context
 * @param cap maximum allowed node degree
 * @param m number of edges to establish for a new node when it is added to the
 *   network
 */
static void
gen_topo_scale_free (struct TopologyContext *tc, uint16_t cap, uint8_t m)
{
  unsigned int *deg;
  unsigned int *etab;
  unsigned int *used;
  unsigned int etaboff;
  unsigned int cnt;
  unsigned int cnt2;
  unsigned int peer;
  unsigned int random_peer;
  unsigned int links;
  unsigned int off;
  unsigned int redo_threshold;

  etaboff = 0;
  tc->link_array_size = tc->num_peers * m;
  switch (tc->type)
  {
  case TOPOLOGYCONTEXT_TYPE_OVERLAY:
    {
      struct TopologyContextOverlay *overlay;

      overlay = &tc->u.overlay;
      overlay->link_array = GNUNET_malloc_large (sizeof (struct OverlayLink) *
                                                 tc->link_array_size);
    }
    break;
  case TOPOLOGYCONTEXT_TYPE_UNDERLAY:
    {
      struct TopologyContextUnderlay *underlay;

      underlay = &tc->u.underlay;
      underlay->link_array = GNUNET_malloc_large (sizeof (struct UnderlayLink) *
                                                  tc->link_array_size);
    }
    break;
  }
  etab = GNUNET_malloc_large (sizeof (unsigned int) * 2 * tc->link_array_size);
  deg = GNUNET_malloc (sizeof (unsigned int) * tc->num_peers);
  used = GNUNET_malloc (sizeof (unsigned int) * m);
  /* start by connecting peer 1 to peer 0 */
  make_link (0, 0, 1, tc);
  deg[0]++;
  deg[1]++;
  etab[etaboff++] = 0;
  etab[etaboff++] = 1;
  links = 1;
  for (peer = 2; peer < tc->num_peers; peer++)
  {
    if (cap < deg[peer])
      continue;
    for (cnt = 0; cnt < GNUNET_MIN (peer, m); cnt++)
    {
      redo_threshold = 0;
    redo:
      off = GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_WEAK, etaboff);
      random_peer = etab[off];
      if (cap < deg[random_peer])
      {
        if (++redo_threshold > GNUNET_MAX (1, cap / 2))
        {
          redo_threshold = 0;
          off = 0;
          for (cnt2 = 0; cnt2 < etaboff; cnt2++)
          {
            if (random_peer == etab[cnt2])
            {
              off++;
              continue;
            }
            etab[cnt2 - off] = etab[cnt2];
          }
          etaboff -= off;
        }
        goto redo;
      }
      for (cnt2 = 0; cnt2 < cnt; cnt2++)
        if (random_peer == used[cnt2])
          goto redo;
      make_link (links + cnt, random_peer, peer, tc);
      deg[random_peer]++;
      deg[peer]++;
      used[cnt] = random_peer;
    }
    for (cnt = 0; cnt < GNUNET_MIN (peer, m); cnt++)
    {
      etab[etaboff++] = used[cnt];
      etab[etaboff++] = peer;
    }
    links += GNUNET_MIN (peer, m);
  }
  GNUNET_free (etab);
  GNUNET_free (used);
  GNUNET_free (deg);
  GNUNET_assert (links <= tc->link_array_size);
  tc->link_array_size = links;
  switch (tc->type)
  {
  case TOPOLOGYCONTEXT_TYPE_OVERLAY:
    {
      struct TopologyContextOverlay *overlay;
      
      overlay = &tc->u.overlay;
      overlay->link_array = 
          GNUNET_realloc (overlay->link_array, sizeof (struct OverlayLink) * tc->link_array_size);
    }
    break;
  case TOPOLOGYCONTEXT_TYPE_UNDERLAY:
    {
      struct TopologyContextUnderlay *underlay;

      underlay = &tc->u.underlay;
      underlay->link_array =
          GNUNET_realloc (underlay->link_array, sizeof (struct UnderlayLink) * tc->link_array_size);
    }
    break;
  }
}


/**
 * Generates topology from the given file
 *
 * @param tc the topology context
 * @param filename the filename of the file containing topology data
 */
static void
gen_topo_from_file (struct TopologyContext *tc, const char *filename)
{
  char *data;
  char *end;
  char *buf;
  uint64_t fs;
  uint64_t offset;
  unsigned long int peer_id;
  unsigned long int other_peer_id;
  enum ParseState
  {

    /**
     * We read the peer index
     */
    PEER_INDEX,

    /**
     * We read the other peer indices
     */
    OTHER_PEER_INDEX,

  } state;
  int status;

  status = GNUNET_SYSERR;
  if (GNUNET_YES != GNUNET_DISK_file_test (filename))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR, _("Topology file %s not found\n"), filename);
    return;
  }
  if (GNUNET_OK !=
      GNUNET_DISK_file_size (filename, &fs, GNUNET_YES, GNUNET_YES))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR, _("Topology file %s has no data\n"),
         filename);
    return;
  }
  data = GNUNET_malloc (fs);
  if (fs != GNUNET_DISK_fn_read (filename, data, fs))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR, _("Topology file %s cannot be read\n"),
         filename);
    goto _exit;
  }

  offset = 0;
  peer_id = 0;
  state = PEER_INDEX;
  while (offset < fs)
  {
    if (0 != isspace (data[offset]))
    {
      offset++;
      continue;
    }
    switch (state)
    {
    case PEER_INDEX:
      buf = strchr (&data[offset], ':');
      if (NULL == buf)
      {
        LOG (GNUNET_ERROR_TYPE_ERROR,
             _("Failed to read peer index from toology file: %s"), filename);
        goto _exit;
      }
      *buf = '\0';
      errno = 0;
      peer_id = (unsigned int) strtoul (&data[offset], &end, 10);
      if (0 != errno)
      {
        LOG (GNUNET_ERROR_TYPE_ERROR,
             _("Value in given topology file: %s out of range\n"), filename);
        goto _exit;
      }
      if (&data[offset] == end)
      {
        LOG (GNUNET_ERROR_TYPE_ERROR,
             _("Failed to read peer index from topology file: %s"), filename);
        goto _exit;
      }
      if (tc->num_peers <= peer_id)
      {
        LOG (GNUNET_ERROR_TYPE_ERROR,
             _("Topology file needs more peers than given ones\n"), filename);
        goto _exit;
      }
      state = OTHER_PEER_INDEX;
      offset += ((unsigned int) (buf - &data[offset])) + 1;
      break;
    case OTHER_PEER_INDEX:
      errno = 0;
      other_peer_id = (unsigned int) strtoul (&data[offset], &end, 10);
      if (0 != errno)
      {
        LOG (GNUNET_ERROR_TYPE_ERROR,
             _("Value in given topology file: %s out of range\n"), filename);
        goto _exit;
      }
      if (&data[offset] == end)
      {
        LOG (GNUNET_ERROR_TYPE_ERROR,
             _("Failed to read peer index from topology file: %s"), filename);
        goto _exit;
      }
      if (tc->num_peers <= other_peer_id)
      {
        LOG (GNUNET_ERROR_TYPE_ERROR,
             _("Topology file needs more peers than given ones\n"), filename);
        goto _exit;
      }
      if (peer_id != other_peer_id)
      {
        tc->link_array_size++;
        switch (tc->type)
        {
        case TOPOLOGYCONTEXT_TYPE_OVERLAY:
          {
            struct TopologyContextOverlay *overlay;
            
            overlay = &tc->u.overlay;
            overlay->link_array = 
                GNUNET_realloc (overlay->link_array,
                                sizeof (struct OverlayLink) * tc->link_array_size);
          }
          break;
        case TOPOLOGYCONTEXT_TYPE_UNDERLAY:
          {
            struct TopologyContextUnderlay *underlay;
            
            underlay = &tc->u.underlay;
            underlay->link_array =
                GNUNET_realloc (underlay->link_array,
                                sizeof (struct UnderlayLink) * tc->link_array_size);
          }
          break;
        }
        offset += end - &data[offset];
        make_link (tc->link_array_size - 1, peer_id, other_peer_id, tc);
      }
      else
        LOG (GNUNET_ERROR_TYPE_WARNING,
             _("Ignoring to connect peer %u to peer %u\n"), peer_id,
             other_peer_id);
      while (('\n' != data[offset]) && ('|' != data[offset]) && (offset < fs))
        offset++;
      if ('\n' == data[offset])
        state = PEER_INDEX;
      else if ('|' == data[offset])
      {
        state = OTHER_PEER_INDEX;
        offset++;
      }
      break;
    }
  }
  status = GNUNET_OK;

_exit:
  GNUNET_free (data);
  if (GNUNET_OK != status)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING, "Removing link data read from the file\n");
    tc->link_array_size = 0;
    switch (tc->type)
    {
    case TOPOLOGYCONTEXT_TYPE_OVERLAY:
      {
        struct TopologyContextOverlay *overlay;
        
        overlay = &tc->u.overlay;
        GNUNET_free_non_null (overlay->link_array);
        overlay->link_array = NULL;
      }
      break;
    case TOPOLOGYCONTEXT_TYPE_UNDERLAY:
      {
        struct TopologyContextUnderlay *underlay;
        
        underlay = &tc->u.underlay;
        GNUNET_free_non_null (underlay->link_array);
        underlay->link_array = NULL;
      }
      break;
    }
  }
}


/**
 * Generates clique topology
 *
 * @param tc the topology context
 */
static void
gen_topo_clique (struct TopologyContext *tc)
{
  unsigned int cnt;
  unsigned int offset;
  unsigned int neighbour;
  
  tc->link_array_size = tc->num_peers * (tc->num_peers - 1);
  switch (tc->type)
  {
  case TOPOLOGYCONTEXT_TYPE_OVERLAY:
    {
      struct TopologyContextOverlay *overlay;

      overlay = &tc->u.overlay;
      overlay->link_array = GNUNET_malloc (sizeof (struct OverlayLink) *
                                           tc->link_array_size);
    }
    break;
  case TOPOLOGYCONTEXT_TYPE_UNDERLAY:
    {
      struct TopologyContextUnderlay *underlay;

      underlay = &tc->u.underlay;
      underlay->link_array = GNUNET_malloc (sizeof (struct UnderlayLink) *
                                            tc->link_array_size);
    }
  }
  offset = 0;
  for (cnt = 0; cnt < tc->num_peers; cnt++)
  {
    for (neighbour = 0; neighbour < tc->num_peers; neighbour++)
    {
      if (neighbour == cnt)
        continue;
      make_link (offset, cnt, neighbour, tc);
      offset++;
    }
  }
}


/**
 * Configure overall network topology to have a particular shape.
 *
 * @param op_cls closure argument to give with the operation event
 * @param num_peers number of peers in 'peers'
 * @param peers array of 'num_peers' with the peers to configure
 * @param topo desired underlay topology to use
 * @param ap topology-specific options
 * @return handle to the operation, NULL if configuring the topology
 *         is not allowed at this time
 */
struct GNUNET_TESTBED_Operation *
GNUNET_TESTBED_underlay_configure_topology_va (void *op_cls,
                                               unsigned int num_peers,
                                               struct GNUNET_TESTBED_Peer
                                               **peers,
                                               enum
                                               GNUNET_TESTBED_TopologyOption
                                               topo, va_list ap)
{
  GNUNET_break (0);
  return NULL;
}


/**
 * Configure overall network topology to have a particular shape.
 *
 * @param op_cls closure argument to give with the operation event
 * @param num_peers number of peers in 'peers'
 * @param peers array of 'num_peers' with the peers to configure
 * @param topo desired underlay topology to use
 * @param ... topology-specific options
 * @return handle to the operation, NULL if configuring the topology
 *         is not allowed at this time
 */
struct GNUNET_TESTBED_Operation *
GNUNET_TESTBED_underlay_configure_topology (void *op_cls,
                                            unsigned int num_peers,
                                            struct GNUNET_TESTBED_Peer **peers,
                                            enum GNUNET_TESTBED_TopologyOption
                                            topo, ...)
{
  GNUNET_break (0);
  return NULL;
}


/**
 * All peers must have been started before calling this function.
 * This function then connects the given peers in the P2P overlay
 * using the given topology.
 *
 * @param op_cls closure argument to give with the peer connect operation events
 *          generated through this function
 * @param num_peers number of peers in 'peers'
 * @param peers array of 'num_peers' with the peers to configure
 * @param max_connections the maximums number of overlay connections that will
 *          be made to achieve the given topology
 * @param comp_cb the completion callback to call when the topology generation
 *          is completed
 * @param comp_cb_cls closure for the above completion callback
 * @param topo desired underlay topology to use
 * @param va topology-specific options
 * @return handle to the operation, NULL if connecting these
 *         peers is fundamentally not possible at this time (peers
 *         not running or underlay disallows) or if num_peers is less than 2
 */
struct GNUNET_TESTBED_Operation *
GNUNET_TESTBED_overlay_configure_topology_va (void *op_cls,
                                              unsigned int num_peers,
                                              struct GNUNET_TESTBED_Peer **peers,
                                              unsigned int *max_connections,
                                              GNUNET_TESTBED_TopologyCompletionCallback
                                              comp_cb,
                                              void *comp_cb_cls,
                                              enum GNUNET_TESTBED_TopologyOption topo,
                                              va_list va)
{
  struct TopologyContext *tc;
  struct TopologyContextOverlay *overlay;
  struct GNUNET_TESTBED_Operation *op;
  struct GNUNET_TESTBED_Controller *c;
  enum GNUNET_TESTBED_TopologyOption secondary_option;

  if (num_peers < 2)
    return NULL;
  c = peers[0]->controller;
  tc = GNUNET_new (struct TopologyContext);
  tc->type = TOPOLOGYCONTEXT_TYPE_OVERLAY;
  overlay = &tc->u.overlay;
  overlay->peers = peers;
  tc->num_peers = num_peers;
  overlay->op_cls = op_cls;
  overlay->retry_cnt = DEFAULT_RETRY_CNT;
  overlay->comp_cb = comp_cb;
  overlay->comp_cb_cls = comp_cb_cls;
  switch (topo)
  {
  case GNUNET_TESTBED_TOPOLOGY_LINE:
    gen_topo_line (tc);
    break;
  case GNUNET_TESTBED_TOPOLOGY_RING:
    gen_topo_ring (tc);
    break;
  case GNUNET_TESTBED_TOPOLOGY_ERDOS_RENYI:
    gen_topo_random (tc, va_arg (va, unsigned int), GNUNET_NO);
    break;
  case GNUNET_TESTBED_TOPOLOGY_SMALL_WORLD_RING:
    gen_topo_ring (tc);
    gen_topo_random (tc, va_arg (va, unsigned int), GNUNET_YES);
    break;
  case GNUNET_TESTBED_TOPOLOGY_CLIQUE:
    gen_topo_clique (tc);
    break;
  case GNUNET_TESTBED_TOPOLOGY_2D_TORUS:
    gen_topo_2dtorus (tc);
    break;
  case GNUNET_TESTBED_TOPOLOGY_SMALL_WORLD:
    gen_topo_2dtorus (tc);
    gen_topo_random (tc, va_arg (va, unsigned int), GNUNET_YES);

    break;
  case GNUNET_TESTBED_TOPOLOGY_SCALE_FREE:
    {
      uint16_t cap;
      uint8_t m;

      cap = (uint16_t) va_arg (va, unsigned int);
      m = (uint8_t) va_arg (va, unsigned int);
      gen_topo_scale_free (tc, cap, m);
    }
    break;
  case GNUNET_TESTBED_TOPOLOGY_FROM_FILE:
  {
    const char *filename;

    filename = va_arg (va, const char *);

    GNUNET_assert (NULL != filename);
    gen_topo_from_file (tc, filename);
  }
    break;
  default:
    GNUNET_break (0);
    GNUNET_free (tc);
    return NULL;
  }
  do
  {
    secondary_option = va_arg (va, enum GNUNET_TESTBED_TopologyOption);

    switch (secondary_option)
    {
    case GNUNET_TESTBED_TOPOLOGY_RETRY_CNT:
      overlay->retry_cnt =  va_arg (va, unsigned int);
      break;
    case GNUNET_TESTBED_TOPOLOGY_OPTION_END:
      break;
    default:
      GNUNET_break (0);         /* Should not use any other option apart from
                                 * the ones handled here */
      GNUNET_free_non_null (overlay->link_array);
      GNUNET_free (tc);
      return NULL;
    }
  }
  while (GNUNET_TESTBED_TOPOLOGY_OPTION_END != secondary_option);
  op = GNUNET_TESTBED_operation_create_ (tc,
                                         &opstart_overlay_configure_topology,
                                         &oprelease_overlay_configure_topology);
  GNUNET_TESTBED_operation_queue_insert_
      (c->opq_parallel_topology_config_operations, op);
  GNUNET_TESTBED_operation_begin_wait_ (op);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Generated %u connections\n",
       tc->link_array_size);
  if (NULL != max_connections)
    *max_connections = tc->link_array_size;
  return op;
}


/**
 * All peers must have been started before calling this function.
 * This function then connects the given peers in the P2P overlay
 * using the given topology.
 *
 * @param op_cls closure argument to give with the peer connect operation events
 *          generated through this function
 * @param num_peers number of peers in 'peers'
 * @param peers array of 'num_peers' with the peers to configure
 * @param max_connections the maximums number of overlay connections that will
 *          be made to achieve the given topology
 * @param comp_cb the completion callback to call when the topology generation
 *          is completed
 * @param comp_cb_cls closure for the above completion callback
 * @param topo desired underlay topology to use
 * @param ... topology-specific options
 * @return handle to the operation, NULL if connecting these
 *         peers is fundamentally not possible at this time (peers
 *         not running or underlay disallows) or if num_peers is less than 2
 */
struct GNUNET_TESTBED_Operation *
GNUNET_TESTBED_overlay_configure_topology (void *op_cls,
                                           unsigned int num_peers,
                                           struct GNUNET_TESTBED_Peer **peers,
                                           unsigned int *max_connections,
                                           GNUNET_TESTBED_TopologyCompletionCallback
                                           comp_cb,
                                           void *comp_cb_cls,
                                           enum GNUNET_TESTBED_TopologyOption topo,
                                           ...)
{
  struct GNUNET_TESTBED_Operation *op;
  va_list vargs;

  GNUNET_assert (topo < GNUNET_TESTBED_TOPOLOGY_OPTION_END);
  va_start (vargs, topo);
  op = GNUNET_TESTBED_overlay_configure_topology_va (op_cls, num_peers, peers,
                                                     max_connections,
                                                     comp_cb, comp_cb_cls,
                                                     topo,
                                                     vargs);
  va_end (vargs);
  return op;
}


/**
 * Get a topology from a string input.
 *
 * @param topology where to write the retrieved topology
 * @param topology_string The string to attempt to
 *        get a configuration value from
 * @return GNUNET_YES if topology string matched a
 *         known topology, GNUNET_NO if not
 */
int
GNUNET_TESTBED_topology_get_ (enum GNUNET_TESTBED_TopologyOption *topology,
                              const char *topology_string)
{
  unsigned int cnt;

  for (cnt = 0; NULL != topology_strings[cnt]; cnt++)
  {
    if (0 == strcasecmp (topology_string, topology_strings[cnt]))
    {
      if (NULL != topology)
        *topology = (enum GNUNET_TESTBED_TopologyOption) cnt;
      return GNUNET_YES;
    }
  }
  return GNUNET_NO;
}


/**
 * Returns the string corresponding to the given topology
 *
 * @param topology the topology
 * @return the string (freshly allocated) of given topology; NULL if topology cannot be
 *           expressed as a string
 */
char *
GNUNET_TESTBED_topology_to_str_ (enum GNUNET_TESTBED_TopologyOption topology)
{
  if (GNUNET_TESTBED_TOPOLOGY_OPTION_END <= topology)
    return NULL;
  return GNUNET_strdup (topology_strings[topology]);
}


/**
 * Function to construct an underlay topology
 *
 * @param num_peers the number of peers for which the topology should be
 *          generated
 * @param proc the underlay link processor callback.  Will be called for each
 *          underlay link generated unless a previous call to this callback
 *          returned GNUNET_SYSERR.  Cannot be NULL.
 * @param cls closure for proc
 * @param ... variable arguments denoting the topology and its parameters.  They
 *          should start with the type of topology to generate followed by their
 *          options.
 * @return GNUNET_OK if underlay link generation is successful; GNUNET_SYSERR
 *          upon error in generating the underlay or if any calls to the
 *          underlay link processor returned GNUNET_SYSERR
 */
int
GNUNET_TESTBED_underlay_construct_ (int num_peers,
                                    underlay_link_processor proc,
                                    void *cls,
                                    ...)
{
  struct TopologyContext tc;
  struct TopologyContextUnderlay *underlay;
  struct UnderlayLink *ulink;
  va_list vargs;
  enum GNUNET_TESTBED_TopologyOption topology;
  unsigned int cnt;
  int ret;
  
  GNUNET_assert (NULL != proc);
  ret = GNUNET_OK;
  memset (&tc, 0, sizeof (tc));
  tc.num_peers = num_peers;
  tc.type = TOPOLOGYCONTEXT_TYPE_UNDERLAY;
  underlay = &tc.u.underlay;
  va_start (vargs, cls);
  topology = va_arg (vargs, enum GNUNET_TESTBED_TopologyOption);
  switch (topology)
  {
  case GNUNET_TESTBED_TOPOLOGY_LINE:
    gen_topo_line (&tc);
    break;
  case GNUNET_TESTBED_TOPOLOGY_RING:
    gen_topo_ring (&tc);
    break;
  case GNUNET_TESTBED_TOPOLOGY_CLIQUE:
    gen_topo_clique (&tc);
    break;
  case GNUNET_TESTBED_TOPOLOGY_2D_TORUS:
    gen_topo_2dtorus (&tc);
    break;
  case GNUNET_TESTBED_TOPOLOGY_ERDOS_RENYI:
    gen_topo_random (&tc, va_arg (vargs, unsigned int), GNUNET_NO);
    break;
  case GNUNET_TESTBED_TOPOLOGY_SMALL_WORLD_RING:
    gen_topo_ring (&tc);
    gen_topo_random (&tc, va_arg (vargs, unsigned int), GNUNET_YES);
    break;
  case GNUNET_TESTBED_TOPOLOGY_SMALL_WORLD:
    gen_topo_2dtorus (&tc);
    gen_topo_random (&tc, va_arg (vargs, unsigned int), GNUNET_YES);
    break;
  case GNUNET_TESTBED_TOPOLOGY_FROM_FILE:
    {
      const char *filename;
      filename = va_arg (vargs, char *);
      GNUNET_assert (NULL != filename);
      gen_topo_from_file (&tc, filename);
    }
    break;
  case GNUNET_TESTBED_TOPOLOGY_SCALE_FREE:
    {
      uint16_t cap;
      uint8_t m;
      cap = (uint16_t) va_arg (vargs, unsigned int);
      m = (uint8_t) va_arg (vargs, unsigned int);
      gen_topo_scale_free (&tc, cap, m);
    }
    break;
  default:
    GNUNET_assert (0);
  }
  va_end (vargs);
  for (cnt = 0; cnt < tc.link_array_size; cnt++)
  {
    ulink = &underlay->link_array[cnt];
    if (GNUNET_SYSERR == proc (cls,
                               ulink->A,
                               ulink->B,
                               ulink->bandwidth,
                               ulink->latency,
                               ulink->loss))
    {
      ret = GNUNET_SYSERR;
      break;
    }
  }
  GNUNET_free_non_null (underlay->link_array);
  return ret;
}

/* end of testbed_api_topology.c */
