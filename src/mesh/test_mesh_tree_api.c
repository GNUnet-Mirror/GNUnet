/*
     This file is part of GNUnet.
     (C) 2011 Christian Grothoff (and other contributing authors)

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
 * @file mesh/test_mesh_tree_api.c
 * @brief test mesh tree api: test of tree & path management api
 * @author Bartlomiej Polot
 */

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_util_lib.h"
#include "gnunet_dht_service.h"
#include "gnunet_mesh_service.h"
#include "mesh.h"
#ifndef MESH_TUNNEL_TREE_C
#include "mesh_tunnel_tree.c"
#define MESH_TUNNEL_TREE_C
#endif

#define VERBOSE 1

int failed;
int cb_call;
struct GNUNET_PeerIdentity *pi[10];
struct MeshTunnelTree *tree;

static void
cb (void *cls, GNUNET_PEER_Id peer_id)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test: CB: Disconnected %u\n", peer_id);
  if (0 == cb_call)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test:      and it shouldn't!\n");
    failed++;
  }
  cb_call--;
}


/**
 * Check if a node has all expected properties.
 *
 * @param peer_id Short ID of the peer to test.
 * @param status Expected status of the peer.
 * @param children Expected number of children of the peer.
 * @param first_hop Short ID of the expected first hop towards the peer.
 */
static void
test_assert (GNUNET_PEER_Id peer_id, enum MeshPeerState status,
             unsigned int children, GNUNET_PEER_Id first_hop)
{
  struct MeshTunnelTreeNode *n;
  struct MeshTunnelTreeNode *c;
  unsigned int i;
  int pre_failed;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test: Checking peer %u\n", peer_id);
  pre_failed = failed;
  n = tree_find_peer (tree, peer_id);
  if (n->peer != peer_id)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Retrieved peer has wrong ID! (Got %u, expected %u)\n", n->peer,
                peer_id);
    failed++;
  }
  if (n->status != status)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Retrieved peer has wrong status! (Got %u, expected %u)\n",
                n->status, status);
    failed++;
  }
  for (c = n->children_head, i = 0; NULL != c; c = c->next, i++) ;
  if (i != children)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Retrieved peer wrong has number of children! (Got %u, expected %u)\n",
                i, children);
    failed++;
  }
  if (0 != first_hop &&
      GNUNET_PEER_search (tree_get_first_hop (tree, peer_id)) != first_hop)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Wrong first hop! (Got %u, expected %u)\n",
                GNUNET_PEER_search (tree_get_first_hop (tree, peer_id)),
                first_hop);
    failed++;
  }
  if (pre_failed != failed)
  {
    struct GNUNET_PeerIdentity id;

    GNUNET_PEER_resolve (peer_id, &id);
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "*** Peer %s (%u) has failed %d checks!\n", GNUNET_i2s (&id),
                peer_id, failed - pre_failed);
  }
}


static void
finish (void)
{
  unsigned int i;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test: Finishing...\n");
  for (i = 0; i < 10; i++)
  {
    GNUNET_free (pi[i]);
  }
}

/**
 * Convert an integer int to a peer identity
 */
static struct GNUNET_PeerIdentity *
get_pi (uint32_t id)
{
  struct GNUNET_PeerIdentity *pi;

  pi = GNUNET_malloc (sizeof (struct GNUNET_PeerIdentity));
  pi->hashPubKey.bits[0] = id + 1;
  return pi;
}


int
main (int argc, char *argv[])
{
  struct MeshTunnelTreeNode *node;
  struct MeshPeerPath *path;
  struct MeshPeerPath *path1;
  unsigned int i;

  failed = 0;
  cb_call = 0;
  GNUNET_log_setup ("test_mesh_api_tree",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);
  for (i = 0; i < 10; i++)
  {
    pi[i] = get_pi (i);
    GNUNET_break (i + 1 == GNUNET_PEER_intern (pi[i]));
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Peer %u: %s\n", i + 1,
                GNUNET_h2s (&pi[i]->hashPubKey));
  }
  tree = tree_new (1);
  tree->me = tree->root;
  path = path_new (5);
  path->peers[0] = 1;
  path->peers[1] = 2;
  path->peers[2] = 3;
  path->peers[3] = 4;
  path->length = 4;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test: Adding first path: 1 2 3 4\n");
  tree_add_path (tree, path, &cb, NULL);
  tree_debug (tree);
  path1 = tree_get_path_to_peer (tree, 4);
  if (NULL == path1 || path->length != path1->length ||
      memcmp (path->peers, path1->peers, path->length) != 0)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Retrieved path != original\n");
    failed++;
  }
  path_destroy (path1);
  test_assert (4, MESH_PEER_SEARCHING, 0, 2);
  test_assert (3, MESH_PEER_RELAY, 1, 0);
  test_assert (2, MESH_PEER_RELAY, 1, 0);
  test_assert (1, MESH_PEER_ROOT, 1, 0);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test: Adding second path: 1 2 3\n");
  path->length--;
  tree_add_path (tree, path, &cb, NULL);
  tree_debug (tree);

  test_assert (4, MESH_PEER_SEARCHING, 0, 2);
  test_assert (3, MESH_PEER_SEARCHING, 1, 2);
  test_assert (2, MESH_PEER_RELAY, 1, 0);
  test_assert (1, MESH_PEER_ROOT, 1, 0);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test: Adding third path 1 2 3 5\n");
  path->length++;
  path->peers[3] = 5;
  tree_add_path (tree, path, &cb, NULL);
  tree_debug (tree);

  test_assert (5, MESH_PEER_SEARCHING, 0, 2);
  test_assert (4, MESH_PEER_SEARCHING, 0, 2);
  test_assert (3, MESH_PEER_SEARCHING, 2, 2);
  test_assert (2, MESH_PEER_RELAY, 1, 0);
  test_assert (1, MESH_PEER_ROOT, 1, 0);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test: Calculating costs...\n");
  for (i = 1; i < 5; i++)
  {
    path->length = i;
    if (tree_get_path_cost (tree, path) != 0)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "test: length %u cost failed!\n",
                  i);
      failed++;
    }
  }
  path->length++;
  path->peers[4] = 6;
  if (tree_get_path_cost (tree, path) != 1)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "test: length %u cost failed!\n", i);
    failed++;
  }
  path->peers[3] = 7;
  if (tree_get_path_cost (tree, path) != 2)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "test: length %u cost failed!\n", i);
    failed++;
  }
  path->length--;
  if (tree_get_path_cost (tree, path) != 1)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "test: length %u cost failed!\n", i);
    failed++;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test: Deleting third path (5)\n");
  tree_set_status (tree, 5, MESH_PEER_READY);
  cb_call = 1;
  node = tree_del_path (tree, 5, &cb, NULL);
  tree_debug (tree);
  if (cb_call != 0)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "%u callbacks missed!\n", cb_call);
    failed++;
  }
  if (node->peer != 5)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Retrieved peer != original\n");
    failed++;
  }

  test_assert (4, MESH_PEER_SEARCHING, 0, 2);
  test_assert (3, MESH_PEER_SEARCHING, 1, 2);
  test_assert (2, MESH_PEER_RELAY, 1, 0);
  test_assert (1, MESH_PEER_ROOT, 1, 0);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test: Destroying node copy...\n");
  GNUNET_free (node);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "test: Adding new shorter first path...\n");
  path->length = 2;
  path->peers[1] = 4;
  cb_call = 1;
  tree_find_peer (tree, 4)->status = MESH_PEER_READY;
  tree_add_path (tree, path, &cb, NULL);
  tree_debug (tree);
  if (cb_call != 0)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "%u callbacks missed!\n", cb_call);
    failed++;
  }

  test_assert (4, MESH_PEER_SEARCHING, 0, 4);
  test_assert (3, MESH_PEER_SEARCHING, 0, 2);
  test_assert (2, MESH_PEER_RELAY, 1, 0);
  test_assert (1, MESH_PEER_ROOT, 2, 0);

  GNUNET_free (path->peers);
  GNUNET_free (path);
  tree_destroy (tree);

  /****************************************************************************/

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test:\n");
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test: Testing relay trees\n");
  for (i = 0; i < 10; i++)
  {
    GNUNET_break (i + 1 == GNUNET_PEER_intern (pi[i]));
  }
  tree = tree_new (2);
  path = path_new (8);
  path->peers[0] = 2;
  path->peers[1] = 1;
  path->peers[2] = 3;
  path->length = 3;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test: Adding first path: 2 1 3\n");
  tree_add_path (tree, path, &cb, NULL);
  tree_debug (tree);

  test_assert (3, MESH_PEER_SEARCHING, 0, 3);
  test_assert (1, MESH_PEER_RELAY, 1, 0);
  test_assert (2, MESH_PEER_ROOT, 1, 0);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test: Adding long path: 2 1 4 5 3\n");
  path->peers[2] = 4;
  path->peers[3] = 5;
  path->peers[4] = 3;
  path->length = 5;
  tree_add_path (tree, path, &cb, NULL);
  tree_debug (tree);

  test_assert (3, MESH_PEER_SEARCHING, 0, 4);
  test_assert (5, MESH_PEER_RELAY, 1, 4);
  test_assert (4, MESH_PEER_RELAY, 1, 4);
  test_assert (1, MESH_PEER_RELAY, 1, 0);
  test_assert (2, MESH_PEER_ROOT, 1, 0);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "test: Even longer path: 2 6 1 7 8 4 5 3\n");
  path->peers[0] = 2;
  path->peers[1] = 6;
  path->peers[2] = 1;
  path->peers[3] = 7;
  path->peers[4] = 8;
  path->peers[5] = 4;
  path->peers[6] = 5;
  path->peers[7] = 3;
  path->length = 8;
  tree_add_path (tree, path, &cb, NULL);
  tree_debug (tree);

  test_assert (3, MESH_PEER_SEARCHING, 0, 7);
  test_assert (5, MESH_PEER_RELAY, 1, 7);
  test_assert (4, MESH_PEER_RELAY, 1, 7);
  test_assert (8, MESH_PEER_RELAY, 1, 7);
  test_assert (7, MESH_PEER_RELAY, 1, 7);
  test_assert (1, MESH_PEER_RELAY, 1, 0);
  test_assert (6, MESH_PEER_RELAY, 1, 0);
  test_assert (2, MESH_PEER_ROOT, 1, 0);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test: Adding first path: 2 1 3\n");
  path->peers[1] = 1;
  path->peers[2] = 3;
  path->length = 3;
  tree_add_path (tree, path, &cb, NULL);
  tree_debug (tree);

  test_assert (3, MESH_PEER_SEARCHING, 0, 3);
  test_assert (1, MESH_PEER_RELAY, 1, 0);
  test_assert (2, MESH_PEER_ROOT, 1, 0);

  GNUNET_free (path->peers);
  GNUNET_free (path);
  tree_destroy (tree);
  finish ();
  if (failed > 0)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "%u tests failed\n", failed);
    return 1;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test: OK\n");

  return 0;
}
