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
 * @file mesh/test_mesh_path.c
 * @brief test mesh path: test of path management api
 * @author Bartlomiej Polot
 */

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_util_lib.h"
#include "gnunet_dht_service.h"
#include "gnunet_mesh_service_new.h"
#include "mesh.h"
#include "mesh_tunnel_tree.h"

#define VERBOSE 1

int failed;
int cb_call;
struct GNUNET_PeerIdentity* pi[10];
struct MeshTunnelTree *tree;

void
cb (const struct MeshTunnelTreeNode *n)
{
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "test: Desconnected %u\n", n->peer);
  if(0 == cb_call)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "test:    and it shouldn't!\n");
    failed++;
  }
  cb_call--;
}


void
finish(void)
{
  unsigned int i;

  for (i = 0; i < 10; i++)
  {
    GNUNET_free(pi[i]);
  }
  tree_destroy(tree);
  exit(0);
}

/**
 * Convert an integer int to a peer identity
 */
static struct GNUNET_PeerIdentity *
get_pi (uint32_t id)
{
  struct GNUNET_PeerIdentity *pi;

  pi = GNUNET_malloc(sizeof(struct GNUNET_PeerIdentity));
  pi->hashPubKey.bits[0] = id;
  return pi;
}


int
main (int argc, char *argv[])
{
  struct MeshTunnelTreeNode *node;
  struct MeshTunnelTreeNode *node2;
  struct MeshPeerPath *path[10];
  unsigned int i;

  failed = 0;
  cb_call = 0;
  GNUNET_log_setup ("test_mesh_api_path",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);
  for (i = 0; i < 10; i++)
  {
      pi[i] = get_pi(i);
      GNUNET_break (i != GNUNET_PEER_intern(pi[i]));
      GNUNET_log(GNUNET_ERROR_TYPE_INFO, "Peer %u: %s\n", i,
                 GNUNET_h2s(&pi[i]->hashPubKey));
  }
  tree = GNUNET_malloc(sizeof(struct MeshTunnelTree));
  tree->first_hops = GNUNET_CONTAINER_multihashmap_create(32);
  tree->root = GNUNET_malloc(sizeof(struct MeshTunnelTreeNode));
  tree->root->peer = 0;
  tree->me = tree->root;
  path[0] = GNUNET_malloc(sizeof(struct MeshPeerPath));
  path[0]->peers = GNUNET_malloc(sizeof(GNUNET_PEER_Id) * 4);
  path[0]->peers[0] = 0;
  path[0]->peers[1] = 1;
  path[0]->peers[2] = 2;
  path[0]->peers[3] = 3;
  path[0]->length = 4;

  finish();
  tree_add_path(tree, path[0], &cb);
  path[1] = tree_get_path_to_peer(tree, 3);
  if (path[0]->length != path[1]->length ||
      memcmp(path[0]->peers, path[1]->peers, path[0]->length) != 0)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Retrieved path != original\n");
    failed++;
  }
  path_destroy(path[1]);
  node = tree_find_peer(tree->root, 3);
  if (node->peer != 3)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Retrieved peer != original\n");
    failed++;
  }
  if (node->status != MESH_PEER_SEARCHING)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Retrieved peer wrong status!\n");
    failed++;
  }
  node->status = MESH_PEER_READY;
  if (GNUNET_PEER_search(path_get_first_hop(tree, 3)) != 1)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Wrong first hop!\n");
    failed++;
  }
  return 0;

  node = tree_find_peer(tree->root, 2);
  if (node->peer != 2)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Retrieved peer != original\n");
    failed++;
  }
  if (node->status != MESH_PEER_RELAY)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Retrieved peer wrong status!\n");
    failed++;
  }
  if (node->nchildren != 1)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Retrieved peer wrong nchildren!\n");
    failed++;
  }
  if (GNUNET_PEER_search(path_get_first_hop(tree, 3)) != 1)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Wrong first hop!\n");
    failed++;
  }

  node = tree_find_peer(tree->root, 1);
  if (node->peer != 1)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Retrieved peer != original\n");
    failed++;
  }
  if (node->status != MESH_PEER_RELAY)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Retrieved peer wrong status!\n");
    failed++;
  }
  if (node->nchildren != 1)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Retrieved peer wrong nchildren!\n");
    failed++;
  }

  path[0]->length--;
  tree_add_path(tree, path[0], &cb);

  node = tree_find_peer(tree->root, 2);
  if (node->peer != 2)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Retrieved peer != original\n");
    failed++;
  }
  if (node->status != MESH_PEER_SEARCHING)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Retrieved peer wrong status!\n");
    failed++;
  }
  if (node->nchildren != 1)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Retrieved peer wrong nchildren!\n");
    failed++;
  }
  if (GNUNET_PEER_search(path_get_first_hop(tree, 3)) != 1)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Wrong first hop!\n");
    failed++;
  }
  if (GNUNET_PEER_search(path_get_first_hop(tree, 2)) != 1)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Wrong first hop!\n");
    failed++;
  }

  node = tree_find_peer(tree->root, 1);
  if (node->peer != 1)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Retrieved peer != original\n");
    failed++;
  }
  if (node->status != MESH_PEER_RELAY)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Retrieved peer wrong status!\n");
    failed++;
  }
  if (node->nchildren != 1)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Retrieved peer wrong nchildren!\n");
    failed++;
  }

  path[0]->length++;
  path[0]->peers[3] = 4;
  tree_add_path(tree, path[0], &cb);

  node = tree_find_peer(tree->root, 2);
  if (node->peer != 2)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Retrieved peer != original\n");
    failed++;
  }
  if (node->status != MESH_PEER_SEARCHING)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Retrieved peer wrong status!\n");
    failed++;
  }
  if (node->nchildren != 2)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Retrieved peer wrong nchildren!\n");
    failed++;
  }
  if (GNUNET_PEER_search(path_get_first_hop(tree, 3)) != 1)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Wrong first hop!\n");
    failed++;
  }
  if (GNUNET_PEER_search(path_get_first_hop(tree, 4)) != 1)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Wrong first hop!\n");
    failed++;
  }

  node = tree_find_peer(tree->root, 1);
  if (node->peer != 1)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Retrieved peer != original\n");
    failed++;
  }
  if (node->status != MESH_PEER_RELAY)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Retrieved peer wrong status!\n");
    failed++;
  }
  if (node->nchildren != 1)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Retrieved peer wrong nchildren!\n");
    failed++;
  }

  node = tree_find_peer(tree->root, 4);
  if (node->peer != 4)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Retrieved peer != original\n");
    failed++;
  }
  node->status = MESH_PEER_READY;
  cb_call = 1;
  node2 = tree_del_path(tree, 4, &cb);
  if (cb_call != 0)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "%u callbacks missed!\n", cb_call);
    failed++;
  }
  if (node2->peer != 4)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Retrieved peer != original\n");
    failed++;
  }
//   GNUNET_free(node2); FIXME destroy
  node = tree_find_peer(tree->root, 2);
  if (node->peer != 2)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Retrieved peer != original\n");
    failed++;
  }
  if (node->status != MESH_PEER_SEARCHING)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Retrieved peer wrong status!\n");
    failed++;
  }
  if (node->nchildren != 1)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Retrieved peer wrong nchildren!\n");
    failed++;
  }

  path[0]->length = 2;
  path[0]->peers[1] = 3;
  cb_call = 1;
  tree_add_path(tree, path[0], cb);
  if (cb_call != 0)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "%u callbacks missed!\n", cb_call);
    failed++;
  }
  node = tree_find_peer(tree->root, 2);
  if (node->peer != 2)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Retrieved peer != original\n");
    failed++;
  }
  if (node->status != MESH_PEER_SEARCHING)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Retrieved peer wrong status!\n");
    failed++;
  }
  if (node->nchildren != 0)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Retrieved peer wrong nchildren!\n");
    failed++;
  }
  node = tree_find_peer(tree->root, 3);
  if (node->peer != 3)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Retrieved peer != original\n");
    failed++;
  }
  if (node->status != MESH_PEER_SEARCHING)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Retrieved peer wrong status!\n");
    failed++;
  }
  if (node->nchildren != 0)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Retrieved peer wrong nchildren!\n");
    failed++;
  }
  if (GNUNET_PEER_search(path_get_first_hop(tree, 2)) != 1)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Wrong first hop!\n");
    failed++;
  }
  if (GNUNET_PEER_search(path_get_first_hop(tree, 3)) != 3)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Wrong first hop!\n");
    failed++;
  }


  if (failed > 0)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "%u tests failed\n", failed);
    return 1;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test ok\n");
  return 0;
}
