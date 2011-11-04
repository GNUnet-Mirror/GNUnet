/*
  This file is part of GNUnet.
  (C) 2008, 2009 Christian Grothoff (and other contributing authors)

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
 * @file util/container_heap.c
 * @brief Implementation of a heap
 * @author Nathan Evans
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util_lib.h"

#define LOG(kind,...) GNUNET_log_from (kind, "util", __VA_ARGS__)

#define DEBUG 0

/**
 * Node in the heap.
 */
struct GNUNET_CONTAINER_HeapNode
{
  /**
   * Heap this node belongs to.
   */
  struct GNUNET_CONTAINER_Heap *heap;

  /**
   * Parent node.
   */
  struct GNUNET_CONTAINER_HeapNode *parent;

  /**
   * Left child.
   */
  struct GNUNET_CONTAINER_HeapNode *left_child;

  /**
   * Right child.
   */
  struct GNUNET_CONTAINER_HeapNode *right_child;

  /**
   * Our element.
   */
  void *element;

  /**
   * Cost for this element.
   */
  GNUNET_CONTAINER_HeapCostType cost;

  /**
   * Number of elements below this node in the heap
   * (excluding this node itself).
   */
  unsigned int tree_size;

};

/**
 * Handle to a node in a heap.
 */
struct GNUNET_CONTAINER_Heap
{

  /**
   * Root of the heap.
   */
  struct GNUNET_CONTAINER_HeapNode *root;

  /**
   * Current position of our random walk.
   */
  struct GNUNET_CONTAINER_HeapNode *walk_pos;

  /**
   * Number of elements in the heap.
   */
  unsigned int size;

  /**
   * How is the heap sorted?
   */
  enum GNUNET_CONTAINER_HeapOrder order;

};


#if DEBUG
/**
 * Check if internal invariants hold for the given node.
 *
 * @param node subtree to check
 */
static void
check (const struct GNUNET_CONTAINER_HeapNode *node)
{
  if (NULL == node)
    return;
  GNUNET_assert (node->tree_size ==
                 ((node->left_child ==
                   NULL) ? 0 : 1 + node->left_child->tree_size) +
                 ((node->right_child ==
                   NULL) ? 0 : 1 + node->right_child->tree_size));
  check (node->left_child);
  check (node->right_child);
}


#define CHECK(n) check(n)
#else
#define CHECK(n) do {} while (0)
#endif


/**
 * Create a new heap.
 *
 * @param order how should the heap be sorted?
 * @return handle to the heap
 */
struct GNUNET_CONTAINER_Heap *
GNUNET_CONTAINER_heap_create (enum GNUNET_CONTAINER_HeapOrder order)
{
  struct GNUNET_CONTAINER_Heap *heap;

  heap = GNUNET_malloc (sizeof (struct GNUNET_CONTAINER_Heap));
  heap->order = order;
  return heap;
}


/**
 * Destroys the heap.  Only call on a heap that
 * is already empty.
 *
 * @param heap heap to destroy
 */
void
GNUNET_CONTAINER_heap_destroy (struct GNUNET_CONTAINER_Heap *heap)
{
  GNUNET_break (heap->size == 0);
  GNUNET_free (heap);
}


/**
 * Get element stored at root of heap.
 *
 * @param heap heap to inspect
 * @return NULL if heap is empty
 */
void *
GNUNET_CONTAINER_heap_peek (const struct GNUNET_CONTAINER_Heap *heap)
{
  if (heap->root == NULL)
    return NULL;
  return heap->root->element;
}


/**
 * Get the current size of the heap
 *
 * @param heap the heap to get the size of
 * @return number of elements stored
 */
unsigned int
GNUNET_CONTAINER_heap_get_size (const struct GNUNET_CONTAINER_Heap *heap)
{
  return heap->size;
}


/**
 * Get the current cost of the node
 *
 * @param node the node to get the cost of
 * @return cost of the node
 */
GNUNET_CONTAINER_HeapCostType
GNUNET_CONTAINER_heap_node_get_cost (const struct GNUNET_CONTAINER_HeapNode
                                     *node)
{
  return node->cost;
}

/**
 * Iterate over the children of the given node.
 *
 * @param heap argument to give to iterator
 * @param node node to iterate over
 * @param iterator function to call on each node
 * @param iterator_cls closure for iterator
 * @return GNUNET_YES to continue to iterate
 */
static int
node_iterator (const struct GNUNET_CONTAINER_Heap *heap,
               struct GNUNET_CONTAINER_HeapNode *node,
               GNUNET_CONTAINER_HeapIterator iterator, void *iterator_cls)
{
  if (node == NULL)
    return GNUNET_YES;
  if (GNUNET_YES !=
      node_iterator (heap, node->left_child, iterator, iterator_cls))
    return GNUNET_NO;
  if (GNUNET_YES !=
      node_iterator (heap, node->right_child, iterator, iterator_cls))
    return GNUNET_NO;
  return iterator (iterator_cls, node, node->element, node->cost);
}


/**
 * Iterate over all entries in the heap.
 *
 * @param heap the heap
 * @param iterator function to call on each entry
 * @param iterator_cls closure for iterator
 */
void
GNUNET_CONTAINER_heap_iterate (const struct GNUNET_CONTAINER_Heap *heap,
                               GNUNET_CONTAINER_HeapIterator iterator,
                               void *iterator_cls)
{
  (void) node_iterator (heap, heap->root, iterator, iterator_cls);
}


/**
 * Perform a random walk of the tree.  The walk is biased
 * towards elements closer to the root of the tree (since
 * each walk starts at the root and ends at a random leaf).
 * The heap internally tracks the current position of the
 * walk.
 *
 * @param heap heap to walk
 * @return data stored at the next random node in the walk;
 *         NULL if the tree is empty.
 */
void *
GNUNET_CONTAINER_heap_walk_get_next (struct GNUNET_CONTAINER_Heap *heap)
{
  struct GNUNET_CONTAINER_HeapNode *pos;
  void *element;

  if (heap->root == NULL)
    return NULL;
  pos = heap->walk_pos;
  if (pos == NULL)
    pos = heap->root;
  element = pos->element;
  heap->walk_pos =
      (0 ==
       GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
                                 2)) ? pos->right_child : pos->left_child;
  return element;
}


/**
 * Insert the given node 'node' into the subtree starting
 * at 'pos' (while keeping the tree somewhat balanced).
 *
 * @param heap heap to modify
 * @param pos existing tree
 * @param node node to insert (which may be a subtree itself)
 */
static void
insert_node (struct GNUNET_CONTAINER_Heap *heap,
             struct GNUNET_CONTAINER_HeapNode *pos,
             struct GNUNET_CONTAINER_HeapNode *node)
{
  struct GNUNET_CONTAINER_HeapNode *parent;

  GNUNET_assert (node->parent == NULL);
  while ((heap->order == GNUNET_CONTAINER_HEAP_ORDER_MAX) ? (pos->cost >=
                                                             node->cost)
         : (pos->cost <= node->cost))
  {
    /* node is descendent of pos */
    pos->tree_size += (1 + node->tree_size);
    if (pos->left_child == NULL)
    {
      pos->left_child = node;
      node->parent = pos;
      return;
    }
    if (pos->right_child == NULL)
    {
      pos->right_child = node;
      node->parent = pos;
      return;
    }
    /* keep it balanced by descending into smaller subtree */
    if (pos->left_child->tree_size < pos->right_child->tree_size)
      pos = pos->left_child;
    else
      pos = pos->right_child;
  }
  /* make 'node' parent of 'pos' */
  parent = pos->parent;
  pos->parent = NULL;
  node->parent = parent;
  if (NULL == parent)
  {
    heap->root = node;
  }
  else
  {
    if (parent->left_child == pos)
      parent->left_child = node;
    else
      parent->right_child = node;
  }
  /* insert 'pos' below 'node' */
  insert_node (heap, node, pos);
  CHECK (pos);
}


/**
 * Inserts a new element into the heap.
 *
 * @param heap heap to modify
 * @param element element to insert
 * @param cost cost for the element
 * @return node for the new element
 */
struct GNUNET_CONTAINER_HeapNode *
GNUNET_CONTAINER_heap_insert (struct GNUNET_CONTAINER_Heap *heap, void *element,
                              GNUNET_CONTAINER_HeapCostType cost)
{
  struct GNUNET_CONTAINER_HeapNode *node;

  node = GNUNET_malloc (sizeof (struct GNUNET_CONTAINER_HeapNode));
  node->heap = heap;
  node->element = element;
  node->cost = cost;
  heap->size++;
  if (NULL == heap->root)
    heap->root = node;
  else
    insert_node (heap, heap->root, node);
  GNUNET_assert (heap->size == heap->root->tree_size + 1);
  CHECK (heap->root);
  return node;
}


/**
 * Remove root of the heap.
 *
 * @param heap heap to modify
 * @return element data stored at the root node, NULL if heap is empty
 */
void *
GNUNET_CONTAINER_heap_remove_root (struct GNUNET_CONTAINER_Heap *heap)
{
  void *ret;
  struct GNUNET_CONTAINER_HeapNode *root;

  if (NULL == (root = heap->root))
    return NULL;
  heap->size--;
  ret = root->element;
  if (root->left_child == NULL)
  {
    heap->root = root->right_child;
    if (root->right_child != NULL)
      root->right_child->parent = NULL;
  }
  else if (root->right_child == NULL)
  {
    heap->root = root->left_child;
    root->left_child->parent = NULL;
  }
  else
  {
    root->left_child->parent = NULL;
    root->right_child->parent = NULL;
    heap->root = root->left_child;
    insert_node (heap, heap->root, root->right_child);
  }
  GNUNET_free (root);
#if DEBUG
  GNUNET_assert (((heap->size == 0) && (heap->root == NULL)) ||
                 (heap->size == heap->root->tree_size + 1));
  CHECK (heap->root);
#endif
  return ret;
}


/**
 * Remove the given node 'node' from the tree and update
 * the 'tree_size' fields accordingly.  Preserves the
 * children of 'node' and does NOT change the overall
 * 'size' field of the tree.
 */
static void
remove_node (struct GNUNET_CONTAINER_HeapNode *node)
{
  struct GNUNET_CONTAINER_HeapNode *ancestor;
  struct GNUNET_CONTAINER_Heap *heap = node->heap;

  /* update 'size' of the ancestors */
  ancestor = node;
  while (NULL != (ancestor = ancestor->parent))
    ancestor->tree_size--;

  /* update 'size' of node itself */
  if (node->left_child != NULL)
    node->tree_size -= (1 + node->left_child->tree_size);
  if (node->right_child != NULL)
    node->tree_size -= (1 + node->right_child->tree_size);

  /* unlink 'node' itself and insert children in its place */
  if (node->parent == NULL)
  {
    if (node->left_child != NULL)
    {
      heap->root = node->left_child;
      node->left_child->parent = NULL;
      if (node->right_child != NULL)
      {
        node->right_child->parent = NULL;
        insert_node (heap, heap->root, node->right_child);
      }
    }
    else
    {
      heap->root = node->right_child;
      if (node->right_child != NULL)
        node->right_child->parent = NULL;
    }
  }
  else
  {
    if (node->parent->left_child == node)
      node->parent->left_child = NULL;
    else
      node->parent->right_child = NULL;
    if (node->left_child != NULL)
    {
      node->left_child->parent = NULL;
      node->parent->tree_size -= (1 + node->left_child->tree_size);
      insert_node (heap, node->parent, node->left_child);
    }
    if (node->right_child != NULL)
    {
      node->right_child->parent = NULL;
      node->parent->tree_size -= (1 + node->right_child->tree_size);
      insert_node (heap, node->parent, node->right_child);
    }
  }
  node->parent = NULL;
  node->left_child = NULL;
  node->right_child = NULL;
  GNUNET_assert (node->tree_size == 0);
  CHECK (heap->root);
}


/**
 * Removes a node from the heap.
 *
 * @param node node to remove
 * @return element data stored at the node
 */
void *
GNUNET_CONTAINER_heap_remove_node (struct GNUNET_CONTAINER_HeapNode *node)
{
  void *ret;
  struct GNUNET_CONTAINER_Heap *heap;

  heap = node->heap;
  CHECK (heap->root);
  if (heap->walk_pos == node)
    (void) GNUNET_CONTAINER_heap_walk_get_next (heap);
  remove_node (node);
  heap->size--;
  ret = node->element;
  if (heap->walk_pos == node)
    heap->walk_pos = NULL;
  GNUNET_free (node);
#if DEBUG
  CHECK (heap->root);
  GNUNET_assert (((heap->size == 0) && (heap->root == NULL)) ||
                 (heap->size == heap->root->tree_size + 1));
#endif
  return ret;
}


/**
 * Updates the cost of any node in the tree
 *
 * @param heap heap to modify
 * @param node node for which the cost is to be changed
 * @param new_cost new cost for the node
 */
void
GNUNET_CONTAINER_heap_update_cost (struct GNUNET_CONTAINER_Heap *heap,
                                   struct GNUNET_CONTAINER_HeapNode *node,
                                   GNUNET_CONTAINER_HeapCostType new_cost)
{
#if DEBUG
  GNUNET_assert (((heap->size == 0) && (heap->root == NULL)) ||
                 (heap->size == heap->root->tree_size + 1));
  CHECK (heap->root);
#endif
  remove_node (node);
#if DEBUG
  CHECK (heap->root);
  GNUNET_assert (((heap->size == 1) && (heap->root == NULL)) ||
                 (heap->size == heap->root->tree_size + 2));
#endif
  node->cost = new_cost;
  if (heap->root == NULL)
    heap->root = node;
  else
    insert_node (heap, heap->root, node);
#if DEBUG
  CHECK (heap->root);
  GNUNET_assert (((heap->size == 0) && (heap->root == NULL)) ||
                 (heap->size == heap->root->tree_size + 1));
#endif
}


/* end of heap.c */
