/*
 This file is part of GNUnet.
 (C) 2008 Christian Grothoff (and other contributing authors)

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
 * @author Nathan Evans
 * @file util/container_heap.c
 * @brief Implementation of heap operations
 */

#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_util_lib.h"

/**
 * Generic heap node structure, contains pointer to parent
 * left child, right child, and actual neighbor.
 */
struct GNUNET_CONTAINER_heap_node
{
  struct GNUNET_CONTAINER_heap_node *parent;

  struct GNUNET_CONTAINER_heap_node *left_child;

  struct GNUNET_CONTAINER_heap_node *right_child;

  GNUNET_CONTAINER_HeapCost cost;

  void *element;

};

struct GNUNET_CONTAINER_Heap
{
  unsigned int size;

  unsigned int max_size;

  enum GNUNET_CONTAINER_HeapOrder type;

  struct GNUNET_CONTAINER_heap_node *root;

  struct GNUNET_CONTAINER_heap_node *traversal_pos;

};


/**
 * Returns element stored at root of tree, doesn't effect anything
 *
 * @param heap the heap
 * @return NULL if the heap is empty
 */
void *
GNUNET_CONTAINER_heap_peek (struct GNUNET_CONTAINER_Heap *heap)
{
  if ((heap == NULL) || (heap->root == NULL))
    return NULL;

  return heap->root->element;
}

static int
next_power_of_2 (int v)
{
  v |= v >> 1;
  v |= v >> 2;
  v |= v >> 4;
  v |= v >> 8;
  v |= v >> 16;
  v++;
  return v;
}

#if 0
static void
internal_print (struct GNUNET_CONTAINER_heap_node *root)
{
  fprintf (stdout, "%llu\n", (unsigned long long) root->cost);
  if (root->left_child != NULL)
    {
      fprintf (stdout, "LEFT of %llu\n", (unsigned long long) root->cost);
      internal_print (root->left_child);
    }
  if (root->right_child != NULL)
    {
      fprintf (stdout, "RIGHT of %llu\n", (unsigned long long) root->cost);
      internal_print (root->right_child);
    }
}

static void
printTree (struct GNUNET_CONTAINER_Heap *root)
{
  internal_print (root->root);
}
#endif

struct GNUNET_CONTAINER_Heap *
GNUNET_CONTAINER_heap_create (enum GNUNET_CONTAINER_HeapOrder type)
{
  struct GNUNET_CONTAINER_Heap *heap;
  heap = malloc (sizeof (struct GNUNET_CONTAINER_Heap));
  heap->max_size = -1;
  heap->type = type;
  heap->root = NULL;
  heap->traversal_pos = NULL;
  heap->size = 0;

  return heap;
}

void
GNUNET_CONTAINER_heap_destroy (struct GNUNET_CONTAINER_Heap *heap)
{
  while (heap->size > 0)
    GNUNET_CONTAINER_heap_remove_root (heap);
  GNUNET_free (heap);
}

static struct GNUNET_CONTAINER_heap_node *
find_element (struct GNUNET_CONTAINER_heap_node *node, void *element)
{
  struct GNUNET_CONTAINER_heap_node *ret;
  ret = NULL;
  if (node == NULL)
    return NULL;

  if (node->element == element)
    return node;

  if (node->left_child != NULL)
    ret = find_element (node->left_child, element);

  if ((ret == NULL) && (node->right_child != NULL))
    ret = find_element (node->right_child, element);

  return ret;
}

static struct GNUNET_CONTAINER_heap_node *
getNextPos (struct GNUNET_CONTAINER_Heap *root)
{
  struct GNUNET_CONTAINER_heap_node *ret;
  struct GNUNET_CONTAINER_heap_node *parent;
  int pos;
  int i;

  ret = GNUNET_malloc (sizeof (struct GNUNET_CONTAINER_heap_node));
  pos = root->size + 1;
  ret->left_child = NULL;
  ret->right_child = NULL;

  if (0 == root->size)
    {
      ret->parent = NULL;
      root->root = ret;
    }
  else
    {
      parent = root->root;
      for (i = next_power_of_2 (pos) >> 2; i > 1; i >>= 1)
        {
          if (((pos / i) % 2) == 0)
            parent = parent->left_child;
          else
            parent = parent->right_child;
        }

      ret->parent = parent;
      if ((pos % 2) == 0)
        parent->left_child = ret;
      else
        parent->right_child = ret;

    }

  return ret;

}

static struct GNUNET_CONTAINER_heap_node *
getPos (struct GNUNET_CONTAINER_Heap *root, unsigned int pos)
{
  struct GNUNET_CONTAINER_heap_node *ret;
  unsigned int i;

  ret = NULL;
  if (pos > root->size)
    {
      return ret;
    }
  else
    {
      ret = root->root;
      for (i = next_power_of_2 (pos) >> 2; i > 0; i >>= 1)
        {
          if (((pos / i) % 2) == 0)
            ret = ret->left_child;
          else
            ret = ret->right_child;
        }
    }

  return ret;

}

void
swapNodes (struct GNUNET_CONTAINER_heap_node *first,
           struct GNUNET_CONTAINER_heap_node *second,
           struct GNUNET_CONTAINER_Heap *root)
{
  void *temp_element;
  GNUNET_CONTAINER_HeapCost temp_cost;

  temp_element = first->element;
  temp_cost = first->cost;
  first->element = second->element;
  first->cost = second->cost;
  second->element = temp_element;
  second->cost = temp_cost;

  return;
}

void
percolateHeap (struct GNUNET_CONTAINER_heap_node *pos,
               struct GNUNET_CONTAINER_Heap *root)
{

  while ((pos->parent != NULL) &&
         (((root->type == GNUNET_CONTAINER_HEAP_ORDER_MAX)
           && (pos->parent->cost < pos->cost))
          || ((root->type == GNUNET_CONTAINER_HEAP_ORDER_MIN)
              && (pos->parent->cost > pos->cost))))
    {
      swapNodes (pos, pos->parent, root);
      pos = pos->parent;
    }

  return;
}



void
percolateDownHeap (struct GNUNET_CONTAINER_heap_node *pos,
                   struct GNUNET_CONTAINER_Heap *root)
{
  struct GNUNET_CONTAINER_heap_node *switchNeighbor;

  switchNeighbor = pos;

  if ((root->type == GNUNET_CONTAINER_HEAP_ORDER_MAX))
    {
      if ((pos->left_child != NULL)
          && (pos->left_child->cost > switchNeighbor->cost))
        {
          switchNeighbor = pos->left_child;
        }

      if ((pos->right_child != NULL)
          && (pos->right_child->cost > switchNeighbor->cost))
        {
          switchNeighbor = pos->right_child;
        }
    }
  else if ((root->type == GNUNET_CONTAINER_HEAP_ORDER_MIN))
    {
      if ((pos->left_child != NULL)
          && (pos->left_child->cost < switchNeighbor->cost))
        {
          switchNeighbor = pos->left_child;
        }

      if ((pos->right_child != NULL)
          && (pos->right_child->cost < switchNeighbor->cost))
        {
          switchNeighbor = pos->right_child;
        }
    }

  if (switchNeighbor != pos)
    {
      swapNodes (switchNeighbor, pos, root);
      percolateDownHeap (switchNeighbor, root);
    }

  return;
}

void *
GNUNET_CONTAINER_heap_remove_node (struct GNUNET_CONTAINER_Heap *root,
                                   void *element)
{
  void *ret;
  struct GNUNET_CONTAINER_heap_node *del_node;
  struct GNUNET_CONTAINER_heap_node *last;
  GNUNET_CONTAINER_HeapCost old_cost;

  del_node = NULL;
  del_node = find_element (root->root, element);

  if (del_node == NULL)
    return NULL;
  else if (del_node == root->root)
    return GNUNET_CONTAINER_heap_remove_root (root);

  ret = del_node->element;
  last = getPos (root, root->size);

  root->size--;

  old_cost = del_node->cost;
  del_node->element = last->element;
  del_node->cost = last->cost;

  if (last->parent->left_child == last)
    last->parent->left_child = NULL;
  if (last->parent->right_child == last)
    last->parent->right_child = NULL;

  if (root->traversal_pos == last)
    {
      root->traversal_pos = root->root;
    }

  if (last == del_node)
  {
    GNUNET_free (last);
    return ret;
  }
  GNUNET_free (last);


  if (del_node->cost > old_cost)
    {
      if (root->type == GNUNET_CONTAINER_HEAP_ORDER_MAX)
        percolateHeap (del_node, root);
      else if (root->type == GNUNET_CONTAINER_HEAP_ORDER_MIN)
        percolateDownHeap (del_node, root);
    }
  else if (del_node->cost < old_cost)
    {
      if (root->type == GNUNET_CONTAINER_HEAP_ORDER_MAX)
        percolateDownHeap (del_node, root);
      else if (root->type == GNUNET_CONTAINER_HEAP_ORDER_MIN)
        percolateHeap (del_node, root);
    }

  return ret;
}

int
GNUNET_CONTAINER_heap_insert (struct GNUNET_CONTAINER_Heap *root,
                              void *element, GNUNET_CONTAINER_HeapCost cost)
{
  struct GNUNET_CONTAINER_heap_node *new_pos;
  int ret;
  ret = GNUNET_YES;

  if (root->max_size > root->size)
    {
      new_pos = getNextPos (root);
      new_pos->element = element;
      new_pos->cost = cost;
      root->size++;

      percolateHeap (new_pos, root);
    }
  else
    {
      ret = GNUNET_NO;
    }

  return ret;
}

void *
GNUNET_CONTAINER_heap_remove_root (struct GNUNET_CONTAINER_Heap *root)
{
  void *ret;
  struct GNUNET_CONTAINER_heap_node *root_node;
  struct GNUNET_CONTAINER_heap_node *last;

  if ((root == NULL) || (root->size == 0) || (root->root == NULL))
    {
      GNUNET_break (0);
      return NULL;
    }

  root_node = root->root;
  ret = root_node->element;
  last = getPos (root, root->size);

  if ((root_node == last) && (root->size == 1))
    {
      /* We are removing the last node in the heap! */
      GNUNET_free (last);
      root->root = NULL;
      root->traversal_pos = NULL;
      GNUNET_assert (0 == --root->size);
      return ret;
    }

  if (last->parent->left_child == last)
    last->parent->left_child = NULL;
  else if (last->parent->right_child == last)
    last->parent->right_child = NULL;

  root_node->element = last->element;
  root_node->cost = last->cost;

  if (root->traversal_pos == last)
    root->traversal_pos = root->root;
  GNUNET_free (last);
  root->size--;
  percolateDownHeap (root->root, root);
  return ret;
}

static int
updatedCost (struct GNUNET_CONTAINER_Heap *root,
             struct GNUNET_CONTAINER_heap_node *node)
{
  struct GNUNET_CONTAINER_heap_node *parent;

  if (node == NULL)
    return GNUNET_SYSERR;

  parent = node->parent;

  if ((root->type == GNUNET_CONTAINER_HEAP_ORDER_MAX) && (parent != NULL)
      && (node->cost > parent->cost))
    percolateHeap (node, root);
  else if ((root->type == GNUNET_CONTAINER_HEAP_ORDER_MIN) && (parent != NULL)
           && (node->cost < parent->cost))
    percolateHeap (node, root);
  else if (root->type == GNUNET_CONTAINER_HEAP_ORDER_MAX)
    percolateDownHeap (node, root);
  else if (root->type == GNUNET_CONTAINER_HEAP_ORDER_MIN)
    percolateDownHeap (node, root);

  return GNUNET_YES;
}


int
GNUNET_CONTAINER_heap_update_cost (struct GNUNET_CONTAINER_Heap *root,
                                   void *element,
                                   GNUNET_CONTAINER_HeapCost new_cost)
{
  struct GNUNET_CONTAINER_heap_node *node;
  int ret = GNUNET_YES;
  node = find_element (root->root, element);
  if (node == NULL)
    return GNUNET_NO;

  node->cost = new_cost;
  ret = updatedCost (root, node);
  return ret;
}

void
internal_iterator (struct GNUNET_CONTAINER_Heap *root,
                   struct GNUNET_CONTAINER_heap_node *node,
                   GNUNET_CONTAINER_HeapIterator iterator, void *cls)
{
  if (node == NULL)
    return;
  internal_iterator (root, node->left_child, iterator, cls);
  internal_iterator (root, node->right_child, iterator, cls);
  iterator (cls, node->element, node->cost);
}

int
GNUNET_CONTAINER_heap_iterate (struct GNUNET_CONTAINER_Heap *heap,
                               GNUNET_CONTAINER_HeapIterator iterator,
                               void *cls)
{
  internal_iterator (heap, heap->root, iterator, cls);
  return GNUNET_OK;
}

void *
GNUNET_CONTAINER_heap_walk_get_next (struct GNUNET_CONTAINER_Heap *root)
{
  unsigned int choice;
  void *element;

  if ((root->traversal_pos == NULL) && (root->root != NULL))
    {
      root->traversal_pos = root->root;
    }

  if (root->traversal_pos == NULL)
    return NULL;

  element = root->traversal_pos->element;

  choice = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, 2);

  switch (choice)
    {
    case 1:
      root->traversal_pos = root->traversal_pos->right_child;
      break;
    case 0:
      root->traversal_pos = root->traversal_pos->left_child;
      break;
    }

  return element;

}

unsigned int
GNUNET_CONTAINER_heap_get_size (struct GNUNET_CONTAINER_Heap *heap)
{
  return heap->size;
}

/* end of heap.c */
