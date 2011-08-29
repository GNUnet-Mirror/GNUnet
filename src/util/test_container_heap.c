/*
 This file is part of GNUnet.
 (C) 2008 Christian Grothoff (and other contributing authors)

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
 * @author Nathan Evans
 * @file util/test_container_heap.c
 * @brief Test of heap operations
 */

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_container_lib.h"

static int
iterator_callback (void *cls, struct GNUNET_CONTAINER_HeapNode *node,
                   void *element, GNUNET_CONTAINER_HeapCostType cost)
{
  return GNUNET_OK;
}

static int
nstrcmp (const char *a, const char *b)
{
  GNUNET_assert (a != NULL);
  GNUNET_assert (b != NULL);
  return strcmp (a, b);
}

static int
check ()
{
  struct GNUNET_CONTAINER_Heap *myHeap;
  struct GNUNET_CONTAINER_HeapNode *n1;
  struct GNUNET_CONTAINER_HeapNode *n2;
  struct GNUNET_CONTAINER_HeapNode *n3;
  struct GNUNET_CONTAINER_HeapNode *n4;
  struct GNUNET_CONTAINER_HeapNode *n5;
  struct GNUNET_CONTAINER_HeapNode *n6;
  struct GNUNET_CONTAINER_HeapNode *n7;
  struct GNUNET_CONTAINER_HeapNode *n8;
  const char *r;

  myHeap = GNUNET_CONTAINER_heap_create (GNUNET_CONTAINER_HEAP_ORDER_MIN);

  // GNUNET_CONTAINER_heap_remove_root heap empty, taking if-branch
  n1 = GNUNET_CONTAINER_heap_remove_root (myHeap);
  GNUNET_assert (NULL == n1);

  // GNUNET_CONTAINER_heap_peek heap empty, taking if-branch
  n1 = GNUNET_CONTAINER_heap_peek (myHeap);
  GNUNET_assert (NULL == n1);

  // GNUNET_CONTAINER_heap_walk_get_next: heap empty, taking if-branch
  n1 = GNUNET_CONTAINER_heap_walk_get_next (myHeap);
  GNUNET_assert (NULL == n1);

  n1 = GNUNET_CONTAINER_heap_insert (myHeap, "11", 11);
  GNUNET_assert (NULL != n1);


  // GNUNET_CONTAINER_heap_peek not empty, taking if-branch
  n2 = NULL;
  n2 = GNUNET_CONTAINER_heap_peek (myHeap);
  GNUNET_assert (NULL != n2);

  // GNUNET_CONTAINER_heap_walk_get_next: 1 element
  n1 = NULL;
  n1 = GNUNET_CONTAINER_heap_walk_get_next (myHeap);
  GNUNET_assert (NULL != n1);

  GNUNET_CONTAINER_heap_iterate (myHeap, &iterator_callback, NULL);
  GNUNET_assert (1 == GNUNET_CONTAINER_heap_get_size (myHeap));
  n2 = GNUNET_CONTAINER_heap_insert (myHeap, "78", 78);
  GNUNET_assert (2 == GNUNET_CONTAINER_heap_get_size (myHeap));
  GNUNET_assert (0 == strcmp ("78", GNUNET_CONTAINER_heap_remove_node (n2)));
  GNUNET_assert (1 == GNUNET_CONTAINER_heap_get_size (myHeap));
  GNUNET_CONTAINER_heap_iterate (myHeap, &iterator_callback, NULL);

  n3 = GNUNET_CONTAINER_heap_insert (myHeap, "15", 5);
  GNUNET_CONTAINER_heap_update_cost (myHeap, n3, 15);
  GNUNET_assert (2 == GNUNET_CONTAINER_heap_get_size (myHeap));
  GNUNET_CONTAINER_heap_iterate (myHeap, &iterator_callback, NULL);

  n4 = GNUNET_CONTAINER_heap_insert (myHeap, "50", 50);
  GNUNET_CONTAINER_heap_update_cost (myHeap, n4, 50);
  GNUNET_assert (3 == GNUNET_CONTAINER_heap_get_size (myHeap));
  GNUNET_CONTAINER_heap_iterate (myHeap, &iterator_callback, NULL);

  n5 = GNUNET_CONTAINER_heap_insert (myHeap, "100", 100);
  n6 = GNUNET_CONTAINER_heap_insert (myHeap, "30/200", 30);
  GNUNET_assert (5 == GNUNET_CONTAINER_heap_get_size (myHeap));
  GNUNET_CONTAINER_heap_remove_node (n5);
  r = GNUNET_CONTAINER_heap_remove_root (myHeap);       /* n1 */
  GNUNET_assert (NULL != r);
  GNUNET_assert (0 == strcmp ("11", r));
  GNUNET_CONTAINER_heap_update_cost (myHeap, n6, 200);
  GNUNET_CONTAINER_heap_remove_node (n3);
  r = GNUNET_CONTAINER_heap_remove_root (myHeap);       /* n4 */
  GNUNET_assert (NULL != r);
  GNUNET_assert (0 == strcmp ("50", r));
  r = GNUNET_CONTAINER_heap_remove_root (myHeap);       /* n6 */
  GNUNET_assert (NULL != r);
  GNUNET_assert (0 == strcmp ("30/200", r));
  GNUNET_assert (0 == GNUNET_CONTAINER_heap_get_size (myHeap));

  GNUNET_CONTAINER_heap_destroy (myHeap);

  // My additions to a complete testcase
  // Testing a GNUNET_CONTAINER_HEAP_ORDER_MIN
  // Testing remove_node

  myHeap = GNUNET_CONTAINER_heap_create (GNUNET_CONTAINER_HEAP_ORDER_MIN);

  n1 = GNUNET_CONTAINER_heap_insert (myHeap, "10", 10);
  GNUNET_CONTAINER_heap_update_cost (myHeap, n1, 15);

  r = GNUNET_CONTAINER_heap_remove_node (n1);
  GNUNET_assert (NULL != r);
  GNUNET_assert (0 == strcmp ("10", r));

  n1 = GNUNET_CONTAINER_heap_insert (myHeap, "10", 10);
  n2 = GNUNET_CONTAINER_heap_insert (myHeap, "20", 10);

  GNUNET_CONTAINER_heap_walk_get_next (myHeap);
  r = GNUNET_CONTAINER_heap_remove_node (n2);
  GNUNET_assert (NULL != r);
  GNUNET_assert (0 == strcmp ("20", r));
  r = GNUNET_CONTAINER_heap_remove_node (n1);
  GNUNET_assert (NULL != r);
  GNUNET_assert (0 == strcmp ("10", r));

  n1 = GNUNET_CONTAINER_heap_insert (myHeap, "10", 10);
  n2 = GNUNET_CONTAINER_heap_insert (myHeap, "20", 10);
  n3 = GNUNET_CONTAINER_heap_insert (myHeap, "30", 10);

  GNUNET_CONTAINER_heap_remove_node (n2);
  GNUNET_CONTAINER_heap_remove_node (n1);
  r = GNUNET_CONTAINER_heap_remove_root (myHeap);
  GNUNET_assert (NULL != r);
  GNUNET_assert (0 == strcmp ("30", r));

  n1 = GNUNET_CONTAINER_heap_insert (myHeap, "10", 10);
  n2 = GNUNET_CONTAINER_heap_insert (myHeap, "20", 10);
  n3 = GNUNET_CONTAINER_heap_insert (myHeap, "30", 10);

  GNUNET_CONTAINER_heap_remove_node (n2);
  GNUNET_CONTAINER_heap_remove_node (n1);
  r = GNUNET_CONTAINER_heap_remove_node (n3);
  GNUNET_assert (NULL != r);
  GNUNET_assert (0 == strcmp ("30", r));

  n1 = GNUNET_CONTAINER_heap_insert (myHeap, "10", 10);
  n2 = GNUNET_CONTAINER_heap_insert (myHeap, "20", 20);
  n3 = GNUNET_CONTAINER_heap_insert (myHeap, "30", 30);

  GNUNET_assert (0 == nstrcmp ("20", GNUNET_CONTAINER_heap_remove_node (n2)));
  GNUNET_assert (0 ==
                 nstrcmp ("10", GNUNET_CONTAINER_heap_remove_root (myHeap)));
  GNUNET_assert (0 ==
                 nstrcmp ("30", GNUNET_CONTAINER_heap_remove_root (myHeap)));

  n1 = GNUNET_CONTAINER_heap_insert (myHeap, "10", 10);
  n2 = GNUNET_CONTAINER_heap_insert (myHeap, "20", 20);
  n3 = GNUNET_CONTAINER_heap_insert (myHeap, "30", 30);
  n4 = GNUNET_CONTAINER_heap_insert (myHeap, "40", 40);
  n5 = GNUNET_CONTAINER_heap_insert (myHeap, "50", 50);
  n6 = GNUNET_CONTAINER_heap_insert (myHeap, "60", 60);

  // Inserting nodes deeper in the tree with lower costs
  n7 = GNUNET_CONTAINER_heap_insert (myHeap, "70", 10);
  n8 = GNUNET_CONTAINER_heap_insert (myHeap, "80", 10);

  GNUNET_assert (0 == nstrcmp ("30", GNUNET_CONTAINER_heap_remove_node (n3)));

  // Cleaning up...
  GNUNET_assert (0 == nstrcmp ("60", GNUNET_CONTAINER_heap_remove_node (n6)));
  GNUNET_assert (0 == nstrcmp ("50", GNUNET_CONTAINER_heap_remove_node (n5)));

  // Testing heap_walk_get_next
  GNUNET_CONTAINER_heap_walk_get_next (myHeap);
  GNUNET_CONTAINER_heap_walk_get_next (myHeap);
  GNUNET_CONTAINER_heap_walk_get_next (myHeap);;
  GNUNET_CONTAINER_heap_walk_get_next (myHeap);
  GNUNET_CONTAINER_heap_walk_get_next (myHeap);

  GNUNET_assert (0 == nstrcmp ("10", GNUNET_CONTAINER_heap_remove_node (n1)));
  GNUNET_assert (0 == nstrcmp ("20", GNUNET_CONTAINER_heap_remove_node (n2)));
  GNUNET_assert (0 == nstrcmp ("40", GNUNET_CONTAINER_heap_remove_node (n4)));
  GNUNET_assert (0 == nstrcmp ("70", GNUNET_CONTAINER_heap_remove_node (n7)));
  GNUNET_assert (0 == nstrcmp ("80", GNUNET_CONTAINER_heap_remove_node (n8)));

  // End Testing remove_node

  // Testing a GNUNET_CONTAINER_HEAP_ORDER_MAX
  GNUNET_CONTAINER_heap_destroy (myHeap);

  myHeap = GNUNET_CONTAINER_heap_create (GNUNET_CONTAINER_HEAP_ORDER_MAX);

  n1 = GNUNET_CONTAINER_heap_insert (myHeap, "10", 10);
  GNUNET_CONTAINER_heap_update_cost (myHeap, n1, 15);

  GNUNET_assert (0 == nstrcmp ("10", GNUNET_CONTAINER_heap_remove_node (n1)));

  n1 = GNUNET_CONTAINER_heap_insert (myHeap, "10", 10);
  n2 = GNUNET_CONTAINER_heap_insert (myHeap, "20", 10);

  GNUNET_CONTAINER_heap_walk_get_next (myHeap);
  GNUNET_assert (0 == nstrcmp ("20", GNUNET_CONTAINER_heap_remove_node (n2)));
  GNUNET_assert (0 == nstrcmp ("10", GNUNET_CONTAINER_heap_remove_node (n1)));

  n1 = GNUNET_CONTAINER_heap_insert (myHeap, "10", 10);
  n2 = GNUNET_CONTAINER_heap_insert (myHeap, "20", 10);
  n3 = GNUNET_CONTAINER_heap_insert (myHeap, "30", 10);

  GNUNET_CONTAINER_heap_remove_node (n2);
  GNUNET_CONTAINER_heap_remove_node (n1);
  GNUNET_assert (0 ==
                 nstrcmp ("30", GNUNET_CONTAINER_heap_remove_root (myHeap)));

  n1 = GNUNET_CONTAINER_heap_insert (myHeap, "10", 10);
  n2 = GNUNET_CONTAINER_heap_insert (myHeap, "20", 10);
  n3 = GNUNET_CONTAINER_heap_insert (myHeap, "30", 10);

  GNUNET_CONTAINER_heap_remove_node (n2);
  GNUNET_CONTAINER_heap_remove_node (n1);
  GNUNET_assert (0 == nstrcmp ("30", GNUNET_CONTAINER_heap_remove_node (n3)));

  n1 = GNUNET_CONTAINER_heap_insert (myHeap, "10", 10);
  n2 = GNUNET_CONTAINER_heap_insert (myHeap, "20", 20);
  n3 = GNUNET_CONTAINER_heap_insert (myHeap, "30", 30);
  n4 = GNUNET_CONTAINER_heap_insert (myHeap, "40", 40);
  n5 = GNUNET_CONTAINER_heap_insert (myHeap, "50", 50);
  n6 = GNUNET_CONTAINER_heap_insert (myHeap, "60", 60);

  // Inserting nodes deeper in the tree with lower costs
  n7 = GNUNET_CONTAINER_heap_insert (myHeap, "70", 10);
  n8 = GNUNET_CONTAINER_heap_insert (myHeap, "80", 10);

  GNUNET_assert (0 == nstrcmp ("30", GNUNET_CONTAINER_heap_remove_node (n3)));

  // Cleaning up...
  GNUNET_assert (0 == nstrcmp ("60", GNUNET_CONTAINER_heap_remove_node (n6)));
  GNUNET_assert (0 == nstrcmp ("50", GNUNET_CONTAINER_heap_remove_node (n5)));

  // Testing heap_walk_get_next
  GNUNET_CONTAINER_heap_walk_get_next (myHeap);
  GNUNET_CONTAINER_heap_walk_get_next (myHeap);
  GNUNET_CONTAINER_heap_walk_get_next (myHeap);;
  GNUNET_CONTAINER_heap_walk_get_next (myHeap);
  GNUNET_CONTAINER_heap_walk_get_next (myHeap);

  GNUNET_assert (0 == nstrcmp ("10", GNUNET_CONTAINER_heap_remove_node (n1)));
  GNUNET_assert (0 == nstrcmp ("20", GNUNET_CONTAINER_heap_remove_node (n2)));
  GNUNET_assert (0 == nstrcmp ("40", GNUNET_CONTAINER_heap_remove_node (n4)));
  GNUNET_assert (0 == nstrcmp ("70", GNUNET_CONTAINER_heap_remove_node (n7)));
  GNUNET_assert (0 == nstrcmp ("80", GNUNET_CONTAINER_heap_remove_node (n8)));

  // End Testing remove_node

  GNUNET_CONTAINER_heap_destroy (myHeap);

  return 0;
}


int
main (int argc, char **argv)
{
  GNUNET_log_setup ("test-container-heap", "WARNING", NULL);
  return check ();
}

/* end of test_container_heap.c */
