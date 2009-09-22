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
 * @file util/test_container_heap.c
 * @brief Test of heap operations
 */

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_container_lib.h"

struct TestItem
{
  unsigned int cost;
};

static int
iterator_callback (void *cls, void *element, GNUNET_CONTAINER_HeapCost cost)
{
  struct TestItem *node;
  node = (struct TestItem *) element;
#ifdef VERBOSE
  fprintf (stdout, "%d\n", node->cost);
#endif

  return GNUNET_OK;
}

int
main (int argc, char **argv)
{
  struct GNUNET_CONTAINER_Heap *myHeap;
  struct TestItem neighbor1;
  struct TestItem neighbor2;
  struct TestItem neighbor3;
  struct TestItem neighbor4;
  struct TestItem neighbor5;
  struct TestItem neighbor6;

  GNUNET_log_setup ("test-container-heap", "WARNING", NULL);

  myHeap = GNUNET_CONTAINER_heap_create (GNUNET_CONTAINER_HEAP_ORDER_MAX);

  neighbor1.cost = 60;
  neighbor2.cost = 50;
  neighbor3.cost = 70;
  neighbor4.cost = 120;
  neighbor5.cost = 100;
  neighbor6.cost = 30;

  GNUNET_CONTAINER_heap_insert (myHeap, &neighbor1, neighbor1.cost);
  GNUNET_CONTAINER_heap_iterate (myHeap, iterator_callback, NULL);
  GNUNET_CONTAINER_heap_insert (myHeap, &neighbor2, neighbor2.cost);
  GNUNET_CONTAINER_heap_iterate (myHeap, iterator_callback, NULL);
  GNUNET_CONTAINER_heap_insert (myHeap, &neighbor3, neighbor3.cost);
  GNUNET_CONTAINER_heap_iterate (myHeap, iterator_callback, NULL);
  GNUNET_CONTAINER_heap_insert (myHeap, &neighbor4, neighbor4.cost);
  GNUNET_CONTAINER_heap_iterate (myHeap, iterator_callback, NULL);
  GNUNET_CONTAINER_heap_insert (myHeap, &neighbor5, neighbor5.cost);
  GNUNET_CONTAINER_heap_iterate (myHeap, iterator_callback, NULL);
  GNUNET_CONTAINER_heap_insert (myHeap, &neighbor6, neighbor6.cost);
  GNUNET_CONTAINER_heap_iterate (myHeap, iterator_callback, NULL);
  GNUNET_CONTAINER_heap_remove_node (myHeap, &neighbor5);
  GNUNET_CONTAINER_heap_iterate (myHeap, iterator_callback, NULL);
  GNUNET_CONTAINER_heap_remove_root (myHeap);
  GNUNET_CONTAINER_heap_iterate (myHeap, iterator_callback, NULL);
  GNUNET_CONTAINER_heap_update_cost (myHeap, &neighbor6, 200);
  GNUNET_CONTAINER_heap_iterate (myHeap, iterator_callback, NULL);
  GNUNET_CONTAINER_heap_destroy (myHeap);

  return 0;
}

/* end of test_container_heap.c */
