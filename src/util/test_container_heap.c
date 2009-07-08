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
 * @file util/containers/heaptest.c
 * @brief Test of heap operations
 */

#include "gnunet_util.h"
#include "gnunet_util_containers.h"
#include "dv.h"

static int
iterator_callback (void *element, GNUNET_CONTAINER_HeapCost cost,
                   struct GNUNET_CONTAINER_Heap *root, void *cls)
{
  struct GNUNET_dv_neighbor *node;
  node = (struct GNUNET_dv_neighbor *) element;
  fprintf (stdout, "%d\n", node->cost);
  //fprintf (stdout, "%d\n", ((struct GNUNET_dv_neighbor *)element)->cost);

  return GNUNET_OK;
}


int
main (int argc, char **argv)
{
  struct GNUNET_CONTAINER_Heap *myHeap;
  struct GNUNET_dv_neighbor *neighbor1;
  struct GNUNET_dv_neighbor *neighbor2;
  struct GNUNET_dv_neighbor *neighbor3;
  struct GNUNET_dv_neighbor *neighbor4;
  struct GNUNET_dv_neighbor *neighbor5;
  struct GNUNET_dv_neighbor *neighbor6;

  GNUNET_log_setup ("test-container-heap", "WARNING", NULL);

  myHeap = GNUNET_CONTAINER_heap_create (GNUNET_CONTAINER_HEAP_ORDER_MAX);

  neighbor1 = malloc (sizeof (struct GNUNET_dv_neighbor));
  neighbor2 = malloc (sizeof (struct GNUNET_dv_neighbor));
  neighbor3 = malloc (sizeof (struct GNUNET_dv_neighbor));
  neighbor4 = malloc (sizeof (struct GNUNET_dv_neighbor));
  neighbor5 = malloc (sizeof (struct GNUNET_dv_neighbor));
  neighbor6 = malloc (sizeof (struct GNUNET_dv_neighbor));

  neighbor1->cost = 60;
  neighbor2->cost = 50;
  neighbor3->cost = 70;
  neighbor4->cost = 120;
  neighbor5->cost = 100;
  neighbor6->cost = 30;

  GNUNET_CONTAINER_heap_insert (myHeap, neighbor1, neighbor1->cost);
  GNUNET_CONTAINER_heap_iterate (myHeap, iterator_callback, NULL);

  fprintf (stdout, "\n");
  GNUNET_CONTAINER_heap_insert (myHeap, neighbor2, neighbor2->cost);

  GNUNET_CONTAINER_heap_iterate (myHeap, iterator_callback, NULL);
  fprintf (stdout, "\n");
  GNUNET_CONTAINER_heap_insert (myHeap, neighbor3, neighbor3->cost);

  GNUNET_CONTAINER_heap_iterate (myHeap, iterator_callback, NULL);
  fprintf (stdout, "\n");
  GNUNET_CONTAINER_heap_insert (myHeap, neighbor4, neighbor4->cost);

  GNUNET_CONTAINER_heap_iterate (myHeap, iterator_callback, NULL);
  fprintf (stdout, "\n");
  GNUNET_CONTAINER_heap_insert (myHeap, neighbor5, neighbor5->cost);

  GNUNET_CONTAINER_heap_iterate (myHeap, iterator_callback, NULL);
  fprintf (stdout, "\n");
  GNUNET_CONTAINER_heap_insert (myHeap, neighbor6, neighbor6->cost);

  GNUNET_CONTAINER_heap_iterate (myHeap, iterator_callback, NULL);
  fprintf (stdout, "\n");
  GNUNET_CONTAINER_heap_remove_node (myHeap, neighbor5);

  GNUNET_CONTAINER_heap_iterate (myHeap, iterator_callback, NULL);
  fprintf (stdout, "\n");
  GNUNET_CONTAINER_heap_remove_root (myHeap);

  GNUNET_CONTAINER_heap_iterate (myHeap, iterator_callback, NULL);
  fprintf (stdout, "\n");
  GNUNET_CONTAINER_heap_update_cost (myHeap, neighbor6, 200);

  GNUNET_CONTAINER_heap_iterate (myHeap, iterator_callback, NULL);
  fprintf (stdout, "\n");
  GNUNET_CONTAINER_heap_destroy (myHeap);
  return 0;
}

/* end of heaptest.c */
