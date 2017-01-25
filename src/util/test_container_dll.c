/*
 This file is part of GNUnet.
 Copyright (C) 2017 GNUnet e.V.

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
 * @author Christian Grothoff
 * @file util/test_container_dll.c
 * @brief Test of DLL operations
 */

#include "platform.h"
#include "gnunet_util_lib.h"

/**
 * Element in the DLL.
 */
struct Element
{
  /**
   * Required pointer to previous element.
   */
  struct Element *prev;

  /**
   * Required pointer to next element.
   */
  struct Element *next;

  /**
   * Used to sort.
   */
  unsigned int value;
};


/**
 * Compare two elements.
 *
 * @param cls closure, NULL
 * @param e1 an element of to sort
 * @param e2 another element to sort
 * @return #GNUNET_YES if @e1 < @e2, otherwise #GNUNET_NO
 */
static int
cmp_elem (void *cls,
          struct Element *e1,
          struct Element *e2)
{
  if (e1->value == e2->value)
    return 0;
  return (e1->value < e2->value) ? 1 : -1;
}


int
main (int argc, char **argv)
{
  unsigned int values2[] = {
    4, 5, 8, 6, 9, 3, 7, 2, 6, 1, 0
  };
  unsigned int values[] = {
    1, 3, 2, 0
  };
  struct Element *head = NULL;
  struct Element *tail = NULL;
  struct Element *e;
  unsigned int want;

  GNUNET_log_setup ("test-container-dll",
                    "WARNING",
                    NULL);
  for (unsigned int off=0;
       0 != values[off];
       off++)
  {
    e = GNUNET_new (struct Element);
    e->value = values[off];
    GNUNET_CONTAINER_DLL_insert_sorted (struct Element,
                                        cmp_elem,
                                        NULL,
                                        head,
                                        tail,
                                        e);
  }

  want = 1;
  while (NULL != (e = head))
  {
    GNUNET_assert (e->value == want);
    GNUNET_CONTAINER_DLL_remove (head,
                                 tail,
                                 e);
    GNUNET_free (e);
    want++;
  }
  return 0;
}

/* end of test_container_heap.c */
