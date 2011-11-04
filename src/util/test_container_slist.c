/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

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
 * @file util/test_container_slist.c
 * @brief Testcases for singly linked lists
 * @author Nils Durner
 */

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_container_lib.h"

int
main (int argc, char *argv[])
{
  struct GNUNET_CONTAINER_SList *l;
  struct GNUNET_CONTAINER_SList_Iterator it;
  unsigned int i;
  int *ip;
  unsigned int j;
  size_t s;
  const void *p;

  GNUNET_log_setup ("test-container-slist", "WARNING", NULL);

  l = GNUNET_CONTAINER_slist_create ();
  GNUNET_assert (l != NULL);
  GNUNET_assert (GNUNET_CONTAINER_slist_count (l) == 0);

  for (i = 0; i < 100; i++)
    GNUNET_CONTAINER_slist_add (l, GNUNET_CONTAINER_SLIST_DISPOSITION_TRANSIENT,
                                &i, sizeof (i));
  GNUNET_assert (GNUNET_CONTAINER_slist_count (l) == 100);

  for (it = GNUNET_CONTAINER_slist_begin (l), i = 99;
       GNUNET_CONTAINER_slist_end (&it) != GNUNET_YES;
       GNUNET_CONTAINER_slist_next (&it), i--)
  {
    p = GNUNET_CONTAINER_slist_get (&it, &s);

    if ((p == NULL) || (i != (j = *(int *) p)) || (s != sizeof (i)))
    {
      GNUNET_CONTAINER_slist_iter_destroy (&it);
      GNUNET_assert (0);
    }
    j *= 2;
    GNUNET_CONTAINER_slist_insert (&it,
                                   GNUNET_CONTAINER_SLIST_DISPOSITION_TRANSIENT,
                                   &j, sizeof (j));
  }
  GNUNET_assert (GNUNET_CONTAINER_slist_count (l) == 200);
  i = 198;
  GNUNET_assert (GNUNET_CONTAINER_slist_contains (l, &i, sizeof (i)));

  for (it = GNUNET_CONTAINER_slist_begin (l);
       GNUNET_CONTAINER_slist_end (&it) != GNUNET_YES;)
  {
    p = GNUNET_CONTAINER_slist_get (&it, &s);
    GNUNET_assert (p != NULL);
    GNUNET_assert (s == sizeof (i));
    i = *(int *) p;

    GNUNET_assert (GNUNET_CONTAINER_slist_next (&it) == GNUNET_YES);
    GNUNET_assert (GNUNET_CONTAINER_slist_end (&it) != GNUNET_YES);

    p = GNUNET_CONTAINER_slist_get (&it, &s);
    GNUNET_assert (p != NULL);
    GNUNET_assert (s == sizeof (j));
    j = *(int *) p;

    GNUNET_assert (j * 2 == i);

    GNUNET_CONTAINER_slist_erase (&it);
  }
  GNUNET_assert (GNUNET_CONTAINER_slist_count (l) == 100);
  i = 99;
  GNUNET_assert (GNUNET_CONTAINER_slist_contains (l, &i, sizeof (i)) ==
                 GNUNET_NO);
  i = 198;
  GNUNET_assert (GNUNET_CONTAINER_slist_contains (l, &i, sizeof (i)) ==
                 GNUNET_YES);

  GNUNET_CONTAINER_slist_clear (l);
  GNUNET_assert (GNUNET_CONTAINER_slist_count (l) == 0);

  for (i = 0; i < 100; i++)
    GNUNET_CONTAINER_slist_add (l, GNUNET_CONTAINER_SLIST_DISPOSITION_TRANSIENT,
                                &i, sizeof (i));
  /*check slist_append */
  GNUNET_CONTAINER_slist_append (l, l);
  GNUNET_assert (GNUNET_CONTAINER_slist_count (l) == 200);

  GNUNET_CONTAINER_slist_destroy (l);

  /*check slist_add_end */
  l = GNUNET_CONTAINER_slist_create ();
  for (i = 0; i < 100; i++)
    GNUNET_CONTAINER_slist_add_end (l,
                                    GNUNET_CONTAINER_SLIST_DISPOSITION_TRANSIENT,
                                    &i, sizeof (i));

  GNUNET_assert (GNUNET_CONTAINER_slist_count (l) == 100);

  for (it = GNUNET_CONTAINER_slist_begin (l), i = 0;
       GNUNET_CONTAINER_slist_end (&it) != GNUNET_YES;
       GNUNET_CONTAINER_slist_next (&it), i++)
  {
    p = GNUNET_CONTAINER_slist_get (&it, &s);

    if ((p == NULL) || (i != *(int *) p) || (s != sizeof (i)))
    {
      GNUNET_assert (0);
    }
  }
  GNUNET_CONTAINER_slist_destroy (l);

  /*check if disp = GNUNET_CONTAINER_SLIST_DISPOSITION_DYNAMIC */
  l = GNUNET_CONTAINER_slist_create ();

  for (i = 0; i < 100; i++)
  {
    ip = GNUNET_malloc (sizeof (int));
    *ip = i;
    GNUNET_CONTAINER_slist_add (l, GNUNET_CONTAINER_SLIST_DISPOSITION_DYNAMIC,
                                ip, sizeof (int));
  }
  //creat_add
  it = GNUNET_CONTAINER_slist_begin (l);
  p = GNUNET_CONTAINER_slist_get (&it, &s);
  GNUNET_assert (p != NULL);
  //slist_erase
  GNUNET_assert (GNUNET_CONTAINER_slist_next (&it) == GNUNET_YES);
  GNUNET_CONTAINER_slist_erase (&it);
  GNUNET_CONTAINER_slist_iter_destroy (&it);
  GNUNET_assert (GNUNET_CONTAINER_slist_count (l) == 99);
  //slist_clear
  GNUNET_CONTAINER_slist_clear (l);
  GNUNET_assert (GNUNET_CONTAINER_slist_count (l) == 0);
  GNUNET_CONTAINER_slist_destroy (l);

  return 0;
}
