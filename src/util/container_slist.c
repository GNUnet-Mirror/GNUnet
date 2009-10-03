/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

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
 * @file util/container_slist.c
 * @brief Implementation of a singly-linked list
 * @author Nils Durner
 */

#include "platform.h"
#include "gnunet_container_lib.h"

struct GNUNET_CONTAINER_SList_Elem
{
  void *elem;
  size_t len;
  int disp;
  struct GNUNET_CONTAINER_SList_Elem *next;
};

struct GNUNET_CONTAINER_SList
{
  struct GNUNET_CONTAINER_SList_Elem head;
};

struct GNUNET_CONTAINER_SList_Iterator
{
  struct GNUNET_CONTAINER_SList_Elem *last;
  struct GNUNET_CONTAINER_SList_Elem *elem;
};

/**
 * Create a new element that is to be inserted into the list
 * @internal
 * @param disp memory disposition
 * @param buf payload buffer
 * @param len length of the buffer
 * @return a new element
 */
static struct GNUNET_CONTAINER_SList_Elem *
create_elem (int disp, const void *buf, size_t len)
{
  struct GNUNET_CONTAINER_SList_Elem *e;

  e = GNUNET_malloc (sizeof (struct GNUNET_CONTAINER_SList_Elem));
  e->disp = disp;
  if (disp == GNUNET_MEM_DISP_TRANSIENT)
    {
      e->elem = GNUNET_malloc (len);
      memcpy (e->elem, buf, len);
    }
  else
    e->elem = (void *) buf;
  e->len = len;

  return e;
}

/**
 * Add a new element to the list
 * @param l list
 * @param disp memory disposition
 * @param buf payload buffer
 * @param len length of the buffer
 */
void
GNUNET_CONTAINER_slist_add (struct GNUNET_CONTAINER_SList *l, int disp,
                            const void *buf, size_t len)
{
  struct GNUNET_CONTAINER_SList_Elem *e;

  e = create_elem (disp, buf, len);
  e->next = l->head.next;
  l->head.next = e;
}

/**
 * Create a new singly linked list
 * @return the new list
 */
struct GNUNET_CONTAINER_SList *
GNUNET_CONTAINER_slist_create ()
{
  struct GNUNET_CONTAINER_SList *ret;

  ret = GNUNET_malloc (sizeof (struct GNUNET_CONTAINER_SList));
  if (NULL == ret)
    return NULL;

  memset (&ret->head, 0, sizeof (struct GNUNET_CONTAINER_SList));

  return ret;
}

/**
 * Destroy a singly linked list
 * @param l the list to be destroyed
 */
void
GNUNET_CONTAINER_slist_destroy (struct GNUNET_CONTAINER_SList *l)
{
  GNUNET_CONTAINER_slist_clear (l);
  GNUNET_free (l);
}

/**
 * Return the beginning of a list
 * @param l list
 * @return iterator pointing to the beginning
 */
const struct GNUNET_CONTAINER_SList_Iterator *
GNUNET_CONTAINER_slist_begin (const struct GNUNET_CONTAINER_SList *l)
{
  struct GNUNET_CONTAINER_SList_Iterator *ret;

  ret = GNUNET_malloc (sizeof (struct GNUNET_CONTAINER_SList_Iterator));
  ret->elem = l->head.next;
  ret->last = (struct GNUNET_CONTAINER_SList_Elem *) &l->head;
  return ret;
}

/**
 * Clear a list
 * @param l list
 */
void
GNUNET_CONTAINER_slist_clear (struct GNUNET_CONTAINER_SList *l)
{
  struct GNUNET_CONTAINER_SList_Elem *e, *n;

  e = l->head.next;
  while (e != NULL)
    {
      if (e->disp != GNUNET_MEM_DISP_STATIC)
        GNUNET_free (e->elem);
      n = e->next;
      GNUNET_free (e);
      e = n;
    }
  l->head.next = NULL;
}

/**
 * Check if a list contains a certain element
 * @param l list
 * @param buf payload buffer to find
 * @param lenght of the payload
 */
int
GNUNET_CONTAINER_slist_contains (const struct GNUNET_CONTAINER_SList *l,
                                 const void *buf, size_t len)
{
  struct GNUNET_CONTAINER_SList_Elem *e;

  for (e = l->head.next; e != NULL; e = e->next)
    if (e->len == len && memcmp (buf, e->elem, len) == 0)
      return GNUNET_YES;

  return GNUNET_NO;
}

/**
 * Count the elements of a list
 * @param l list
 * @return number of elements in the list
 */
int
GNUNET_CONTAINER_slist_count (const struct GNUNET_CONTAINER_SList *l)
{
  int n;
  struct GNUNET_CONTAINER_SList_Elem *e;

  for (n = 0, e = l->head.next; e != NULL; e = e->next)
    n++;

  return n;
}

/**
 * Remove an element from the list
 * @param i iterator that points to the element to be removed
 */
void
GNUNET_CONTAINER_slist_erase (struct GNUNET_CONTAINER_SList_Iterator *i)
{
  struct GNUNET_CONTAINER_SList_Elem *next;

  next = i->elem->next;
  i->last->next = next;
  if (i->elem->disp != GNUNET_MEM_DISP_STATIC)
    GNUNET_free (i->elem->elem);
  GNUNET_free (i->elem);
  i->elem = next;
}

/**
 * Insert an element into a list at a specific position
 * @param before where to insert the new element
 * @param disp memory disposition
 * @param buf payload buffer
 * @param len length of the payload
 */
void
GNUNET_CONTAINER_slist_insert (struct GNUNET_CONTAINER_SList_Iterator *before,
                               int disp, const void *buf, size_t len)
{
  struct GNUNET_CONTAINER_SList_Elem *e;

  e = create_elem (disp, buf, len);
  e->next = before->elem;
  before->last->next = e;
}

/**
 * Advance an iterator to the next element
 * @param i iterator
 * @return GNUNET_YES on success, GNUNET_NO if the end has been reached
 */
int
GNUNET_CONTAINER_slist_next (struct GNUNET_CONTAINER_SList_Iterator *i)
{
  i->last = i->elem;
  i->elem = i->elem->next;

  return i->elem != NULL;
}

/**
 * Check if an iterator points beyond the end of a list
 * @param i iterator
 * @return GNUNET_YES if the end has been reached, GNUNET_NO if the iterator
 *         points to a valid element
 */
int
GNUNET_CONTAINER_slist_end (struct GNUNET_CONTAINER_SList_Iterator *i)
{
  return i->elem == NULL;
}

/**
 * Retrieve the element at a specific position in a list
 * @param i iterator
 * @param len payload length
 * @return payload
 */
void *
GNUNET_CONTAINER_slist_get (const struct GNUNET_CONTAINER_SList_Iterator *i,
                            size_t * len)
{
  if (len)
    *len = i->elem->len;
  return i->elem->elem;
}
