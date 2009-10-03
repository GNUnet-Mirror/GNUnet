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

/**
 * Element in our linked list.
 */
struct GNUNET_CONTAINER_SList_Elem
{
  /**
   * This is a linked list.
   */ 
  struct GNUNET_CONTAINER_SList_Elem *next;

  /**
   * Application data stored at this element.
   */
  void *elem;

  /**
   * Number of bytes stored in elem.
   */
  size_t len;

  /**
   * Disposition of the element.
   */
  enum GNUNET_CONTAINER_SListDisposition disp;
};


/**
 * Handle to a singly linked list  
 */
struct GNUNET_CONTAINER_SList
{
  /**
   * Head of the linked list.
   */
  struct GNUNET_CONTAINER_SList_Elem *head;

  /**
   * Number of elements in the list.
   */
  unsigned int length;
};


/**
 * Handle to a singly linked list iterator 
 */
struct GNUNET_CONTAINER_SList_Iterator
{
  /**
   * Linked list that we are iterating over.
   */
  struct GNUNET_CONTAINER_SList *list;

  /**
   * Last element accessed.
   */
  struct GNUNET_CONTAINER_SList_Elem *last;

  /**
   * Current list element.
   */
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
create_elem (enum GNUNET_CONTAINER_SListDisposition disp, 
	     const void *buf, 
	     size_t len)
{
  struct GNUNET_CONTAINER_SList_Elem *e;

  if (disp == GNUNET_CONTAINER_SLIST_DISPOSITION_TRANSIENT)
    {
      e = GNUNET_malloc (sizeof (struct GNUNET_CONTAINER_SList_Elem) + len);
      memcpy (&e[1], buf, len);
      e->elem = (void*) &e[1];
    }
  else
    {
      e = GNUNET_malloc (sizeof (struct GNUNET_CONTAINER_SList_Elem));
      e->elem = (void*) buf;
    }
  e->disp = disp;
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
GNUNET_CONTAINER_slist_add (struct GNUNET_CONTAINER_SList *l, 
			    enum GNUNET_CONTAINER_SListDisposition disp, 
                            const void *buf, size_t len)
{
  struct GNUNET_CONTAINER_SList_Elem *e;

  e = create_elem (disp, buf, len);
  e->next = l->head;
  l->head = e;
  l->length++;
}


/**
 * Create a new singly linked list
 * @return the new list
 */
struct GNUNET_CONTAINER_SList *
GNUNET_CONTAINER_slist_create ()
{
  return GNUNET_malloc (sizeof (struct GNUNET_CONTAINER_SList));
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
struct GNUNET_CONTAINER_SList_Iterator *
GNUNET_CONTAINER_slist_begin (struct GNUNET_CONTAINER_SList *l)
{
  struct GNUNET_CONTAINER_SList_Iterator *ret;

  ret = GNUNET_malloc (sizeof (struct GNUNET_CONTAINER_SList_Iterator));
  ret->elem = l->head;
  ret->list = l;
  return ret;
}


/**
 * Clear a list
 * @param l list
 */
void
GNUNET_CONTAINER_slist_clear (struct GNUNET_CONTAINER_SList *l)
{
  struct GNUNET_CONTAINER_SList_Elem *e;
  struct GNUNET_CONTAINER_SList_Elem *n;

  e = l->head;
  while (e != NULL)
    {
      n = e->next;
      if (e->disp == GNUNET_CONTAINER_SLIST_DISPOSITION_DYNAMIC)
	GNUNET_free (e->elem);
      GNUNET_free (e);
      e = n;
    }
  l->head = NULL;
  l->length = 0;
}


/**
 * Check if a list contains a certain element
 *
 * @param l list
 * @param buf payload buffer to find
 * @param lenght of the payload
 */
int
GNUNET_CONTAINER_slist_contains (const struct GNUNET_CONTAINER_SList *l,
                                 const void *buf, size_t len)
{
  struct GNUNET_CONTAINER_SList_Elem *e;

  for (e = l->head; e != NULL; e = e->next)
    if ( (e->len == len) && 
	 (memcmp (buf, e->elem, len) == 0) )
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
  return l->length;
}


/**
 * Remove an element from the list
 *
 * @param i iterator that points to the element to be removed
 */
void
GNUNET_CONTAINER_slist_erase (struct GNUNET_CONTAINER_SList_Iterator *i)
{
  struct GNUNET_CONTAINER_SList_Elem *next;

  next = i->elem->next;
  if (i->last != NULL)
    i->last->next = next;
  else
    i->list->head = next;
  if (i->elem->disp == GNUNET_CONTAINER_SLIST_DISPOSITION_DYNAMIC)
    GNUNET_free (i->elem->elem);
  GNUNET_free (i->elem);
  i->list->length--;
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
                               enum GNUNET_CONTAINER_SListDisposition disp, 
			       const void *buf, size_t len)
{
  struct GNUNET_CONTAINER_SList_Elem *e;

  e = create_elem (disp, buf, len);
  e->next = before->elem;
  if (before->last != NULL)
    before->last->next = e;
  else
    before->list->head = e;
  before->list->length++;
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

  return (i->elem != NULL) ? GNUNET_YES : GNUNET_NO;
}


/**
 * Check if an iterator points beyond the end of a list
 *
 * @param i iterator
 * @return GNUNET_YES if the end has been reached, GNUNET_NO if the iterator
 *         points to a valid element
 */
int
GNUNET_CONTAINER_slist_end (struct GNUNET_CONTAINER_SList_Iterator *i)
{
  return (i->elem == NULL) ? GNUNET_YES : GNUNET_NO;
}


/**
 * Retrieve the element at a specific position in a list
 * @param i iterator
 * @param len payload length
 * @return payload
 */
const void *
GNUNET_CONTAINER_slist_get (const struct GNUNET_CONTAINER_SList_Iterator *i,
                            size_t * len)
{
  if (len)
    *len = i->elem->len;
  return i->elem->elem;
}

/* end of container_slist.c */
