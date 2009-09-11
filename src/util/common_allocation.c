/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file util/common_allocation.c
 * @brief wrapper around malloc/free
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_common.h"

#ifndef INT_MAX
#define INT_MAX 0x7FFFFFFF
#endif

/**
 * Allocate memory. Checks the return value, aborts if no more
 * memory is available.
 *
 * @param size how many bytes of memory to allocate, do NOT use
 *  this function (or GNUNET_malloc) to allocate more than several MB
 *  of memory, if you are possibly needing a very large chunk use
 *  GNUNET_xmalloc_unchecked_ instead.
 * @param filename where in the code was the call to GNUNET_array_grow
 * @param linenumber where in the code was the call to GNUNET_array_grow
 * @return pointer to size bytes of memory
 */
void *
GNUNET_xmalloc_ (size_t size, const char *filename, int linenumber)
{
  /* As a security precaution, we generally do not allow very large
     allocations using the default 'GNUNET_malloc' macro */
  GNUNET_assert_at (size <= GNUNET_MAX_MALLOC_CHECKED, filename,
                    linenumber);
  return GNUNET_xmalloc_unchecked_ (size, filename, linenumber);
}

void *
GNUNET_xmalloc_unchecked_ (size_t size, const char *filename, int linenumber)
{
  void *result;

  GNUNET_assert_at (size < INT_MAX, filename, linenumber);
  result = malloc (size);
  if (result == NULL)
    {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "malloc");
      abort ();
    }
  memset (result, 0, size);
  return result;
}

/**
 * Reallocate memory. Checks the return value, aborts if no more
 * memory is available.
 *
 * @ptr the pointer to reallocate
 * @param size how many bytes of memory to allocate, do NOT use
 *  this function (or GNUNET_malloc) to allocate more than several MB
 *  of memory
 * @param filename where in the code was the call to GNUNET_realloc
 * @param linenumber where in the code was the call to GNUNET_realloc
 * @return pointer to size bytes of memory
 */
void *
GNUNET_xrealloc_ (void *ptr,
                  const size_t n, const char *filename, int linenumber)
{
  ptr = realloc (ptr, n);
  if (!ptr)
    {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "realloc");
      abort ();
    }
  return ptr;
}

/**
 * Free memory. Merely a wrapper for the case that we
 * want to keep track of allocations.
 *
 * @param ptr the pointer to free
 * @param filename where in the code was the call to GNUNET_array_grow
 * @param linenumber where in the code was the call to GNUNET_array_grow
 */
void
GNUNET_xfree_ (void *ptr, const char *filename, int linenumber)
{
  GNUNET_assert_at (ptr != NULL, filename, linenumber);
  free (ptr);
}

/**
 * Dup a string (same semantics as strdup).
 *
 * @param str the string to dup
 * @param filename where in the code was the call to GNUNET_array_grow
 * @param linenumber where in the code was the call to GNUNET_array_grow
 * @return strdup(str)
 */
char *
GNUNET_xstrdup_ (const char *str, const char *filename, int linenumber)
{
  char *res;

  GNUNET_assert_at (str != NULL, filename, linenumber);
  res = GNUNET_xmalloc_ (strlen (str) + 1, filename, linenumber);
  memcpy (res, str, strlen (str) + 1);
  return res;
}

/**
 * Grow an array.  Grows old by (*oldCount-newCount)*elementSize bytes
 * and sets *oldCount to newCount.
 *
 * @param old address of the pointer to the array
 *        *old may be NULL
 * @param elementSize the size of the elements of the array
 * @param oldCount address of the number of elements in the *old array
 * @param newCount number of elements in the new array, may be 0
 * @param filename where in the code was the call to GNUNET_array_grow
 * @param linenumber where in the code was the call to GNUNET_array_grow
 */
void
GNUNET_xgrow_ (void **old,
               size_t elementSize,
               unsigned int *oldCount,
               unsigned int newCount, const char *filename, int linenumber)
{
  void *tmp;
  size_t size;

  GNUNET_assert_at (INT_MAX / elementSize > newCount, filename, linenumber);
  size = newCount * elementSize;
  if (size == 0)
    {
      tmp = NULL;
    }
  else
    {
      tmp = GNUNET_xmalloc_ (size, filename, linenumber);
      memset (tmp, 0, size);    /* client code should not rely on this, though... */
      if (*oldCount > newCount)
        *oldCount = newCount;   /* shrink is also allowed! */
      memcpy (tmp, *old, elementSize * (*oldCount));
    }

  if (*old != NULL)
    {
      GNUNET_xfree_ (*old, filename, linenumber);
    }
  *old = tmp;
  *oldCount = newCount;
}


int
GNUNET_asprintf (char **buf, const char *format, ...)
{
  int ret;
  va_list args;

  va_start (args, format);
  ret = VSNPRINTF (NULL, 0, format, args);
  va_end (args);
  *buf = GNUNET_malloc (ret + 1);
  va_start (args, format);
  ret = VSPRINTF (*buf, format, args);
  va_end (args);
  return ret;
}

int
GNUNET_snprintf (char *buf, size_t size, const char *format, ...)
{
  int ret;
  va_list args;

  va_start (args, format);
  ret = VSNPRINTF (buf, size, format, args);
  va_end (args);
  GNUNET_assert (ret <= size);
  return ret;
}


/* end of common_allocation.c */
