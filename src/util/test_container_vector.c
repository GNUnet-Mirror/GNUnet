/*
      This file is part of GNUnet
      (C) 2005, 2006, 2009 Christian Grothoff (and other contributing authors)

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
 * This is a testcase for the vector, waiting to be extended.
 */

#include "platform.h"
#include "gnunet_container_lib.h"

#define DUMP(v) fprintf(stderr, "At %d: \n", __LINE__); GNUNET_CONTAINER_vector_dump(v);

static int test(int size) {
  struct GNUNET_CONTAINER_Vector * v;

  v = GNUNET_CONTAINER_vector_new(size);
  if (0 != GNUNET_CONTAINER_vector_size(v))
    { DUMP(v); return 1; }
  if (GNUNET_OK != GNUNET_CONTAINER_vector_insert_at(v, "first", 0))
    { DUMP(v); return 1; }
  if (GNUNET_OK == GNUNET_CONTAINER_vector_insert_at(v, "not", 2))
    { DUMP(v); return 1; }
  if (GNUNET_OK != GNUNET_CONTAINER_vector_insert_at(v, "zero", 0))
    { DUMP(v); return 1; }
  if (GNUNET_OK != GNUNET_CONTAINER_vector_insert_at(v, "second", 2))
    { DUMP(v); return 1; }
  GNUNET_CONTAINER_vector_insert_last(v, "third");
  if (4 != GNUNET_CONTAINER_vector_size(v))
    { DUMP(v); return 1; }
  if (0 != strcmp(GNUNET_CONTAINER_vector_get_at(v, 1), "first"))
    { DUMP(v); return 1; }
  if (0 != strcmp(GNUNET_CONTAINER_vector_get_at(v, 3), "third"))
    { DUMP(v); return 1; }
  if (0 != strcmp(GNUNET_CONTAINER_vector_get_at(v, 0), "zero"))
    { DUMP(v); return 1; }
  if (0 != strcmp(GNUNET_CONTAINER_vector_get_first(v), "zero"))
    { DUMP(v); return 1; }
  if (0 != strcmp(GNUNET_CONTAINER_vector_get_last(v), "third"))
    { DUMP(v); return 1; }
  if (0 != strcmp(GNUNET_CONTAINER_vector_remove_at(v, 1), "first"))
    { DUMP(v); return 1; }
  if (0 != strcmp(GNUNET_CONTAINER_vector_get_at(v, 1), "second"))
    { DUMP(v); return 1; }
  if (NULL != GNUNET_CONTAINER_vector_remove_at(v, 3))
    { DUMP(v); return 1; }
  if (3 != GNUNET_CONTAINER_vector_size(v))
    { DUMP(v); return 1; }
  if (0 != strcmp(GNUNET_CONTAINER_vector_remove_at(v, 1), "second"))
    { DUMP(v); return 1; }
  if (0 != strcmp(GNUNET_CONTAINER_vector_remove_object(v, "third"), "third"))
    { DUMP(v); return 1; }
  if (NULL != GNUNET_CONTAINER_vector_remove_object(v, "third"))
    { DUMP(v); return 1; }
  if (0 != strcmp(GNUNET_CONTAINER_vector_remove_last(v), "zero"))
    { DUMP(v); return 1; }
  if (0 != GNUNET_CONTAINER_vector_size(v))
    { DUMP(v); return 1; }
  if (NULL != GNUNET_CONTAINER_vector_remove_last(v))
    { DUMP(v); return 1; }
  if (0 != GNUNET_CONTAINER_vector_size(v))
    { DUMP(v); return 1; }
  GNUNET_CONTAINER_vector_free(v);
  return 0;
}

static int test2(int size) {
  long i;
  struct GNUNET_CONTAINER_Vector * v;

  v = GNUNET_CONTAINER_vector_new(size);

  for (i=0;i<500;i++)
    if (GNUNET_OK != GNUNET_CONTAINER_vector_insert_at(v, (void*)i, 0))
      { DUMP(v); return 1; }
  if (500 != GNUNET_CONTAINER_vector_size(v))
    { DUMP(v); return 1; }
  for (i=0;i<500;i++)
    if (499 - i != (long) GNUNET_CONTAINER_vector_get_at(v, i))
      { DUMP(v); return 1; }
  if (499 != (long) GNUNET_CONTAINER_vector_get_first(v))
    { DUMP(v); return 1; }
  for (i=498;i>=0;i--)
    if (i != (long) GNUNET_CONTAINER_vector_get_next(v))
      { DUMP(v); return 1; }

  if (499 != (long) GNUNET_CONTAINER_vector_get_first(v))
    { DUMP(v); return 1; }
  for (i=498;i>=250;i--)
    if (i != (long) GNUNET_CONTAINER_vector_get_next(v))
      { DUMP(v); return 1; }
  for (i=251;i<499;i++)
    if (i != (long) GNUNET_CONTAINER_vector_get_previous(v))
      { DUMP(v); return 1; }

  GNUNET_CONTAINER_vector_free(v);
  return 0;
}


int main(int argc,
	 char * argv[]) {
  if (NULL != GNUNET_CONTAINER_vector_new(0))
    { printf("At %d\n", __LINE__); return 1; }
  if (NULL != GNUNET_CONTAINER_vector_new(1))
    { printf("At %d\n", __LINE__); return 1; }
  if (test(2) != 0)
    { printf("At %d\n", __LINE__); return 1; }
  if (test(3) != 0)
    { printf("At %d\n", __LINE__); return 1; }
  if (test(4) != 0)
    { printf("At %d\n", __LINE__); return 1; }
  if (test(128) != 0)
    { printf("At %d\n", __LINE__); return 1; }
  if (test(65536) != 0)
    { printf("At %d\n", __LINE__); return 1; }
  if (test(2*65536) != 0)
    { printf("At %d\n", __LINE__); return 1; }

  if (test2(2) != 0)
    { printf("At %d\n", __LINE__); return 1; }
  if (test2(3) != 0)
    { printf("At %d\n", __LINE__); return 1; }
  if (test2(4) != 0)
    { printf("At %d\n", __LINE__); return 1; }
  if (test2(128) != 0)
    { printf("At %d\n", __LINE__); return 1; }
  return 0;
}
