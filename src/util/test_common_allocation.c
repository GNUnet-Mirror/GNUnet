/*
     This file is part of GNUnet.
     Copyright (C) 2001, 2002, 2003, 2005, 2006, 2017 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.
*/

/**
 * @file util/test_common_allocation.c
 * @brief testcase for common_allocation.c
 */
#include "platform.h"
#include "gnunet_util_lib.h"


static int
check ()
{
#define MAX_TESTVAL 1024
  char *ptrs[MAX_TESTVAL];
  unsigned int **a2;
  char ***a3;
  int i;
  int j;
  int k;
  unsigned int ui;

  /* GNUNET_malloc/GNUNET_free test */
  k = 352;                      /* random start value */
  for (i = 1; i < MAX_TESTVAL; i++)
  {
    ptrs[i] = GNUNET_malloc (i);
    for (j = 0; j < i; j++)
      ptrs[i][j] = k++;
  }

  for (i = MAX_TESTVAL - 1; i >= 1; i--)
  {
    for (j = i - 1; j >= 0; j--)
      if (ptrs[i][j] != (char) --k)
        return 1;
    GNUNET_free (ptrs[i]);
  }

  /* GNUNET_free_non_null test */
  GNUNET_free_non_null (NULL);
  GNUNET_free_non_null (GNUNET_malloc (4));

  /* GNUNET_strdup tests */
  ptrs[0] = GNUNET_strdup ("bar");
  if (0 != strcmp (ptrs[0], "bar"))
    return 3;
  /* now realloc */
  ptrs[0] = GNUNET_realloc (ptrs[0], 12);
  strcpy (ptrs[0], "Hello World");

  GNUNET_free (ptrs[0]);
  GNUNET_asprintf (&ptrs[0], "%s %s", "Hello", "World");
  GNUNET_assert (strlen (ptrs[0]) == 11);
  GNUNET_free (ptrs[0]);

  /* GNUNET_array_grow tests */
  ptrs[0] = NULL;
  ui = 0;
  GNUNET_array_grow (ptrs[0], ui, 42);
  if (ui != 42)
    return 4;
  GNUNET_array_grow (ptrs[0], ui, 22);
  if (ui != 22)
    return 5;
  for (j = 0; j < 22; j++)
    ptrs[0][j] = j;
  GNUNET_array_grow (ptrs[0], ui, 32);
  for (j = 0; j < 22; j++)
    if (ptrs[0][j] != j)
      return 6;
  for (j = 22; j < 32; j++)
    if (ptrs[0][j] != 0)
      return 7;
  GNUNET_array_grow (ptrs[0], ui, 0);
  if (i != 0)
    return 8;
  if (ptrs[0] != NULL)
    return 9;

  /* GNUNET_new_array_2d tests */
  a2 = GNUNET_new_array_2d (17, 22, unsigned int);
  for (i = 0; i < 17; i++)
  {
    for (j = 0; j < 22; j++)
    {
      if (0 != a2[i][j])
      {
        GNUNET_free (a2);
        return 10;
      }
      a2[i][j] = i * 100 + j;
    }
  }
  GNUNET_free (a2);

  /* GNUNET_new_array_3d tests */
  a3 = GNUNET_new_array_3d (2, 3, 4, char);
  for (i = 0; i < 2; i++)
  {
    for (j = 0; j < 3; j++)
    {
      for (k = 0; k < 4; k++)
      {
        if (0 != a3[i][j][k])
        {
          GNUNET_free (a3);
          return 11;
        }
        a3[i][j][k] = i * 100 + j * 10 + k;
      }
    }
  }
  GNUNET_free (a3);
  return 0;
}


int
main (int argc, char *argv[])
{
  int ret;

  GNUNET_log_setup ("test-common-allocation",
                    "WARNING",
                    NULL);
  ret = check ();
  if (ret != 0)
    FPRINTF (stderr,
             "ERROR %d.\n",
             ret);
  return ret;
}

/* end of test_common_allocation.c */
