/*
     This file is part of GNUnet.
     Copyright (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @author Christian Grothoff
 * @file util/perf_malloc.c
 * @brief measure performance of allocation functions
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include <gauger.h>

static uint64_t
perfMalloc ()
{
  size_t i;
  uint64_t ret;

  ret = 0;
  for (i=1;i<1024 * 1024;i+=1024)
    {
      ret += i;
      GNUNET_free (GNUNET_malloc (i));
    }
  return ret;
}


int
main (int argc, char *argv[])
{
  struct GNUNET_TIME_Absolute start;
  uint64_t kb;

  start = GNUNET_TIME_absolute_get ();
  kb = perfMalloc ();
  printf ("Malloc perf took %s\n",
          GNUNET_STRINGS_relative_time_to_string (GNUNET_TIME_absolute_get_duration (start),
						  GNUNET_YES));
  GAUGER ("UTIL", "Allocation",
          kb / 1024 / (1 +
		       GNUNET_TIME_absolute_get_duration
		       (start).rel_value_us / 1000LL), "kb/ms");
  return 0;
}

/* end of perf_malloc.c */
