/*
     This file is part of GNUnet
     Copyright (C) 2011, 2014 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License, or
     (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
 */

/**
 * @file contrib/test_gnunet_prefix.c
 * @brief test if environment variable GNUNET_PREFIX is set so that
 *        we have a chance to run tests
 * @author Christian Grothoff
 */
#include "platform.h"


int
main (int argc, char **argv)
{
  const char *basename;
  const char *dirname;

  basename = getenv ("GNUNET_PREFIX");
  if (NULL == basename)
  {
    fprintf (stderr, _ ("Environment variable GNUNET_PREFIX not set\n"));
    fprintf (stderr, _ ("Testcases will not work!\n"));
    return 1;
  }
  dirname = DIR_SEPARATOR_STR ".." DIR_SEPARATOR_STR "share" DIR_SEPARATOR_STR
            "gnunet" DIR_SEPARATOR_STR "config.d";
  {
    char tmp[strlen (basename) + strlen (dirname) + 1];
    sprintf (tmp, "%s%s", basename, dirname);
    if (0 != access (tmp, R_OK))
    {
      fprintf (stderr,
               _ ("Failed to access `%s': %s\n"),
               tmp,
               strerror (errno));
      fprintf (
        stderr,
        _ (
          "Check that you did run `make install' and that GNUNET_PREFIX='%s' is the correct prefix.\n"),
        basename);
      fprintf (stderr, _ ("Testcases will not work!\n"));
      return 2;
    }
  }
  return 0;
}
