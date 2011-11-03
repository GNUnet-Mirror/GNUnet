/*
      This file is part of GNUnet
     (C) 2011 Christian Grothoff (and other contributing authors)

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
      Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
      Boston, MA 02110-1301, USA.
 */

/**
 * @file contrib/test_gnunet_prefix.c
 * @brief test if environment variable GNUNET_PREFIX is set so that
 *        we have a chance to run tests
 * @author Christian Grothoff
 */
#include "platform.h"


int 
main (int argc,
      char **argv)
{
  const char *basename;
  const char *dirname;

  basename = getenv ("GNUNET_PREFIX");  
  if (NULL == basename)
  {
    fprintf (stderr,
	     _("Environment variable GNUNET_PREFIX not set\n"));
    fprintf (stderr, 
	     _("Testcases will not work!\n"));
    return 1;
  }
  dirname = DIR_SEPARATOR_STR "share" DIR_SEPARATOR_STR "gnunet" DIR_SEPARATOR_STR "config.d";
  {
    char tmp[strlen (basename) + strlen (dirname) + 1];
    sprintf (tmp, "%s%s", basename, dirname);
    if (0 != access (tmp, R_OK))
    {
      fprintf (stderr,
	       _("Failed to access `%s': %s\n"),
	       tmp,
	       STRERROR (errno));
      fprintf (stderr,
	       _("Check that you did run `make install' and that GNUNET_PREFIX='%s' is the correct prefix.\n"),
	       basename);
      fprintf (stderr, 
	       _("Testcases will not work!\n"));
      return 2;
    }
  }
  return 0;
}
