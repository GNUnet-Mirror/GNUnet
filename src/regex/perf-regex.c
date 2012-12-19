/*
     This file is part of GNUnet.
     (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @file src/regex/prof-regex.c
 * @brief Test how long it takes to create a automaton from a string regex.
 * @author Bartlomiej Polot
 */
#include <regex.h>
#include <time.h>
#include "platform.h"
#include "gnunet_regex_lib.h"
#include "regex_test_lib.h"

static const char *exe;

static void
usage(void)
{
  fprintf (stderr, "Usage: %s REGEX_FILE COMPRESSION\n", exe);
}

/**
 * The main function to obtain peer information.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  struct GNUNET_REGEX_Automaton* dfa;
  char **regexes;
  char *buffer;
  char *regex;
  int compression;
  long size;

  GNUNET_log_setup ("perf-regex", "DEBUG", NULL);
  exe = argv[0];
  if (3 != argc)
  {
    usage();
    return 1;
  }
  regexes = GNUNET_REGEX_read_from_file (argv[1]);

  if (NULL == regexes)
  {
    usage();
    return 2;
  }
  buffer = GNUNET_REGEX_combine (regexes);

  GNUNET_asprintf (&regex, "GNVPN-0001-PAD(%s)(0|1)*", buffer);
  size = strlen (regex);

  // fprintf (stderr, "Combined regex (%ld bytes):\n%s\n", size, regex);
  //   return 0;

  compression = atoi (argv[2]);
  dfa = GNUNET_REGEX_construct_dfa (regex, size, compression);
  GNUNET_REGEX_automaton_destroy (dfa);
  GNUNET_free (buffer);
  GNUNET_REGEX_free_from_file (regexes);
  return 0;
}

/* end of prof-regex.c */
