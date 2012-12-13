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
 * @file regex/prof-regex.c
 * @brief Test how long it takes to create a automaton from a string regex.
 * @author Bartlomiej Polot
 */
#include <regex.h>
#include <time.h>
#include "platform.h"
#include "gnunet_regex_lib.h"

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
  FILE *f;
  struct GNUNET_REGEX_Automaton* dfa;
  long size;
  char *regex;
  int compression;

  exe = argv[0];
  if (3 != argc)
  {
    usage();
    return 1;
  }
  f = fopen (argv[1], "r");
  if (NULL == f)
  {
    fprintf (stderr, "Can't open file %s\n", argv[1]);
    usage();
    return 2;
  }
  fseek (f, 0, SEEK_END);
  size = ftell (f);
  fseek (f, 0, SEEK_SET);
  regex = GNUNET_malloc (size);
  if (fread (regex, sizeof(char), size, f) != size)
  {
    fprintf (stderr, "Can't read file %s\n", argv[1]);
    usage();
    return 3;
  }
  compression = atoi (argv[2]);
  dfa = GNUNET_REGEX_construct_dfa (regex, size, compression);
  GNUNET_REGEX_automaton_destroy (dfa);
  GNUNET_free (regex);
  return 0;
}

/* end of prof-regex.c */
