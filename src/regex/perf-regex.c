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
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/

/**
 * @file src/regex/perf-regex.c
 * @brief Test how long it takes to create a automaton from a string regex.
 * @author Bartlomiej Polot
 */
#include <regex.h>
#include <time.h>
#include "platform.h"
#include "regex_internal_lib.h"
#include "regex_test_lib.h"


/**
 * Print information about the given node and its edges
 * to stdout.
 *
 * @param cls closure, unused.
 * @param key hash for current state.
 * @param proof proof for current state.
 * @param accepting GNUNET_YES if this is an accepting state, GNUNET_NO if not.
 * @param num_edges number of edges leaving current state.
 * @param edges edges leaving current state.
 */
static void
print_edge (void *cls,
	    const struct GNUNET_HashCode *key,
	    const char *proof,
	    int accepting,
	    unsigned int num_edges,
	    const struct REGEX_BLOCK_Edge *edges)
{
  unsigned int i;

  printf ("%s: %s, proof: `%s'\n",
	  GNUNET_h2s (key),
	  accepting ? "ACCEPTING" : "",
	  proof);
  for (i = 0; i < num_edges; i++)
    printf ("    `%s': %s\n",
	    edges[i].label,
	    GNUNET_h2s (&edges[i].destination));
}


/**
 * The main function of the regex performace test.
 *
 * Read a set of regex from a file, combine them and create a DFA from the
 * resulting combined regex.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  struct REGEX_INTERNAL_Automaton* dfa;
  char **regexes;
  char *buffer;
  char *regex;
  int compression;
  long size;

  GNUNET_log_setup ("perf-regex", "DEBUG", NULL);
  if (3 != argc)
  {
    fprintf (stderr,
	     "Usage: %s REGEX_FILE COMPRESSION\n",
	     argv[0]);
    return 1;
  }
  regexes = REGEX_TEST_read_from_file (argv[1]);
  if (NULL == regexes)
  {
    fprintf (stderr,
	     "Failed to read regexes from `%s'\n",
	     argv[1]);
    return 2;
  }
  compression = atoi (argv[2]);

  buffer = REGEX_TEST_combine (regexes);
  GNUNET_asprintf (&regex, "GNUNET_REGEX_PROFILER_(%s)(0|1)*", buffer);
  size = strlen (regex);

  fprintf (stderr,
	   "Combined regex (%ld bytes):\n%s\n",
	   size,
	   regex);
  dfa = REGEX_INTERNAL_construct_dfa (regex, size, compression);
  printf ("********* ALL EDGES *********'\n");
  REGEX_INTERNAL_iterate_all_edges (dfa, &print_edge, NULL);
  printf ("\n\n********* REACHABLE EDGES *********'\n");
  REGEX_INTERNAL_iterate_reachable_edges (dfa, &print_edge, NULL);
  REGEX_INTERNAL_automaton_destroy (dfa);
  GNUNET_free (buffer);
  REGEX_TEST_free_from_file (regexes);
  GNUNET_free (regex);
  return 0;
}

/* end of prof-regex.c */
