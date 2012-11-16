/*
     This file is part of GNUnet
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
 * @file regex/test_regex_graph_api.c
 * @brief test for regex_graph.c
 * @author Maximilian Szengel
 */
#include <regex.h>
#include <time.h>
#include "platform.h"
#include "gnunet_regex_lib.h"
#include "regex_internal.h"

#define KEEP_FILES 1

/**
 * Check if 'filename' exists and is not empty.
 *
 * @param filename name of the file that should be checked
 *
 * @return 0 if ok, non 0 on error.
 */
static int
filecheck (const char *filename)
{
  int error = 0;
  FILE *fp;

  /* Check if file was created and delete it again */
  if (NULL == (fp = fopen (filename, "r")))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Could not find graph %s\n", filename);
    return 1;
  }

  GNUNET_break (0 == fseek (fp, 0L, SEEK_END));
  if (1 > ftell (fp))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Graph writing failed, got empty file (%s)!\n", filename);
    error = 2;
  }

  GNUNET_assert (0 == fclose (fp));

  if (!KEEP_FILES)
  {
    if (0 != unlink (filename))
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR, "unlink", filename);
  }
  return error;
}


int
main (int argc, char *argv[])
{
  int error;
  struct GNUNET_REGEX_Automaton *a;
  unsigned int i;
  const char *filename = "test_graph.dot";

  const char *regex[12] = {
    "ab(c|d)+c*(a(b|c)+d)+(bla)+",
    "(bla)*",
    "b(lab)*la",
    "(ab)*",
    "ab(c|d)+c*(a(b|c)+d)+(bla)(bla)*",
    "z(abc|def)?xyz",
    "1*0(0|1)*",
    "a*b*",
    "a+X*y+c|p|R|Z*K*y*R+w|Y*6+n+h*k*w+V*F|W*B*e*",
    "a",
    "a|b",
    "PADPADPADPADPADPabcdefghixxxxxxxxxxxxxjklmnop*qstoisdjfguisdfguihsdfgbdsuivggsd"
  };

  GNUNET_log_setup ("test-regex", "WARNING", NULL);
  error = 0;
  for (i = 0; i < 12; i++)
  {
    /* Check NFA graph creation */
    a = GNUNET_REGEX_construct_nfa (regex[i], strlen (regex[i]));
    GNUNET_REGEX_automaton_save_graph (a, filename, GNUNET_REGEX_GRAPH_DEFAULT);
    GNUNET_REGEX_automaton_destroy (a);
    error += filecheck (filename);

    a = GNUNET_REGEX_construct_nfa (regex[i], strlen (regex[i]));
    GNUNET_REGEX_automaton_save_graph (a, filename,
                                       GNUNET_REGEX_GRAPH_DEFAULT |
                                       GNUNET_REGEX_GRAPH_VERBOSE);
    GNUNET_REGEX_automaton_destroy (a);
    error += filecheck (filename);

    a = GNUNET_REGEX_construct_nfa (regex[i], strlen (regex[i]));
    GNUNET_REGEX_automaton_save_graph (a, filename,
                                       GNUNET_REGEX_GRAPH_DEFAULT |
                                       GNUNET_REGEX_GRAPH_COLORING);
    GNUNET_REGEX_automaton_destroy (a);
    error += filecheck (filename);

    a = GNUNET_REGEX_construct_nfa (regex[i], strlen (regex[i]));
    GNUNET_REGEX_automaton_save_graph (a, filename,
                                       GNUNET_REGEX_GRAPH_DEFAULT |
                                       GNUNET_REGEX_GRAPH_VERBOSE |
                                       GNUNET_REGEX_GRAPH_COLORING);
    GNUNET_REGEX_automaton_destroy (a);
    error += filecheck (filename);


    /* Check DFA graph creation */
    a = GNUNET_REGEX_construct_dfa (regex[i], strlen (regex[i]), 0);
    GNUNET_REGEX_automaton_save_graph (a, filename, GNUNET_REGEX_GRAPH_DEFAULT);
    GNUNET_REGEX_automaton_destroy (a);
    error += filecheck (filename);

    a = GNUNET_REGEX_construct_dfa (regex[i], strlen (regex[i]), 0);
    GNUNET_REGEX_automaton_save_graph (a, filename,
                                       GNUNET_REGEX_GRAPH_DEFAULT |
                                       GNUNET_REGEX_GRAPH_VERBOSE);
    GNUNET_REGEX_automaton_destroy (a);
    error += filecheck (filename);

    a = GNUNET_REGEX_construct_dfa (regex[i], strlen (regex[i]), 0);
    GNUNET_REGEX_automaton_save_graph (a, filename,
                                       GNUNET_REGEX_GRAPH_DEFAULT |
                                       GNUNET_REGEX_GRAPH_COLORING);
    GNUNET_REGEX_automaton_destroy (a);
    error += filecheck (filename);


    a = GNUNET_REGEX_construct_dfa (regex[i], strlen (regex[i]), 4);
    GNUNET_REGEX_automaton_save_graph (a, filename, GNUNET_REGEX_GRAPH_DEFAULT);
    GNUNET_REGEX_automaton_destroy (a);
    error += filecheck (filename);

  }

  return error;
}
