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
 * @file regex/test_regex_iterate_api.c
 * @brief test for regex.c
 * @author Maximilian Szengel
 */
#include <regex.h>
#include <time.h>
#include "platform.h"
#include "gnunet_regex_lib.h"

void
key_iterator (void *cls, const GNUNET_HashCode * key, const char *proof,
              int accepting, unsigned int num_edges,
              const struct GNUNET_REGEX_Edge *edges)
{
  int i;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Iterating...\n");
  for (i = 0; i < num_edges; i++)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Edge %i: %s\n", i, edges[i].label);
  }

  if (NULL != proof)
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Proof: %s\n", proof);
}

int
main (int argc, char *argv[])
{
  GNUNET_log_setup ("test-regex",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);

  int error;
  const char *regex;
  struct GNUNET_REGEX_Automaton *dfa;
  struct GNUNET_REGEX_Automaton *nfa;

  error = 0;
  /*regex = "ab?|xy|(abcd)?"; */
  /*regex = "(ab|cd|ef)xy"; */
  /*regex = "(ac|bc)de"; */
  /*regex = "((a|b)c)de"; */
  /*regex = "a+X*y+c|p|R|Z*K*y*R+w|Y*6+n+h*k*w+V*F|W*B*e*"; */
  regex = "ab(c|d)+c*(a(b|c)d)+";
  /*regex = "ab?(abcd)?"; */
  const char *regex1 = "(ac|bc)de";
  const char *regex2 = "((a|b)c)de";

  /*nfa = GNUNET_REGEX_construct_nfa (regex, strlen (regex)); */
  /*GNUNET_REGEX_automaton_save_graph (nfa, "nfa.dot"); */
  dfa = GNUNET_REGEX_construct_dfa (regex, strlen (regex));
  GNUNET_REGEX_automaton_save_graph (dfa, "dfa.dot");
  GNUNET_REGEX_iterate_all_edges (dfa, key_iterator, NULL);
  GNUNET_REGEX_automaton_destroy (dfa);
  dfa = GNUNET_REGEX_construct_dfa (regex1, strlen (regex1));
  GNUNET_REGEX_automaton_save_graph (dfa, "dfa1.dot");
  GNUNET_REGEX_automaton_destroy (dfa);
  dfa = GNUNET_REGEX_construct_dfa (regex2, strlen (regex2));
  GNUNET_REGEX_automaton_save_graph (dfa, "dfa2.dot");
  GNUNET_REGEX_automaton_destroy (dfa);

  return error;
}
