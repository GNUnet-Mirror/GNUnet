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
#include "regex_internal.h"

static unsigned int transition_counter;

void
key_iterator (void *cls, const struct GNUNET_HashCode *key, const char *proof,
              int accepting, unsigned int num_edges,
              const struct GNUNET_REGEX_Edge *edges)
{
  unsigned int i;
  int *error = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Iterating... (accepting: %i)\n",
              accepting);

  if (NULL != proof)
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Proof: %s\n", proof);

  if (NULL != key)
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Hash: %s\n", GNUNET_h2s (key));

  for (i = 0; i < num_edges; i++)
  {
    transition_counter++;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Edge %i: Label: %s Destination: %s\n",
                i, edges[i].label, GNUNET_h2s (&edges[i].destination));
  }

  *error += (GNUNET_OK == GNUNET_REGEX_check_proof (proof, key)) ? 0 : 1;
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
  int i;
  struct GNUNET_REGEX_Automaton *dfa;
  unsigned int num_transitions;

  error = 0;

  const char *regex[17] = {
    "ab(c|d)+c*(a(b|c)+d)+(bla)+",
    "(bla)*",
    "b(lab)*la",
    "(ab)*",
    "ab(c|d)+c*(a(b|c)+d)+(bla)(bla)*",
    "z(abc|def)?xyz",
    "1*0(0|1)*",
    "a*b*",
    "a+X*y+c|p|R|Z*K*y*R+w|Y*6+n+h*k*w+V*F|W*B*e*",
    "abcd:(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1):(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)",
    "abc(1|0)*def",
    "ab|ac",
    "(ab)(ab)*",
    "ab|cd|ef|gh",
    "a|b|c|d|e|f|g",
    "(ab)|(ac)",
    "x*|(0|1|2)(a|b|c|d)"
  };

  for (i = 0; i < 17; i++)
  {
    transition_counter = 0;
    dfa = GNUNET_REGEX_construct_dfa (regex[i], strlen (regex[i]));
    GNUNET_REGEX_iterate_all_edges (dfa, key_iterator, &error);
    num_transitions = GNUNET_REGEX_get_transition_count (dfa);
    if (transition_counter != num_transitions)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Automaton has %d transitions, iterated over %d transitions\n",
                  num_transitions, transition_counter);
    }
    GNUNET_REGEX_automaton_destroy (dfa);
  }

  for (i = 0; i < 17; i++)
  {
    dfa = GNUNET_REGEX_construct_dfa (regex[i], strlen (regex[i]));
    GNUNET_REGEX_add_multi_strides_to_dfa (NULL, dfa, 2);
    GNUNET_REGEX_iterate_all_edges (dfa, key_iterator, &error);
    GNUNET_REGEX_automaton_destroy (dfa);
  }

  return error;
}
