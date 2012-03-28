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
 * @file regex/test_regex.c
 * @brief test for regex.c
 * @author Maximilian Szengel
 */
#include "platform.h"
#include "gnunet_regex_lib.h"

static int err = 0;

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

  struct GNUNET_REGEX_Automaton *nfa;
  struct GNUNET_REGEX_Automaton *dfa;
  char *regex;

  nfa = NULL;
  dfa = NULL;

  regex = "a\\*b(c|d)+c*(a(b|c)d)+";
  /*regex = "\\*a(a|b)b"; */
  /*regex = "a(a|b)c"; */
  /*regex = "(a|aa)+"; */
  nfa = GNUNET_REGEX_construct_nfa (regex, strlen (regex));

  if (nfa)
  {
    GNUNET_REGEX_automaton_save_graph (nfa, "nfa_graph.dot");
    GNUNET_REGEX_automaton_destroy (nfa);
  }
  else
    err = 1;

  dfa = GNUNET_REGEX_construct_dfa (regex, strlen (regex));
  if (dfa)
  {
    GNUNET_REGEX_automaton_save_graph (dfa, "dfa_graph.dot");
    GNUNET_REGEX_automaton_destroy (dfa);
  }
  return err;
}
