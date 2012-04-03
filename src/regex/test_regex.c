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
#include <regex.h>

#include "platform.h"
#include "gnunet_regex_lib.h"

enum Match_Result
{
  match = 0,
  nomatch = 1
};

struct Regex_String_Pair
{
  char *regex;
  char *string;
  enum Match_Result expected_result;
};


int
test_automaton (struct GNUNET_REGEX_Automaton *a, struct Regex_String_Pair *rxstr)
{
  regex_t rx;
  int result;
  int eval;
  int eval_check;

  if (NULL == a)
    return 1;

  result = 0;

  eval = GNUNET_REGEX_eval (a, rxstr->string);
  regcomp (&rx, rxstr->regex, REG_EXTENDED);
  eval_check = regexec (&rx, rxstr->string, 0, NULL, 0);

  if ((rxstr->expected_result == match
       && (0 != eval || 0 != eval_check))
      ||
      (rxstr->expected_result == nomatch
       && (0 == eval || 0 == eval_check)))
  {
      result = 1;
      char error[200];
      regerror (eval_check, &rx, error, sizeof error);
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, 
                  "Unexpected result:\nregex: %s\nstring: %s\nexpected result: %i\ngnunet regex: %i\nglibc regex: %i\nglibc error: %s\n\n", 
                  rxstr->regex, rxstr->string, rxstr->expected_result, eval, eval_check, error);
  }

  regfree (&rx);

  return result;
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

  int check_nfa;
  int check_dfa;
  struct Regex_String_Pair rxstr[3];
  struct GNUNET_REGEX_Automaton *a;
  int i;

  rxstr[0].regex = "ab(c|d)+c*(a(b|c)d)+";
  rxstr[0].string = "abcdcdcdcdddddabd";
  rxstr[0].expected_result = match;

  rxstr[1].regex = "a*";
  rxstr[1].string = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  rxstr[1].expected_result = match;

  rxstr[2].regex = "a*b*c*d+";
  rxstr[2].string = "a";
  rxstr[2].expected_result = nomatch;

  for (i=0; i<3; i++)
  {
    // NFA test
    a = GNUNET_REGEX_construct_nfa (rxstr[i].regex, strlen (rxstr[i].regex));
    check_nfa += test_automaton (a, &rxstr[i]);
    GNUNET_REGEX_automaton_destroy (a);

    // DFA test
    a = GNUNET_REGEX_construct_dfa (rxstr[i].regex, strlen (rxstr[i].regex));
    check_dfa += test_automaton (a, &rxstr[i]);
    GNUNET_REGEX_automaton_destroy (a);
  }

  return check_nfa + check_dfa;
}
