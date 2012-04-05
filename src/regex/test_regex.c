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
#include <time.h>
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
  int string_count;
  char **strings;
  enum Match_Result *expected_results;
};

int
test_random (unsigned int rx_length, unsigned int max_str_len, unsigned int str_count)
{
  int i;
  int rx_exp;
  char rand_rx[rx_length+1];
  char matching_str[str_count][max_str_len+1];
  char *rand_rxp;
  char *matching_strp;
  int char_op_switch;
  int last_was_op;
  char current_char;
  int eval;
  int eval_check;
  struct GNUNET_REGEX_Automaton *dfa;
  regex_t rx;
  regmatch_t matchptr[1];
  int char_offset;
  char error[200];
  int result;

  // At least one string is needed for matching
  GNUNET_assert (str_count > 0);
  // The string should be at least as long as the regex itself
  GNUNET_assert (max_str_len >= rx_length);

  rand_rxp = rand_rx;
  matching_strp = matching_str[0];

  // Generate random regex and a string that matches the regex
  for (i=0; i<rx_length; i++)
  {
    char_op_switch = 0 + (int)(1.0 * rand() / (RAND_MAX + 1.0));
    char_offset = (rand()%2) ? 65 : 97;

    if (0 == char_op_switch
        && !last_was_op)
    {
      last_was_op = 1;
      rx_exp = rand () % 3;

      switch (rx_exp)
      {
        case 0:
          current_char = '+';
          break;
        case 1:
          current_char = '*';
          break;
        case 2:
          if (i < rx_length -1)
            current_char = '|';
          else
            current_char = (char)(char_offset + (int)( 25.0 * rand() / (RAND_MAX + 1.0)));
          break;
      }
    }
    else
    {
      current_char = (char)(char_offset + (int)( 25.0 * rand() / (RAND_MAX + 1.0)));
      last_was_op = 0;
    }

    if (current_char != '+'
        && current_char != '*'
        && current_char != '|')
    {
      *matching_strp = current_char;
      matching_strp++;
    }

    *rand_rxp = current_char;
    rand_rxp++;
  }
  *rand_rxp = '\0';
  *matching_strp = '\0';

  result = 0;

  for (i=0; i<str_count; i++)
  {
    // Match string using DFA
    dfa = GNUNET_REGEX_construct_dfa (rand_rx, strlen (rand_rx));
    if (NULL == dfa)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Constructing DFA failed\n");
      return -1;
    }

    eval = GNUNET_REGEX_eval (dfa, matching_str[i]);
    GNUNET_REGEX_automaton_destroy (dfa);

    // Match string using glibc regex
    if (0 != regcomp (&rx, rand_rx, REG_EXTENDED))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Could not compile regex using regcomp\n");
      return -1;
    }

    eval_check = regexec (&rx, matching_str[i], 1, matchptr, 0);

    // We only want to match the whole string, because that's what our DFA does, too.
    if (eval_check == 0 && (matchptr[0].rm_so != 0 || matchptr[0].rm_eo != strlen (matching_str[i])))
      eval_check = 1;

    // compare result
    if (eval_check != eval)
    {
      regerror (eval_check, &rx, error, sizeof error);
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Unexpected result:\nregex: %s\nstring: %s\ngnunet regex: %i\nglibc regex: %i\nglibc error: %s\n\n",
                  rand_rx, matching_str, eval, eval_check, error);
      result += 1;
    }
  }
  return result;
}

int
test_automaton (struct GNUNET_REGEX_Automaton *a, regex_t *rx, struct Regex_String_Pair *rxstr)
{
  int result;
  int eval;
  int eval_check;
  char error[200];
  int i;

  if (NULL == a)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Automaton was NULL\n");
    return 1;
  }

  result = 0;

  for (i=0; i<rxstr->string_count; i++)
  {
    eval = GNUNET_REGEX_eval (a, rxstr->strings[i]);
    eval_check = regexec (rx, rxstr->strings[i], 0, NULL, 0);

    if ((rxstr->expected_results[i] == match
         && (0 != eval || 0 != eval_check))
        ||
        (rxstr->expected_results[i] == nomatch
         && (0 == eval || 0 == eval_check)))
    {
        result = 1;
        regerror (eval_check, rx, error, sizeof error);
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    "Unexpected result:\nregex: %s\nstring: %s\nexpected result: %i\ngnunet regex: %i\nglibc regex: %i\nglibc error: %s\n\n",
                    rxstr->regex, rxstr->strings[i], rxstr->expected_results[i], eval, eval_check, error);
    }
  }
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
  int check_rand;
  struct Regex_String_Pair rxstr[3];
  struct GNUNET_REGEX_Automaton *a;
  regex_t rx;
  int i;

  check_nfa = 0;
  check_dfa = 0;
  check_rand = 0;

  rxstr[0].regex = "ab(c|d)+c*(a(b|c)d)+";
  rxstr[0].string_count = 5;
  rxstr[0].strings = GNUNET_malloc (sizeof (char *) * rxstr[0].string_count);
  rxstr[0].strings[0] = "abcdcdcdcdddddabd";
  rxstr[0].strings[1] = "abcd";
  rxstr[0].strings[2] = "abcddddddccccccccccccccccccccccccabdacdabd";
  rxstr[0].strings[3] = "abccccca";
  rxstr[0].strings[4] = "abcdcdcdccdabdabd";
  rxstr[0].expected_results = GNUNET_malloc (sizeof (enum Match_Result) * rxstr[0].string_count);
  rxstr[0].expected_results[0] = match;
  rxstr[0].expected_results[1] = nomatch;
  rxstr[0].expected_results[2] = match;
  rxstr[0].expected_results[3] = nomatch;
  rxstr[0].expected_results[4] = match;

  for (i=0; i<1; i++)
  {
    if (0 != regcomp (&rx, rxstr->regex, REG_EXTENDED | REG_NOSUB))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Could not compile regex using regcomp()\n");
      return 1;
    }

    // NFA test
    a = GNUNET_REGEX_construct_nfa (rxstr[i].regex, strlen (rxstr[i].regex));
    check_nfa += test_automaton (a, &rx, &rxstr[i]);
    GNUNET_REGEX_automaton_destroy (a);

    // DFA test
    a = GNUNET_REGEX_construct_dfa (rxstr[i].regex, strlen (rxstr[i].regex));
    check_dfa += test_automaton (a, &rx, &rxstr[i]);
    GNUNET_REGEX_automaton_destroy (a);

    regfree (&rx);
  }

  srand (time(NULL));
  for (i=0; i< 100; i++)
    check_rand += test_random (100, 100, 1);

  return check_nfa + check_dfa + check_rand;
}
