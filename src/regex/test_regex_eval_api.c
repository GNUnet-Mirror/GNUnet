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
 * @file regex/test_regex_eval_api.c
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
  char *strings[20];
  enum Match_Result expected_results[20];
};

static const char allowed_literals[] =
    "0123456789" "ABCDEFGHIJKLMNOPQRSTUVWXYZ" "abcdefghijklmnopqrstuvwxyz";

int
test_random (unsigned int rx_length, unsigned int max_str_len,
             unsigned int str_count)
{
  int i;
  int j;
  int rx_exp;
  char rand_rx[rx_length + 1];
  char matching_str[str_count][max_str_len + 1];
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
  char error[200];
  int result;
  unsigned int str_len;

  // At least one string is needed for matching
  GNUNET_assert (str_count > 0);
  // The string should be at least as long as the regex itself
  GNUNET_assert (max_str_len >= rx_length);

  rand_rxp = rand_rx;
  matching_strp = matching_str[0];
  current_char = 0;
  last_was_op = 1;

  // Generate random regex and a string that matches the regex
  for (i = 0; i < rx_length; i++)
  {
    char_op_switch = 0 + (int) (1.0 * rand () / (RAND_MAX + 1.0));

    if (0 == char_op_switch && !last_was_op)
    {
      last_was_op = 1;
      rx_exp = rand () % 4;

      switch (rx_exp)
      {
      case 0:
        current_char = '+';
        break;
      case 1:
        current_char = '*';
        break;
      case 2:
        current_char = '?';
        break;
      case 3:
        if (i < rx_length - 1)  // '|' cannot be at the end
          current_char = '|';
        else
          current_char =
              allowed_literals[rand () % (sizeof (allowed_literals) - 1)];
        break;
      }
    }
    else
    {
      current_char =
          allowed_literals[rand () % (sizeof (allowed_literals) - 1)];
      last_was_op = 0;
    }

    if (current_char != '+' && current_char != '*' && current_char != '?' &&
        current_char != '|')
    {
      *matching_strp = current_char;
      matching_strp++;
    }

    *rand_rxp = current_char;
    rand_rxp++;
  }
  *rand_rxp = '\0';
  *matching_strp = '\0';

  // Generate some random strings for matching...
  // Start at 1, because the first string is generated above during regex generation
  for (i = 1; i < str_count; i++)
  {
    str_len = rand () % max_str_len;
    for (j = 0; j < str_len; j++)
      matching_str[i][j] =
          allowed_literals[rand () % (sizeof (allowed_literals) - 1)];
    matching_str[i][str_len] = '\0';
  }

  // Now match
  result = 0;
  for (i = 0; i < str_count; i++)
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
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Could not compile regex using regcomp\n");
      return -1;
    }

    eval_check = regexec (&rx, matching_str[i], 1, matchptr, 0);
    regfree (&rx);

    // We only want to match the whole string, because that's what our DFA does, too.
    if (eval_check == 0 &&
        (matchptr[0].rm_so != 0 ||
         matchptr[0].rm_eo != strlen (matching_str[i])))
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
test_automaton (struct GNUNET_REGEX_Automaton *a, regex_t * rx,
                struct Regex_String_Pair *rxstr)
{
  int result;
  int eval;
  int eval_check;
  char error[200];
  regmatch_t matchptr[1];
  int i;

  if (NULL == a)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Automaton was NULL\n");
    return 1;
  }

  result = 0;

  for (i = 0; i < rxstr->string_count; i++)
  {
    eval = GNUNET_REGEX_eval (a, rxstr->strings[i]);
    eval_check = regexec (rx, rxstr->strings[i], 1, matchptr, 0);

    // We only want to match the whole string, because that's what our DFA does, too.
    if (eval_check == 0 &&
        (matchptr[0].rm_so != 0 ||
         matchptr[0].rm_eo != strlen (rxstr->strings[i])))
      eval_check = 1;

    if ((rxstr->expected_results[i] == match && (0 != eval || 0 != eval_check))
        || (rxstr->expected_results[i] == nomatch &&
            (0 == eval || 0 == eval_check)))
    {
      result = 1;
      regerror (eval_check, rx, error, sizeof error);
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Unexpected result:\nregex: %s\nstring: %s\nexpected result: %i\n"
                  "gnunet regex: %i\nglibc regex: %i\nglibc error: %s\nrm_so: %i\nrm_eo: %i\n\n",
                  rxstr->regex, rxstr->strings[i], rxstr->expected_results[i],
                  eval, eval_check, error, matchptr[0].rm_so,
                  matchptr[0].rm_eo);
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

  struct GNUNET_REGEX_Automaton *a;
  regex_t rx;
  int i;
  int check_nfa;
  int check_dfa;
  int check_rand;

  struct Regex_String_Pair rxstr[8] = {
    {"ab?(abcd)?", 5,
     {"ababcd", "abab", "aabcd", "a", "abb"},
     {match, nomatch, match, match, nomatch}},
    {"ab(c|d)+c*(a(b|c)d)+", 5,
     {"abcdcdcdcdddddabd", "abcd", "abcddddddccccccccccccccccccccccccabdacdabd",
      "abccccca", "abcdcdcdccdabdabd"},
     {match, nomatch, match, nomatch, match}},
    {"ab+c*(a(bx|c)d)+", 5,
     {"abcdcdcdcdddddabd", "abcd", "abcddddddccccccccccccccccccccccccabdacdabd",
      "abccccca", "abcdcdcdccdabdabd"},
     {nomatch, nomatch, nomatch, nomatch, nomatch}},
    {"a+X*y+c|p|R|Z*K*y*R+w|Y*6+n+h*k*w+V*F|W*B*e*", 1,
     {"kaXycQepRZKyRwY6nhkwVFWBegNVtLPj39XhJJ6bEifRSZRYZg"},
     {nomatch}},
    {"k|a+X*y+c|Q*e|p|R|Z*K*y*R+w|Y*6+n+h*k*w+V*F|W*B*e*g|N+V|t+L|P*j*3*9+X*h*J|J*6|b|E*i*f*R+S|Z|R|Y*Z|g*", 1,
     {"kaXycQepRZKyRwY6nhkwVFWBegNVtLPj39XhJJ6bEifRSZRYZg"},
     {nomatch}},
    {"F?W+m+2*6*c*s|P?U?a|B|y*i+t+A|V|6*C*7*e?Z*n*i|J?5+g?W*V?7*j?p?1|r?B?C+E+3+6*i+W*P?K?0|D+7?y*m+3?g?K?", 1,
     {"osfjsodfonONONOnosndfsdnfsd"},
     {nomatch}},
    {"V|M*o?x*p*d+h+b|E*m?h?Y*E*O?W*W*P+o?Z+H*M|I*q+C*a+5?5*9|b?z|G*y*k?R|p+u|8*h?B+l*H|e|L*O|1|F?v*0?5|C+", 1,
     {"VMoxpdhbEmhYEOWWPoZHMIqCa559bzGykRpu8hBlHeLO1Fv05C"},
     {nomatch}},
    {"ab(c|d)+c*(a(b|c)d)+", 1,
     {"abacd"},
     {nomatch}}
  };

  check_nfa = 0;
  check_dfa = 0;
  check_rand = 0;

  for (i = 0; i < 8; i++)
  {
    if (0 != regcomp (&rx, rxstr[i].regex, REG_EXTENDED))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Could not compile regex using regcomp()\n");
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

  srand (time (NULL));
  for (i = 0; i < 150; i++)
    check_rand += test_random (150, 200, 25);

  return check_nfa + check_dfa + check_rand;
}
