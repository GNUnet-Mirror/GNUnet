/*
     This file is part of GNUnet
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
#include "regex_internal_lib.h"
#include "regex_test_lib.h"
#include "regex_internal.h"

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


/**
 * Random regex test. Generate a random regex as well as 'str_count' strings to
 * match it against. Will match using GNUNET_REGEX implementation and compare
 * the result to glibc regex result. 'rx_length' has to be smaller then
 * 'max_str_len'.
 *
 * @param rx_length length of the regular expression.
 * @param max_str_len maximum length of the random strings.
 * @param str_count number of generated random strings.
 *
 * @return 0 on success, non 0 otherwise.
 */
int
test_random (unsigned int rx_length, unsigned int max_str_len,
             unsigned int str_count)
{
  unsigned int i;
  char *rand_rx;
  char *matching_str;
  int eval;
  int eval_check;
  int eval_canonical;
  int eval_canonical_check;
  struct REGEX_INTERNAL_Automaton *dfa;
  regex_t rx;
  regmatch_t matchptr[1];
  char error[200];
  int result;
  char *canonical_regex = NULL;

  /* At least one string is needed for matching */
  GNUNET_assert (str_count > 0);
  /* The string should be at least as long as the regex itself */
  GNUNET_assert (max_str_len >= rx_length);

  /* Generate random regex and a string that matches the regex */
  matching_str = GNUNET_malloc (rx_length + 1);
  rand_rx = REGEX_TEST_generate_random_regex (rx_length, matching_str);

  /* Now match */
  result = 0;
  for (i = 0; i < str_count; i++)
  {
    if (0 < i)
    {
      matching_str = REGEX_TEST_generate_random_string (max_str_len);
    }

    /* Match string using DFA */
    dfa = REGEX_INTERNAL_construct_dfa (rand_rx, strlen (rand_rx), 0);
    if (NULL == dfa)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Constructing DFA failed\n");
      goto error;
    }

    eval = REGEX_INTERNAL_eval (dfa, matching_str);
    /* save the canonical regex for later comparison */
    canonical_regex = GNUNET_strdup (REGEX_INTERNAL_get_canonical_regex (dfa));
    REGEX_INTERNAL_automaton_destroy (dfa);

    /* Match string using glibc regex */
    if (0 != regcomp (&rx, rand_rx, REG_EXTENDED))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Could not compile regex using regcomp: %s\n", rand_rx);
      goto error;
    }

    eval_check = regexec (&rx, matching_str, 1, matchptr, 0);
    regfree (&rx);

    /* We only want to match the whole string, because that's what our DFA does,
     * too. */
    if (eval_check == 0 &&
        (matchptr[0].rm_so != 0 || matchptr[0].rm_eo != strlen (matching_str)))
      eval_check = 1;

    /* Match canonical regex */
    dfa =
        REGEX_INTERNAL_construct_dfa (canonical_regex, strlen (canonical_regex),
                                    0);
    if (NULL == dfa)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Constructing DFA failed\n");
      goto error;
    }

    eval_canonical = REGEX_INTERNAL_eval (dfa, matching_str);
    REGEX_INTERNAL_automaton_destroy (dfa);

    if (0 != regcomp (&rx, canonical_regex, REG_EXTENDED))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Could not compile regex using regcomp: %s\n",
                  canonical_regex);
      goto error;
    }

    eval_canonical_check = regexec (&rx, matching_str, 1, matchptr, 0);
    regfree (&rx);

    /* We only want to match the whole string, because that's what our DFA does,
     * too. */
    if (eval_canonical_check == 0 &&
        (matchptr[0].rm_so != 0 || matchptr[0].rm_eo != strlen (matching_str)))
      eval_canonical_check = 1;

    /* compare results */
    if (eval_check != eval || eval_canonical != eval_canonical_check)
    {
      regerror (eval_check, &rx, error, sizeof error);
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Unexpected result:\nregex: %s\ncanonical_regex: %s\n\
                   string: %s\ngnunet regex: %i\nglibc regex: %i\n\
                   canonical regex: %i\ncanonical regex glibc: %i\n\
                   glibc error: %s\n\n", rand_rx, canonical_regex, matching_str,
                  eval, eval_check, eval_canonical, eval_canonical_check, error);
      result += 1;
    }
    GNUNET_free (canonical_regex);
    GNUNET_free (matching_str);
    canonical_regex = NULL;
    matching_str = NULL;
  }

  GNUNET_free (rand_rx);

  return result;

error:
  GNUNET_free_non_null (matching_str);
  GNUNET_free_non_null (rand_rx);
  GNUNET_free_non_null (canonical_regex);
  return -1;
}

/**
 * Automaton test that compares the result of matching regular expression 'rx'
 * with the strings and expected results in 'rxstr' with the result of matching
 * the same strings with glibc regex.
 *
 * @param a automaton.
 * @param rx compiled glibc regex.
 * @param rxstr regular expression and strings with expected results to
 *              match against.
 *
 * @return 0 on successfull, non 0 otherwise
 */
int
test_automaton (struct REGEX_INTERNAL_Automaton *a, regex_t * rx,
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
    eval = REGEX_INTERNAL_eval (a, rxstr->strings[i]);
    eval_check = regexec (rx, rxstr->strings[i], 1, matchptr, 0);

    /* We only want to match the whole string, because that's what our DFA does,
     * too. */
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
                  "Unexpected result:\nregex: %s\ncanonical_regex: %s\n"
                  "string: %s\nexpected result: %i\n"
                  "gnunet regex: %i\nglibc regex: %i\nglibc error: %s\n"
                  "rm_so: %i\nrm_eo: %i\n\n", rxstr->regex,
                  REGEX_INTERNAL_get_canonical_regex (a), rxstr->strings[i],
                  rxstr->expected_results[i], eval, eval_check, error,
                  matchptr[0].rm_so, matchptr[0].rm_eo);
    }
  }
  return result;
}

int
main (int argc, char *argv[])
{
  GNUNET_log_setup ("test-regex", "WARNING", NULL);

  struct REGEX_INTERNAL_Automaton *a;
  regex_t rx;
  int i;
  int check_nfa;
  int check_dfa;
  int check_rand;
  char *check_proof;

  struct Regex_String_Pair rxstr[19] = {
    {"ab?(abcd)?", 5,
     {"ababcd", "abab", "aabcd", "a", "abb"},
     {match, nomatch, match, match, nomatch}},
    {"ab(c|d)+c*(a(b|c)d)+", 5,
     {"abcdcdcdcdddddabd", "abcd",
      "abcddddddccccccccccccccccccccccccabdacdabd",
      "abccccca", "abcdcdcdccdabdabd"},
     {match, nomatch, match, nomatch, match}},
    {"ab+c*(a(bx|c)d)+", 5,
     {"abcdcdcdcdddddabd", "abcd",
      "abcddddddccccccccccccccccccccccccabdacdabd",
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
    {"(bla)*", 8,
     {"", "bla", "blabla", "bl", "la", "b", "l", "a"},
     {match, match, match, nomatch, nomatch, nomatch, nomatch, nomatch}},
    {"ab(c|d)+c*(a(b|c)+d)+(bla)(bla)*", 8,
     {"ab", "abcabdbla", "abdcccccccccccabcbccdblablabla", "bl", "la", "b",
      "l",
      "a"},
     {nomatch, match, match, nomatch, nomatch, nomatch, nomatch, nomatch}},
    {"a|aa*a", 6,
     {"", "a", "aa", "aaa", "aaaa", "aaaaa"},
     {nomatch, match, match, match, match, match}},
    {"ab(c|d)+c*(a(b|c)+d)+(bla)+", 1,
     {"abcabdblaacdbla"},
     {nomatch}},
    {"(ac|b)+", 8,
     {"b", "bb", "ac", "", "acb", "bacbacac", "acacac", "abc"},
     {match, match, match, nomatch, match, match, match, nomatch}},
    {"(ab|c)+", 7,
     {"", "ab", "c", "abc", "ababcc", "acc", "abac"},
     {nomatch, match, match, match, match, nomatch, nomatch}},
    {"((j|2j)K|(j|2j)AK|(j|2j)(D|e|(j|2j)A(D|e))D*K)", 1,
     {"", "2j2jADK", "j2jADK"},
     {nomatch, match, match}},
    {"((j|2j)K|(j|2j)(D|e|((j|2j)j|(j|2j)2j)A(D|e))D*K|(j|2j)AK)", 2,
     {"", "2j2jjADK", "j2jADK"},
     {nomatch, match, match}},
    {"ab(c|d)+c*(a(b|c)d)+", 1,
     {"abacd"},
     {nomatch}},
    {"d|5kl", 1,
     {"d5kl"},
     {nomatch}},
    {"a()b", 1,
     {"ab"},
     {match}},
    {"GNVPN-0001-PAD(001110101001001010(0|1)*|001110101001001010000(0|1)*|001110101001001010001(0|1)*|001110101001001010010(0|1)*|001110101001001010011(0|1)*|001110101001001010100(0|1)*|001110101001001010101(0|1)*|001110101001001010110(0|1)*|001110101001001010111(0|1)*|0011101010110110(0|1)*|001110101011011000000(0|1)*|001110101011011000001(0|1)*|001110101011011000010(0|1)*|001110101011011000011(0|1)*|001110101011011000100(0|1)*|001110101011011000101(0|1)*|001110101011011000110(0|1)*|001110101011011000111(0|1)*|001110101011011001000(0|1)*|001110101011011001001(0|1)*|001110101011011001010(0|1)*|001110101011011001011(0|1)*|001110101011011001100(0|1)*|001110101011011001101(0|1)*|001110101011011001110(0|1)*|001110101011011001111(0|1)*|001110101011011010000(0|1)*|001110101011011010001(0|1)*|001110101011011010010(0|1)*|001110101011011010011(0|1)*|001110101011011010100(0|1)*|001110101011011010101(0|1)*|001110101011011010110(0|1)*|001110101011011010111(0|1)*|001110101011011011000(0|1)*|001110101011011011001(0|1)*|001110101011011011010(0|1)*|001110101011011011011(0|1)*|001110101011011011100(0|1)*|001110101011011011101(0|1)*|001110101011011011110(0|1)*|001110101011011011111(0|1)*|0011101110111101(0|1)*|001110111011110100000(0|1)*|001110111011110100001(0|1)*|001110111011110100010(0|1)*|001110111011110100011(0|1)*|001110111011110100100(0|1)*|001110111011110100101(0|1)*|001110111011110100110(0|1)*|001110111011110100111(0|1)*|001110111011110101000(0|1)*|001110111011110101001(0|1)*|001110111011110101010(0|1)*|001110111011110101011(0|1)*|001110111011110101100(0|1)*|001110111011110101101(0|1)*|001110111011110101110(0|1)*|001110111011110101111(0|1)*|001110111011110110000(0|1)*|001110111011110110001(0|1)*|001110111011110110010(0|1)*|001110111011110110011(0|1)*|001110111011110110100(0|1)*|001110111011110110101(0|1)*|001110111011110110110(0|1)*|001110111011110110111(0|1)*|001110111011110111000(0|1)*|001110111011110111001(0|1)*|001110111011110111010(0|1)*|001110111011110111011(0|1)*|001110111011110111100(0|1)*|001110111011110111101(0|1)*|001110111011110111110(0|1)*|0111010001010110(0|1)*|011101000101011000000(0|1)*|011101000101011000001(0|1)*|011101000101011000010(0|1)*|011101000101011000011(0|1)*|011101000101011000100(0|1)*|011101000101011000101(0|1)*|011101000101011000110(0|1)*|011101000101011000111(0|1)*|011101000101011001000(0|1)*|011101000101011001001(0|1)*|011101000101011001010(0|1)*|011101000101011001011(0|1)*|011101000101011001100(0|1)*|011101000101011001101(0|1)*|011101000101011001110(0|1)*|011101000101011001111(0|1)*|011101000101011010000(0|1)*|011101000101011010001(0|1)*|011101000101011010010(0|1)*|011101000101011010011(0|1)*|011101000101011010100(0|1)*|011101000101011010101(0|1)*|011101000101011010110(0|1)*|011101000101011010111(0|1)*|011101000101011011000(0|1)*|011101000101011011001(0|1)*|011101000101011011010(0|1)*|011101000101011011011(0|1)*|011101000101011011100(0|1)*|011101000101011011101(0|1)*|011101000101011011110(0|1)*|011101000101011011111(0|1)*|0111010001010111(0|1)*|011101000101011100000(0|1)*|011101000101011100001(0|1)*|011101000101011100010(0|1)*|011101000101011100011(0|1)*|011101000101011100100(0|1)*|011101000101011100101(0|1)*|011101000101011100110(0|1)*|011101000101011100111(0|1)*|011101000101011101000(0|1)*|011101000101011101001(0|1)*|011101000101011101010(0|1)*|011101000101011101011(0|1)*|011101000101011101100(0|1)*|011101000101011101101(0|1)*|011101000101011101110(0|1)*|011101000101011101111(0|1)*|011101000101011110000(0|1)*|011101000101011110001(0|1)*|011101000101011110010(0|1)*|011101000101011110011(0|1)*|011101000101011110100(0|1)*|011101000101011110101(0|1)*|011101000101011110110(0|1)*|011101000101011110111(0|1)*|011101000101011111000(0|1)*|011101000101011111001(0|1)*|011101000101011111010(0|1)*|011101000101011111011(0|1)*|011101000101011111100(0|1)*|011101000101011111101(0|1)*|011101000101011111110(0|1)*|011101000101011111111(0|1)*|0111010001011000(0|1)*|011101000101100000000(0|1)*|011101000101100000001(0|1)*|011101000101100000010(0|1)*|011101000101100000011(0|1)*|011101000101100000100(0|1)*|011101000101100000101(0|1)*|011101000101100000110(0|1)*|011101000101100000111(0|1)*|011101000101100001000(0|1)*|011101000101100001001(0|1)*|011101000101100001010(0|1)*|011101000101100001011(0|1)*|011101000101100001100(0|1)*|011101000101100001101(0|1)*|011101000101100001110(0|1)*|011101000101100001111(0|1)*|011101000101100010000(0|1)*|011101000101100010001(0|1)*|011101000101100010010(0|1)*|011101000101100010011(0|1)*|011101000101100010100(0|1)*|011101000101100010101(0|1)*|011101000101100010110(0|1)*|011101000101100010111(0|1)*|011101000101100011000(0|1)*|011101000101100011001(0|1)*|011101000101100011010(0|1)*|011101000101100011011(0|1)*|011101000101100011100(0|1)*|011101000101100011101(0|1)*|011101000101100011110(0|1)*|011101000101100011111(0|1)*|01110100010110010(0|1)*|011101000101100100000(0|1)*|011101000101100100001(0|1)*|011101000101100100010(0|1)*|011101000101100100011(0|1)*|011101000101100100100(0|1)*|011101000101100100101(0|1)*|011101000101100100110(0|1)*|011101000101100100111(0|1)*|011101000101100101000(0|1)*|011101000101100101001(0|1)*|011101000101100101010(0|1)*|011101000101100101011(0|1)*|011101000101100101100(0|1)*|011101000101100101101(0|1)*|011101000101100101110(0|1)*|011101000101100101111(0|1)*|011101000101100101111000(0|1)*|1100101010011100(0|1)*|110010101001110000000(0|1)*|110010101001110000000001(0|1)*|110010101001110000000010(0|1)*|110010101001110000000110(0|1)*|110010101001110000001(0|1)*|110010101001110000001000(0|1)*|110010101001110000001001(0|1)*|110010101001110000001010(0|1)*|110010101001110000001011(0|1)*|110010101001110000001101(0|1)*|110010101001110000001110(0|1)*|110010101001110000010(0|1)*|110010101001110000011(0|1)*|110010101001110000100(0|1)*|110010101001110000101(0|1)*|110010101001110000110(0|1)*|110010101001110000111(0|1)*|110010101001110001000(0|1)*|110010101001110001001(0|1)*|110010101001110001010(0|1)*|110010101001110001011(0|1)*|110010101001110001100(0|1)*|110010101001110001101(0|1)*|110010101001110001110(0|1)*|110010101001110001111(0|1)*|110010101001110010000(0|1)*|110010101001110010001(0|1)*|110010101001110010010(0|1)*|110010101001110010011(0|1)*|110010101001110010100(0|1)*|110010101001110010101(0|1)*|110010101001110010110(0|1)*|110010101001110010111(0|1)*|110010101001110011000(0|1)*|110010101001110011001(0|1)*|110010101001110011010(0|1)*|110010101001110011011(0|1)*|110010101001110011100(0|1)*|110010101001110011101(0|1)*|110010101001110011110(0|1)*|110010101001110011111(0|1)*|1101101010111010(0|1)*|110110101011101000000(0|1)*|110110101011101000000001(0|1)*|110110101011101000001000(0|1)*|110110101011101000001001(0|1)*|110110101011101000001010(0|1)*|110110101011101000001011(0|1)*|110110101011101000001100(0|1)*|110110101011101000001110(0|1)*|110110101011101000001111(0|1)*|110110101011101000010(0|1)*|110110101011101000010000(0|1)*|110110101011101000010001(0|1)*|110110101011101000010010(0|1)*|110110101011101000010011(0|1)*|110110101011101000011(0|1)*|110110101011101000100(0|1)*|110110101011101000101(0|1)*|110110101011101000110(0|1)*|110110101011101000111(0|1)*|110110101011101001000(0|1)*|110110101011101001001(0|1)*|110110101011101001010(0|1)*|110110101011101001011(0|1)*|110110101011101001100(0|1)*|110110101011101001101(0|1)*|110110101011101001110(0|1)*|110110101011101001111(0|1)*|110110101011101010000(0|1)*|110110101011101010001(0|1)*|110110101011101010010(0|1)*|110110101011101010011(0|1)*|110110101011101010100(0|1)*|110110101011101010101(0|1)*|110110101011101010110(0|1)*|110110101011101010111(0|1)*|110110101011101011000(0|1)*|110110101011101011001(0|1)*|110110101011101011010(0|1)*|110110101011101011011(0|1)*|110110101011101011100(0|1)*|110110101011101011101(0|1)*|110110101011101011110(0|1)*|110110101011101011111(0|1)*|1101101011010100(0|1)*|110110101101010000000(0|1)*|110110101101010000001(0|1)*|110110101101010000010(0|1)*|110110101101010000011(0|1)*|110110101101010000100(0|1)*|110110101101010000101(0|1)*|110110101101010000110(0|1)*|110110101101010000111(0|1)*|110110101101010001000(0|1)*|110110101101010001001(0|1)*|110110101101010001010(0|1)*|110110101101010001011(0|1)*|110110101101010001100(0|1)*|110110101101010001101(0|1)*|110110101101010001110(0|1)*|110110101101010001111(0|1)*|110110101101010010000(0|1)*|110110101101010010001(0|1)*|110110101101010010010(0|1)*|110110101101010010011(0|1)*|110110101101010010100(0|1)*|1101101011010100101000(0|1)*|110110101101010010101(0|1)*|110110101101010010110(0|1)*|110110101101010010111(0|1)*|110110101101010011000(0|1)*|110110101101010011010(0|1)*|110110101101010011011(0|1)*|110110101101010011100(0|1)*|110110101101010011101(0|1)*|110110101101010011110(0|1)*|110110101101010011111(0|1)*|1101111010100100(0|1)*|110111101010010000000(0|1)*|110111101010010000001(0|1)*|110111101010010000010(0|1)*|110111101010010000011(0|1)*|110111101010010000100(0|1)*|110111101010010000101(0|1)*|110111101010010000110(0|1)*|110111101010010000111(0|1)*|110111101010010001000(0|1)*|110111101010010001001(0|1)*|110111101010010001010(0|1)*|110111101010010001011(0|1)*|110111101010010001100(0|1)*|110111101010010001101(0|1)*|110111101010010001110(0|1)*|110111101010010001111(0|1)*|110111101010010010000(0|1)*|110111101010010010001(0|1)*|110111101010010010010(0|1)*|110111101010010010011(0|1)*|110111101010010010100(0|1)*|110111101010010010101(0|1)*|110111101010010010110(0|1)*|110111101010010010111(0|1)*|110111101010010011000(0|1)*|110111101010010011001(0|1)*|110111101010010011010(0|1)*|110111101010010011011(0|1)*|110111101010010011100(0|1)*|110111101010010011101(0|1)*|110111101010010011110(0|1)*|110111101010010011111(0|1)*|11011110101001010(0|1)*|110111101010010100000(0|1)*|110111101010010100001(0|1)*|110111101010010100010(0|1)*|110111101010010100011(0|1)*|110111101010010100100(0|1)*|110111101010010100101(0|1)*|110111101010010100110(0|1)*|110111101010010100111(0|1)*|110111101010010101000(0|1)*|110111101010010101001(0|1)*|110111101010010101010(0|1)*|110111101010010101011(0|1)*|110111101010010101100(0|1)*|110111101010010101101(0|1)*|110111101010010101110(0|1)*|110111101010010101111(0|1)*)",
     2,
     {"GNVPN-0001-PAD1101111010100101011101010101010101",
      "GNVPN-0001-PAD11001010100111000101101010101"},
     {match, match}}
  };

  check_nfa = 0;
  check_dfa = 0;
  check_rand = 0;

  for (i = 0; i < 19; i++)
  {
    if (0 != regcomp (&rx, rxstr[i].regex, REG_EXTENDED))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Could not compile regex using regcomp()\n");
      return 1;
    }

    /* NFA test */
    a = REGEX_INTERNAL_construct_nfa (rxstr[i].regex, strlen (rxstr[i].regex));
    check_nfa += test_automaton (a, &rx, &rxstr[i]);
    REGEX_INTERNAL_automaton_destroy (a);

    /* DFA test */
    a = REGEX_INTERNAL_construct_dfa (rxstr[i].regex, strlen (rxstr[i].regex), 0);
    check_dfa += test_automaton (a, &rx, &rxstr[i]);
    check_proof = GNUNET_strdup (REGEX_INTERNAL_get_canonical_regex (a));
    REGEX_INTERNAL_automaton_destroy (a);

    a = REGEX_INTERNAL_construct_dfa (check_proof, strlen (check_proof), 0);
    check_dfa += test_automaton (a, &rx, &rxstr[i]);
    REGEX_INTERNAL_automaton_destroy (a);
    if (0 != check_dfa)
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "check_proof: %s\n", check_proof);
    GNUNET_free_non_null (check_proof);

    regfree (&rx);
  }

  /* Random tests */
  srand (time (NULL));
  for (i = 0; i < 20; i++)
    check_rand += test_random (50, 60, 10);

  return check_nfa + check_dfa + check_rand;
}
