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
 * @file regex/test_regex_proofs.c
 * @brief test for regex.c
 * @author Maximilian Szengel
 */
#include "platform.h"
#include "regex_internal_lib.h"
#include "regex_test_lib.h"
#include "regex_internal.h"


/**
 * Test if the given regex's canonical regex is the same as this canonical
 * regex's canonical regex. Confused? Ok, then: 1. construct a dfa A from the
 * given 'regex' 2. get the canonical regex of dfa A 3. construct a dfa B from
 * this canonical regex 3. compare the canonical regex of dfa A with the
 * canonical regex of dfa B.
 *
 * @param regex regular expression used for this test (see above).
 *
 * @return 0 on success, 1 on failure
 */
static unsigned int
test_proof (const char *regex)
{
  unsigned int error;
  struct REGEX_INTERNAL_Automaton *dfa;
  char *c_rx1;
  const char *c_rx2;

  dfa = REGEX_INTERNAL_construct_dfa (regex, strlen (regex), 1);
  GNUNET_assert (NULL != dfa);
  c_rx1 = GNUNET_strdup (REGEX_INTERNAL_get_canonical_regex (dfa));
  REGEX_INTERNAL_automaton_destroy (dfa);
  dfa = REGEX_INTERNAL_construct_dfa (c_rx1, strlen (c_rx1), 1);
  GNUNET_assert (NULL != dfa);
  c_rx2 = REGEX_INTERNAL_get_canonical_regex (dfa);

  error = (0 == strcmp (c_rx1, c_rx2)) ? 0 : 1;

  if (error > 0)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Comparing canonical regex of\n%s\nfailed:\n%s\nvs.\n%s\n",
                regex, c_rx1, c_rx2);
  }

  GNUNET_free (c_rx1);
  REGEX_INTERNAL_automaton_destroy (dfa);

  return error;
}


/**
 * Use 'test_proof' function to randomly test the canonical regexes of 'count'
 * random expressions of length 'rx_length'.
 *
 * @param count number of random regular expressions to test.
 * @param rx_length length of the random regular expressions.
 *
 * @return 0 on succes, number of failures otherwise.
 */
static unsigned int
test_proofs_random (unsigned int count, size_t rx_length)
{
  unsigned int i;
  char *rand_rx;
  unsigned int failures;

  failures = 0;

  for (i = 0; i < count; i++)
  {
    rand_rx = REGEX_TEST_generate_random_regex (rx_length, NULL);
    failures += test_proof (rand_rx);
    GNUNET_free (rand_rx);
  }

  return failures;
}


/**
 * Test a number of known examples of regexes for proper canonicalization.
 *
 * @return 0 on success, number of failures otherwise.
 */
static unsigned int
test_proofs_static ()
{
  unsigned int i;
  unsigned int error;

  const char *regex[8] = {
    "a|aa*a",
    "a+",
    "a*",
    "a*a*",
    "(F*C|WfPf|y+F*C)",
    "y*F*C|WfPf",
    "((a|b)c|(a|b)(d|(a|b)e))",
    "((a|b)(c|d)|(a|b)(a|b)e)"
  };

  const char *canon_rx1;
  const char *canon_rx2;
  struct REGEX_INTERNAL_Automaton *dfa1;
  struct REGEX_INTERNAL_Automaton *dfa2;

  error = 0;

  for (i = 0; i < 8; i += 2)
  {
    dfa1 = REGEX_INTERNAL_construct_dfa (regex[i], strlen (regex[i]), 1);
    dfa2 = REGEX_INTERNAL_construct_dfa (regex[i + 1], strlen (regex[i + 1]), 1);
    GNUNET_assert (NULL != dfa1);
    GNUNET_assert (NULL != dfa2);

    canon_rx1 = REGEX_INTERNAL_get_canonical_regex (dfa1);
    canon_rx2 = REGEX_INTERNAL_get_canonical_regex (dfa2);

    error += (0 == strcmp (canon_rx1, canon_rx2)) ? 0 : 1;

    if (error > 0)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Comparing canonical regex failed:\nrx1:\t%s\ncrx1:\t%s\nrx2:\t%s\ncrx2:\t%s\n",
                  regex[i], canon_rx1, regex[i + 1], canon_rx2);
    }

    REGEX_INTERNAL_automaton_destroy (dfa1);
    REGEX_INTERNAL_automaton_destroy (dfa2);
  }

  return error;
}


int
main (int argc, char *argv[])
{
  GNUNET_log_setup ("test-regex", "WARNING", NULL);

  int error;

  error = 0;

  error += test_proofs_static ();
  error += test_proofs_random (100, 30);

  return error;
}
