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
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/
/**
 * @file src/regex/regex_test_random.c
 * @brief functions for creating random regular expressions and strings
 * @author Maximilian Szengel
 */
#include "platform.h"
#include "regex_test_lib.h"
#include "gnunet_crypto_lib.h"
#include "regex_internal.h"


/**
 * Get a (pseudo) random valid literal for building a regular expression.
 *
 * @return random valid literal
 */
static char
get_random_literal ()
{
  uint32_t ridx;

  ridx =
      GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
                                (uint32_t) strlen (ALLOWED_LITERALS));

  return ALLOWED_LITERALS[ridx];
}


/**
 * Generate a (pseudo) random regular expression of length 'rx_length', as well
 * as a (optional) string that will be matched by the generated regex. The
 * returned regex needs to be freed.
 *
 * @param rx_length length of the random regex.
 * @param matching_str (optional) pointer to a string that will contain a string
 *                     that will be matched by the generated regex, if
 *                     'matching_str' pointer was not NULL. Make sure you
 *                     allocated at least rx_length+1 bytes for this sting.
 *
 * @return NULL if 'rx_length' is 0, a random regex of length 'rx_length', which
 *         needs to be freed, otherwise.
 */
char *
REGEX_TEST_generate_random_regex (size_t rx_length, char *matching_str)
{
  char *rx;
  char *rx_p;
  char *matching_strp;
  unsigned int i;
  unsigned int char_op_switch;
  unsigned int last_was_op;
  int rx_op;
  char current_char;

  if (0 == rx_length)
    return NULL;

  if (NULL != matching_str)
    matching_strp = matching_str;
  else
    matching_strp = NULL;

  rx = GNUNET_malloc (rx_length + 1);
  rx_p = rx;
  current_char = 0;
  last_was_op = 1;

  for (i = 0; i < rx_length; i++)
  {
    char_op_switch = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, 2);

    if (0 == char_op_switch && !last_was_op)
    {
      last_was_op = 1;
      rx_op = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, 4);

      switch (rx_op)
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
        if (i < rx_length - 1)  /* '|' cannot be at the end */
          current_char = '|';
        else
          current_char = get_random_literal ();
        break;
      }
    }
    else
    {
      current_char = get_random_literal ();
      last_was_op = 0;
    }

    if (NULL != matching_strp &&
        (current_char != '+' && current_char != '*' && current_char != '?' &&
         current_char != '|'))
    {
      *matching_strp = current_char;
      matching_strp++;
    }

    *rx_p = current_char;
    rx_p++;
  }
  *rx_p = '\0';
  if (NULL != matching_strp)
    *matching_strp = '\0';

  return rx;
}


/**
 * Generate a random string of maximum length 'max_len' that only contains literals allowed
 * in a regular expression. The string might be 0 chars long but is garantueed
 * to be shorter or equal to 'max_len'.
 *
 * @param max_len maximum length of the string that should be generated.
 *
 * @return random string that needs to be freed.
 */
char *
REGEX_TEST_generate_random_string (size_t max_len)
{
  unsigned int i;
  char *str;
  size_t len;

  if (1 > max_len)
    return GNUNET_strdup ("");

  len = (size_t) GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, max_len);
  str = GNUNET_malloc (len + 1);

  for (i = 0; i < len; i++)
  {
    str[i] = get_random_literal ();
  }

  str[i] = '\0';

  return str;
}
