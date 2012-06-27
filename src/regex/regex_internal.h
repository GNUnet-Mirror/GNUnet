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
 * @file src/regex/regex_internal.h
 * @brief common internal definitions for regex library
 * @author Maximilian Szengel
 */
#ifndef REGEX_INTERNAL_H
#define REGEX_INTERNAL_H

#include "gnunet_regex_lib.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * char array of literals that are allowed inside a regex (apart from the
 * operators)
 */
#define ALLOWED_LITERALS "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


/**
 * Get the canonical regex of the given automaton.
 * When constructing the automaton a proof is computed for each state,
 * consisting of the regular expression leading to this state. A complete
 * regex for the automaton can be computed by combining these proofs.
 * As of now this function is only useful for testing.
 *
 * @param a automaton for which the canonical regex should be returned.
 *
 * @return
 */
const char *
GNUNET_REGEX_get_canonical_regex (struct GNUNET_REGEX_Automaton *a);


/**
 * Generate a (pseudo) random regular expression of length 'rx_length', as well
 * as a (optional) string that will be matched by the generated regex. The
 * returned regex needs to be freed.
 *
 * @param rx_length length of the random regex.
 * @param matching_str (optional) pointer to a string that will contain a string
 *                     that will be matched by the generated regex, if
 *                     'matching_str' pointer was not NULL.
 *
 * @return NULL if 'rx_length' is 0, a random regex of length 'rx_length', which
 *         needs to be freed, otherwise.
 */
char *
GNUNET_REGEX_generate_random_regex (size_t rx_length, char *matching_str);


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
GNUNET_REGEX_generate_random_string (size_t max_len);

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif
