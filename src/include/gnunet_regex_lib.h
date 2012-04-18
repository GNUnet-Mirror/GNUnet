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
 * @file include/gnunet_regex_lib.h
 * @brief library to parse regular expressions into dfa
 * @author Maximilian Szengel
 *
 */

#ifndef GNUNET_REGEX_LIB_H
#define GNUNET_REGEX_LIB_H

#include "gnunet_util_lib.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * Automaton (NFA/DFA) representation.
 */
struct GNUNET_REGEX_Automaton;

/**
 * Edge representation.
 */
struct GNUNET_REGEX_Edge
{
  /**
   * Label of the edge.
   */
  const char *label;

  /**
   * Destionation of the edge.
   */
  GNUNET_HashCode destination;
};

/**
 * Construct an NFA by parsing the regex string of length 'len'.
 *
 * @param regex regular expression string.
 * @param len length of the string.
 *
 * @return NFA, needs to be freed using GNUNET_REGEX_destroy_automaton.
 */
struct GNUNET_REGEX_Automaton *
GNUNET_REGEX_construct_nfa (const char *regex, const size_t len);

/**
 * Construct DFA for the given 'regex' of length 'len'.
 *
 * @param regex regular expression string.
 * @param len length of the regular expression.
 *
 * @return DFA, needs to be freed using GNUNET_REGEX_destroy_automaton.
 */
struct GNUNET_REGEX_Automaton *
GNUNET_REGEX_construct_dfa (const char *regex, const size_t len);

/**
 * Free the memory allocated by constructing the GNUNET_REGEX_Automaton.
 * data structure.
 *
 * @param a automaton to be destroyed.
 */
void
GNUNET_REGEX_automaton_destroy (struct GNUNET_REGEX_Automaton *a);

/**
 * Save the given automaton as a GraphViz dot file.
 *
 * @param a the automaton to be saved.
 * @param filename where to save the file.
 */
void
GNUNET_REGEX_automaton_save_graph (struct GNUNET_REGEX_Automaton *a,
                                   const char *filename);

/**
 * Evaluates the given 'string' against the given compiled regex.
 *
 * @param a automaton.
 * @param string string to check.
 *
 * @return 0 if string matches, non 0 otherwise.
 */
int
GNUNET_REGEX_eval (struct GNUNET_REGEX_Automaton *a,
                   const char *string);

/**
 * Get the first key for the given 'input_string'. This hashes
 * the first x bits of the 'input_strings'.
 *
 * @param input_string string.
 * @param string_len length of the 'input_string'.
 * @param key pointer to where to write the hash code.
 *
 * @return number of bits of 'input_string' that have been consumed
 *         to construct the key
 */
unsigned int
GNUNET_REGEX_get_first_key (const char *input_string, unsigned int string_len,
                            GNUNET_HashCode * key);

/**
 * Check if the given 'proof' matches the given 'key'.
 *
 * @param proof partial regex
 * @param key hash
 *
 * @return GNUNET_OK if the proof is valid for the given key
 */
int
GNUNET_REGEX_check_proof (const char *proof,
                          const GNUNET_HashCode *key);

/**
 * Iterator callback function.
 *
 * @param cls closure.
 * @param key hash for current state.
 * @param proof proof for current state.
 * @param accepting GNUNET_YES if this is an accepting state, GNUNET_NO if not.
 * @param num_edges number of edges leaving current state.
 * @param edges edges leaving current state.
 */
typedef void (*GNUNET_REGEX_KeyIterator)(void *cls,
                                         const GNUNET_HashCode *key,
                                         const char *proof,
                                         int accepting,
                                         unsigned int num_edges,
                                         const struct GNUNET_REGEX_Edge *edges);

/**
 * Iterate over all edges starting from start state of automaton 'a'. Calling
 * iterator for each edge.
 *
 * @param a automaton.
 * @param iterator iterator called for each edge.
 * @param iterator_cls closure.
 */
void
GNUNET_REGEX_iterate_all_edges (struct GNUNET_REGEX_Automaton *a,
                                GNUNET_REGEX_KeyIterator iterator,
                                void *iterator_cls);

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* end of gnunet_regex_lib.h */
#endif

