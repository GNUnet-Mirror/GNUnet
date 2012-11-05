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
 * Constant for how many bytes the initial string regex should have.
 */
#define GNUNET_REGEX_INITIAL_BYTES 24


/**
 * Maximum regex string length for use with GNUNET_REGEX_ipv4toregex
 */
#define GNUNET_REGEX_IPV4_REGEXLEN 32 + 6


/**
 * Maximum regex string length for use with GNUNET_REGEX_ipv6toregex
 */
#define GNUNET_REGEX_IPV6_REGEXLEN 128 + 6


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
   * Label of the edge.  FIXME: might want to not consume exactly multiples of 8 bits, need length?
   */
  const char *label;

  /**
   * Destionation of the edge.
   */
  struct GNUNET_HashCode destination;
};


/**
 * Construct DFA for the given 'regex' of length 'len'.
 *
 * Path compression means, that for example a DFA o -> a -> b -> c -> o will be
 * compressed to o -> abc -> o. Note that this parameter influences the
 * non-determinism of states of the resulting NFA in the DHT (number of outgoing
 * edges with the same label). For example for an application that stores IPv4
 * addresses as bitstrings it could make sense to limit the path compression to
 * 4 or 8.
 *
 * @param regex regular expression string.
 * @param len length of the regular expression.
 * @param max_path_len limit the path compression length to the
 *        given value. If set to 1, no path compression is applied. Set to 0 for
 *        maximal possible path compression (generally not desireable).
 * @return DFA, needs to be freed using GNUNET_REGEX_automaton_destroy.
 */
struct GNUNET_REGEX_Automaton *
GNUNET_REGEX_construct_dfa (const char *regex, const size_t len,
                            int max_path_len);


/**
 * Free the memory allocated by constructing the GNUNET_REGEX_Automaton.
 * data structure.
 *
 * @param a automaton to be destroyed.
 */
void
GNUNET_REGEX_automaton_destroy (struct GNUNET_REGEX_Automaton *a);


/**
 * Options for graph creation function
 * GNUNET_REGEX_automaton_save_graph.
 */
enum GNUNET_REGEX_GraphSavingOptions
{
  /**
   * Default. Do nothing special.
   */
  GNUNET_REGEX_GRAPH_DEFAULT = 0,

  /**
   * The generated graph will include extra information such as the NFA states
   * that were used to generate the DFA state.
   */
  GNUNET_REGEX_GRAPH_VERBOSE = 1,

  /**
   * Enable graph coloring. Will color each SCC in a different color.
   */
  GNUNET_REGEX_GRAPH_COLORING = 2
};


/**
 * Save the given automaton as a GraphViz dot file.
 *
 * @param a the automaton to be saved.
 * @param filename where to save the file.
 * @param options options for graph generation that include coloring or verbose
 *                mode
 */
void
GNUNET_REGEX_automaton_save_graph (struct GNUNET_REGEX_Automaton *a,
                                   const char *filename,
                                   enum GNUNET_REGEX_GraphSavingOptions options);


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
 * the first x bits of the 'input_string'.
 *
 * @param input_string string.
 * @param string_len length of the 'input_string'.
 * @param key pointer to where to write the hash code.
 *
 * @return number of bits of 'input_string' that have been consumed
 *         to construct the key
 */
size_t
GNUNET_REGEX_get_first_key (const char *input_string, size_t string_len,
                            struct GNUNET_HashCode * key);


/**
 * Check if the given 'proof' matches the given 'key'.
 *
 * @param proof partial regex of a state.
 * @param key hash of a state.
 *
 * @return GNUNET_OK if the proof is valid for the given key.
 */
int
GNUNET_REGEX_check_proof (const char *proof,
                          const struct GNUNET_HashCode *key);


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
                                         const struct GNUNET_HashCode *key,
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


/**
 * Create a regex in 'rxstr' from the given 'ip' and 'netmask'.
 *
 * @param ip IPv4 representation.
 * @param netmask netmask for the ip.
 * @param rxstr generated regex, must be at least GNUNET_REGEX_IPV4_REGEXLEN
 *              bytes long.
 */
void
GNUNET_REGEX_ipv4toregex (const struct in_addr *ip, const char *netmask,
                          char *rxstr);


/**
 * Create a regex in 'rxstr' from the given 'ipv6' and 'prefixlen'.
 *
 * @param ipv6 IPv6 representation.
 * @param prefixlen length of the ipv6 prefix.
 * @param rxstr generated regex, must be at least GNUNET_REGEX_IPV6_REGEXLEN
 *              bytes long.
 */
void
GNUNET_REGEX_ipv6toregex (const struct in6_addr *ipv6,
                          unsigned int prefixlen, char *rxstr);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* end of gnunet_regex_lib.h */
#endif
