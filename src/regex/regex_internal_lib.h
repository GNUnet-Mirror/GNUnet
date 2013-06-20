/*
     This file is part of GNUnet
     (C) 2012, 2013 Christian Grothoff (and other contributing authors)

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
 * @file regex/regex_internal_lib.h
 * @brief library to parse regular expressions into dfa
 * @author Maximilian Szengel
 *
 */

#ifndef REGEX_INTERNAL_LIB_H
#define REGEX_INTERNAL_LIB_H

#include "gnunet_util_lib.h"
#include "gnunet_dht_service.h"
#include "gnunet_statistics_service.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif




/**
 * Automaton (NFA/DFA) representation.
- */
struct REGEX_ITERNAL_Automaton;


/**
 * Edge representation.
 */
struct REGEX_ITERNAL_Edge
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
 * @return DFA, needs to be freed using REGEX_ITERNAL_automaton_destroy.
 */
struct REGEX_ITERNAL_Automaton *
REGEX_ITERNAL_construct_dfa (const char *regex, const size_t len,
                            unsigned int max_path_len);


/**
 * Free the memory allocated by constructing the REGEX_ITERNAL_Automaton.
 * data structure.
 *
 * @param a automaton to be destroyed.
 */
void
REGEX_ITERNAL_automaton_destroy (struct REGEX_ITERNAL_Automaton *a);


/**
 * Options for graph creation function
 * REGEX_ITERNAL_automaton_save_graph.
 */
enum REGEX_ITERNAL_GraphSavingOptions
{
  /**
   * Default. Do nothing special.
   */
  REGEX_ITERNAL_GRAPH_DEFAULT = 0,

  /**
   * The generated graph will include extra information such as the NFA states
   * that were used to generate the DFA state.
   */
  REGEX_ITERNAL_GRAPH_VERBOSE = 1,

  /**
   * Enable graph coloring. Will color each SCC in a different color.
   */
  REGEX_ITERNAL_GRAPH_COLORING = 2
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
REGEX_ITERNAL_automaton_save_graph (struct REGEX_ITERNAL_Automaton *a,
                                   const char *filename,
                                   enum REGEX_ITERNAL_GraphSavingOptions options);


/**
 * Evaluates the given 'string' against the given compiled regex.
 *
 * @param a automaton.
 * @param string string to check.
 *
 * @return 0 if string matches, non 0 otherwise.
 */
int
REGEX_ITERNAL_eval (struct REGEX_ITERNAL_Automaton *a,
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
REGEX_ITERNAL_get_first_key (const char *input_string, size_t string_len,
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
REGEX_ITERNAL_check_proof (const char *proof,
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
typedef void (*REGEX_ITERNAL_KeyIterator)(void *cls,
                                         const struct GNUNET_HashCode *key,
                                         const char *proof,
                                         int accepting,
                                         unsigned int num_edges,
                                         const struct REGEX_ITERNAL_Edge *edges);


/**
 * Iterate over all edges starting from start state of automaton 'a'. Calling
 * iterator for each edge.
 *
 * @param a automaton.
 * @param iterator iterator called for each edge.
 * @param iterator_cls closure.
 */
void
REGEX_ITERNAL_iterate_all_edges (struct REGEX_ITERNAL_Automaton *a,
                                REGEX_ITERNAL_KeyIterator iterator,
                                void *iterator_cls);



/**
 * Handle to store cached data about a regex announce.
 */
struct REGEX_ITERNAL_Announcement;

/**
 * Handle to store data about a regex search.
 */
struct REGEX_ITERNAL_Search;

/**
 * Announce a regular expression: put all states of the automaton in the DHT.
 * Does not free resources, must call REGEX_ITERNAL_announce_cancel for that.
 * 
 * @param dht An existing and valid DHT service handle. CANNOT be NULL.
 * @param id ID to announce as provider of regex. Own ID in most cases.
 * @param regex Regular expression to announce.
 * @param compression How many characters per edge can we squeeze?
 * @param stats Optional statistics handle to report usage. Can be NULL.
 * 
 * @return Handle to reuse o free cached resources.
 *         Must be freed by calling REGEX_ITERNAL_announce_cancel.
 */
struct REGEX_ITERNAL_Announcement *
REGEX_ITERNAL_announce (struct GNUNET_DHT_Handle *dht,
                       const struct GNUNET_PeerIdentity *id,
                       const char *regex,
                       uint16_t compression,
                       struct GNUNET_STATISTICS_Handle *stats);

/**
 * Announce again a regular expression previously announced.
 * Does use caching to speed up process.
 * 
 * @param h Handle returned by a previous REGEX_ITERNAL_announce call.
 */
void
REGEX_ITERNAL_reannounce (struct REGEX_ITERNAL_Announcement *h);


/**
 * Clear all cached data used by a regex announce.
 * Does not close DHT connection.
 * 
 * @param h Handle returned by a previous REGEX_ITERNAL_announce call.
 */
void
REGEX_ITERNAL_announce_cancel (struct REGEX_ITERNAL_Announcement *h);


/**
 * Search callback function.
 *
 * @param cls Closure provided in REGEX_ITERNAL_search.
 * @param id Peer providing a regex that matches the string.
 * @param get_path Path of the get request.
 * @param get_path_length Lenght of get_path.
 * @param put_path Path of the put request.
 * @param put_path_length Length of the put_path.
 */
typedef void (*REGEX_ITERNAL_Found)(void *cls,
                                   const struct GNUNET_PeerIdentity *id,
                                   const struct GNUNET_PeerIdentity *get_path,
                                   unsigned int get_path_length,
                                   const struct GNUNET_PeerIdentity *put_path,
                                   unsigned int put_path_length);


/**
 * Search for a peer offering a regex matching certain string in the DHT.
 * The search runs until REGEX_ITERNAL_search_cancel is called, even if results
 * are returned.
 *
 * @param dht An existing and valid DHT service handle.
 * @param string String to match against the regexes in the DHT.
 * @param callback Callback for found peers.
 * @param callback_cls Closure for @c callback.
 * @param stats Optional statistics handle to report usage. Can be NULL.
 * 
 * @return Handle to stop search and free resources.
 *         Must be freed by calling REGEX_ITERNAL_search_cancel.
 */
struct REGEX_ITERNAL_Search *
REGEX_ITERNAL_search (struct GNUNET_DHT_Handle *dht,
                     const char *string,
                     REGEX_ITERNAL_Found callback,
                     void *callback_cls,
                     struct GNUNET_STATISTICS_Handle *stats);

/**
 * Stop search and free all data used by a REGEX_ITERNAL_search call.
 * Does not close DHT connection.
 * 
 * @param h Handle returned by a previous REGEX_ITERNAL_search call.
 */
void
REGEX_ITERNAL_search_cancel (struct REGEX_ITERNAL_Search *h);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* end of regex_internal_lib.h */
#endif
