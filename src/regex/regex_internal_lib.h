/*
     This file is part of GNUnet
     Copyright (C) 2012, 2013 Christian Grothoff (and other contributing authors)

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
 * @file regex/regex_internal_lib.h
 * @brief library to parse regular expressions into dfa
 * @author Maximilian Szengel
 */

#ifndef REGEX_INTERNAL_LIB_H
#define REGEX_INTERNAL_LIB_H

#include "gnunet_util_lib.h"
#include "gnunet_dht_service.h"
#include "gnunet_statistics_service.h"
#include "regex_block_lib.h"

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
struct REGEX_INTERNAL_Automaton;


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
 * @return DFA, needs to be freed using #REGEX_INTERNAL_automaton_destroy().
 */
struct REGEX_INTERNAL_Automaton *
REGEX_INTERNAL_construct_dfa (const char *regex,
                              const size_t len,
                              unsigned int max_path_len);


/**
 * Free the memory allocated by constructing the REGEX_INTERNAL_Automaton.
 * data structure.
 *
 * @param a automaton to be destroyed.
 */
void
REGEX_INTERNAL_automaton_destroy (struct REGEX_INTERNAL_Automaton *a);


/**
 * Evaluates the given 'string' against the given compiled regex.
 *
 * @param a automaton.
 * @param string string to check.
 *
 * @return 0 if string matches, non 0 otherwise.
 */
int
REGEX_INTERNAL_eval (struct REGEX_INTERNAL_Automaton *a,
                     const char *string);


/**
 * Get the first key for the given @a input_string. This hashes
 * the first x bits of the @a input_string.
 *
 * @param input_string string.
 * @param string_len length of the @a input_string.
 * @param key pointer to where to write the hash code.
 * @return number of bits of @a input_string that have been consumed
 *         to construct the key
 */
size_t
REGEX_INTERNAL_get_first_key (const char *input_string,
                              size_t string_len,
                              struct GNUNET_HashCode * key);


/**
 * Iterator callback function.
 *
 * @param cls closure.
 * @param key hash for current state.
 * @param proof proof for current state
 * @param accepting #GNUNET_YES if this is an accepting state, #GNUNET_NO if not.
 * @param num_edges number of edges leaving current state.
 * @param edges edges leaving current state.
 */
typedef void
(*REGEX_INTERNAL_KeyIterator)(void *cls,
                              const struct GNUNET_HashCode *key,
                              const char *proof,
                              int accepting,
                              unsigned int num_edges,
                              const struct REGEX_BLOCK_Edge *edges);


/**
 * Iterate over all edges starting from start state of automaton 'a'. Calling
 * iterator for each edge.
 *
 * @param a automaton.
 * @param iterator iterator called for each edge.
 * @param iterator_cls closure.
 */
void
REGEX_INTERNAL_iterate_all_edges (struct REGEX_INTERNAL_Automaton *a,
                                  REGEX_INTERNAL_KeyIterator iterator,
                                  void *iterator_cls);


/**
 * Iterate over all edges of automaton 'a' that are reachable from a state with
 * a proof of at least #GNUNET_REGEX_INITIAL_BYTES characters.
 *
 * Call the iterator for each such edge.
 *
 * @param a automaton.
 * @param iterator iterator called for each reachable edge.
 * @param iterator_cls closure.
 */
void
REGEX_INTERNAL_iterate_reachable_edges (struct REGEX_INTERNAL_Automaton *a,
                                        REGEX_INTERNAL_KeyIterator iterator,
                                        void *iterator_cls);



/**
 * Handle to store cached data about a regex announce.
 */
struct REGEX_INTERNAL_Announcement;

/**
 * Handle to store data about a regex search.
 */
struct REGEX_INTERNAL_Search;


/**
 * Announce a regular expression: put all states of the automaton in the DHT.
 * Does not free resources, must call #REGEX_INTERNAL_announce_cancel() for that.
 *
 * @param dht An existing and valid DHT service handle. CANNOT be NULL.
 * @param priv our private key, must remain valid until the announcement is cancelled
 * @param regex Regular expression to announce.
 * @param compression How many characters per edge can we squeeze?
 * @param stats Optional statistics handle to report usage. Can be NULL.
 * @return Handle to reuse o free cached resources.
 *         Must be freed by calling #REGEX_INTERNAL_announce_cancel().
 */
struct REGEX_INTERNAL_Announcement *
REGEX_INTERNAL_announce (struct GNUNET_DHT_Handle *dht,
			 const struct GNUNET_CRYPTO_EddsaPrivateKey *priv,
			 const char *regex,
			 uint16_t compression,
			 struct GNUNET_STATISTICS_Handle *stats);


/**
 * Announce again a regular expression previously announced.
 * Does use caching to speed up process.
 *
 * @param h Handle returned by a previous #REGEX_INTERNAL_announce() call.
 */
void
REGEX_INTERNAL_reannounce (struct REGEX_INTERNAL_Announcement *h);


/**
 * Clear all cached data used by a regex announce.
 * Does not close DHT connection.
 *
 * @param h Handle returned by a previous #REGEX_INTERNAL_announce() call.
 */
void
REGEX_INTERNAL_announce_cancel (struct REGEX_INTERNAL_Announcement *h);


/**
 * Search callback function.
 *
 * @param cls Closure provided in #REGEX_INTERNAL_search().
 * @param id Peer providing a regex that matches the string.
 * @param get_path Path of the get request.
 * @param get_path_length Length of @a get_path.
 * @param put_path Path of the put request.
 * @param put_path_length Length of the @a put_path.
 */
typedef void
(*REGEX_INTERNAL_Found)(void *cls,
                        const struct GNUNET_PeerIdentity *id,
                        const struct GNUNET_PeerIdentity *get_path,
                        unsigned int get_path_length,
                        const struct GNUNET_PeerIdentity *put_path,
                        unsigned int put_path_length);


/**
 * Search for a peer offering a regex matching certain string in the DHT.
 * The search runs until #REGEX_INTERNAL_search_cancel() is called, even if results
 * are returned.
 *
 * @param dht An existing and valid DHT service handle.
 * @param string String to match against the regexes in the DHT.
 * @param callback Callback for found peers.
 * @param callback_cls Closure for @c callback.
 * @param stats Optional statistics handle to report usage. Can be NULL.
 * @return Handle to stop search and free resources.
 *         Must be freed by calling #REGEX_INTERNAL_search_cancel().
 */
struct REGEX_INTERNAL_Search *
REGEX_INTERNAL_search (struct GNUNET_DHT_Handle *dht,
                       const char *string,
                       REGEX_INTERNAL_Found callback,
                       void *callback_cls,
                       struct GNUNET_STATISTICS_Handle *stats);

/**
 * Stop search and free all data used by a #REGEX_INTERNAL_search() call.
 * Does not close DHT connection.
 *
 * @param h Handle returned by a previous #REGEX_INTERNAL_search() call.
 */
void
REGEX_INTERNAL_search_cancel (struct REGEX_INTERNAL_Search *h);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* end of regex_internal_lib.h */
#endif
