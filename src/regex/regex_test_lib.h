/*
 *  This file is part of GNUnet
 *  Copyright (C) 2012 Christian Grothoff (and other contributing authors)
 *
 *  GNUnet is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published
 *  by the Free Software Foundation; either version 3, or (at your
 *  option) any later version.
 *
 *  GNUnet is distributed in the hope that it will be useful, but
 *  WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GNUnet; see the file COPYING.  If not, write to the
 *  Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 *  Boston, MA 02111-1307, USA.
 */
/**
 * @file src/regex/regex_test_lib.h
 * @brief library to read regexes representing IP networks from a file.
 *        and simplifying the into one big regex, in order to run
 *        tests (regex performance, regex profiler).
 * @author Bertlomiej Polot
 */

#ifndef REGEX_INTERNAL_TEST_LIB_H
#define REGEX_INTERNAL_TEST_LIB_H

#include "regex_internal_lib.h"

#ifdef __cplusplus
extern "C"
{
  #if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * Combine an array of regexes into a single prefix-shared regex.
 *
 * @param regexes A NULL-terminated array of regexes.
 *
 * @return A string with a single regex that matches any of the original regexes
 */
char *
REGEX_TEST_combine(char * const regexes[]);


/**
 * Read a set of regexes from a file, one per line and return them in an array
 * suitable for REGEX_TEST_combine.
 * The array must be free'd using REGEX_TEST_free_from_file.
 *
 * @param filename Name of the file containing the regexes.
 *
 * @return A newly allocated, NULL terminated array of regexes.
 */
char **
REGEX_TEST_read_from_file (const char *filename);


/**
 * Free all memory reserved for a set of regexes created by read_from_file.
 *
 * @param regexes NULL-terminated array of regexes.
 */
void
REGEX_TEST_free_from_file (char **regexes);


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
REGEX_TEST_generate_random_regex (size_t rx_length, char *matching_str);


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
REGEX_TEST_generate_random_string (size_t max_len);


/**
 * Options for graph creation function
 * REGEX_TEST_automaton_save_graph.
 */
enum REGEX_TEST_GraphSavingOptions
{
  /**
   * Default. Do nothing special.
   */
  REGEX_TEST_GRAPH_DEFAULT = 0,

  /**
   * The generated graph will include extra information such as the NFA states
   * that were used to generate the DFA state.
   */
  REGEX_TEST_GRAPH_VERBOSE = 1,

  /**
   * Enable graph coloring. Will color each SCC in a different color.
   */
  REGEX_TEST_GRAPH_COLORING = 2
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
REGEX_TEST_automaton_save_graph (struct REGEX_INTERNAL_Automaton *a,
                                   const char *filename,
                                   enum REGEX_TEST_GraphSavingOptions options);



#if 0                           /* keep Emacsens' auto-indent happy */
{
  #endif
  #ifdef __cplusplus
}
#endif

/* end of regex_internal_lib.h */
#endif
