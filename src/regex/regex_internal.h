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
 * Transition between two states. Each state can have 0-n transitions.  If label
 * is 0, this is considered to be an epsilon transition.
 */
struct GNUNET_REGEX_Transition
{
  /**
   * This is a linked list.
   */
  struct GNUNET_REGEX_Transition *prev;

  /**
   * This is a linked list.
   */
  struct GNUNET_REGEX_Transition *next;

  /**
   * Unique id of this transition.
   */
  unsigned int id;

  /**
   * Label for this transition. This is basically the edge label for the graph.
   */
  char *label;

  /**
   * State to which this transition leads.
   */
  struct GNUNET_REGEX_State *to_state;

  /**
   * State from which this transition origins.
   */
  struct GNUNET_REGEX_State *from_state;
};


/**
 * A state. Can be used in DFA and NFA automatons.
 */
struct GNUNET_REGEX_State
{
  /**
   * This is a linked list.
   */
  struct GNUNET_REGEX_State *prev;

  /**
   * This is a linked list.
   */
  struct GNUNET_REGEX_State *next;

  /**
   * Unique state id.
   */
  unsigned int id;

  /**
   * Unique state id that is used for traversing the automaton. It is guaranteed
   * to be > 0 and < state_count.
   */
  unsigned int traversal_id;

  /**
   * If this is an accepting state or not.
   */
  int accepting;

  /**
   * Marking of the state. This is used for marking all visited states when
   * traversing all states of an automaton and for cases where the state id
   * cannot be used (dfa minimization).
   */
  int marked;

  /**
   * Marking the state as contained. This is used for checking, if the state is
   * contained in a set in constant time
   */
  int contained;

  /**
   * Marking the state as part of an SCC (Strongly Connected Component).  All
   * states with the same scc_id are part of the same SCC. scc_id is 0, if state
   * is not a part of any SCC.
   */
  unsigned int scc_id;

  /**
   * Used for SCC detection.
   */
  int index;

  /**
   * Used for SCC detection.
   */
  int lowlink;

  /**
   * Human readable name of the automaton. Used for debugging and graph
   * creation.
   */
  char *name;

  /**
   * Hash of the state.
   */
  struct GNUNET_HashCode hash;

  /**
   * Linear state ID accquired by depth-first-search. This ID should be used for
   * storing information about the state in an array, because the 'id' of the
   * state is not guaranteed to be linear. The 'dfs_id' is guaranteed to be > 0
   * and < 'state_count'.
   */
  unsigned int dfs_id;

  /**
   * Proof for this state.
   */
  char *proof;

  /**
   * Number of transitions from this state to other states.
   */
  unsigned int transition_count;

  /**
   * DLL of transitions.
   */
  struct GNUNET_REGEX_Transition *transitions_head;

  /**
   * DLL of transitions.
   */
  struct GNUNET_REGEX_Transition *transitions_tail;

  /**
   * Set of states on which this state is based on. Used when creating a DFA out
   * of several NFA states.
   */
  struct GNUNET_REGEX_StateSet *nfa_set;
};


/**
 * Type of an automaton.
 */
enum GNUNET_REGEX_AutomatonType
{
  NFA,
  DFA
};


/**
 * Automaton representation.
 */
struct GNUNET_REGEX_Automaton
{
  /**
   * Linked list of NFAs used for partial NFA creation.
   */
  struct GNUNET_REGEX_Automaton *prev;

  /**
   * Linked list of NFAs used for partial NFA creation.
   */
  struct GNUNET_REGEX_Automaton *next;

  /**
   * First state of the automaton. This is mainly used for constructing an NFA,
   * where each NFA itself consists of one or more NFAs linked together.
   */
  struct GNUNET_REGEX_State *start;

  /**
   * End state of the partial NFA. This is undefined for DFAs
   */
  struct GNUNET_REGEX_State *end;

  /**
   * Number of states in the automaton.
   */
  unsigned int state_count;

  /**
   * DLL of states.
   */
  struct GNUNET_REGEX_State *states_head;

  /**
   * DLL of states
   */
  struct GNUNET_REGEX_State *states_tail;

  /**
   * Type of the automaton.
   */
  enum GNUNET_REGEX_AutomatonType type;

  /**
   * Regex
   */
  char *regex;

  /**
   * Canonical regex (result of RX->NFA->DFA->RX)
   */
  char *canonical_regex;
};


/**
 * Function that get's passed to automaton traversal and is called before each
 * next traversal from state 's' using transition 't' to check if traversal
 * should proceed. Return GNUNET_NO to stop traversal or GNUNET_YES to continue.
 *
 * @param cls closure for the check.
 * @param s current state in the traversal.
 * @param t current transition from state 's' that will be used for the next
 *          step.
 *
 * @return GNUNET_YES to proceed traversal, GNUNET_NO to stop.
 */
typedef int (*GNUNET_REGEX_traverse_check) (void *cls,
                                            struct GNUNET_REGEX_State * s,
                                            struct GNUNET_REGEX_Transition * t);


/**
 * Function that is called with each state, when traversing an automaton.
 *
 * @param cls closure.
 * @param count current count of the state, from 0 to a->state_count -1.
 * @param s state.
 */
typedef void (*GNUNET_REGEX_traverse_action) (void *cls,
                                              const unsigned int count,
                                              struct GNUNET_REGEX_State * s);


/**
 * Traverses the given automaton using depth-first-search (DFS) from it's start
 * state, visiting all reachable states and calling 'action' on each one of
 * them.
 *
 * @param a automaton to be traversed.
 * @param start start state, pass a->start or NULL to traverse the whole automaton.
 * @param check function that is checked before advancing on each transition
 *              in the DFS.
 * @param check_cls closure for check.
 * @param action action to be performed on each state.
 * @param action_cls closure for action
 */
void
GNUNET_REGEX_automaton_traverse (const struct GNUNET_REGEX_Automaton *a,
                                 struct GNUNET_REGEX_State *start,
                                 GNUNET_REGEX_traverse_check check,
                                 void *check_cls,
                                 GNUNET_REGEX_traverse_action action,
                                 void *action_cls);

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
