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
 * @file src/regex/regex_internal.h
 * @brief common internal definitions for regex library.
 * @author Maximilian Szengel
 */
#ifndef REGEX_INTERNAL_H
#define REGEX_INTERNAL_H

#include "regex_internal_lib.h"

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
 * Transition between two states. Transitions are stored at the states from
 * which they origin ('from_state'). Each state can have 0-n transitions.
 * If label is NULL, this is considered to be an epsilon transition.
 */
struct REGEX_INTERNAL_Transition
{
  /**
   * This is a linked list.
   */
  struct REGEX_INTERNAL_Transition *prev;

  /**
   * This is a linked list.
   */
  struct REGEX_INTERNAL_Transition *next;

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
  struct REGEX_INTERNAL_State *to_state;

  /**
   * State from which this transition origins.
   */
  struct REGEX_INTERNAL_State *from_state;
};


/**
 * A state. Can be used in DFA and NFA automatons.
 */
struct REGEX_INTERNAL_State;


/**
 * Set of states.
 */
struct REGEX_INTERNAL_StateSet
{
  /**
   * Array of states.
   */
  struct REGEX_INTERNAL_State **states;

  /**
   * Number of entries in *use* in the 'states' array.
   */
  unsigned int off;

  /**
   * Length of the 'states' array.
   */
  unsigned int size;
};


/**
 * A state. Can be used in DFA and NFA automatons.
 */
struct REGEX_INTERNAL_State
{
  /**
   * This is a linked list to keep states in an automaton.
   */
  struct REGEX_INTERNAL_State *prev;

  /**
   * This is a linked list to keep states in an automaton.
   */
  struct REGEX_INTERNAL_State *next;

  /**
   * This is a multi DLL for StateSet_MDLL.
   */
  struct REGEX_INTERNAL_State *prev_SS;

  /**
   * This is a multi DLL for StateSet_MDLL.
   */
  struct REGEX_INTERNAL_State *next_SS;

  /**
   * This is a multi DLL for StateSet_MDLL Stack.
   */
  struct REGEX_INTERNAL_State *prev_ST;

  /**
   * This is a multi DLL for StateSet_MDLL Stack.
   */
  struct REGEX_INTERNAL_State *next_ST;

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
   * contained in a set in constant time.
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
   * Human readable name of the state. Used for debugging and graph
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
  struct REGEX_INTERNAL_Transition *transitions_head;

  /**
   * DLL of transitions.
   */
  struct REGEX_INTERNAL_Transition *transitions_tail;

  /**
   * Number of incoming transitions. Used for compressing DFA paths.
   */
  unsigned int incoming_transition_count;

  /**
   * Set of states on which this state is based on. Used when creating a DFA out
   * of several NFA states.
   */
  struct REGEX_INTERNAL_StateSet nfa_set;
};


/**
 * Type of an automaton.
 */
enum REGEX_INTERNAL_AutomatonType
{
  NFA,
  DFA
};


/**
 * Automaton representation.
 */
struct REGEX_INTERNAL_Automaton
{
  /**
   * Linked list of NFAs used for partial NFA creation.
   */
  struct REGEX_INTERNAL_Automaton *prev;

  /**
   * Linked list of NFAs used for partial NFA creation.
   */
  struct REGEX_INTERNAL_Automaton *next;

  /**
   * First state of the automaton. This is mainly used for constructing an NFA,
   * where each NFA itself consists of one or more NFAs linked together.
   */
  struct REGEX_INTERNAL_State *start;

  /**
   * End state of the partial NFA. This is undefined for DFAs
   */
  struct REGEX_INTERNAL_State *end;

  /**
   * Number of states in the automaton.
   */
  unsigned int state_count;

  /**
   * DLL of states.
   */
  struct REGEX_INTERNAL_State *states_head;

  /**
   * DLL of states
   */
  struct REGEX_INTERNAL_State *states_tail;

  /**
   * Type of the automaton.
   */
  enum REGEX_INTERNAL_AutomatonType type;

  /**
   * Regex
   */
  char *regex;

  /**
   * Canonical regex (result of RX->NFA->DFA->RX)
   */
  char *canonical_regex;

  /**
   * GNUNET_YES, if multi strides have been added to the Automaton.
   */
  int is_multistrided;
};


/**
 * Construct an NFA by parsing the regex string of length 'len'.
 *
 * @param regex regular expression string.
 * @param len length of the string.
 *
 * @return NFA, needs to be freed using REGEX_INTERNAL_automaton_destroy.
 */
struct REGEX_INTERNAL_Automaton *
REGEX_INTERNAL_construct_nfa (const char *regex, const size_t len);


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
typedef int (*REGEX_INTERNAL_traverse_check) (void *cls,
                                            struct REGEX_INTERNAL_State * s,
                                            struct REGEX_INTERNAL_Transition * t);


/**
 * Function that is called with each state, when traversing an automaton.
 *
 * @param cls closure.
 * @param count current count of the state, from 0 to a->state_count -1.
 * @param s state.
 */
typedef void (*REGEX_INTERNAL_traverse_action) (void *cls,
                                              const unsigned int count,
                                              struct REGEX_INTERNAL_State * s);


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
REGEX_INTERNAL_automaton_traverse (const struct REGEX_INTERNAL_Automaton *a,
                                 struct REGEX_INTERNAL_State *start,
                                 REGEX_INTERNAL_traverse_check check,
                                 void *check_cls,
                                 REGEX_INTERNAL_traverse_action action,
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
 * @return canonical regex string.
 */
const char *
REGEX_INTERNAL_get_canonical_regex (struct REGEX_INTERNAL_Automaton *a);


/**
 * Get the number of transitions that are contained in the given automaton.
 *
 * @param a automaton for which the number of transitions should be returned.
 *
 * @return number of transitions in the given automaton.
 */
unsigned int
REGEX_INTERNAL_get_transition_count (struct REGEX_INTERNAL_Automaton *a);


/**
 * Context that contains an id counter for states and transitions as well as a
 * DLL of automatons used as a stack for NFA construction.
 */
struct REGEX_INTERNAL_Context
{
  /**
   * Unique state id.
   */
  unsigned int state_id;

  /**
   * Unique transition id.
   */
  unsigned int transition_id;

  /**
   * DLL of REGEX_INTERNAL_Automaton's used as a stack.
   */
  struct REGEX_INTERNAL_Automaton *stack_head;

  /**
   * DLL of REGEX_INTERNAL_Automaton's used as a stack.
   */
  struct REGEX_INTERNAL_Automaton *stack_tail;
};


/**
 * Adds multi-strided transitions to the given 'dfa'.
 *
 * @param regex_ctx regex context needed to add transitions to the automaton.
 * @param dfa DFA to which the multi strided transitions should be added.
 * @param stride_len length of the strides.
 */
void
REGEX_INTERNAL_dfa_add_multi_strides (struct REGEX_INTERNAL_Context *regex_ctx,
                                    struct REGEX_INTERNAL_Automaton *dfa,
                                    const unsigned int stride_len);



#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif
