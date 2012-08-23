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
 * @file src/regex/regex.c
 * @brief library to create automatons from regular expressions
 * @author Maximilian Szengel
 */
#include "platform.h"
#include "gnunet_container_lib.h"
#include "gnunet_crypto_lib.h"
#include "gnunet_regex_lib.h"
#include "regex_internal.h"


/**
 * Constant for how many bits the initial string regex should have.
 */
#define INITIAL_BITS 8


/**
 * Context that contains an id counter for states and transitions as well as a
 * DLL of automatons used as a stack for NFA construction.
 */
struct GNUNET_REGEX_Context
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
   * DLL of GNUNET_REGEX_Automaton's used as a stack.
   */
  struct GNUNET_REGEX_Automaton *stack_head;

  /**
   * DLL of GNUNET_REGEX_Automaton's used as a stack.
   */
  struct GNUNET_REGEX_Automaton *stack_tail;
};


/**
 * Set of states.
 */
struct GNUNET_REGEX_StateSet
{
  /**
   * Array of states.
   */
  struct GNUNET_REGEX_State **states;

  /**
   * Length of the 'states' array.
   */
  unsigned int len;
};


/*
 * Debug helper functions
 */

/**
 * Print all the transitions of state 's'.
 *
 * @param s state for which to print it's transitions.
 */
void
debug_print_transitions (struct GNUNET_REGEX_State *s);


/**
 * Print information of the given state 's'.
 *
 * @param s state for which debug information should be printed.
 */
void
debug_print_state (struct GNUNET_REGEX_State *s)
{
  char *proof;

  if (NULL == s->proof)
    proof = "NULL";
  else
    proof = s->proof;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "State %i: %s marked: %i accepting: %i scc_id: %i transitions: %i proof: %s\n",
              s->id, s->name, s->marked, s->accepting, s->scc_id,
              s->transition_count, proof);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Transitions:\n");
  debug_print_transitions (s);
}


/**
 * Print debug information for all states contained in the automaton 'a'.
 *
 * @param a automaton for which debug information of it's states should be printed.
 */
void
debug_print_states (struct GNUNET_REGEX_Automaton *a)
{
  struct GNUNET_REGEX_State *s;

  for (s = a->states_head; NULL != s; s = s->next)
    debug_print_state (s);
}


/**
 * Print debug information for given transition 't'.
 *
 * @param t transition for which to print debug info.
 */
void
debug_print_transition (struct GNUNET_REGEX_Transition *t)
{
  char *to_state;
  char *from_state;
  char *label;

  if (NULL == t)
    return;

  if (0 == t->label)
    label = "0";
  else
    label = t->label;

  if (NULL == t->to_state)
    to_state = "NULL";
  else
    to_state = t->to_state->name;

  if (NULL == t->from_state)
    from_state = "NULL";
  else
    from_state = t->from_state->name;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Transition %i: From %s on %s to %s\n",
              t->id, from_state, label, to_state);
}


void
debug_print_transitions (struct GNUNET_REGEX_State *s)
{
  struct GNUNET_REGEX_Transition *t;

  for (t = s->transitions_head; NULL != t; t = t->next)
    debug_print_transition (t);
}


/**
 * Compare two strings for equality. If either is NULL they are not equal.
 *
 * @param str1 first string for comparison.
 * @param str2 second string for comparison.
 *
 * @return 0 if the strings are the same or both NULL, 1 or -1 if not.
 */
static int
nullstrcmp (const char *str1, const char *str2)
{
  if ((NULL == str1) != (NULL == str2))
    return -1;
  if ((NULL == str1) && (NULL == str2))
    return 0;

  return strcmp (str1, str2);
}


/**
 * Adds a transition from one state to another on 'label'. Does not add
 * duplicate states.
 *
 * @param ctx context
 * @param from_state starting state for the transition
 * @param label transition label
 * @param to_state state to where the transition should point to
 */
static void
state_add_transition (struct GNUNET_REGEX_Context *ctx,
                      struct GNUNET_REGEX_State *from_state, const char *label,
                      struct GNUNET_REGEX_State *to_state)
{
  int is_dup;
  struct GNUNET_REGEX_Transition *t;
  struct GNUNET_REGEX_Transition *oth;

  if (NULL == from_state)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Could not create Transition.\n");
    return;
  }

  // Do not add duplicate state transitions
  is_dup = GNUNET_NO;
  for (t = from_state->transitions_head; NULL != t; t = t->next)
  {
    if (t->to_state == to_state && 0 == nullstrcmp (t->label, label) &&
        t->from_state == from_state)
    {
      is_dup = GNUNET_YES;
      break;
    }
  }

  if (GNUNET_YES == is_dup)
    return;

  // sort transitions by label
  for (oth = from_state->transitions_head; NULL != oth; oth = oth->next)
  {
    if (0 < nullstrcmp (oth->label, label))
      break;
  }

  t = GNUNET_malloc (sizeof (struct GNUNET_REGEX_Transition));
  if (NULL != ctx)
    t->id = ctx->transition_id++;
  if (NULL != label)
    t->label = GNUNET_strdup (label);
  else
    t->label = NULL;
  t->to_state = to_state;
  t->from_state = from_state;

  // Add outgoing transition to 'from_state'
  from_state->transition_count++;
  GNUNET_CONTAINER_DLL_insert_before (from_state->transitions_head,
                                      from_state->transitions_tail, oth, t);
}


/**
 * Remove a 'transition' from 'state'.
 *
 * @param state state from which the to-be-removed transition originates.
 * @param transition transition that should be removed from state 'state'.
 */
static void
state_remove_transition (struct GNUNET_REGEX_State *state,
                         struct GNUNET_REGEX_Transition *transition)
{
  if (NULL == state || NULL == transition)
    return;

  if (transition->from_state != state)
    return;

  state->transition_count--;
  GNUNET_CONTAINER_DLL_remove (state->transitions_head, state->transitions_tail,
                               transition);
  GNUNET_free_non_null (transition->label);
  GNUNET_free (transition);
}


/**
 * Compare two states. Used for sorting.
 *
 * @param a first state
 * @param b second state
 *
 * @return an integer less than, equal to, or greater than zero
 *         if the first argument is considered to be respectively
 *         less than, equal to, or greater than the second.
 */
static int
state_compare (const void *a, const void *b)
{
  struct GNUNET_REGEX_State **s1;
  struct GNUNET_REGEX_State **s2;

  s1 = (struct GNUNET_REGEX_State **) a;
  s2 = (struct GNUNET_REGEX_State **) b;

  return (*s1)->id - (*s2)->id;
}


/**
 * Get all edges leaving state 's'.
 *
 * @param s state.
 * @param edges all edges leaving 's', expected to be allocated and have enough
 *        space for s->transitions_count elements.
 *
 * @return number of edges.
 */
static unsigned int
state_get_edges (struct GNUNET_REGEX_State *s, struct GNUNET_REGEX_Edge *edges)
{
  struct GNUNET_REGEX_Transition *t;
  unsigned int count;

  if (NULL == s)
    return 0;

  count = 0;

  for (t = s->transitions_head; NULL != t; t = t->next)
  {
    if (NULL != t->to_state)
    {
      edges[count].label = t->label;
      edges[count].destination = t->to_state->hash;
      count++;
    }
  }
  return count;
}


/**
 * Compare to state sets by comparing the id's of the states that are contained
 * in each set. Both sets are expected to be sorted by id!
 *
 * @param sset1 first state set
 * @param sset2 second state set
 *
 * @return an integer less than, equal to, or greater than zero
 *         if the first argument is considered to be respectively
 *         less than, equal to, or greater than the second.
 */
static int
state_set_compare (struct GNUNET_REGEX_StateSet *sset1,
                   struct GNUNET_REGEX_StateSet *sset2)
{
  int result;
  unsigned int i;

  if (NULL == sset1 || NULL == sset2)
    return 1;

  result = sset1->len - sset2->len;

  for (i = 0; i < sset1->len; i++)
  {
    if (0 != result)
      break;

    result = state_compare (&sset1->states[i], &sset2->states[i]);
  }
  return result;
}


/**
 * Clears the given StateSet 'set'
 *
 * @param set set to be cleared
 */
static void
state_set_clear (struct GNUNET_REGEX_StateSet *set)
{
  if (NULL != set)
  {
    GNUNET_free_non_null (set->states);
    GNUNET_free (set);
  }
}


/**
 * Clears an automaton fragment. Does not destroy the states inside the
 * automaton.
 *
 * @param a automaton to be cleared
 */
static void
automaton_fragment_clear (struct GNUNET_REGEX_Automaton *a)
{
  if (NULL == a)
    return;

  a->start = NULL;
  a->end = NULL;
  a->states_head = NULL;
  a->states_tail = NULL;
  a->state_count = 0;
  GNUNET_free (a);
}


/**
 * Frees the memory used by State 's'
 *
 * @param s state that should be destroyed
 */
static void
automaton_destroy_state (struct GNUNET_REGEX_State *s)
{
  struct GNUNET_REGEX_Transition *t;
  struct GNUNET_REGEX_Transition *next_t;

  if (NULL == s)
    return;

  GNUNET_free_non_null (s->name);
  GNUNET_free_non_null (s->proof);

  for (t = s->transitions_head; NULL != t; t = next_t)
  {
    next_t = t->next;
    GNUNET_CONTAINER_DLL_remove (s->transitions_head, s->transitions_tail, t);
    GNUNET_free_non_null (t->label);
    GNUNET_free (t);
  }

  state_set_clear (s->nfa_set);

  GNUNET_free (s);
}


/**
 * Remove a state from the given automaton 'a'. Always use this function when
 * altering the states of an automaton. Will also remove all transitions leading
 * to this state, before destroying it.
 *
 * @param a automaton
 * @param s state to remove
 */
static void
automaton_remove_state (struct GNUNET_REGEX_Automaton *a,
                        struct GNUNET_REGEX_State *s)
{
  struct GNUNET_REGEX_State *ss;
  struct GNUNET_REGEX_State *s_check;
  struct GNUNET_REGEX_Transition *t_check;

  if (NULL == a || NULL == s)
    return;

  // remove state
  ss = s;
  GNUNET_CONTAINER_DLL_remove (a->states_head, a->states_tail, s);
  a->state_count--;

  // remove all transitions leading to this state
  for (s_check = a->states_head; NULL != s_check; s_check = s_check->next)
  {
    for (t_check = s_check->transitions_head; NULL != t_check;
         t_check = t_check->next)
    {
      if (t_check->to_state == ss)
      {
        GNUNET_CONTAINER_DLL_remove (s_check->transitions_head,
                                     s_check->transitions_tail, t_check);
        s_check->transition_count--;
      }
    }
  }

  automaton_destroy_state (ss);
}


/**
 * Merge two states into one. Will merge 's1' and 's2' into 's1' and destroy
 * 's2'.
 *
 * @param ctx context
 * @param a automaton
 * @param s1 first state
 * @param s2 second state, will be destroyed
 */
static void
automaton_merge_states (struct GNUNET_REGEX_Context *ctx,
                        struct GNUNET_REGEX_Automaton *a,
                        struct GNUNET_REGEX_State *s1,
                        struct GNUNET_REGEX_State *s2)
{
  struct GNUNET_REGEX_State *s_check;
  struct GNUNET_REGEX_Transition *t_check;
  struct GNUNET_REGEX_Transition *t;
  struct GNUNET_REGEX_Transition *t_next;
  char *new_name;
  int is_dup;

  GNUNET_assert (NULL != ctx && NULL != a && NULL != s1 && NULL != s2);

  if (s1 == s2)
    return;

  // 1. Make all transitions pointing to s2 point to s1, unless this transition
  // does not already exists, if it already exists remove transition.
  for (s_check = a->states_head; NULL != s_check; s_check = s_check->next)
  {
    for (t_check = s_check->transitions_head; NULL != t_check; t_check = t_next)
    {
      t_next = t_check->next;

      if (s2 == t_check->to_state)
      {
        is_dup = GNUNET_NO;
        for (t = t_check->from_state->transitions_head; NULL != t; t = t->next)
        {
          if (t->to_state == s1 && 0 == strcmp (t_check->label, t->label))
            is_dup = GNUNET_YES;
        }
        if (GNUNET_NO == is_dup)
          t_check->to_state = s1;
        else
          state_remove_transition (t_check->from_state, t_check);
      }
    }
  }

  // 2. Add all transitions from s2 to sX to s1
  for (t_check = s2->transitions_head; NULL != t_check; t_check = t_check->next)
  {
    if (t_check->to_state != s1)
      state_add_transition (ctx, s1, t_check->label, t_check->to_state);
  }

  // 3. Rename s1 to {s1,s2}
  new_name = s1->name;
  GNUNET_asprintf (&s1->name, "{%s,%s}", new_name, s2->name);
  GNUNET_free (new_name);

  // remove state
  GNUNET_CONTAINER_DLL_remove (a->states_head, a->states_tail, s2);
  a->state_count--;
  automaton_destroy_state (s2);
}


/**
 * Add a state to the automaton 'a', always use this function to alter the
 * states DLL of the automaton.
 *
 * @param a automaton to add the state to
 * @param s state that should be added
 */
static void
automaton_add_state (struct GNUNET_REGEX_Automaton *a,
                     struct GNUNET_REGEX_State *s)
{
  GNUNET_CONTAINER_DLL_insert (a->states_head, a->states_tail, s);
  a->state_count++;
}


/**
 * Depth-first traversal (DFS) of all states that are reachable from state
 * 's'. Performs 'action' on each visited state.
 *
 * @param s start state.
 * @param marks an array of size a->state_count to remember which state was
 *        already visited.
 * @param count current count of the state.
 * @param check function that is checked before advancing on each transition
 *              in the DFS.
 * @param check_cls closure for check.
 * @param action action to be performed on each state.
 * @param action_cls closure for action.
 */
static void
automaton_state_traverse (struct GNUNET_REGEX_State *s, int *marks,
                          unsigned int *count,
                          GNUNET_REGEX_traverse_check check, void *check_cls,
                          GNUNET_REGEX_traverse_action action, void *action_cls)
{
  struct GNUNET_REGEX_Transition *t;

  if (GNUNET_YES == marks[s->traversal_id])
    return;

  marks[s->traversal_id] = GNUNET_YES;

  if (NULL != action)
    action (action_cls, *count, s);

  (*count)++;

  for (t = s->transitions_head; NULL != t; t = t->next)
  {
    if (NULL == check ||
        (NULL != check && GNUNET_YES == check (check_cls, s, t)))
    {
      automaton_state_traverse (t->to_state, marks, count, check, check_cls,
                                action, action_cls);
    }
  }
}


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
                                 void *action_cls)
{
  unsigned int count;
  struct GNUNET_REGEX_State *s;
  int marks[a->state_count];

  if (NULL == a || 0 == a->state_count)
    return;

  for (count = 0, s = a->states_head; NULL != s && count < a->state_count;
       s = s->next, count++)
  {
    s->traversal_id = count;
    marks[s->traversal_id] = GNUNET_NO;
  }

  count = 0;

  if (NULL == start)
    s = a->start;
  else
    s = start;

  automaton_state_traverse (s, marks, &count, check, check_cls, action,
                            action_cls);
}


/**
 * Context for adding strided transitions to a DFA.
 */
struct GNUNET_REGEX_Strided_Context
{
  /**
   * Length of the strides.
   */
  const unsigned int stride;

  /**
   * Strided transitions DLL. New strided transitions will be stored in this DLL
   * and afterwards added to the DFA.
   */
  struct GNUNET_REGEX_Transition *transitions_head;

  /**
   * Strided transitions DLL.
   */
  struct GNUNET_REGEX_Transition *transitions_tail;
};


/**
 * Recursive helper function to add strides to a DFA.
 *
 * @param cls context, contains stride length and strided transitions DLL.
 * @param depth current depth of the depth-first traversal of the graph.
 * @param label current label, string that contains all labels on the path from
 *        'start' to 's'.
 * @param start start state for the depth-first traversal of the graph.
 * @param s current state in the depth-first traversal
 */
void
add_multi_strides_to_dfa_helper (void *cls, const unsigned int depth,
                                 char *label, struct GNUNET_REGEX_State *start,
                                 struct GNUNET_REGEX_State *s)
{
  struct GNUNET_REGEX_Strided_Context *ctx = cls;
  struct GNUNET_REGEX_Transition *t;
  char *new_label;

  if (depth == ctx->stride)
  {
    t = GNUNET_malloc (sizeof (struct GNUNET_REGEX_Transition));
    t->label = GNUNET_strdup (label);
    t->to_state = s;
    t->from_state = start;
    GNUNET_CONTAINER_DLL_insert (ctx->transitions_head, ctx->transitions_tail,
                                 t);
  }
  else
  {
    for (t = s->transitions_head; NULL != t; t = t->next)
    {
      /* Do not consider self-loops, because it end's up in too many
       * transitions */
      if (t->to_state == t->from_state)
        continue;

      if (NULL != label)
      {
        GNUNET_asprintf (&new_label, "%s%s", label, t->label);
      }
      else
        new_label = GNUNET_strdup (t->label);

      add_multi_strides_to_dfa_helper (cls, (depth + 1), new_label, start,
                                       t->to_state);
    }
  }
  GNUNET_free_non_null (label);
}


/**
 * Function called for each state in the DFA. Starts a traversal of depth set in
 * context starting from state 's'.
 *
 * @param cls context.
 * @param count not used.
 * @param s current state.
 */
void
add_multi_strides_to_dfa (void *cls, const unsigned int count,
                          struct GNUNET_REGEX_State *s)
{
  add_multi_strides_to_dfa_helper (cls, 0, NULL, s, s);
}


/**
 * Adds multi-strided transitions to the given 'dfa'.
 *
 * @param regex_ctx regex context needed to add transitions to the automaton.
 * @param dfa DFA to which the multi strided transitions should be added.
 * @param stride_len length of the strides.
 */
void
GNUNET_REGEX_add_multi_strides_to_dfa (struct GNUNET_REGEX_Context *regex_ctx,
                                       struct GNUNET_REGEX_Automaton *dfa,
                                       const unsigned int stride_len)
{
  struct GNUNET_REGEX_Strided_Context ctx = { stride_len, NULL, NULL };
  struct GNUNET_REGEX_Transition *t;
  struct GNUNET_REGEX_Transition *t_next;

  GNUNET_REGEX_automaton_traverse (dfa, dfa->start, NULL, NULL,
                                   &add_multi_strides_to_dfa, &ctx);

  for (t = ctx.transitions_head; NULL != t; t = t_next)
  {
    t_next = t->next;
    state_add_transition (regex_ctx, t->from_state, t->label, t->to_state);
    GNUNET_CONTAINER_DLL_remove (ctx.transitions_head, ctx.transitions_tail, t);
    GNUNET_free_non_null (t->label);
    GNUNET_free (t);
  }
}



/**
 * Check if the given string 'str' needs parentheses around it when
 * using it to generate a regex.
 *
 * @param str string
 *
 * @return GNUNET_YES if parentheses are needed, GNUNET_NO otherwise
 */
static int
needs_parentheses (const char *str)
{
  size_t slen;
  const char *op;
  const char *cl;
  const char *pos;
  unsigned int cnt;

  if ((NULL == str) || ((slen = strlen (str)) < 2))
    return GNUNET_NO;

  if ('(' != str[0])
    return GNUNET_YES;
  cnt = 1;
  pos = &str[1];
  while (cnt > 0)
  {
    cl = strchr (pos, ')');
    if (NULL == cl)
    {
      GNUNET_break (0);
      return GNUNET_YES;
    }
    op = strchr (pos, '(');
    if ((NULL != op) && (op < cl))
    {
      cnt++;
      pos = op + 1;
      continue;
    }
    /* got ')' first */
    cnt--;
    pos = cl + 1;
  }
  return (*pos == '\0') ? GNUNET_NO : GNUNET_YES;
}


/**
 * Remove parentheses surrounding string 'str'.
 * Example: "(a)" becomes "a", "(a|b)|(a|c)" stays the same.
 * You need to GNUNET_free the returned string.
 *
 * @param str string, free'd or re-used by this function, can be NULL
 *
 * @return string without surrounding parentheses, string 'str' if no preceding
 *         epsilon could be found, NULL if 'str' was NULL
 */
static char *
remove_parentheses (char *str)
{
  size_t slen;
  const char *pos;

  if ((NULL == str) || ('(' != str[0]) ||
      (str[(slen = strlen (str)) - 1] != ')'))
    return str;

  pos = strchr (&str[1], ')');
  if (pos == &str[slen - 1])
  {
    memmove (str, &str[1], slen - 2);
    str[slen - 2] = '\0';
  }
  return str;
}


/**
 * Check if the string 'str' starts with an epsilon (empty string).
 * Example: "(|a)" is starting with an epsilon.
 *
 * @param str string to test
 *
 * @return 0 if str has no epsilon, 1 if str starts with '(|' and ends with ')'
 */
static int
has_epsilon (const char *str)
{
  return (NULL != str) && ('(' == str[0]) && ('|' == str[1]) &&
      (')' == str[strlen (str) - 1]);
}


/**
 * Remove an epsilon from the string str. Where epsilon is an empty string
 * Example: str = "(|a|b|c)", result: "a|b|c"
 * The returned string needs to be freed.
 *
 * @param str string
 *
 * @return string without preceding epsilon, string 'str' if no preceding
 *         epsilon could be found, NULL if 'str' was NULL
 */
static char *
remove_epsilon (const char *str)
{
  size_t len;

  if (NULL == str)
    return NULL;
  if (('(' == str[0]) && ('|' == str[1]))
  {
    len = strlen (str);
    if (')' == str[len - 1])
      return GNUNET_strndup (&str[2], len - 3);
  }
  return GNUNET_strdup (str);
}


/**
 * Compare 'str1', starting from position 'k',  with whole 'str2'
 *
 * @param str1 first string to compare, starting from position 'k'
 * @param str2 second string for comparison
 * @param k starting position in 'str1'
 *
 * @return -1 if any of the strings is NULL, 0 if equal, non 0 otherwise
 */
static int
strkcmp (const char *str1, const char *str2, size_t k)
{
  if ((NULL == str1) || (NULL == str2) || (strlen (str1) < k))
    return -1;
  return strcmp (&str1[k], str2);
}


/**
 * Helper function used as 'action' in 'GNUNET_REGEX_automaton_traverse'
 * function to create the depth-first numbering of the states.
 *
 * @param cls states array.
 * @param count current state counter.
 * @param s current state.
 */
void
number_states (void *cls, const unsigned int count,
               struct GNUNET_REGEX_State *s)
{
  struct GNUNET_REGEX_State **states = cls;

  s->dfs_id = count;
  if (NULL != states)
    states[count] = s;
}


/**
 * Construct the regular expression given the inductive step,
 * $R^{(k)}_{ij} = R^{(k-1)}_{ij} | R^{(k-1)}_{ik} ( R^{(k-1)}_{kk} )^*
 * R^{(k-1)}_{kj}, and simplify the resulting expression saved in R_cur_ij.
 *
 * @param R_last_ij value of  $R^{(k-1)_{ij}.
 * @param R_last_ik value of  $R^{(k-1)_{ik}.
 * @param R_last_kk value of  $R^{(k-1)_{kk}.
 * @param R_last_kj value of  $R^{(k-1)_{kj}.
 * @param R_cur_ij result for this inductive step is saved in R_cur_ij, R_cur_ij
 *                 is expected to be NULL when called!
 */
static void
automaton_create_proofs_simplify (char *R_last_ij, char *R_last_ik,
                                  char *R_last_kk, char *R_last_kj,
                                  char **R_cur_ij)
{
  char *R_cur_l;
  char *R_cur_r;
  char *temp_a;
  char *temp_b;
  char *R_temp_ij;
  char *R_temp_ik;
  char *R_temp_kj;
  char *R_temp_kk;

  int eps_check;
  int ij_ik_cmp;
  int ij_kj_cmp;

  int ik_kk_cmp;
  int kk_kj_cmp;
  int clean_ik_kk_cmp;
  int clean_kk_kj_cmp;
  unsigned int cnt;

  size_t length;
  size_t length_l;
  size_t length_r;

  GNUNET_assert (NULL == *R_cur_ij && NULL != R_cur_ij);

  // $R^{(k)}_{ij} = R^{(k-1)}_{ij} | R^{(k-1)}_{ik} ( R^{(k-1)}_{kk} )^* R^{(k-1)}_{kj}
  // R_last == R^{(k-1)}, R_cur == R^{(k)}
  // R_cur_ij = R_cur_l | R_cur_r
  // R_cur_l == R^{(k-1)}_{ij}
  // R_cur_r == R^{(k-1)}_{ik} ( R^{(k-1)}_{kk} )^* R^{(k-1)}_{kj}

  if ((NULL == R_last_ij) && ((NULL == R_last_ik) || (NULL == R_last_kk) ||     /* technically cannot happen, but looks saner */
                              (NULL == R_last_kj)))
  {
    /* R^{(k)}_{ij} = N | N */
    *R_cur_ij = NULL;
    return;
  }

  if ((NULL == R_last_ik) || (NULL == R_last_kk) ||     /* technically cannot happen, but looks saner */
      (NULL == R_last_kj))
  {
    /*  R^{(k)}_{ij} = R^{(k-1)}_{ij} | N */
    *R_cur_ij = GNUNET_strdup (R_last_ij);
    return;
  }

  // $R^{(k)}_{ij} = N | R^{(k-1)}_{ik} ( R^{(k-1)}_{kk} )^* R^{(k-1)}_{kj} OR
  // $R^{(k)}_{ij} = R^{(k-1)}_{ij} | R^{(k-1)}_{ik} ( R^{(k-1)}_{kk} )^* R^{(k-1)}_{kj}

  R_cur_r = NULL;
  R_cur_l = NULL;

  // cache results from strcmp, we might need these many times
  ij_kj_cmp = nullstrcmp (R_last_ij, R_last_kj);
  ij_ik_cmp = nullstrcmp (R_last_ij, R_last_ik);
  ik_kk_cmp = nullstrcmp (R_last_ik, R_last_kk);
  kk_kj_cmp = nullstrcmp (R_last_kk, R_last_kj);

  // Assign R_temp_(ik|kk|kj) to R_last[][] and remove epsilon as well
  // as parentheses, so we can better compare the contents
  R_temp_ik = remove_parentheses (remove_epsilon (R_last_ik));
  R_temp_kk = remove_parentheses (remove_epsilon (R_last_kk));
  R_temp_kj = remove_parentheses (remove_epsilon (R_last_kj));

  clean_ik_kk_cmp = nullstrcmp (R_last_ik, R_temp_kk);
  clean_kk_kj_cmp = nullstrcmp (R_temp_kk, R_last_kj);

  // construct R_cur_l (and, if necessary R_cur_r)
  if (NULL != R_last_ij)
  {
    // Assign R_temp_ij to R_last_ij and remove epsilon as well
    // as parentheses, so we can better compare the contents
    R_temp_ij = remove_parentheses (remove_epsilon (R_last_ij));

    if (0 == strcmp (R_temp_ij, R_temp_ik) && 0 == strcmp (R_temp_ik, R_temp_kk)
        && 0 == strcmp (R_temp_kk, R_temp_kj))
    {
      if (0 == strlen (R_temp_ij))
      {
        R_cur_r = GNUNET_strdup ("");
      }
      else if ((0 == strncmp (R_last_ij, "(|", 2)) ||
               (0 == strncmp (R_last_ik, "(|", 2) &&
                0 == strncmp (R_last_kj, "(|", 2)))
      {
        // a|(e|a)a*(e|a) = a*
        // a|(e|a)(e|a)*(e|a) = a*
        // (e|a)|aa*a = a*
        // (e|a)|aa*(e|a) = a*
        // (e|a)|(e|a)a*a = a*
        // (e|a)|(e|a)a*(e|a) = a*
        // (e|a)|(e|a)(e|a)*(e|a) = a*
        if (GNUNET_YES == needs_parentheses (R_temp_ij))
          GNUNET_asprintf (&R_cur_r, "(%s)*", R_temp_ij);
        else
          GNUNET_asprintf (&R_cur_r, "%s*", R_temp_ij);
      }
      else
      {
        // a|aa*a = a+
        // a|(e|a)a*a = a+
        // a|aa*(e|a) = a+
        // a|(e|a)(e|a)*a = a+
        // a|a(e|a)*(e|a) = a+
        if (GNUNET_YES == needs_parentheses (R_temp_ij))
          GNUNET_asprintf (&R_cur_r, "(%s)+", R_temp_ij);
        else
          GNUNET_asprintf (&R_cur_r, "%s+", R_temp_ij);
      }
    }
    else if (0 == ij_ik_cmp && 0 == clean_kk_kj_cmp && 0 != clean_ik_kk_cmp)
    {
      // a|ab*b = ab*
      if (strlen (R_last_kk) < 1)
        R_cur_r = GNUNET_strdup (R_last_ij);
      else if (GNUNET_YES == needs_parentheses (R_temp_kk))
        GNUNET_asprintf (&R_cur_r, "%s(%s)*", R_last_ij, R_temp_kk);
      else
        GNUNET_asprintf (&R_cur_r, "%s%s*", R_last_ij, R_last_kk);

      R_cur_l = NULL;
    }
    else if (0 == ij_kj_cmp && 0 == clean_ik_kk_cmp && 0 != clean_kk_kj_cmp)
    {
      // a|bb*a = b*a
      if (strlen (R_last_kk) < 1)
        R_cur_r = GNUNET_strdup (R_last_kj);
      else if (GNUNET_YES == needs_parentheses (R_temp_kk))
        GNUNET_asprintf (&R_cur_r, "(%s)*%s", R_temp_kk, R_last_kj);
      else
        GNUNET_asprintf (&R_cur_r, "%s*%s", R_temp_kk, R_last_kj);

      R_cur_l = NULL;
    }
    else if (0 == ij_ik_cmp && 0 == kk_kj_cmp && !has_epsilon (R_last_ij) &&
             has_epsilon (R_last_kk))
    {
      // a|a(e|b)*(e|b) = a|ab* = a|a|ab|abb|abbb|... = ab*
      if (needs_parentheses (R_temp_kk))
        GNUNET_asprintf (&R_cur_r, "%s(%s)*", R_last_ij, R_temp_kk);
      else
        GNUNET_asprintf (&R_cur_r, "%s%s*", R_last_ij, R_temp_kk);

      R_cur_l = NULL;
    }
    else if (0 == ij_kj_cmp && 0 == ik_kk_cmp && !has_epsilon (R_last_ij) &&
             has_epsilon (R_last_kk))
    {
      // a|(e|b)(e|b)*a = a|b*a = a|a|ba|bba|bbba|...  = b*a
      if (needs_parentheses (R_temp_kk))
        GNUNET_asprintf (&R_cur_r, "(%s)*%s", R_temp_kk, R_last_ij);
      else
        GNUNET_asprintf (&R_cur_r, "%s*%s", R_temp_kk, R_last_ij);

      R_cur_l = NULL;
    }
    else
    {
      temp_a = (NULL == R_last_ij) ? NULL : GNUNET_strdup (R_last_ij);
      temp_a = remove_parentheses (temp_a);
      R_cur_l = temp_a;
    }

    GNUNET_free_non_null (R_temp_ij);
  }
  else
  {
    // we have no left side
    R_cur_l = NULL;
  }

  // construct R_cur_r, if not already constructed
  if (NULL == R_cur_r)
  {
    length = strlen (R_temp_kk) - strlen (R_last_ik);

    // a(ba)*bx = (ab)+x
    if (length > 0 && NULL != R_last_kk && 0 < strlen (R_last_kk) &&
        NULL != R_last_kj && 0 < strlen (R_last_kj) && NULL != R_last_ik &&
        0 < strlen (R_last_ik) && 0 == strkcmp (R_temp_kk, R_last_ik, length) &&
        0 == strncmp (R_temp_kk, R_last_kj, length))
    {
      temp_a = GNUNET_malloc (length + 1);
      temp_b = GNUNET_malloc ((strlen (R_last_kj) - length) + 1);

      length_l = 0;
      length_r = 0;

      for (cnt = 0; cnt < strlen (R_last_kj); cnt++)
      {
        if (cnt < length)
        {
          temp_a[length_l] = R_last_kj[cnt];
          length_l++;
        }
        else
        {
          temp_b[length_r] = R_last_kj[cnt];
          length_r++;
        }
      }
      temp_a[length_l] = '\0';
      temp_b[length_r] = '\0';

      // e|(ab)+ = (ab)*
      if (NULL != R_cur_l && 0 == strlen (R_cur_l) && 0 == strlen (temp_b))
      {
        GNUNET_asprintf (&R_cur_r, "(%s%s)*", R_last_ik, temp_a);
        GNUNET_free (R_cur_l);
        R_cur_l = NULL;
      }
      else
      {
        GNUNET_asprintf (&R_cur_r, "(%s%s)+%s", R_last_ik, temp_a, temp_b);
      }
      GNUNET_free (temp_a);
      GNUNET_free (temp_b);
    }
    else if (0 == strcmp (R_temp_ik, R_temp_kk) &&
             0 == strcmp (R_temp_kk, R_temp_kj))
    {
      // (e|a)a*(e|a) = a*
      // (e|a)(e|a)*(e|a) = a*
      if (has_epsilon (R_last_ik) && has_epsilon (R_last_kj))
      {
        if (needs_parentheses (R_temp_kk))
          GNUNET_asprintf (&R_cur_r, "(%s)*", R_temp_kk);
        else
          GNUNET_asprintf (&R_cur_r, "%s*", R_temp_kk);
      }
      // aa*a = a+a
      else if (0 == clean_ik_kk_cmp && 0 == clean_kk_kj_cmp &&
               !has_epsilon (R_last_ik))
      {
        if (needs_parentheses (R_temp_kk))
          GNUNET_asprintf (&R_cur_r, "(%s)+%s", R_temp_kk, R_temp_kk);
        else
          GNUNET_asprintf (&R_cur_r, "(%s)+%s", R_temp_kk, R_temp_kk);
      }
      // (e|a)a*a = a+
      // aa*(e|a) = a+
      // a(e|a)*(e|a) = a+
      // (e|a)a*a = a+
      else
      {
        eps_check =
            (has_epsilon (R_last_ik) + has_epsilon (R_last_kk) +
             has_epsilon (R_last_kj));

        if (eps_check == 1)
        {
          if (needs_parentheses (R_temp_kk))
            GNUNET_asprintf (&R_cur_r, "(%s)+", R_temp_kk);
          else
            GNUNET_asprintf (&R_cur_r, "%s+", R_temp_kk);
        }
      }
    }
    // aa*b = a+b
    // (e|a)(e|a)*b = a*b
    else if (0 == strcmp (R_temp_ik, R_temp_kk))
    {
      if (has_epsilon (R_last_ik))
      {
        if (needs_parentheses (R_temp_kk))
          GNUNET_asprintf (&R_cur_r, "(%s)*%s", R_temp_kk, R_last_kj);
        else
          GNUNET_asprintf (&R_cur_r, "%s*%s", R_temp_kk, R_last_kj);
      }
      else
      {
        if (needs_parentheses (R_temp_kk))
          GNUNET_asprintf (&R_cur_r, "(%s)+%s", R_temp_kk, R_last_kj);
        else
          GNUNET_asprintf (&R_cur_r, "%s+%s", R_temp_kk, R_last_kj);
      }
    }
    // ba*a = ba+
    // b(e|a)*(e|a) = ba*
    else if (0 == strcmp (R_temp_kk, R_temp_kj))
    {
      if (has_epsilon (R_last_kj))
      {
        if (needs_parentheses (R_temp_kk))
          GNUNET_asprintf (&R_cur_r, "%s(%s)*", R_last_ik, R_temp_kk);
        else
          GNUNET_asprintf (&R_cur_r, "%s%s*", R_last_ik, R_temp_kk);
      }
      else
      {
        if (needs_parentheses (R_temp_kk))
          GNUNET_asprintf (&R_cur_r, "(%s)+%s", R_last_ik, R_temp_kk);
        else
          GNUNET_asprintf (&R_cur_r, "%s+%s", R_last_ik, R_temp_kk);
      }
    }
    else
    {
      if (strlen (R_temp_kk) > 0)
      {
        if (needs_parentheses (R_temp_kk))
        {
          GNUNET_asprintf (&R_cur_r, "%s(%s)*%s", R_last_ik, R_temp_kk,
                           R_last_kj);
        }
        else
        {
          GNUNET_asprintf (&R_cur_r, "%s%s*%s", R_last_ik, R_temp_kk,
                           R_last_kj);
        }
      }
      else
      {
        GNUNET_asprintf (&R_cur_r, "%s%s", R_last_ik, R_last_kj);
      }
    }
  }

  GNUNET_free_non_null (R_temp_ik);
  GNUNET_free_non_null (R_temp_kk);
  GNUNET_free_non_null (R_temp_kj);

  if (NULL == R_cur_l && NULL == R_cur_r)
  {
    *R_cur_ij = NULL;
    return;
  }

  if (NULL != R_cur_l && NULL == R_cur_r)
  {
    *R_cur_ij = R_cur_l;
    return;
  }

  if (NULL == R_cur_l && NULL != R_cur_r)
  {
    *R_cur_ij = R_cur_r;
    return;
  }

  if (0 == nullstrcmp (R_cur_l, R_cur_r))
  {
    *R_cur_ij = R_cur_l;
    GNUNET_free (R_cur_r);
    return;
  }

  GNUNET_asprintf (R_cur_ij, "(%s|%s)", R_cur_l, R_cur_r);

  GNUNET_free (R_cur_l);
  GNUNET_free (R_cur_r);
}


/**
 * create proofs for all states in the given automaton. Implementation of the
 * algorithm descriped in chapter 3.2.1 of "Automata Theory, Languages, and
 * Computation 3rd Edition" by Hopcroft, Motwani and Ullman.
 *
 * @param a automaton.
 */
static void
automaton_create_proofs (struct GNUNET_REGEX_Automaton *a)
{
  unsigned int n = a->state_count;
  struct GNUNET_REGEX_State *states[n];
  char *R_last[n][n];
  char *R_cur[n][n];
  char *temp;
  struct GNUNET_REGEX_Transition *t;
  char *complete_regex;
  unsigned int i;
  unsigned int j;
  unsigned int k;

  if (NULL == a)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Could not create proofs, automaton was NULL\n");
    return;
  }

  /* create depth-first numbering of the states, initializes 'state' */
  GNUNET_REGEX_automaton_traverse (a, a->start, NULL, NULL, &number_states,
                                   states);

  for (i = 0; i < n; i++)
    GNUNET_assert (NULL != states[i]);

  /* Compute regular expressions of length "1" between each pair of states */
  for (i = 0; i < n; i++)
  {
    for (j = 0; j < n; j++)
    {
      R_cur[i][j] = NULL;
      R_last[i][j] = NULL;
    }
    for (t = states[i]->transitions_head; NULL != t; t = t->next)
    {
      j = t->to_state->dfs_id;
      if (NULL == R_last[i][j])
        GNUNET_asprintf (&R_last[i][j], "%s", t->label);
      else
      {
        temp = R_last[i][j];
        GNUNET_asprintf (&R_last[i][j], "%s|%s", R_last[i][j], t->label);
        GNUNET_free (temp);
      }
    }
    if (NULL == R_last[i][i])
      GNUNET_asprintf (&R_last[i][i], "");
    else
    {
      temp = R_last[i][i];
      GNUNET_asprintf (&R_last[i][i], "(|%s)", R_last[i][i]);
      GNUNET_free (temp);
    }
  }
  for (i = 0; i < n; i++)
    for (j = 0; j < n; j++)
      if (needs_parentheses (R_last[i][j]))
      {
        temp = R_last[i][j];
        GNUNET_asprintf (&R_last[i][j], "(%s)", R_last[i][j]);
        GNUNET_free (temp);
      }

  /* Compute regular expressions of length "k" between each pair of states per
   * induction */
  for (k = 0; k < n; k++)
  {
    for (i = 0; i < n; i++)
    {
      for (j = 0; j < n; j++)
      {
        // Basis for the recursion:
        // $R^{(k)}_{ij} = R^{(k-1)}_{ij} | R^{(k-1)}_{ik} ( R^{(k-1)}_{kk} )^* R^{(k-1)}_{kj}
        // R_last == R^{(k-1)}, R_cur == R^{(k)}

        // Create R_cur[i][j] and simplify the expression
        automaton_create_proofs_simplify (R_last[i][j], R_last[i][k],
                                          R_last[k][k], R_last[k][j],
                                          &R_cur[i][j]);
      }
    }

    // set R_last = R_cur
    for (i = 0; i < n; i++)
    {
      for (j = 0; j < n; j++)
      {
        GNUNET_free_non_null (R_last[i][j]);
        R_last[i][j] = R_cur[i][j];
        R_cur[i][j] = NULL;
      }
    }
  }

  // assign proofs and hashes
  for (i = 0; i < n; i++)
  {
    if (NULL != R_last[a->start->dfs_id][i])
    {
      states[i]->proof = GNUNET_strdup (R_last[a->start->dfs_id][i]);
      GNUNET_CRYPTO_hash (states[i]->proof, strlen (states[i]->proof),
                          &states[i]->hash);
    }
  }

  // complete regex for whole DFA: union of all pairs (start state/accepting
  // state(s)).
  complete_regex = NULL;
  for (i = 0; i < n; i++)
  {
    if (states[i]->accepting)
    {
      if (NULL == complete_regex && 0 < strlen (R_last[a->start->dfs_id][i]))
      {
        GNUNET_asprintf (&complete_regex, "%s", R_last[a->start->dfs_id][i]);
      }
      else if (NULL != R_last[a->start->dfs_id][i] &&
               0 < strlen (R_last[a->start->dfs_id][i]))
      {
        temp = complete_regex;
        GNUNET_asprintf (&complete_regex, "%s|%s", complete_regex,
                         R_last[a->start->dfs_id][i]);
        GNUNET_free (temp);
      }
    }
  }
  a->canonical_regex = complete_regex;

  // cleanup
  for (i = 0; i < n; i++)
  {
    for (j = 0; j < n; j++)
      GNUNET_free_non_null (R_last[i][j]);
  }
}


/**
 * Creates a new DFA state based on a set of NFA states. Needs to be freed using
 * automaton_destroy_state.
 *
 * @param ctx context
 * @param nfa_states set of NFA states on which the DFA should be based on
 *
 * @return new DFA state
 */
static struct GNUNET_REGEX_State *
dfa_state_create (struct GNUNET_REGEX_Context *ctx,
                  struct GNUNET_REGEX_StateSet *nfa_states)
{
  struct GNUNET_REGEX_State *s;
  char *name;
  int len = 0;
  struct GNUNET_REGEX_State *cstate;
  struct GNUNET_REGEX_Transition *ctran;
  unsigned int i;

  s = GNUNET_malloc (sizeof (struct GNUNET_REGEX_State));
  s->id = ctx->state_id++;
  s->accepting = 0;
  s->marked = GNUNET_NO;
  s->name = NULL;
  s->scc_id = 0;
  s->index = -1;
  s->lowlink = -1;
  s->contained = 0;
  s->proof = NULL;

  if (NULL == nfa_states)
  {
    GNUNET_asprintf (&s->name, "s%i", s->id);
    return s;
  }

  s->nfa_set = nfa_states;

  if (nfa_states->len < 1)
    return s;

  // Create a name based on 'sset'
  s->name = GNUNET_malloc (sizeof (char) * 2);
  strcat (s->name, "{");
  name = NULL;

  for (i = 0; i < nfa_states->len; i++)
  {
    cstate = nfa_states->states[i];
    GNUNET_asprintf (&name, "%i,", cstate->id);

    if (NULL != name)
    {
      len = strlen (s->name) + strlen (name) + 1;
      s->name = GNUNET_realloc (s->name, len);
      strcat (s->name, name);
      GNUNET_free (name);
      name = NULL;
    }

    // Add a transition for each distinct label to NULL state
    for (ctran = cstate->transitions_head; NULL != ctran; ctran = ctran->next)
    {
      if (NULL != ctran->label)
        state_add_transition (ctx, s, ctran->label, NULL);
    }

    // If the nfa_states contain an accepting state, the new dfa state is also
    // accepting
    if (cstate->accepting)
      s->accepting = 1;
  }

  s->name[strlen (s->name) - 1] = '}';

  return s;
}


/**
 * Move from the given state 's' to the next state on transition 'label'
 *
 * @param s starting state
 * @param label edge label to follow
 *
 * @return new state or NULL, if transition on label not possible
 */
static struct GNUNET_REGEX_State *
dfa_move (struct GNUNET_REGEX_State *s, const char *label)
{
  struct GNUNET_REGEX_Transition *t;
  struct GNUNET_REGEX_State *new_s;

  if (NULL == s)
    return NULL;

  new_s = NULL;

  for (t = s->transitions_head; NULL != t; t = t->next)
  {
    // TODO: Use strstr to match substring and return number of char's that have
    // been consumed'
    if (0 == strcmp (label, t->label))
    {
      new_s = t->to_state;
      break;
    }
  }

  return new_s;
}

/**
 * Set the given state 'marked' to GNUNET_YES. Used by the
 * 'dfa_remove_unreachable_states' function to detect unreachable states in the
 * automaton.
 *
 * @param cls closure, not used.
 * @param count count, not used.
 * @param s state where the marked attribute will be set to GNUNET_YES.
 */
void
mark_states (void *cls, const unsigned int count, struct GNUNET_REGEX_State *s)
{
  s->marked = GNUNET_YES;
}

/**
 * Remove all unreachable states from DFA 'a'. Unreachable states are those
 * states that are not reachable from the starting state.
 *
 * @param a DFA automaton
 */
static void
dfa_remove_unreachable_states (struct GNUNET_REGEX_Automaton *a)
{
  struct GNUNET_REGEX_State *s;
  struct GNUNET_REGEX_State *s_next;

  // 1. unmark all states
  for (s = a->states_head; NULL != s; s = s->next)
    s->marked = GNUNET_NO;

  // 2. traverse dfa from start state and mark all visited states
  GNUNET_REGEX_automaton_traverse (a, a->start, NULL, NULL, &mark_states, NULL);

  // 3. delete all states that were not visited
  for (s = a->states_head; NULL != s; s = s_next)
  {
    s_next = s->next;
    if (GNUNET_NO == s->marked)
      automaton_remove_state (a, s);
  }
}


/**
 * Remove all dead states from the DFA 'a'. Dead states are those states that do
 * not transition to any other state but themselves.
 *
 * @param a DFA automaton
 */
static void
dfa_remove_dead_states (struct GNUNET_REGEX_Automaton *a)
{
  struct GNUNET_REGEX_State *s;
  struct GNUNET_REGEX_Transition *t;
  int dead;

  GNUNET_assert (DFA == a->type);

  for (s = a->states_head; NULL != s; s = s->next)
  {
    if (s->accepting)
      continue;

    dead = 1;
    for (t = s->transitions_head; NULL != t; t = t->next)
    {
      if (NULL != t->to_state && t->to_state != s)
      {
        dead = 0;
        break;
      }
    }

    if (0 == dead)
      continue;

    // state s is dead, remove it
    automaton_remove_state (a, s);
  }
}


/**
 * Merge all non distinguishable states in the DFA 'a'
 *
 * @param ctx context
 * @param a DFA automaton
 */
static void
dfa_merge_nondistinguishable_states (struct GNUNET_REGEX_Context *ctx,
                                     struct GNUNET_REGEX_Automaton *a)
{
  int table[a->state_count][a->state_count];
  struct GNUNET_REGEX_State *s1;
  struct GNUNET_REGEX_State *s2;
  struct GNUNET_REGEX_Transition *t1;
  struct GNUNET_REGEX_Transition *t2;
  struct GNUNET_REGEX_State *s1_next;
  struct GNUNET_REGEX_State *s2_next;
  int change;
  unsigned int num_equal_edges;
  unsigned int i;

  for (i = 0, s1 = a->states_head; i < a->state_count && NULL != s1;
       i++, s1 = s1->next)
  {
    s1->marked = i;
  }

  // Mark all pairs of accepting/!accepting states
  for (s1 = a->states_head; NULL != s1; s1 = s1->next)
  {
    for (s2 = a->states_head; NULL != s2; s2 = s2->next)
    {
      table[s1->marked][s2->marked] = 0;

      if ((s1->accepting && !s2->accepting) ||
          (!s1->accepting && s2->accepting))
      {
        table[s1->marked][s2->marked] = 1;
      }
    }
  }

  // Find all equal states
  change = 1;
  while (0 != change)
  {
    change = 0;
    for (s1 = a->states_head; NULL != s1; s1 = s1->next)
    {
      for (s2 = a->states_head; NULL != s2 && s1 != s2; s2 = s2->next)
      {
        if (0 != table[s1->marked][s2->marked])
          continue;

        num_equal_edges = 0;
        for (t1 = s1->transitions_head; NULL != t1; t1 = t1->next)
        {
          for (t2 = s2->transitions_head; NULL != t2; t2 = t2->next)
          {
            if (0 == strcmp (t1->label, t2->label))
            {
              num_equal_edges++;
              if (0 != table[t1->to_state->marked][t2->to_state->marked] ||
                  0 != table[t2->to_state->marked][t1->to_state->marked])
              {
                table[s1->marked][s2->marked] = 1;
                change = 1;
              }
            }
          }
        }
        if (num_equal_edges != s1->transition_count ||
            num_equal_edges != s2->transition_count)
        {
          // Make sure ALL edges of possible equal states are the same
          table[s1->marked][s2->marked] = -2;
        }
      }
    }
  }

  // Merge states that are equal
  for (s1 = a->states_head; NULL != s1; s1 = s1_next)
  {
    s1_next = s1->next;
    for (s2 = a->states_head; NULL != s2 && s1 != s2; s2 = s2_next)
    {
      s2_next = s2->next;
      if (table[s1->marked][s2->marked] == 0)
        automaton_merge_states (ctx, a, s1, s2);
    }
  }
}


/**
 * Minimize the given DFA 'a' by removing all unreachable states, removing all
 * dead states and merging all non distinguishable states
 *
 * @param ctx context
 * @param a DFA automaton
 */
static void
dfa_minimize (struct GNUNET_REGEX_Context *ctx,
              struct GNUNET_REGEX_Automaton *a)
{
  if (NULL == a)
    return;

  GNUNET_assert (DFA == a->type);

  // 1. remove unreachable states
  dfa_remove_unreachable_states (a);

  // 2. remove dead states
  dfa_remove_dead_states (a);

  // 3. Merge nondistinguishable states
  dfa_merge_nondistinguishable_states (ctx, a);
}


/**
 * Creates a new NFA fragment. Needs to be cleared using
 * automaton_fragment_clear.
 *
 * @param start starting state
 * @param end end state
 *
 * @return new NFA fragment
 */
static struct GNUNET_REGEX_Automaton *
nfa_fragment_create (struct GNUNET_REGEX_State *start,
                     struct GNUNET_REGEX_State *end)
{
  struct GNUNET_REGEX_Automaton *n;

  n = GNUNET_malloc (sizeof (struct GNUNET_REGEX_Automaton));

  n->type = NFA;
  n->start = NULL;
  n->end = NULL;
  n->state_count = 0;

  if (NULL == start || NULL == end)
    return n;

  automaton_add_state (n, end);
  automaton_add_state (n, start);

  n->state_count = 2;

  n->start = start;
  n->end = end;

  return n;
}


/**
 * Adds a list of states to the given automaton 'n'.
 *
 * @param n automaton to which the states should be added
 * @param states_head head of the DLL of states
 * @param states_tail tail of the DLL of states
 */
static void
nfa_add_states (struct GNUNET_REGEX_Automaton *n,
                struct GNUNET_REGEX_State *states_head,
                struct GNUNET_REGEX_State *states_tail)
{
  struct GNUNET_REGEX_State *s;

  if (NULL == n || NULL == states_head)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Could not add states\n");
    return;
  }

  if (NULL == n->states_head)
  {
    n->states_head = states_head;
    n->states_tail = states_tail;
    return;
  }

  if (NULL != states_head)
  {
    n->states_tail->next = states_head;
    n->states_tail = states_tail;
  }

  for (s = states_head; NULL != s; s = s->next)
    n->state_count++;
}


/**
 * Creates a new NFA state. Needs to be freed using automaton_destroy_state.
 *
 * @param ctx context
 * @param accepting is it an accepting state or not
 *
 * @return new NFA state
 */
static struct GNUNET_REGEX_State *
nfa_state_create (struct GNUNET_REGEX_Context *ctx, int accepting)
{
  struct GNUNET_REGEX_State *s;

  s = GNUNET_malloc (sizeof (struct GNUNET_REGEX_State));
  s->id = ctx->state_id++;
  s->accepting = accepting;
  s->marked = GNUNET_NO;
  s->contained = 0;
  s->index = -1;
  s->lowlink = -1;
  s->scc_id = 0;
  s->name = NULL;
  GNUNET_asprintf (&s->name, "s%i", s->id);

  return s;
}


/**
 * Calculates the NFA closure set for the given state.
 *
 * @param nfa the NFA containing 's'
 * @param s starting point state
 * @param label transitioning label on which to base the closure on,
 *                pass NULL for epsilon transition
 *
 * @return sorted nfa closure on 'label' (epsilon closure if 'label' is NULL)
 */
static struct GNUNET_REGEX_StateSet *
nfa_closure_create (struct GNUNET_REGEX_Automaton *nfa,
                    struct GNUNET_REGEX_State *s, const char *label)
{
  struct GNUNET_REGEX_StateSet *cls;
  struct GNUNET_REGEX_StateSet *cls_check;
  struct GNUNET_REGEX_State *clsstate;
  struct GNUNET_REGEX_State *currentstate;
  struct GNUNET_REGEX_Transition *ctran;

  if (NULL == s)
    return NULL;

  cls = GNUNET_malloc (sizeof (struct GNUNET_REGEX_StateSet));
  cls_check = GNUNET_malloc (sizeof (struct GNUNET_REGEX_StateSet));

  for (clsstate = nfa->states_head; NULL != clsstate; clsstate = clsstate->next)
    clsstate->contained = 0;

  // Add start state to closure only for epsilon closure
  if (NULL == label)
    GNUNET_array_append (cls->states, cls->len, s);

  GNUNET_array_append (cls_check->states, cls_check->len, s);
  while (cls_check->len > 0)
  {
    currentstate = cls_check->states[cls_check->len - 1];
    GNUNET_array_grow (cls_check->states, cls_check->len, cls_check->len - 1);

    for (ctran = currentstate->transitions_head; NULL != ctran;
         ctran = ctran->next)
    {
      if (NULL != ctran->to_state && 0 == nullstrcmp (label, ctran->label))
      {
        clsstate = ctran->to_state;

        if (NULL != clsstate && 0 == clsstate->contained)
        {
          GNUNET_array_append (cls->states, cls->len, clsstate);
          GNUNET_array_append (cls_check->states, cls_check->len, clsstate);
          clsstate->contained = 1;
        }
      }
    }
  }
  GNUNET_assert (0 == cls_check->len);
  GNUNET_free (cls_check);

  // sort the states
  if (cls->len > 1)
    qsort (cls->states, cls->len, sizeof (struct GNUNET_REGEX_State *),
           state_compare);

  return cls;
}


/**
 * Calculates the closure set for the given set of states.
 *
 * @param nfa the NFA containing 's'
 * @param states list of states on which to base the closure on
 * @param label transitioning label for which to base the closure on,
 *                pass NULL for epsilon transition
 *
 * @return sorted nfa closure on 'label' (epsilon closure if 'label' is NULL)
 */
static struct GNUNET_REGEX_StateSet *
nfa_closure_set_create (struct GNUNET_REGEX_Automaton *nfa,
                        struct GNUNET_REGEX_StateSet *states, const char *label)
{
  struct GNUNET_REGEX_State *s;
  struct GNUNET_REGEX_StateSet *sset;
  struct GNUNET_REGEX_StateSet *cls;
  unsigned int i;
  unsigned int j;
  unsigned int k;
  unsigned int contains;

  if (NULL == states)
    return NULL;

  cls = GNUNET_malloc (sizeof (struct GNUNET_REGEX_StateSet));

  for (i = 0; i < states->len; i++)
  {
    s = states->states[i];
    sset = nfa_closure_create (nfa, s, label);

    for (j = 0; j < sset->len; j++)
    {
      contains = 0;
      for (k = 0; k < cls->len; k++)
      {
        if (sset->states[j]->id == cls->states[k]->id)
        {
          contains = 1;
          break;
        }
      }
      if (!contains)
        GNUNET_array_append (cls->states, cls->len, sset->states[j]);
    }
    state_set_clear (sset);
  }

  if (cls->len > 1)
    qsort (cls->states, cls->len, sizeof (struct GNUNET_REGEX_State *),
           state_compare);

  return cls;
}


/**
 * Pops two NFA fragments (a, b) from the stack and concatenates them (ab)
 *
 * @param ctx context
 */
static void
nfa_add_concatenation (struct GNUNET_REGEX_Context *ctx)
{
  struct GNUNET_REGEX_Automaton *a;
  struct GNUNET_REGEX_Automaton *b;
  struct GNUNET_REGEX_Automaton *new_nfa;

  b = ctx->stack_tail;
  GNUNET_assert (NULL != b);
  GNUNET_CONTAINER_DLL_remove (ctx->stack_head, ctx->stack_tail, b);
  a = ctx->stack_tail;
  GNUNET_assert (NULL != a);
  GNUNET_CONTAINER_DLL_remove (ctx->stack_head, ctx->stack_tail, a);

  state_add_transition (ctx, a->end, NULL, b->start);
  a->end->accepting = 0;
  b->end->accepting = 1;

  new_nfa = nfa_fragment_create (NULL, NULL);
  nfa_add_states (new_nfa, a->states_head, a->states_tail);
  nfa_add_states (new_nfa, b->states_head, b->states_tail);
  new_nfa->start = a->start;
  new_nfa->end = b->end;
  new_nfa->state_count += a->state_count + b->state_count;
  automaton_fragment_clear (a);
  automaton_fragment_clear (b);

  GNUNET_CONTAINER_DLL_insert_tail (ctx->stack_head, ctx->stack_tail, new_nfa);
}


/**
 * Pops a NFA fragment from the stack (a) and adds a new fragment (a*)
 *
 * @param ctx context
 */
static void
nfa_add_star_op (struct GNUNET_REGEX_Context *ctx)
{
  struct GNUNET_REGEX_Automaton *a;
  struct GNUNET_REGEX_Automaton *new_nfa;
  struct GNUNET_REGEX_State *start;
  struct GNUNET_REGEX_State *end;

  a = ctx->stack_tail;

  if (NULL == a)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "nfa_add_star_op failed, because there was no element on the stack");
    return;
  }

  GNUNET_CONTAINER_DLL_remove (ctx->stack_head, ctx->stack_tail, a);

  start = nfa_state_create (ctx, 0);
  end = nfa_state_create (ctx, 1);

  state_add_transition (ctx, start, NULL, a->start);
  state_add_transition (ctx, start, NULL, end);
  state_add_transition (ctx, a->end, NULL, a->start);
  state_add_transition (ctx, a->end, NULL, end);

  a->end->accepting = 0;
  end->accepting = 1;

  new_nfa = nfa_fragment_create (start, end);
  nfa_add_states (new_nfa, a->states_head, a->states_tail);
  automaton_fragment_clear (a);

  GNUNET_CONTAINER_DLL_insert_tail (ctx->stack_head, ctx->stack_tail, new_nfa);
}


/**
 * Pops an NFA fragment (a) from the stack and adds a new fragment (a+)
 *
 * @param ctx context
 */
static void
nfa_add_plus_op (struct GNUNET_REGEX_Context *ctx)
{
  struct GNUNET_REGEX_Automaton *a;

  a = ctx->stack_tail;
  GNUNET_CONTAINER_DLL_remove (ctx->stack_head, ctx->stack_tail, a);

  state_add_transition (ctx, a->end, NULL, a->start);

  GNUNET_CONTAINER_DLL_insert_tail (ctx->stack_head, ctx->stack_tail, a);
}


/**
 * Pops an NFA fragment (a) from the stack and adds a new fragment (a?)
 *
 * @param ctx context
 */
static void
nfa_add_question_op (struct GNUNET_REGEX_Context *ctx)
{
  struct GNUNET_REGEX_Automaton *a;
  struct GNUNET_REGEX_Automaton *new_nfa;
  struct GNUNET_REGEX_State *start;
  struct GNUNET_REGEX_State *end;

  a = ctx->stack_tail;

  if (NULL == a)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "nfa_add_question_op failed, because there was no element on the stack");
    return;
  }

  GNUNET_CONTAINER_DLL_remove (ctx->stack_head, ctx->stack_tail, a);

  start = nfa_state_create (ctx, 0);
  end = nfa_state_create (ctx, 1);

  state_add_transition (ctx, start, NULL, a->start);
  state_add_transition (ctx, start, NULL, end);
  state_add_transition (ctx, a->end, NULL, end);

  a->end->accepting = 0;

  new_nfa = nfa_fragment_create (start, end);
  nfa_add_states (new_nfa, a->states_head, a->states_tail);
  automaton_fragment_clear (a);

  GNUNET_CONTAINER_DLL_insert_tail (ctx->stack_head, ctx->stack_tail, new_nfa);
}


/**
 * Pops two NFA fragments (a, b) from the stack and adds a new NFA fragment that
 * alternates between a and b (a|b)
 *
 * @param ctx context
 */
static void
nfa_add_alternation (struct GNUNET_REGEX_Context *ctx)
{
  struct GNUNET_REGEX_Automaton *a;
  struct GNUNET_REGEX_Automaton *b;
  struct GNUNET_REGEX_Automaton *new_nfa;
  struct GNUNET_REGEX_State *start;
  struct GNUNET_REGEX_State *end;

  b = ctx->stack_tail;
  GNUNET_assert (NULL != b);
  GNUNET_CONTAINER_DLL_remove (ctx->stack_head, ctx->stack_tail, b);
  a = ctx->stack_tail;
  GNUNET_assert (NULL != a);
  GNUNET_CONTAINER_DLL_remove (ctx->stack_head, ctx->stack_tail, a);

  start = nfa_state_create (ctx, 0);
  end = nfa_state_create (ctx, 1);
  state_add_transition (ctx, start, NULL, a->start);
  state_add_transition (ctx, start, NULL, b->start);

  state_add_transition (ctx, a->end, NULL, end);
  state_add_transition (ctx, b->end, NULL, end);

  a->end->accepting = 0;
  b->end->accepting = 0;
  end->accepting = 1;

  new_nfa = nfa_fragment_create (start, end);
  nfa_add_states (new_nfa, a->states_head, a->states_tail);
  nfa_add_states (new_nfa, b->states_head, b->states_tail);
  automaton_fragment_clear (a);
  automaton_fragment_clear (b);

  GNUNET_CONTAINER_DLL_insert_tail (ctx->stack_head, ctx->stack_tail, new_nfa);
}


/**
 * Adds a new nfa fragment to the stack
 *
 * @param ctx context
 * @param label label for nfa transition
 */
static void
nfa_add_label (struct GNUNET_REGEX_Context *ctx, const char *label)
{
  struct GNUNET_REGEX_Automaton *n;
  struct GNUNET_REGEX_State *start;
  struct GNUNET_REGEX_State *end;

  GNUNET_assert (NULL != ctx);

  start = nfa_state_create (ctx, 0);
  end = nfa_state_create (ctx, 1);
  state_add_transition (ctx, start, label, end);
  n = nfa_fragment_create (start, end);
  GNUNET_assert (NULL != n);
  GNUNET_CONTAINER_DLL_insert_tail (ctx->stack_head, ctx->stack_tail, n);
}


/**
 * Initialize a new context
 *
 * @param ctx context
 */
static void
GNUNET_REGEX_context_init (struct GNUNET_REGEX_Context *ctx)
{
  if (NULL == ctx)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Context was NULL!");
    return;
  }
  ctx->state_id = 0;
  ctx->transition_id = 0;
  ctx->stack_head = NULL;
  ctx->stack_tail = NULL;
}


/**
 * Construct an NFA by parsing the regex string of length 'len'.
 *
 * @param regex regular expression string
 * @param len length of the string
 *
 * @return NFA, needs to be freed using GNUNET_REGEX_destroy_automaton
 */
struct GNUNET_REGEX_Automaton *
GNUNET_REGEX_construct_nfa (const char *regex, const size_t len)
{
  struct GNUNET_REGEX_Context ctx;
  struct GNUNET_REGEX_Automaton *nfa;
  const char *regexp;
  char curlabel[2];
  char *error_msg;
  unsigned int count;
  unsigned int altcount;
  unsigned int atomcount;
  unsigned int pcount;
  struct
  {
    int altcount;
    int atomcount;
  }     *p;

  GNUNET_REGEX_context_init (&ctx);

  regexp = regex;
  curlabel[1] = '\0';
  p = NULL;
  error_msg = NULL;
  altcount = 0;
  atomcount = 0;
  pcount = 0;

  for (count = 0; count < len && *regexp; count++, regexp++)
  {
    switch (*regexp)
    {
    case '(':
      if (atomcount > 1)
      {
        --atomcount;
        nfa_add_concatenation (&ctx);
      }
      GNUNET_array_grow (p, pcount, pcount + 1);
      p[pcount - 1].altcount = altcount;
      p[pcount - 1].atomcount = atomcount;
      altcount = 0;
      atomcount = 0;
      break;
    case '|':
      if (0 == atomcount)
      {
        error_msg = "Cannot append '|' to nothing";
        goto error;
      }
      while (--atomcount > 0)
        nfa_add_concatenation (&ctx);
      altcount++;
      break;
    case ')':
      if (0 == pcount)
      {
        error_msg = "Missing opening '('";
        goto error;
      }
      if (0 == atomcount)
      {
        // Ignore this: "()"
        pcount--;
        altcount = p[pcount].altcount;
        atomcount = p[pcount].atomcount;
        break;
      }
      while (--atomcount > 0)
        nfa_add_concatenation (&ctx);
      for (; altcount > 0; altcount--)
        nfa_add_alternation (&ctx);
      pcount--;
      altcount = p[pcount].altcount;
      atomcount = p[pcount].atomcount;
      atomcount++;
      break;
    case '*':
      if (atomcount == 0)
      {
        error_msg = "Cannot append '*' to nothing";
        goto error;
      }
      nfa_add_star_op (&ctx);
      break;
    case '+':
      if (atomcount == 0)
      {
        error_msg = "Cannot append '+' to nothing";
        goto error;
      }
      nfa_add_plus_op (&ctx);
      break;
    case '?':
      if (atomcount == 0)
      {
        error_msg = "Cannot append '?' to nothing";
        goto error;
      }
      nfa_add_question_op (&ctx);
      break;
    case 92:                   /* escape: \ */
      regexp++;
      count++;
      /* fall through! */
    default:
      if (atomcount > 1)
      {
        --atomcount;
        nfa_add_concatenation (&ctx);
      }
      curlabel[0] = *regexp;
      nfa_add_label (&ctx, curlabel);
      atomcount++;
      break;
    }
  }
  if (0 != pcount)
  {
    error_msg = "Unbalanced parenthesis";
    goto error;
  }
  while (--atomcount > 0)
    nfa_add_concatenation (&ctx);
  for (; altcount > 0; altcount--)
    nfa_add_alternation (&ctx);

  GNUNET_free_non_null (p);

  nfa = ctx.stack_tail;
  GNUNET_CONTAINER_DLL_remove (ctx.stack_head, ctx.stack_tail, nfa);

  if (NULL != ctx.stack_head)
  {
    error_msg = "Creating the NFA failed. NFA stack was not empty!";
    goto error;
  }

  nfa->regex = GNUNET_strdup (regex);

  /* create depth-first numbering of the states for pretty printing */
  GNUNET_REGEX_automaton_traverse (nfa, NULL, NULL, NULL, &number_states, NULL);

  return nfa;

error:
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Could not parse regex: %s\n", regex);
  if (NULL != error_msg)
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "%s\n", error_msg);

  GNUNET_free_non_null (p);

  while (NULL != (nfa = ctx.stack_head))
  {
    GNUNET_CONTAINER_DLL_remove (ctx.stack_head, ctx.stack_tail, nfa);
    GNUNET_REGEX_automaton_destroy (nfa);
  }

  return NULL;
}


/**
 * Create DFA states based on given 'nfa' and starting with 'dfa_state'.
 *
 * @param ctx context.
 * @param nfa NFA automaton.
 * @param dfa DFA automaton.
 * @param dfa_state current dfa state, pass epsilon closure of first nfa state
 *                  for starting.
 */
static void
construct_dfa_states (struct GNUNET_REGEX_Context *ctx,
                      struct GNUNET_REGEX_Automaton *nfa,
                      struct GNUNET_REGEX_Automaton *dfa,
                      struct GNUNET_REGEX_State *dfa_state)
{
  struct GNUNET_REGEX_Transition *ctran;
  struct GNUNET_REGEX_State *state_iter;
  struct GNUNET_REGEX_State *new_dfa_state;
  struct GNUNET_REGEX_State *state_contains;
  struct GNUNET_REGEX_StateSet *tmp;
  struct GNUNET_REGEX_StateSet *nfa_set;

  for (ctran = dfa_state->transitions_head; NULL != ctran; ctran = ctran->next)
  {
    if (NULL == ctran->label || NULL != ctran->to_state)
      continue;

    tmp = nfa_closure_set_create (nfa, dfa_state->nfa_set, ctran->label);
    nfa_set = nfa_closure_set_create (nfa, tmp, 0);
    state_set_clear (tmp);
    new_dfa_state = dfa_state_create (ctx, nfa_set);
    state_contains = NULL;
    for (state_iter = dfa->states_head; NULL != state_iter;
         state_iter = state_iter->next)
    {
      if (0 == state_set_compare (state_iter->nfa_set, new_dfa_state->nfa_set))
        state_contains = state_iter;
    }

    if (NULL == state_contains)
    {
      automaton_add_state (dfa, new_dfa_state);
      ctran->to_state = new_dfa_state;
      construct_dfa_states (ctx, nfa, dfa, new_dfa_state);
    }
    else
    {
      ctran->to_state = state_contains;
      automaton_destroy_state (new_dfa_state);
    }
  }
}


/**
 * Construct DFA for the given 'regex' of length 'len'
 *
 * @param regex regular expression string
 * @param len length of the regular expression
 *
 * @return DFA, needs to be freed using GNUNET_REGEX_destroy_automaton
 */
struct GNUNET_REGEX_Automaton *
GNUNET_REGEX_construct_dfa (const char *regex, const size_t len)
{
  struct GNUNET_REGEX_Context ctx;
  struct GNUNET_REGEX_Automaton *dfa;
  struct GNUNET_REGEX_Automaton *nfa;
  struct GNUNET_REGEX_StateSet *nfa_set;

  GNUNET_REGEX_context_init (&ctx);

  // Create NFA
  nfa = GNUNET_REGEX_construct_nfa (regex, len);

  if (NULL == nfa)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Could not create DFA, because NFA creation failed\n");
    return NULL;
  }

  dfa = GNUNET_malloc (sizeof (struct GNUNET_REGEX_Automaton));
  dfa->type = DFA;
  dfa->state_count = 0;
  dfa->states_head = NULL;
  dfa->states_tail = NULL;
  dfa->regex = GNUNET_strdup (regex);

  // Create DFA start state from epsilon closure
  nfa_set = nfa_closure_create (nfa, nfa->start, 0);
  dfa->start = dfa_state_create (&ctx, nfa_set);
  automaton_add_state (dfa, dfa->start);

  construct_dfa_states (&ctx, nfa, dfa, dfa->start);

  GNUNET_REGEX_automaton_destroy (nfa);

  // Minimize DFA
  dfa_minimize (&ctx, dfa);

  // Create proofs for all states
  automaton_create_proofs (dfa);

  // Add strides to DFA
  // GNUNET_REGEX_add_multi_strides_to_dfa (&ctx, dfa, 2);

  return dfa;
}


/**
 * Free the memory allocated by constructing the GNUNET_REGEX_Automaton data
 * structure.
 *
 * @param a automaton to be destroyed
 */
void
GNUNET_REGEX_automaton_destroy (struct GNUNET_REGEX_Automaton *a)
{
  struct GNUNET_REGEX_State *s;
  struct GNUNET_REGEX_State *next_state;

  if (NULL == a)
    return;

  GNUNET_free_non_null (a->regex);
  GNUNET_free_non_null (a->canonical_regex);

  for (s = a->states_head; NULL != s;)
  {
    next_state = s->next;
    automaton_destroy_state (s);
    s = next_state;
  }

  GNUNET_free (a);
}


/**
 * Evaluates the given string using the given DFA automaton
 *
 * @param a automaton, type must be DFA
 * @param string string that should be evaluated
 *
 * @return 0 if string matches, non 0 otherwise
 */
static int
evaluate_dfa (struct GNUNET_REGEX_Automaton *a, const char *string)
{
  const char *strp;
  char str[2];
  struct GNUNET_REGEX_State *s;

  if (DFA != a->type)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Tried to evaluate DFA, but NFA automaton given");
    return -1;
  }

  s = a->start;

  // If the string is empty but the starting state is accepting, we accept.
  if ((NULL == string || 0 == strlen (string)) && s->accepting)
    return 0;

  str[1] = '\0';
  for (strp = string; NULL != strp && *strp; strp++)
  {
    str[0] = *strp;
    s = dfa_move (s, str);
    if (NULL == s)
      break;
  }

  if (NULL != s && s->accepting)
    return 0;

  return 1;
}


/**
 * Evaluates the given string using the given NFA automaton
 *
 * @param a automaton, type must be NFA
 * @param string string that should be evaluated
 *
 * @return 0 if string matches, non 0 otherwise
 */
static int
evaluate_nfa (struct GNUNET_REGEX_Automaton *a, const char *string)
{
  const char *strp;
  char str[2];
  struct GNUNET_REGEX_State *s;
  struct GNUNET_REGEX_StateSet *sset;
  struct GNUNET_REGEX_StateSet *new_sset;
  unsigned int i;
  int result;

  if (NFA != a->type)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Tried to evaluate NFA, but DFA automaton given");
    return -1;
  }

  // If the string is empty but the starting state is accepting, we accept.
  if ((NULL == string || 0 == strlen (string)) && a->start->accepting)
    return 0;

  result = 1;
  sset = nfa_closure_create (a, a->start, 0);

  str[1] = '\0';
  for (strp = string; NULL != strp && *strp; strp++)
  {
    str[0] = *strp;
    new_sset = nfa_closure_set_create (a, sset, str);
    state_set_clear (sset);
    sset = nfa_closure_set_create (a, new_sset, 0);
    state_set_clear (new_sset);
  }

  for (i = 0; i < sset->len; i++)
  {
    s = sset->states[i];
    if (NULL != s && s->accepting)
    {
      result = 0;
      break;
    }
  }

  state_set_clear (sset);
  return result;
}


/**
 * Evaluates the given 'string' against the given compiled regex
 *
 * @param a automaton
 * @param string string to check
 *
 * @return 0 if string matches, non 0 otherwise
 */
int
GNUNET_REGEX_eval (struct GNUNET_REGEX_Automaton *a, const char *string)
{
  int result;

  switch (a->type)
  {
  case DFA:
    result = evaluate_dfa (a, string);
    break;
  case NFA:
    result = evaluate_nfa (a, string);
    break;
  default:
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Evaluating regex failed, automaton has no type!\n");
    result = GNUNET_SYSERR;
    break;
  }

  return result;
}


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
GNUNET_REGEX_get_canonical_regex (struct GNUNET_REGEX_Automaton *a)
{
  if (NULL == a)
    return NULL;

  return a->canonical_regex;
}


/**
 * Get the first key for the given 'input_string'. This hashes the first x bits
 * of the 'input_string'.
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
                            struct GNUNET_HashCode * key)
{
  unsigned int size;

  size = string_len < INITIAL_BITS ? string_len : INITIAL_BITS;

  if (NULL == input_string)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Given input string was NULL!\n");
    return 0;
  }

  GNUNET_CRYPTO_hash (input_string, size, key);

  return size;
}


/**
 * Check if the given 'proof' matches the given 'key'.
 *
 * @param proof partial regex of a state.
 * @param key hash of a state.
 *
 * @return GNUNET_OK if the proof is valid for the given key.
 */
int
GNUNET_REGEX_check_proof (const char *proof, const struct GNUNET_HashCode *key)
{
  struct GNUNET_HashCode key_check;

  if (NULL == proof || NULL == key)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Proof check failed, was NULL.\n");
    return GNUNET_NO;
  }

  GNUNET_CRYPTO_hash (proof, strlen (proof), &key_check);
  return (0 ==
          GNUNET_CRYPTO_hash_cmp (key, &key_check)) ? GNUNET_OK : GNUNET_NO;
}


/**
 * Recursive helper function for iterate_initial_edges. Will call iterator
 * function for each initial state.
 *
 * @param min_len minimum length of the path in the graph.
 * @param max_len maximum length of the path in the graph.
 * @param cur_len current length of the path already traversed.
 * @param consumed_string string consumed by traversing the graph till this state.
 * @param state current state of the automaton.
 * @param iterator iterator function called for each edge.
 * @param iterator_cls closure for the iterator function.
 */
static void
iterate_initial_edge (const unsigned int min_len, const unsigned int max_len,
                      unsigned int cur_len, char *consumed_string,
                      struct GNUNET_REGEX_State *state,
                      GNUNET_REGEX_KeyIterator iterator, void *iterator_cls)
{
  unsigned int i;
  char *temp;
  struct GNUNET_REGEX_Transition *t;
  unsigned int num_edges = state->transition_count;
  struct GNUNET_REGEX_Edge edges[num_edges];
  struct GNUNET_HashCode hash;

  if (cur_len > min_len && NULL != consumed_string && cur_len <= max_len)
  {
    for (i = 0, t = state->transitions_head; NULL != t; t = t->next, i++)
    {
      edges[i].label = t->label;
      edges[i].destination = t->to_state->hash;
    }

    GNUNET_CRYPTO_hash (consumed_string, strlen (consumed_string), &hash);
    iterator (iterator_cls, &hash, consumed_string, state->accepting, num_edges,
              edges);
  }

  if (cur_len < max_len)
  {
    cur_len++;
    for (t = state->transitions_head; NULL != t; t = t->next)
    {
      if (NULL != consumed_string)
        GNUNET_asprintf (&temp, "%s%s", consumed_string, t->label);
      else
        GNUNET_asprintf (&temp, "%s", t->label);

      iterate_initial_edge (min_len, max_len, cur_len, temp, t->to_state,
                            iterator, iterator_cls);
      GNUNET_free (temp);
    }
  }
}


/**
 * Iterate over all initial edges that aren't actually part of the automaton.
 * This is needed to find the initial states returned by
 * GNUNET_REGEX_get_first_key. Iteration will start at the first state that has
 * more than one outgoing edge, i.e. the state that branches the graph.
 * For example consider the following graph:
 * a -> b -> c -> d -> ...
 *            \-> e -> ...
 *
 * This function will not iterate over the edges leading to "c", because these
 * will be covered by the iterate_edges function.
 *
 * @param a the automaton for which the initial states should be computed.
 * @param initial_len length of the initial state string.
 * @param iterator iterator function called for each edge.
 * @param iterator_cls closure for the iterator function.
 */
void
iterate_initial_edges (struct GNUNET_REGEX_Automaton *a,
                       const unsigned int initial_len,
                       GNUNET_REGEX_KeyIterator iterator, void *iterator_cls)
{
  char *consumed_string;
  char *temp;
  struct GNUNET_REGEX_State *s;
  unsigned int cur_len;

  if (1 > initial_len)
    return;

  consumed_string = NULL;
  s = a->start;
  cur_len = 0;

  if (1 == s->transition_count)
  {
    do
    {
      if (NULL != consumed_string)
      {
        temp = consumed_string;
        GNUNET_asprintf (&consumed_string, "%s%s", consumed_string,
                         s->transitions_head->label);
        GNUNET_free (temp);
      }
      else
        GNUNET_asprintf (&consumed_string, "%s", s->transitions_head->label);

      s = s->transitions_head->to_state;
      cur_len += strlen (s->transitions_head->label);
    }
    while (cur_len < initial_len && 1 == s->transition_count);
  }

  iterate_initial_edge (cur_len, initial_len, cur_len, consumed_string, s,
                        iterator, iterator_cls);

  GNUNET_free_non_null (consumed_string);
}


/**
 * Iterate over all edges helper function starting from state 's', calling
 * iterator function for each edge.
 *
 * @param s state.
 * @param iterator iterator function called for each edge.
 * @param iterator_cls closure.
 */
static void
iterate_edge (struct GNUNET_REGEX_State *s, GNUNET_REGEX_KeyIterator iterator,
              void *iterator_cls)
{
  struct GNUNET_REGEX_Transition *t;
  struct GNUNET_REGEX_Edge edges[s->transition_count];
  unsigned int num_edges;

  if (GNUNET_YES != s->marked)
  {
    s->marked = GNUNET_YES;

    num_edges = state_get_edges (s, edges);

    if ((NULL != s->proof && 0 < strlen (s->proof)) || s->accepting)
      iterator (iterator_cls, &s->hash, s->proof, s->accepting, num_edges,
                edges);

    for (t = s->transitions_head; NULL != t; t = t->next)
      iterate_edge (t->to_state, iterator, iterator_cls);
  }
}


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
                                void *iterator_cls)
{
  struct GNUNET_REGEX_State *s;

  for (s = a->states_head; NULL != s; s = s->next)
    s->marked = GNUNET_NO;

  iterate_initial_edges (a, INITIAL_BITS, iterator, iterator_cls);
  iterate_edge (a->start, iterator, iterator_cls);
}
