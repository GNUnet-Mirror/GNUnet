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
 * @brief library to create Deterministic Finite Automatons (DFAs) from regular
 * expressions (regexes). Used by mesh for announcing regexes in the network and
 * matching strings against published regexes.
 * @author Maximilian Szengel
 */
#include "platform.h"
#include "gnunet_container_lib.h"
#include "gnunet_crypto_lib.h"
#include "gnunet_regex_lib.h"
#include "regex_internal.h"

/**
 * Set this to GNUNET_YES to enable state naming. Used to debug NFA->DFA
 * creation. Disabled by default for better performance.
 */
#define REGEX_DEBUG_DFA GNUNET_NO

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

/**
 * Set of states using MDLL API.
 */
struct GNUNET_REGEX_StateSet_MDLL
{
  /**
   * MDLL of states.
   */
  struct GNUNET_REGEX_State *head;

  /**
   * MDLL of states.
   */
  struct GNUNET_REGEX_State *tail;

  /**
   * Length of the MDLL.
   */
  unsigned int len;
};


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
  struct GNUNET_REGEX_Transition *t;
  struct GNUNET_REGEX_Transition *oth;

  if (NULL == from_state)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Could not create Transition.\n");
    return;
  }

  /* Do not add duplicate state transitions */
  for (t = from_state->transitions_head; NULL != t; t = t->next)
  {
    if (t->to_state == to_state && 0 == nullstrcmp (t->label, label) &&
        t->from_state == from_state)
      return;
  }

  /* sort transitions by label */
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

  /* Add outgoing transition to 'from_state' */
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

  GNUNET_free_non_null (transition->label);

  state->transition_count--;
  GNUNET_CONTAINER_DLL_remove (state->transitions_head, state->transitions_tail,
                               transition);

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
  if (NULL == set)
    return;

  if (set->len > 0)
    GNUNET_array_grow (set->states, set->len, 0);
  GNUNET_free (set);
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
  state_set_clear (s->nfa_set);

  for (t = s->transitions_head; NULL != t; t = next_t)
  {
    next_t = t->next;
    state_remove_transition (s, t);
  }

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
  struct GNUNET_REGEX_State *s_check;
  struct GNUNET_REGEX_Transition *t_check;
  struct GNUNET_REGEX_Transition *t_check_next;

  if (NULL == a || NULL == s)
    return;

  /* remove all transitions leading to this state */
  for (s_check = a->states_head; NULL != s_check; s_check = s_check->next)
  {
    for (t_check = s_check->transitions_head; NULL != t_check;
         t_check = t_check_next)
    {
      t_check_next = t_check->next;
      if (t_check->to_state == s)
        state_remove_transition (s_check, t_check);
    }
  }

  /* remove state */
  GNUNET_CONTAINER_DLL_remove (a->states_head, a->states_tail, s);
  a->state_count--;

  automaton_destroy_state (s);
}


/**
 * Merge two states into one. Will merge 's1' and 's2' into 's1' and destroy
 * 's2'. 's1' will contain all (non-duplicate) outgoing transitions of 's2'.
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
  int is_dup;

  GNUNET_assert (NULL != ctx && NULL != a && NULL != s1 && NULL != s2);

  if (s1 == s2)
    return;

  /* 1. Make all transitions pointing to s2 point to s1, unless this transition
   * does not already exists, if it already exists remove transition. */
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

  /* 2. Add all transitions from s2 to sX to s1 */
  for (t_check = s2->transitions_head; NULL != t_check; t_check = t_check->next)
  {
    if (t_check->to_state != s1)
      state_add_transition (ctx, s1, t_check->label, t_check->to_state);
  }

  /* 3. Rename s1 to {s1,s2} */
#if REGEX_DEBUG_DFA
  char *new_name;

  new_name = s1->name;
  GNUNET_asprintf (&s1->name, "{%s,%s}", new_name, s2->name);
  GNUNET_free (new_name);
#endif

  /* remove state */
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

  if (NULL == a || 0 == a->state_count)
    return;

  int marks[a->state_count];

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
remove_epsilon (char *str)
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
  /*
   * $R^{(k)}_{ij} = R^{(k-1)}_{ij} | R^{(k-1)}_{ik} ( R^{(k-1)}_{kk} )^* R^{(k-1)}_{kj}
   * R_last == R^{(k-1)}, R_cur == R^{(k)}
   * R_cur_ij = R_cur_l | R_cur_r
   * R_cur_l == R^{(k-1)}_{ij}
   * R_cur_r == R^{(k-1)}_{ik} ( R^{(k-1)}_{kk} )^* R^{(k-1)}_{kj}
   */

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

  /* $R^{(k)}_{ij} = N | R^{(k-1)}_{ik} ( R^{(k-1)}_{kk} )^* R^{(k-1)}_{kj} OR
   * $R^{(k)}_{ij} = R^{(k-1)}_{ij} | R^{(k-1)}_{ik} ( R^{(k-1)}_{kk} )^* R^{(k-1)}_{kj} */

  R_cur_r = NULL;
  R_cur_l = NULL;

  /* cache results from strcmp, we might need these many times */
  ij_kj_cmp = nullstrcmp (R_last_ij, R_last_kj);
  ij_ik_cmp = nullstrcmp (R_last_ij, R_last_ik);
  ik_kk_cmp = nullstrcmp (R_last_ik, R_last_kk);
  kk_kj_cmp = nullstrcmp (R_last_kk, R_last_kj);

  /* Assign R_temp_(ik|kk|kj) to R_last[][] and remove epsilon as well
   * as parentheses, so we can better compare the contents */
  R_temp_ik = remove_parentheses (remove_epsilon (R_last_ik));
  R_temp_kk = remove_parentheses (remove_epsilon (R_last_kk));
  R_temp_kj = remove_parentheses (remove_epsilon (R_last_kj));

  clean_ik_kk_cmp = nullstrcmp (R_last_ik, R_temp_kk);
  clean_kk_kj_cmp = nullstrcmp (R_temp_kk, R_last_kj);

  /* construct R_cur_l (and, if necessary R_cur_r) */
  if (NULL != R_last_ij)
  {
    /* Assign R_temp_ij to R_last_ij and remove epsilon as well
     * as parentheses, so we can better compare the contents */
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
        /*
         * a|(e|a)a*(e|a) = a*
         * a|(e|a)(e|a)*(e|a) = a*
         * (e|a)|aa*a = a*
         * (e|a)|aa*(e|a) = a*
         * (e|a)|(e|a)a*a = a*
         * (e|a)|(e|a)a*(e|a) = a*
         * (e|a)|(e|a)(e|a)*(e|a) = a*
         */
        if (GNUNET_YES == needs_parentheses (R_temp_ij))
          GNUNET_asprintf (&R_cur_r, "(%s)*", R_temp_ij);
        else
          GNUNET_asprintf (&R_cur_r, "%s*", R_temp_ij);
      }
      else
      {
        /*
         * a|aa*a = a+
         * a|(e|a)a*a = a+
         * a|aa*(e|a) = a+
         * a|(e|a)(e|a)*a = a+
         * a|a(e|a)*(e|a) = a+
         */
        if (GNUNET_YES == needs_parentheses (R_temp_ij))
          GNUNET_asprintf (&R_cur_r, "(%s)+", R_temp_ij);
        else
          GNUNET_asprintf (&R_cur_r, "%s+", R_temp_ij);
      }
    }
    else if (0 == ij_ik_cmp && 0 == clean_kk_kj_cmp && 0 != clean_ik_kk_cmp)
    {
      /* a|ab*b = ab* */
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
      /* a|bb*a = b*a */
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
      /* a|a(e|b)*(e|b) = a|ab* = a|a|ab|abb|abbb|... = ab* */
      if (needs_parentheses (R_temp_kk))
        GNUNET_asprintf (&R_cur_r, "%s(%s)*", R_last_ij, R_temp_kk);
      else
        GNUNET_asprintf (&R_cur_r, "%s%s*", R_last_ij, R_temp_kk);

      R_cur_l = NULL;
    }
    else if (0 == ij_kj_cmp && 0 == ik_kk_cmp && !has_epsilon (R_last_ij) &&
             has_epsilon (R_last_kk))
    {
      /* a|(e|b)(e|b)*a = a|b*a = a|a|ba|bba|bbba|...  = b*a */
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
    /* we have no left side */
    R_cur_l = NULL;
  }

  /* construct R_cur_r, if not already constructed */
  if (NULL == R_cur_r)
  {
    length = strlen (R_temp_kk) - strlen (R_last_ik);

    /* a(ba)*bx = (ab)+x */
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

      /* e|(ab)+ = (ab)* */
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
      /*
       * (e|a)a*(e|a) = a*
       * (e|a)(e|a)*(e|a) = a*
       */
      if (has_epsilon (R_last_ik) && has_epsilon (R_last_kj))
      {
        if (needs_parentheses (R_temp_kk))
          GNUNET_asprintf (&R_cur_r, "(%s)*", R_temp_kk);
        else
          GNUNET_asprintf (&R_cur_r, "%s*", R_temp_kk);
      }
      /* aa*a = a+a */
      else if (0 == clean_ik_kk_cmp && 0 == clean_kk_kj_cmp &&
               !has_epsilon (R_last_ik))
      {
        if (needs_parentheses (R_temp_kk))
          GNUNET_asprintf (&R_cur_r, "(%s)+%s", R_temp_kk, R_temp_kk);
        else
          GNUNET_asprintf (&R_cur_r, "(%s)+%s", R_temp_kk, R_temp_kk);
      }
      /*
       * (e|a)a*a = a+
       * aa*(e|a) = a+
       * a(e|a)*(e|a) = a+
       * (e|a)a*a = a+
       */
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
    /*
     * aa*b = a+b
     * (e|a)(e|a)*b = a*b
     */
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
    /*
     * ba*a = ba+
     * b(e|a)*(e|a) = ba*
     */
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
 * Create proofs for all states in the given automaton. Implementation of the
 * algorithm descriped in chapter 3.2.1 of "Automata Theory, Languages, and
 * Computation 3rd Edition" by Hopcroft, Motwani and Ullman.
 *
 * Each state in the automaton gets assigned 'proof' and 'hash' (hash of the
 * proof) fields. The starting state will only have a valid proof/hash if it has
 * any incoming transitions.
 *
 * @param a automaton for which to assign proofs and hashes.
 */
static void
automaton_create_proofs (struct GNUNET_REGEX_Automaton *a)
{
  if (NULL == a)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Could not create proofs, automaton was NULL\n");
    return;
  }

  unsigned int n = a->state_count;
  struct GNUNET_REGEX_State *states[n];
  char **R_last;
  char **R_cur;
  char *temp;
  struct GNUNET_REGEX_Transition *t;
  char *complete_regex;
  unsigned int i;
  unsigned int j;
  unsigned int k;

  R_last = GNUNET_malloc_large (sizeof (char *) * n * n);
  R_cur = GNUNET_malloc_large (sizeof (char *) * n * n);

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
      R_cur[i * n + j] = NULL;
      R_last[i * n + j] = NULL;
    }
    for (t = states[i]->transitions_head; NULL != t; t = t->next)
    {
      j = t->to_state->dfs_id;
      if (NULL == R_last[i * n + j])
        GNUNET_asprintf (&R_last[i * n + j], "%s", t->label);
      else
      {
        temp = R_last[i * n + j];
        GNUNET_asprintf (&R_last[i * n + j], "%s|%s", R_last[i * n + j],
                         t->label);
        GNUNET_free (temp);
      }
    }
    if (NULL == R_last[i * n + i])
      GNUNET_asprintf (&R_last[i * n + i], "");
    else
    {
      temp = R_last[i * n + i];
      GNUNET_asprintf (&R_last[i * n + i], "(|%s)", R_last[i * n + i]);
      GNUNET_free (temp);
    }
  }
  for (i = 0; i < n; i++)
    for (j = 0; j < n; j++)
      if (needs_parentheses (R_last[i * n + j]))
      {
        temp = R_last[i * n + j];
        GNUNET_asprintf (&R_last[i * n + j], "(%s)", R_last[i * n + j]);
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
        /* Basis for the recursion:
         * $R^{(k)}_{ij} = R^{(k-1)}_{ij} | R^{(k-1)}_{ik} ( R^{(k-1)}_{kk} )^* R^{(k-1)}_{kj}
         * R_last == R^{(k-1)}, R_cur == R^{(k)}
         */

        /* Create R_cur[i][j] and simplify the expression */
        automaton_create_proofs_simplify (R_last[i * n + j], R_last[i * n + k],
                                          R_last[k * n + k], R_last[k * n + j],
                                          &R_cur[i * n + j]);
      }
    }

    /* set R_last = R_cur */
    for (i = 0; i < n; i++)
    {
      for (j = 0; j < n; j++)
      {
        GNUNET_free_non_null (R_last[i * n + j]);
        R_last[i * n + j] = R_cur[i * n + j];
        R_cur[i * n + j] = NULL;
      }
    }
  }

  /* assign proofs and hashes */
  for (i = 0; i < n; i++)
  {
    if (NULL != R_last[a->start->dfs_id * n + i])
    {
      states[i]->proof = GNUNET_strdup (R_last[a->start->dfs_id * n + i]);
      GNUNET_CRYPTO_hash (states[i]->proof, strlen (states[i]->proof),
                          &states[i]->hash);
    }
  }

  /* complete regex for whole DFA: union of all pairs (start state/accepting
   * state(s)). */
  complete_regex = NULL;
  for (i = 0; i < n; i++)
  {
    if (states[i]->accepting)
    {
      if (NULL == complete_regex &&
          0 < strlen (R_last[a->start->dfs_id * n + i]))
      {
        GNUNET_asprintf (&complete_regex, "%s",
                         R_last[a->start->dfs_id * n + i]);
      }
      else if (NULL != R_last[a->start->dfs_id * n + i] &&
               0 < strlen (R_last[a->start->dfs_id * n + i]))
      {
        temp = complete_regex;
        GNUNET_asprintf (&complete_regex, "%s|%s", complete_regex,
                         R_last[a->start->dfs_id * n + i]);
        GNUNET_free (temp);
      }
    }
  }
  a->canonical_regex = complete_regex;

  /* cleanup */
  for (i = 0; i < n; i++)
  {
    for (j = 0; j < n; j++)
      GNUNET_free_non_null (R_last[i * n + j]);
  }
  GNUNET_free (R_cur);
  GNUNET_free (R_last);
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
  s->index = -1;
  s->lowlink = -1;

  if (NULL == nfa_states)
  {
    GNUNET_asprintf (&s->name, "s%i", s->id);
    return s;
  }

  s->nfa_set = nfa_states;

  if (nfa_states->len < 1)
    return s;

  /* Create a name based on 'nfa_states' */
  s->name = GNUNET_malloc (sizeof (char) * 2);
  strcat (s->name, "{");
  name = NULL;

  for (i = 0; i < nfa_states->len; i++)
  {
    cstate = nfa_states->states[i];
    GNUNET_asprintf (&name, "%i,", cstate->id);

    len = strlen (s->name) + strlen (name) + 1;
    s->name = GNUNET_realloc (s->name, len);
    strcat (s->name, name);
    GNUNET_free (name);
    name = NULL;    

    /* Add a transition for each distinct label to NULL state */
    for (ctran = cstate->transitions_head; NULL != ctran; ctran = ctran->next)    
      if (NULL != ctran->label)
        state_add_transition (ctx, s, ctran->label, NULL);    

    /* If the nfa_states contain an accepting state, the new dfa state is also
     * accepting. */
    if (cstate->accepting)
      s->accepting = 1;
  }

  s->name[strlen (s->name) - 1] = '}';

  return s;
}


/**
 * Move from the given state 's' to the next state on transition 'str'. Consumes
 * as much of the given 'str' as possible (usefull for strided DFAs). On return
 * 's' will point to the next state, and the length of the substring used for
 * this transition will be returned. If no transition possible 0 is returned and
 * 's' points to NULL.
 *
 * @param s starting state, will point to the next state or NULL (if no
 * transition possible)
 * @param str edge label to follow (will match longest common prefix)
 *
 * @return length of the substring comsumed from 'str'
 */
static unsigned int
dfa_move (struct GNUNET_REGEX_State **s, const char *str)
{
  struct GNUNET_REGEX_Transition *t;
  struct GNUNET_REGEX_State *new_s;
  unsigned int len;
  unsigned int max_len;

  if (NULL == s)
    return 0;

  new_s = NULL;
  max_len = 0;
  for (t = (*s)->transitions_head; NULL != t; t = t->next)
  {
    len = strlen (t->label);

    if (0 == strncmp (t->label, str, len))
    {
      if (len >= max_len)
      {
        max_len = len;
        new_s = t->to_state;
      }
    }
  }

  *s = new_s;
  return max_len;
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

  /* 1. unmark all states */
  for (s = a->states_head; NULL != s; s = s->next)
    s->marked = GNUNET_NO;

  /* 2. traverse dfa from start state and mark all visited states */
  GNUNET_REGEX_automaton_traverse (a, a->start, NULL, NULL, &mark_states, NULL);

  /* 3. delete all states that were not visited */
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
  struct GNUNET_REGEX_State *s_next;
  struct GNUNET_REGEX_Transition *t;
  int dead;

  GNUNET_assert (DFA == a->type);

  for (s = a->states_head; NULL != s; s = s_next)
  {
    s_next = s->next;

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

    /* state s is dead, remove it */
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
  int *table;
  struct GNUNET_REGEX_State *s1;
  struct GNUNET_REGEX_State *s2;
  struct GNUNET_REGEX_Transition *t1;
  struct GNUNET_REGEX_Transition *t2;
  struct GNUNET_REGEX_State *s1_next;
  struct GNUNET_REGEX_State *s2_next;
  int change;
  unsigned int num_equal_edges;
  unsigned int i;
  unsigned int state_cnt;

  if (NULL == a || 0 == a->state_count)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Could not merge nondistinguishable states, automaton was NULL.\n");
    return;
  }

  state_cnt = a->state_count;
  table =
      (int *) GNUNET_malloc_large (sizeof (int) * state_cnt * a->state_count);

  for (i = 0, s1 = a->states_head; i < state_cnt && NULL != s1;
       i++, s1 = s1->next)
  {
    s1->marked = i;
  }

  /* Mark all pairs of accepting/!accepting states */
  for (s1 = a->states_head; NULL != s1; s1 = s1->next)
  {
    for (s2 = a->states_head; NULL != s2; s2 = s2->next)
    {
      table[((s1->marked * state_cnt) + s2->marked)] = 0;

      if ((s1->accepting && !s2->accepting) ||
          (!s1->accepting && s2->accepting))
      {
        table[((s1->marked * state_cnt) + s2->marked)] = 1;
      }
    }
  }

  /* Find all equal states */
  change = 1;
  while (0 != change)
  {
    change = 0;
    for (s1 = a->states_head; NULL != s1; s1 = s1->next)
    {
      for (s2 = a->states_head; NULL != s2 && s1 != s2; s2 = s2->next)
      {
        if (0 != table[((s1->marked * state_cnt) + s2->marked)])
          continue;

        num_equal_edges = 0;
        for (t1 = s1->transitions_head; NULL != t1; t1 = t1->next)
        {
          for (t2 = s2->transitions_head; NULL != t2; t2 = t2->next)
          {
            if (0 == strcmp (t1->label, t2->label))
            {
              num_equal_edges++;
              if (0 !=
                  table[((t1->to_state->marked * state_cnt) +
                         t2->to_state->marked)] ||
                  0 !=
                  table[((t2->to_state->marked * state_cnt) +
                         t1->to_state->marked)])
              {
                table[((s1->marked * state_cnt) + s2->marked)] = 1;
                change = 1;
              }
            }
          }
        }
        if (num_equal_edges != s1->transition_count ||
            num_equal_edges != s2->transition_count)
        {
          /* Make sure ALL edges of possible equal states are the same */
          table[((s1->marked * state_cnt) + s2->marked)] = -2;
        }
      }
    }
  }

  /* Merge states that are equal */
  for (s1 = a->states_head; NULL != s1; s1 = s1_next)
  {
    s1_next = s1->next;
    for (s2 = a->states_head; NULL != s2 && s1 != s2; s2 = s2_next)
    {
      s2_next = s2->next;
      if (0 == table[((s1->marked * state_cnt) + s2->marked)])
        automaton_merge_states (ctx, a, s1, s2);
    }
  }

  GNUNET_free (table);
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

  /* 1. remove unreachable states */
  dfa_remove_unreachable_states (a);

  /* 2. remove dead states */
  dfa_remove_dead_states (a);

  /* 3. Merge nondistinguishable states */
  dfa_merge_nondistinguishable_states (ctx, a);
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
dfa_add_multi_strides_helper (void *cls, const unsigned int depth, char *label,
                              struct GNUNET_REGEX_State *start,
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

      dfa_add_multi_strides_helper (cls, (depth + 1), new_label, start,
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
dfa_add_multi_strides (void *cls, const unsigned int count,
                       struct GNUNET_REGEX_State *s)
{
  dfa_add_multi_strides_helper (cls, 0, NULL, s, s);
}


/**
 * Adds multi-strided transitions to the given 'dfa'.
 *
 * @param regex_ctx regex context needed to add transitions to the automaton.
 * @param dfa DFA to which the multi strided transitions should be added.
 * @param stride_len length of the strides.
 */
void
GNUNET_REGEX_dfa_add_multi_strides (struct GNUNET_REGEX_Context *regex_ctx,
                                    struct GNUNET_REGEX_Automaton *dfa,
                                    const unsigned int stride_len)
{
  struct GNUNET_REGEX_Strided_Context ctx = { stride_len, NULL, NULL };
  struct GNUNET_REGEX_Transition *t;
  struct GNUNET_REGEX_Transition *t_next;

  if (1 > stride_len || GNUNET_YES == dfa->is_multistrided)
    return;

  /* Compute the new transitions of given stride_len */
  GNUNET_REGEX_automaton_traverse (dfa, dfa->start, NULL, NULL,
                                   &dfa_add_multi_strides, &ctx);

  /* Add all the new transitions to the automaton. */
  for (t = ctx.transitions_head; NULL != t; t = t_next)
  {
    t_next = t->next;
    state_add_transition (regex_ctx, t->from_state, t->label, t->to_state);
    GNUNET_CONTAINER_DLL_remove (ctx.transitions_head, ctx.transitions_tail, t);
    GNUNET_free_non_null (t->label);
    GNUNET_free (t);
  }

  /* Mark this automaton as multistrided */
  dfa->is_multistrided = GNUNET_YES;
}

/**
 * Recursive Helper function for DFA path compression. Does DFS on the DFA graph
 * and adds new transitions to the given transitions DLL and marks states that
 * should be removed by setting state->contained to GNUNET_YES.
 *
 * @param dfa DFA for which the paths should be compressed.
 * @param start starting state for linear path search.
 * @param cur current state in the recursive DFS.
 * @param label current label (string of traversed labels).
 * @param max_len maximal path compression length.
 * @param transitions_head transitions DLL.
 * @param transitions_tail transitions DLL.
 */
void
dfa_compress_paths_helper (struct GNUNET_REGEX_Automaton *dfa,
                           struct GNUNET_REGEX_State *start,
                           struct GNUNET_REGEX_State *cur, char *label,
                           unsigned int max_len,
                           struct GNUNET_REGEX_Transition **transitions_head,
                           struct GNUNET_REGEX_Transition **transitions_tail)
{
  struct GNUNET_REGEX_Transition *t;
  char *new_label;


  if (NULL != label &&
      ((cur->incoming_transition_count > 1 || GNUNET_YES == cur->accepting ||
        GNUNET_YES == cur->marked) || (start != dfa->start && max_len > 0 &&
                                       max_len == strlen (label)) ||
       (start == dfa->start && GNUNET_REGEX_INITIAL_BYTES == strlen (label))))
  {
    t = GNUNET_malloc (sizeof (struct GNUNET_REGEX_Transition));
    t->label = GNUNET_strdup (label);
    t->to_state = cur;
    t->from_state = start;
    GNUNET_CONTAINER_DLL_insert (*transitions_head, *transitions_tail, t);

    if (GNUNET_NO == cur->marked)
    {
      dfa_compress_paths_helper (dfa, cur, cur, NULL, max_len, transitions_head,
                                 transitions_tail);
    }
    return;
  }
  else if (cur != start)
    cur->contained = GNUNET_YES;

  if (GNUNET_YES == cur->marked && cur != start)
    return;

  cur->marked = GNUNET_YES;


  for (t = cur->transitions_head; NULL != t; t = t->next)
  {
    if (NULL != label)
      GNUNET_asprintf (&new_label, "%s%s", label, t->label);
    else
      new_label = GNUNET_strdup (t->label);

    if (t->to_state != cur)
    {
      dfa_compress_paths_helper (dfa, start, t->to_state, new_label, max_len,
                                 transitions_head, transitions_tail);
    }
    GNUNET_free (new_label);
  }
}

/**
 * Compress paths in the given 'dfa'. Linear paths like 0->1->2->3 will be
 * compressed to 0->3 by combining transitions.
 *
 * @param regex_ctx context for adding new transitions.
 * @param dfa DFA representation, will directly modify the given DFA.
 * @param max_len maximal length of the compressed paths.
 */
static void
dfa_compress_paths (struct GNUNET_REGEX_Context *regex_ctx,
                    struct GNUNET_REGEX_Automaton *dfa, unsigned int max_len)
{
  struct GNUNET_REGEX_State *s;
  struct GNUNET_REGEX_State *s_next;
  struct GNUNET_REGEX_Transition *t;
  struct GNUNET_REGEX_Transition *t_next;
  struct GNUNET_REGEX_Transition *transitions_head = NULL;
  struct GNUNET_REGEX_Transition *transitions_tail = NULL;

  if (NULL == dfa)
    return;

  /* Count the incoming transitions on each state. */
  for (s = dfa->states_head; NULL != s; s = s->next)
  {
    for (t = s->transitions_head; NULL != t; t = t->next)
    {
      if (NULL != t->to_state)
        t->to_state->incoming_transition_count++;
    }
  }

  /* Unmark all states. */
  for (s = dfa->states_head; NULL != s; s = s->next)
  {
    s->marked = GNUNET_NO;
    s->contained = GNUNET_NO;
  }

  /* Add strides and mark states that can be deleted. */
  dfa_compress_paths_helper (dfa, dfa->start, dfa->start, NULL, max_len,
                             &transitions_head, &transitions_tail);

  /* Add all the new transitions to the automaton. */
  for (t = transitions_head; NULL != t; t = t_next)
  {
    t_next = t->next;
    state_add_transition (regex_ctx, t->from_state, t->label, t->to_state);
    GNUNET_CONTAINER_DLL_remove (transitions_head, transitions_tail, t);
    GNUNET_free_non_null (t->label);
    GNUNET_free (t);
  }

  /* Remove marked states (including their incoming and outgoing transitions). */
  for (s = dfa->states_head; NULL != s; s = s_next)
  {
    s_next = s->next;
    if (GNUNET_YES == s->contained)
      automaton_remove_state (dfa, s);
  }
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
  unsigned int i;
  struct GNUNET_REGEX_StateSet *cls;
  struct GNUNET_REGEX_StateSet_MDLL cls_stack;
  struct GNUNET_REGEX_State *clsstate;
  struct GNUNET_REGEX_State *currentstate;
  struct GNUNET_REGEX_Transition *ctran;

  if (NULL == s)
    return NULL;

  cls = GNUNET_malloc (sizeof (struct GNUNET_REGEX_StateSet));
  cls_stack.head = NULL;
  cls_stack.tail = NULL;

  /* Add start state to closure only for epsilon closure */
  if (NULL == label)
    GNUNET_array_append (cls->states, cls->len, s);

  GNUNET_CONTAINER_MDLL_insert (ST, cls_stack.head, cls_stack.tail, s);
  cls_stack.len = 1;

  while (cls_stack.len > 0)
  {
    currentstate = cls_stack.tail;
    GNUNET_CONTAINER_MDLL_remove (ST, cls_stack.head, cls_stack.tail,
                                  currentstate);
    cls_stack.len--;

    for (ctran = currentstate->transitions_head; NULL != ctran;
         ctran = ctran->next)
    {
      if (NULL != ctran->to_state && 0 == nullstrcmp (label, ctran->label))
      {
        clsstate = ctran->to_state;

        if (NULL != clsstate && 0 == clsstate->contained)
        {
          GNUNET_array_append (cls->states, cls->len, clsstate);
          GNUNET_CONTAINER_MDLL_insert_tail (ST, cls_stack.head, cls_stack.tail,
                                             clsstate);
          cls_stack.len++;
          clsstate->contained = 1;
        }
      }
    }
  }

  for (i = 0; i < cls->len; i++)
    cls->states[i]->contained = 0;

  /* sort the states */
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

  if (NULL == a)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "nfa_add_plus_op failed, because there was no element on the stack");
    return;
  }

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
  GNUNET_CONTAINER_DLL_insert_tail (ctx->stack_head, ctx->stack_tail, new_nfa);
  automaton_fragment_clear (a);
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

  if (NULL == regex || 0 == strlen (regex) || 0 == len)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Could not parse regex. Empty regex string provided.\n");

    return NULL;
  }

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
        /* Ignore this: "()" */
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

  /* Remember the regex that was used to generate this NFA */
  nfa->regex = GNUNET_strdup (regex);

  /* create depth-first numbering of the states for pretty printing */
  GNUNET_REGEX_automaton_traverse (nfa, NULL, NULL, NULL, &number_states, NULL);

  /* No multistriding added so far */
  nfa->is_multistrided = GNUNET_NO;

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
                            int max_path_len)
{
  struct GNUNET_REGEX_Context ctx;
  struct GNUNET_REGEX_Automaton *dfa;
  struct GNUNET_REGEX_Automaton *nfa;
  struct GNUNET_REGEX_StateSet *nfa_start_eps_cls;

  GNUNET_REGEX_context_init (&ctx);

  /* Create NFA */
  nfa = GNUNET_REGEX_construct_nfa (regex, len);

  if (NULL == nfa)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Could not create DFA, because NFA creation failed\n");
    return NULL;
  }

  dfa = GNUNET_malloc (sizeof (struct GNUNET_REGEX_Automaton));
  dfa->type = DFA;
  dfa->regex = GNUNET_strdup (regex);

  /* Create DFA start state from epsilon closure */
  nfa_start_eps_cls = nfa_closure_create (nfa, nfa->start, 0);
  dfa->start = dfa_state_create (&ctx, nfa_start_eps_cls);
  automaton_add_state (dfa, dfa->start);

  construct_dfa_states (&ctx, nfa, dfa, dfa->start);

  GNUNET_REGEX_automaton_destroy (nfa);

  /* Minimize DFA */
  dfa_minimize (&ctx, dfa);

  /* Create proofs and hashes for all states */
  automaton_create_proofs (dfa);

  /* Compress linear DFA paths */
  if (1 != max_path_len)
    dfa_compress_paths (&ctx, dfa, max_path_len);

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

  for (s = a->states_head; NULL != s; s = next_state)
  {
    next_state = s->next;
    GNUNET_CONTAINER_DLL_remove (a->states_head, a->states_tail, s);
    automaton_destroy_state (s);
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
  struct GNUNET_REGEX_State *s;
  unsigned int step_len;

  if (DFA != a->type)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Tried to evaluate DFA, but NFA automaton given");
    return -1;
  }

  s = a->start;

  /* If the string is empty but the starting state is accepting, we accept. */
  if ((NULL == string || 0 == strlen (string)) && s->accepting)
    return 0;

  for (strp = string; NULL != strp && *strp; strp += step_len)
  {
    step_len = dfa_move (&s, strp);

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

  /* If the string is empty but the starting state is accepting, we accept. */
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
 * Get the number of transitions that are contained in the given automaton.
 *
 * @param a automaton for which the number of transitions should be returned.
 *
 * @return number of transitions in the given automaton.
 */
unsigned int
GNUNET_REGEX_get_transition_count (struct GNUNET_REGEX_Automaton *a)
{
  unsigned int t_count;
  struct GNUNET_REGEX_State *s;

  if (NULL == a)
    return 0;

  t_count = 0;
  for (s = a->states_head; NULL != s; s = s->next)
    t_count += s->transition_count;

  return t_count;
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

  size =
      string_len <
      GNUNET_REGEX_INITIAL_BYTES ? string_len : GNUNET_REGEX_INITIAL_BYTES;

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
 * Recursive function that calls the iterator for each synthetic start state.
 *
 * @param min_len minimum length of the path in the graph.
 * @param max_len maximum length of the path in the graph.
 * @param consumed_string string consumed by traversing the graph till this state.
 * @param state current state of the automaton.
 * @param iterator iterator function called for each edge.
 * @param iterator_cls closure for the iterator function.
 */
static void
iterate_initial_edge (const unsigned int min_len, const unsigned int max_len,
                      char *consumed_string, struct GNUNET_REGEX_State *state,
                      GNUNET_REGEX_KeyIterator iterator, void *iterator_cls)
{
  unsigned int i;
  char *temp;
  struct GNUNET_REGEX_Transition *t;
  unsigned int num_edges = state->transition_count;
  struct GNUNET_REGEX_Edge edges[num_edges];
  struct GNUNET_REGEX_Edge edge[1];
  struct GNUNET_HashCode hash;
  struct GNUNET_HashCode hash_new;

  unsigned int cur_len;

  if (NULL != consumed_string)
    cur_len = strlen (consumed_string);
  else
    cur_len = 0;

  if ((cur_len >= min_len || GNUNET_YES == state->accepting) && cur_len > 0 &&
      NULL != consumed_string)
  {
    if (cur_len <= max_len)
    {
      if (state->proof != NULL && 0 != strcmp (consumed_string, state->proof))
      {
        for (i = 0, t = state->transitions_head; NULL != t && i < num_edges;
             t = t->next, i++)
        {
          edges[i].label = t->label;
          edges[i].destination = t->to_state->hash;
        }
        GNUNET_CRYPTO_hash (consumed_string, strlen (consumed_string), &hash);
        iterator (iterator_cls, &hash, consumed_string, state->accepting,
                  num_edges, edges);
      }

      if (GNUNET_YES == state->accepting && cur_len > 1 &&
          state->transition_count < 1 && cur_len < max_len)
      {
        /* Special case for regex consisting of just a string that is shorter than
         * max_len */
        edge[0].label = &consumed_string[cur_len - 1];
        edge[0].destination = state->hash;
        temp = GNUNET_strdup (consumed_string);
        temp[cur_len - 1] = '\0';
        GNUNET_CRYPTO_hash (temp, cur_len - 1, &hash_new);
        iterator (iterator_cls, &hash_new, temp, GNUNET_NO, 1, edge);
        GNUNET_free (temp);
      }
    }
    else if (max_len < cur_len)
    {
      /* Case where the concatenated labels are longer than max_len, then split. */
      edge[0].label = &consumed_string[max_len];
      edge[0].destination = state->hash;
      temp = GNUNET_strdup (consumed_string);
      temp[max_len] = '\0';
      GNUNET_CRYPTO_hash (temp, max_len, &hash);
      iterator (iterator_cls, &hash, temp, GNUNET_NO, 1, edge);
      GNUNET_free (temp);
    }
  }

  if (cur_len < max_len)
  {
    for (t = state->transitions_head; NULL != t; t = t->next)
    {
      if (NULL != consumed_string)
        GNUNET_asprintf (&temp, "%s%s", consumed_string, t->label);
      else
        GNUNET_asprintf (&temp, "%s", t->label);

      iterate_initial_edge (min_len, max_len, temp, t->to_state, iterator,
                            iterator_cls);
      GNUNET_free (temp);
    }
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
  {
    struct GNUNET_REGEX_Edge edges[s->transition_count];
    unsigned int num_edges;

    num_edges = state_get_edges (s, edges);

    if ((NULL != s->proof && 0 < strlen (s->proof)) || s->accepting)
      iterator (iterator_cls, &s->hash, s->proof, s->accepting, num_edges,
                edges);

    s->marked = GNUNET_NO;
  }

  iterate_initial_edge (GNUNET_REGEX_INITIAL_BYTES, GNUNET_REGEX_INITIAL_BYTES,
                        NULL, a->start, iterator, iterator_cls);
}


/**
 * Create a string with binary IP notation for the given 'addr' in 'str'.
 *
 * @param af address family of the given 'addr'.
 * @param addr address that should be converted to a string.
 *             struct in_addr * for IPv4 and struct in6_addr * for IPv6.
 * @param str string that will contain binary notation of 'addr'. Expected
 *            to be at least 33 bytes long for IPv4 and 129 bytes long for IPv6.
 */
static void
iptobinstr (const int af, const void *addr, char *str)
{
  int i;

  switch (af)
  {
  case AF_INET:
  {
    uint32_t b = htonl (((struct in_addr *) addr)->s_addr);

    str[32] = '\0';
    str += 31;
    for (i = 31; i >= 0; i--)
    {
      *str = (b & 1) + '0';
      str--;
      b >>= 1;
    }
    break;
  }
  case AF_INET6:
  {
    struct in6_addr b = *(const struct in6_addr *) addr;

    str[128] = '\0';
    str += 127;
    for (i = 127; i >= 0; i--)
    {
      *str = (b.s6_addr[i / 8] & 1) + '0';
      str--;
      b.s6_addr[i / 8] >>= 1;
    }
    break;
  }
  }
}


/**
 * Get the ipv4 network prefix from the given 'netmask'.
 *
 * @param netmask netmask for which to get the prefix len.
 *
 * @return length of ipv4 prefix for 'netmask'.
 */
static unsigned int
ipv4netmasktoprefixlen (const char *netmask)
{
  struct in_addr a;
  unsigned int len;
  uint32_t t;

  if (1 != inet_pton (AF_INET, netmask, &a))
    return 0;
  len = 32;
  for (t = htonl (~a.s_addr); 0 != t; t >>= 1)
    len--;
  return len;
}


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
                          char *rxstr)
{
  unsigned int pfxlen;

  pfxlen = ipv4netmasktoprefixlen (netmask);
  iptobinstr (AF_INET, ip, rxstr);
  rxstr[pfxlen] = '\0';
  if (pfxlen < 32)
    strcat (rxstr, "(0|1)+");
}


/**
 * Create a regex in 'rxstr' from the given 'ipv6' and 'prefixlen'.
 *
 * @param ipv6 IPv6 representation.
 * @param prefixlen length of the ipv6 prefix.
 * @param rxstr generated regex, must be at least GNUNET_REGEX_IPV6_REGEXLEN
 *              bytes long.
 */
void
GNUNET_REGEX_ipv6toregex (const struct in6_addr *ipv6, unsigned int prefixlen,
                          char *rxstr)
{
  iptobinstr (AF_INET6, ipv6, rxstr);
  rxstr[prefixlen] = '\0';
  if (prefixlen < 128)
    strcat (rxstr, "(0|1)+");
}
