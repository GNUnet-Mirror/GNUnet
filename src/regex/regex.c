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
#include "gnunet_regex_lib.h"
#include "regex.h"

/**
 * Context that contains an id counter for states and transitions
 * as well as a DLL of automatons used as a stack for NFA construction.
 */
struct GNUNET_REGEX_Context
{
  unsigned int state_id;
  unsigned int transition_id;

  /**
   * DLL of GNUNET_REGEX_Automaton's used as a stack
   */
  struct GNUNET_REGEX_Automaton *stack_head;
  struct GNUNET_REGEX_Automaton *stack_tail;
};

enum GNUNET_REGEX_automaton_type
{
  NFA,
  DFA
};

/**
 * Automaton representation
 */
struct GNUNET_REGEX_Automaton
{
  struct GNUNET_REGEX_Automaton *prev;
  struct GNUNET_REGEX_Automaton *next;

  struct State *start;
  struct State *end;

  unsigned int state_count;
  struct State *states_head;
  struct State *states_tail;

  enum GNUNET_REGEX_automaton_type type;
};

/**
 * A state. Can be used in DFA and NFA automatons.
 */
struct State
{
  struct State *prev;
  struct State *next;

  unsigned int id;
  int accepting;
  int marked;
  char *name;

  unsigned int transition_count;
  struct Transition *transitions_head;
  struct Transition *transitions_tail;

  struct StateSet *nfa_set;
};

/**
 * Transition between two states. Each state can have 0-n transitions.
 * If literal is 0, this is considered to be an epsilon transition.
 */
struct Transition
{
  struct Transition *prev;
  struct Transition *next;

  unsigned int id;
  char literal;
  struct State *state;
};

/**
 * Set of states
 */
struct StateSet
{
  /**
   * Array of states
   */
  struct State **states;
  unsigned int len;
};

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

static void
debug_print_state (struct State *s)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "State %i: %s marked: %i accepting: %i\n", s->id, s->name,
              s->marked, s->accepting);
}

static void
debug_print_states (struct StateSet *sset)
{
  struct State *s;
  int i;

  for (i = 0; i < sset->len; i++)
  {
    s = sset->states[i];
    debug_print_state (s);
  }
}

static void
debug_print_transitions (struct State *s)
{
  struct Transition *t;
  char *state;
  char literal;

  for (t = s->transitions_head; NULL != t; t = t->next)
  {
    if (0 == t->literal)
      literal = '0';
    else
      literal = t->literal;

    if (NULL == t->state)
      state = "NULL";
    else
      state = t->state->name;

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Transition %i: On %c to %s\n", t->id,
                literal, state);
  }
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
  struct State **s1;
  struct State **s2;

  s1 = (struct State **) a;
  s2 = (struct State **) b;

  return (*s1)->id - (*s2)->id;
}

/**
 * Compare to state sets by comparing the id's of the states that are
 * contained in each set. Both sets are expected to be sorted by id!
 *
 * @param sset1 first state set
 * @param sset2 second state set
 *
 * @return 0 if they are equal, non 0 otherwise
 */
static int
state_set_compare (struct StateSet *sset1, struct StateSet *sset2)
{
  int i;

  if (sset1->len != sset2->len)
    return 1;

  for (i = 0; i < sset1->len; i++)
  {
    if (sset1->states[i]->id != sset2->states[i]->id)
    {
      return 1;
    }
  }
  return 0;
}

/**
 * Checks if 'elem' is contained in 'set'
 *
 * @param set set of states
 * @param elem state
 *
 * @return GNUNET_YES if 'set' contains 'elem, GNUNET_NO otherwise
 */
static int
state_set_contains (struct StateSet *set, struct State *elem)
{
  struct State *s;
  int i;

  for (i = 0; i < set->len; i++)
  {
    s = set->states[i];
    if (0 == memcmp (s, elem, sizeof (struct State)))
      return GNUNET_YES;
  }
  return GNUNET_NO;
}

/**
 * Clears the given StateSet 'set'
 *
 * @param set set to be cleared
 */
static void
state_set_clear (struct StateSet *set)
{
  if (NULL != set)
  {
    if (NULL != set->states)
      GNUNET_free (set->states);
    GNUNET_free (set);
  }
}

/**
 * Adds a transition from one state to another on 'literal'
 *
 * @param ctx context
 * @param from_state starting state for the transition
 * @param literal transition label
 * @param to_state state to where the transition should point to
 */
static void
add_transition (struct GNUNET_REGEX_Context *ctx, struct State *from_state,
                const char literal, struct State *to_state)
{
  struct Transition *t;

  if (NULL == from_state)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Could not create Transition.\n");
    return;
  }

  t = GNUNET_malloc (sizeof (struct Transition));

  t->id = ctx->transition_id++;
  t->literal = literal;
  t->state = to_state;

  GNUNET_CONTAINER_DLL_insert (from_state->transitions_head,
                               from_state->transitions_tail, t);
}

/**
 * Clears an automaton fragment. Does not destroy the states inside
 * the automaton.
 *
 * @param a automaton to be cleared
 */
static void
automaton_fragment_clear (struct GNUNET_REGEX_Automaton *a)
{
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
automaton_destroy_state (struct State *s)
{
  struct Transition *t;
  struct Transition *next_t;

  if (NULL != s->name)
    GNUNET_free (s->name);

  for (t = s->transitions_head; NULL != t;)
  {
    next_t = t->next;
    GNUNET_CONTAINER_DLL_remove (s->transitions_head, s->transitions_tail, t);
    GNUNET_free (t);
    t = next_t;
  }

  state_set_clear (s->nfa_set);

  GNUNET_free (s);
}

/**
 * Remove a state from the given automaton 'a'. Always use this function
 * when altering the states of an automaton. Will also remove all transitions
 * leading to this state, before destroying it.
 *
 * @param a automaton
 * @param s state to remove
 */
static void
automaton_remove_state (struct GNUNET_REGEX_Automaton *a, struct State *s)
{
  struct State *ss;
  struct State *s_check;
  struct Transition *t_check;

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
      if (t_check->state == ss)
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
 * Merge two states into one. Will merge 's1' and 's2' into 's1' and destroy 's2'.
 *
 * @param ctx context
 * @param a automaton
 * @param s1 first state
 * @param s2 second state, will be destroyed
 */
static void
automaton_merge_states (struct GNUNET_REGEX_Context *ctx,
                        struct GNUNET_REGEX_Automaton *a, struct State *s1,
                        struct State *s2)
{
  struct State *s_check;
  struct Transition *t_check;
  struct Transition *t;
  char *new_name;

  GNUNET_assert (NULL != ctx && NULL != a && NULL != s1 && NULL != s2);

  // 1. Make all transitions pointing to s2 point to s1
  for (s_check = a->states_head; NULL != s_check; s_check = s_check->next)
  {
    for (t_check = s_check->transitions_head; NULL != t_check;
         t_check = t_check->next)
    {
      if (s_check != s1 && s2 == t_check->state)
        t_check->state = s1;
    }
  }

  // 2. Add all transitions from s2 to sX to s1
  for (t_check = s2->transitions_head; NULL != t_check; t_check = t_check->next)
  {
    for (t = s1->transitions_head; NULL != t; t = t->next)
    {
      if (t_check->literal != t->literal && NULL != t_check->state &&
          t_check->state != t->state && t_check->state != s2)
      {
        add_transition (ctx, s1, t_check->literal, t_check->state);
      }
    }
  }

  // 3. Rename s1 to {s1,s2}
  new_name = GNUNET_malloc (strlen (s1->name) + strlen (s2->name) + 1);
  strncat (new_name, s1->name, strlen (s1->name));
  strncat (new_name, s2->name, strlen (s2->name));
  if (NULL != s1->name)
    GNUNET_free (s1->name);
  s1->name = new_name;

  // remove state
  s_check = s2;
  GNUNET_CONTAINER_DLL_remove (a->states_head, a->states_tail, s_check);
  a->state_count--;
  automaton_destroy_state (s_check);
}

/**
 * Add a state to the automaton 'a', always use this function to
 * alter the states DLL of the automaton.
 *
 * @param a automaton to add the state to
 * @param s state that should be added
 */
static void
automaton_add_state (struct GNUNET_REGEX_Automaton *a, struct State *s)
{
  GNUNET_CONTAINER_DLL_insert (a->states_head, a->states_tail, s);
  a->state_count++;
}

/**
 * Creates a new DFA state based on a set of NFA states. Needs to be freed
 * using automaton_destroy_state.
 *
 * @param ctx context
 * @param nfa_states set of NFA states on which the DFA should be based on
 *
 * @return new DFA state
 */
static struct State *
dfa_state_create (struct GNUNET_REGEX_Context *ctx, struct StateSet *nfa_states)
{
  struct State *s;
  char *name;
  int len = 0;
  struct State *cstate;
  struct Transition *ctran;
  int insert = 1;
  struct Transition *t;
  int i;

  s = GNUNET_malloc (sizeof (struct State));
  s->id = ctx->state_id++;
  s->accepting = 0;
  s->marked = 0;
  s->name = NULL;

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

    // Add a transition for each distinct literal to NULL state
    for (ctran = cstate->transitions_head; NULL != ctran; ctran = ctran->next)
    {
      if (0 != ctran->literal)
      {
        insert = 1;

        for (t = s->transitions_head; NULL != t; t = t->next)
        {
          if (t->literal == ctran->literal)
          {
            insert = 0;
            break;
          }
        }

        if (insert)
          add_transition (ctx, s, ctran->literal, NULL);
      }
    }

    // If the nfa_states contain an accepting state, the new dfa state is also accepting
    if (cstate->accepting)
      s->accepting = 1;
  }

  s->name[strlen (s->name) - 1] = '}';

  return s;
}

/**
 * Move from the given state 's' to the next state on
 * transition 'literal'
 *
 * @param s starting state
 * @param literal edge label to follow
 *
 * @return new state or NULL, if transition on literal not possible
 */
static struct State *
dfa_move (struct State *s, const char literal)
{
  struct Transition *t;
  struct State *new_s;

  if (NULL == s)
    return NULL;

  new_s = NULL;

  for (t = s->transitions_head; NULL != t; t = t->next)
  {
    if (literal == t->literal)
    {
      new_s = t->state;
      break;
    }
  }

  return new_s;
}

/**
 * Remove all unreachable states from DFA 'a'. Unreachable states
 * are those states that are not reachable from the starting state.
 *
 * @param a DFA automaton
 */
static void
dfa_remove_unreachable_states (struct GNUNET_REGEX_Automaton *a)
{
  struct State *stack[a->state_count];
  int stack_len;
  struct State *s;
  struct Transition *t;

  stack_len = 0;

  // 1. unmark all states
  for (s = a->states_head; NULL != s; s = s->next)
  {
    s->marked = 0;
  }

  // 2. traverse dfa from start state and mark all visited states
  stack[stack_len] = a->start;
  stack_len++;
  while (stack_len > 0)
  {
    s = stack[stack_len - 1];
    stack_len--;
    s->marked = 1;              // mark s as visited
    for (t = s->transitions_head; NULL != t; t = t->next)
    {
      if (NULL != t->state && 0 == t->state->marked)
      {
        // add next states to stack
        stack[stack_len] = t->state;
        stack_len++;
      }
    }
  }

  // 3. delete all states that were not visited
  for (s = a->states_head; NULL != s; s = s->next)
  {
    if (0 == s->marked)
      automaton_remove_state (a, s);
  }
}

/**
 * Remove all dead states from the DFA 'a'. Dead states are those
 * states that do not transition to any other state but themselfes.
 *
 * @param a DFA automaton
 */
static void
dfa_remove_dead_states (struct GNUNET_REGEX_Automaton *a)
{
  struct State *s;
  struct Transition *t;
  int dead;

  GNUNET_assert (DFA == a->type);

  for (s = a->states_head; NULL != s; s = s->next)
  {
    if (s->accepting)
      continue;

    dead = 1;
    for (t = s->transitions_head; NULL != t; t = t->next)
    {
      if (NULL != t->state && t->state != s)
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
  int i;
  int table[a->state_count][a->state_count];
  struct State *s1;
  struct State *s2;
  struct Transition *t1;
  struct Transition *t2;
  int change;

  change = 1;
  for (i = 0, s1 = a->states_head; i < a->state_count && NULL != s1;
       i++, s1 = s1->next)
    s1->marked = i;

  // Mark all pairs of accepting/!accepting states
  for (s1 = a->states_head; NULL != s1; s1 = s1->next)
  {
    for (s2 = a->states_head; NULL != s2 && s1 != s2; s2 = s2->next)
    {
      if ((s1->accepting && !s2->accepting) ||
          (!s1->accepting && s2->accepting))
      {
        table[s1->marked][s2->marked] = 1;
      }
      else
        table[s1->marked][s2->marked] = 0;
    }
  }

  while (0 != change)
  {
    change = 0;
    for (s1 = a->states_head; NULL != s1; s1 = s1->next)
    {
      for (s2 = a->states_head; NULL != s2 && s1 != s2; s2 = s2->next)
      {
        if (0 != table[s1->marked][s2->marked])
          continue;

        for (t1 = s1->transitions_head; NULL != t1; t1 = t1->next)
        {
          for (t2 = s2->transitions_head; NULL != t2; t2 = t2->next)
          {
            if (t1->literal == t2->literal && t1->state == t2->state &&
                (0 != table[t1->state->marked][t2->state->marked] ||
                 0 != table[t2->state->marked][t1->state->marked]))
            {
              table[s1->marked][s2->marked] = t1->literal;
              change = 1;
            }
            else if (t1->literal != t2->literal && t1->state != t2->state)
            {
              table[s1->marked][s2->marked] = -1;
              change = 1;
            }
          }
        }
      }
    }
  }

  struct State *s2_next;

  for (i = 0, s1 = a->states_head; NULL != s1; s1 = s1->next)
  {
    for (s2 = a->states_head; NULL != s2 && s1 != s2; s2 = s2_next)
    {
      s2_next = s2->next;
      if (s1 != s2 && table[s1->marked][s2->marked] == 0)
        automaton_merge_states (ctx, a, s1, s2);
    }
  }
}

/**
 * Minimize the given DFA 'a' by removing all unreachable states,
 * removing all dead states and merging all non distinguishable states
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
 * Creates a new NFA fragment. Needs to be cleared using automaton_fragment_clear.
 *
 * @param start starting state
 * @param end end state
 *
 * @return new NFA fragment
 */
static struct GNUNET_REGEX_Automaton *
nfa_fragment_create (struct State *start, struct State *end)
{
  struct GNUNET_REGEX_Automaton *n;

  n = GNUNET_malloc (sizeof (struct GNUNET_REGEX_Automaton));

  n->type = NFA;
  n->start = NULL;
  n->end = NULL;

  if (NULL == start && NULL == end)
    return n;

  automaton_add_state (n, end);
  automaton_add_state (n, start);

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
nfa_add_states (struct GNUNET_REGEX_Automaton *n, struct State *states_head,
                struct State *states_tail)
{
  struct State *s;

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
static struct State *
nfa_state_create (struct GNUNET_REGEX_Context *ctx, int accepting)
{
  struct State *s;

  s = GNUNET_malloc (sizeof (struct State));
  s->id = ctx->state_id++;
  s->accepting = accepting;
  s->marked = 0;
  s->name = NULL;
  GNUNET_asprintf (&s->name, "s%i", s->id);

  return s;
}

/**
 * Calculates the NFA closure set for the given state
 *
 * @param s starting point state
 * @param literal transitioning literal on which to base the closure on,
 *                pass 0 for epsilon transition
 *
 * @return nfa closure on 'literal' (epsilon closure if 'literal' is 0)
 */
static struct StateSet *
nfa_closure_create (struct State *s, const char literal)
{
  struct StateSet *cls;
  struct StateSet *cls_check;
  struct State *clsstate;
  struct State *currentstate;
  struct Transition *ctran;

  if (NULL == s)
    return NULL;

  cls = GNUNET_malloc (sizeof (struct StateSet));
  cls_check = GNUNET_malloc (sizeof (struct StateSet));

  // Add start state to closure only for epsilon closure
  if (0 == literal)
    GNUNET_array_append (cls->states, cls->len, s);

  GNUNET_array_append (cls_check->states, cls_check->len, s);
  while (cls_check->len > 0)
  {
    currentstate = cls_check->states[cls_check->len - 1];
    GNUNET_array_grow (cls_check->states, cls_check->len, cls_check->len - 1);

    for (ctran = currentstate->transitions_head; NULL != ctran;
         ctran = ctran->next)
    {
      if (NULL != ctran->state && literal == ctran->literal)
      {
        clsstate = ctran->state;

        if (NULL != clsstate &&
            GNUNET_YES != state_set_contains (cls, clsstate))
        {
          GNUNET_array_append (cls->states, cls->len, clsstate);
          GNUNET_array_append (cls_check->states, cls_check->len, clsstate);
        }
      }
    }
  }
  GNUNET_assert (0 == cls_check->len);
  GNUNET_free (cls_check);

  if (cls->len > 1)
    qsort (cls->states, cls->len, sizeof (struct State *), state_compare);

  return cls;
}

/**
 * Calculates the closure set for the given set of states.
 *
 * @param states list of states on which to base the closure on
 * @param literal transitioning literal for which to base the closure on,
 *                pass 0 for epsilon transition
 *
 * @return nfa closure on 'literal' (epsilon closure if 'literal' is 0)
 */
static struct StateSet *
nfa_closure_set_create (struct StateSet *states, const char literal)
{
  struct State *s;
  struct StateSet *sset;
  struct StateSet *cls;
  int i;
  int j;
  int k;
  int contains;

  if (NULL == states)
    return NULL;

  cls = GNUNET_malloc (sizeof (struct StateSet));

  for (i = 0; i < states->len; i++)
  {
    s = states->states[i];
    sset = nfa_closure_create (s, literal);

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
    qsort (cls->states, cls->len, sizeof (struct State *), state_compare);

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
  struct GNUNET_REGEX_Automaton *new;

  b = ctx->stack_tail;
  GNUNET_CONTAINER_DLL_remove (ctx->stack_head, ctx->stack_tail, b);
  a = ctx->stack_tail;
  GNUNET_CONTAINER_DLL_remove (ctx->stack_head, ctx->stack_tail, a);

  add_transition (ctx, a->end, 0, b->start);
  a->end->accepting = 0;
  b->end->accepting = 1;

  new = nfa_fragment_create (NULL, NULL);
  nfa_add_states (new, a->states_head, a->states_tail);
  nfa_add_states (new, b->states_head, b->states_tail);
  new->start = a->start;
  new->end = b->end;
  automaton_fragment_clear (a);
  automaton_fragment_clear (b);

  GNUNET_CONTAINER_DLL_insert_tail (ctx->stack_head, ctx->stack_tail, new);
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
  struct GNUNET_REGEX_Automaton *new;
  struct State *start;
  struct State *end;

  a = ctx->stack_tail;
  GNUNET_CONTAINER_DLL_remove (ctx->stack_head, ctx->stack_tail, a);

  if (NULL == a)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "nfa_add_star_op failed, because there was no element on the stack");
    return;
  }

  start = nfa_state_create (ctx, 0);
  end = nfa_state_create (ctx, 1);

  add_transition (ctx, start, 0, a->start);
  add_transition (ctx, start, 0, end);
  add_transition (ctx, a->end, 0, a->start);
  add_transition (ctx, a->end, 0, end);

  a->end->accepting = 0;
  end->accepting = 1;

  new = nfa_fragment_create (start, end);
  nfa_add_states (new, a->states_head, a->states_tail);
  automaton_fragment_clear (a);

  GNUNET_CONTAINER_DLL_insert_tail (ctx->stack_head, ctx->stack_tail, new);
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

  add_transition (ctx, a->end, 0, a->start);

  GNUNET_CONTAINER_DLL_insert_tail (ctx->stack_head, ctx->stack_tail, a);
}

/**
 * Pops two NFA fragments (a, b) from the stack and adds a new NFA fragment
 * that alternates between a and b (a|b)
 *
 * @param ctx context
 */
static void
nfa_add_alternation (struct GNUNET_REGEX_Context *ctx)
{
  struct GNUNET_REGEX_Automaton *a;
  struct GNUNET_REGEX_Automaton *b;
  struct GNUNET_REGEX_Automaton *new;
  struct State *start;
  struct State *end;

  b = ctx->stack_tail;
  GNUNET_CONTAINER_DLL_remove (ctx->stack_head, ctx->stack_tail, b);
  a = ctx->stack_tail;
  GNUNET_CONTAINER_DLL_remove (ctx->stack_head, ctx->stack_tail, a);

  start = nfa_state_create (ctx, 0);
  end = nfa_state_create (ctx, 1);
  add_transition (ctx, start, 0, a->start);
  add_transition (ctx, start, 0, b->start);

  add_transition (ctx, a->end, 0, end);
  add_transition (ctx, b->end, 0, end);

  a->end->accepting = 0;
  b->end->accepting = 0;
  end->accepting = 1;

  new = nfa_fragment_create (start, end);
  nfa_add_states (new, a->states_head, a->states_tail);
  nfa_add_states (new, b->states_head, b->states_tail);
  automaton_fragment_clear (a);
  automaton_fragment_clear (b);

  GNUNET_CONTAINER_DLL_insert_tail (ctx->stack_head, ctx->stack_tail, new);
}

/**
 * Adds a new nfa fragment to the stack
 *
 * @param ctx context
 * @param lit literal for nfa transition
 */
static void
nfa_add_literal (struct GNUNET_REGEX_Context *ctx, const char lit)
{
  struct GNUNET_REGEX_Automaton *n;
  struct State *start;
  struct State *end;

  GNUNET_assert (NULL != ctx);

  start = nfa_state_create (ctx, 0);
  end = nfa_state_create (ctx, 1);
  add_transition (ctx, start, lit, end);
  n = nfa_fragment_create (start, end);
  GNUNET_assert (NULL != n);
  GNUNET_CONTAINER_DLL_insert_tail (ctx->stack_head, ctx->stack_tail, n);
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
        error_msg = "Cannot append '+' to nothing";
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
    case 92:                   /* escape: \ */
      regexp++;
      count++;
    default:
      if (atomcount > 1)
      {
        --atomcount;
        nfa_add_concatenation (&ctx);
      }
      nfa_add_literal (&ctx, *regexp);
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

  if (NULL != p)
    GNUNET_free (p);

  nfa = ctx.stack_tail;
  GNUNET_CONTAINER_DLL_remove (ctx.stack_head, ctx.stack_tail, nfa);


  if (NULL != ctx.stack_head)
  {
    error_msg = "Creating the NFA failed. NFA stack was not empty!";
    goto error;
  }

  return nfa;

error:
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Could not parse regex\n");
  if (NULL != error_msg)
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "%s\n", error_msg);
  if (NULL != p)
    GNUNET_free (p);
  while (NULL != ctx.stack_tail)
  {
    GNUNET_REGEX_automaton_destroy (ctx.stack_tail);
    GNUNET_CONTAINER_DLL_remove (ctx.stack_head, ctx.stack_tail,
                                 ctx.stack_tail);
  }
  return NULL;
}

/**
 * Free the memory allocated by constructing the GNUNET_REGEX_Automaton
 * data structure.
 *
 * @param a automaton to be destroyed
 */
void
GNUNET_REGEX_automaton_destroy (struct GNUNET_REGEX_Automaton *a)
{
  struct State *s;
  struct State *next_state;

  if (NULL == a)
    return;

  for (s = a->states_head; NULL != s;)
  {
    next_state = s->next;
    automaton_destroy_state (s);
    s = next_state;
  }

  GNUNET_free (a);
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
  struct StateSet *tmp;
  struct StateSet *nfa_set;
  struct StateSet *dfa_stack;
  struct Transition *ctran;
  struct State *dfa_state;
  struct State *new_dfa_state;
  struct State *state_contains;
  struct State *state_iter;

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

  // Create DFA start state from epsilon closure
  dfa_stack = GNUNET_malloc (sizeof (struct StateSet));
  nfa_set = nfa_closure_create (nfa->start, 0);
  dfa->start = dfa_state_create (&ctx, nfa_set);
  automaton_add_state (dfa, dfa->start);
  GNUNET_array_append (dfa_stack->states, dfa_stack->len, dfa->start);

  // Create dfa states by combining nfa states
  while (dfa_stack->len > 0)
  {
    dfa_state = dfa_stack->states[dfa_stack->len - 1];
    GNUNET_array_grow (dfa_stack->states, dfa_stack->len, dfa_stack->len - 1);

    for (ctran = dfa_state->transitions_head; NULL != ctran;
         ctran = ctran->next)
    {
      if (0 != ctran->literal && NULL == ctran->state)
      {
        tmp = nfa_closure_set_create (dfa_state->nfa_set, ctran->literal);
        nfa_set = nfa_closure_set_create (tmp, 0);
        state_set_clear (tmp);
        new_dfa_state = dfa_state_create (&ctx, nfa_set);
        state_contains = NULL;
        for (state_iter = dfa->states_head; NULL != state_iter;
             state_iter = state_iter->next)
        {
          if (0 ==
              state_set_compare (state_iter->nfa_set, new_dfa_state->nfa_set))
            state_contains = state_iter;
        }

        if (NULL == state_contains)
        {
          automaton_add_state (dfa, new_dfa_state);
          GNUNET_array_append (dfa_stack->states, dfa_stack->len,
                               new_dfa_state);
          ctran->state = new_dfa_state;
        }
        else
        {
          ctran->state = state_contains;
          automaton_destroy_state (new_dfa_state);
        }
      }
    }
  }

  GNUNET_free (dfa_stack);
  GNUNET_REGEX_automaton_destroy (nfa);

  dfa_minimize (&ctx, dfa);

  return dfa;
}

/**
 * Save the given automaton as a GraphViz dot file
 *
 * @param a the automaton to be saved
 * @param filename where to save the file
 */
void
GNUNET_REGEX_automaton_save_graph (struct GNUNET_REGEX_Automaton *a,
                                   const char *filename)
{
  struct State *s;
  struct Transition *ctran;
  char *s_acc = NULL;
  char *s_tran = NULL;
  char *start;
  char *end;
  FILE *p;

  if (NULL == a)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Could not print NFA, was NULL!");
    return;
  }

  if (NULL == filename || strlen (filename) < 1)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "No Filename given!");
    return;
  }

  p = fopen (filename, "w");

  if (p == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Could not open file for writing: %s",
                filename);
    return;
  }

  start = "digraph G {\nrankdir=LR\n";
  fwrite (start, strlen (start), 1, p);

  for (s = a->states_head; NULL != s; s = s->next)
  {
    if (s->accepting)
    {
      GNUNET_asprintf (&s_acc, "\"%s\" [shape=doublecircle];\n", s->name);
      fwrite (s_acc, strlen (s_acc), 1, p);
      GNUNET_free (s_acc);
    }

    s->marked = 1;

    for (ctran = s->transitions_head; NULL != ctran; ctran = ctran->next)
    {
      if (NULL == ctran->state)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    "Transition from State %i has has no state for transitioning\n",
                    s->id);
        continue;
      }

      if (ctran->literal == 0)
      {
        GNUNET_asprintf (&s_tran, "\"%s\" -> \"%s\" [label = \"epsilon\"];\n",
                         s->name, ctran->state->name);
      }
      else
      {
        GNUNET_asprintf (&s_tran, "\"%s\" -> \"%s\" [label = \"%c\"];\n",
                         s->name, ctran->state->name, ctran->literal);
      }

      fwrite (s_tran, strlen (s_tran), 1, p);
      GNUNET_free (s_tran);
    }
  }

  end = "\n}\n";
  fwrite (end, strlen (end), 1, p);
  fclose (p);
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
  struct State *s;

  if (DFA != a->type)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Tried to evaluate DFA, but NFA automaton given");
    return -1;
  }

  s = a->start;

  for (strp = string; NULL != strp && *strp; strp++)
  {
    s = dfa_move (s, *strp);
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
  struct State *s;
  struct StateSet *sset;
  struct StateSet *new_sset;
  int i;
  int result;

  if (NFA != a->type)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Tried to evaluate NFA, but DFA automaton given");
    return -1;
  }

  result = 1;
  strp = string;
  sset = nfa_closure_create (a->start, 0);

  for (strp = string; NULL != strp && *strp; strp++)
  {
    new_sset = nfa_closure_set_create (sset, *strp);
    state_set_clear (sset);
    sset = nfa_closure_set_create (new_sset, 0);
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
