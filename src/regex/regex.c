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
#include "regex.h"

#define initial_bits 10

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
   * Unique SCC (Strongly Connected Component) id.
   */
  unsigned int scc_id;

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
 * Type of an automaton.
 */
enum GNUNET_REGEX_automaton_type
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
   * This is a linked list.
   */
  struct GNUNET_REGEX_Automaton *prev;

  /**
   * This is a linked list.
   */
  struct GNUNET_REGEX_Automaton *next;

  /**
   * First state of the automaton. This is mainly used for constructing an NFA,
   * where each NFA itself consists of one or more NFAs linked together.
   */
  struct GNUNET_REGEX_State *start;

  /**
   * End state of the automaton.
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
  enum GNUNET_REGEX_automaton_type type;
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
  GNUNET_HashCode hash;

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
  struct Transition *transitions_head;

  /**
   * DLL of transitions.
   */
  struct Transition *transitions_tail;

  /**
   * Set of states on which this state is based on. Used when creating a DFA out
   * of several NFA states.
   */
  struct GNUNET_REGEX_StateSet *nfa_set;
};

/**
 * Transition between two states. Each state can have 0-n transitions.  If label
 * is 0, this is considered to be an epsilon transition.
 */
struct Transition
{
  /**
   * This is a linked list.
   */
  struct Transition *prev;

  /**
   * This is a linked list.
   */
  struct Transition *next;

  /**
   * Unique id of this transition.
   */
  unsigned int id;

  /**
   * Label for this transition. This is basically the edge label for the graph.
   */
  char label;

  /**
   * State to which this transition leads.
   */
  struct GNUNET_REGEX_State *to_state;

  /**
   * State from which this transition origins.
   */
  struct GNUNET_REGEX_State *from_state;

  /**
   * Mark this transition. For example when reversing the automaton.
   */
  int mark;
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
void
debug_print_transitions (struct GNUNET_REGEX_State *);

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

void
debug_print_states (struct GNUNET_REGEX_Automaton *a)
{
  struct GNUNET_REGEX_State *s;

  for (s = a->states_head; NULL != s; s = s->next)
    debug_print_state (s);
}

void
debug_print_transition (struct Transition *t)
{
  char *to_state;
  char *from_state;
  char label;

  if (NULL == t)
    return;

  if (0 == t->label)
    label = '0';
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

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Transition %i: From %s on %c to %s\n",
              t->id, from_state, label, to_state);
}

void
debug_print_transitions (struct GNUNET_REGEX_State *s)
{
  struct Transition *t;

  for (t = s->transitions_head; NULL != t; t = t->next)
    debug_print_transition (t);
}

/**
 * Recursive function doing DFS with 'v' as a start, detecting all SCCs inside
 * the subgraph reachable from 'v'. Used with scc_tarjan function to detect all
 * SCCs inside an automaton.
 *
 * @param ctx context
 * @param v start vertex
 * @param index current index
 * @param stack stack for saving all SCCs
 * @param stack_size current size of the stack
 */
static void
scc_tarjan_strongconnect (struct GNUNET_REGEX_Context *ctx,
                          struct GNUNET_REGEX_State *v, int *index,
                          struct GNUNET_REGEX_State **stack,
                          unsigned int *stack_size)
{
  struct GNUNET_REGEX_State *w;
  struct Transition *t;

  v->index = *index;
  v->lowlink = *index;
  (*index)++;
  stack[(*stack_size)++] = v;
  v->contained = 1;

  for (t = v->transitions_head; NULL != t; t = t->next)
  {
    w = t->to_state;
    if (NULL != w && w->index < 0)
    {
      scc_tarjan_strongconnect (ctx, w, index, stack, stack_size);
      v->lowlink = (v->lowlink > w->lowlink) ? w->lowlink : v->lowlink;
    }
    else if (0 != w->contained)
      v->lowlink = (v->lowlink > w->index) ? w->index : v->lowlink;
  }

  if (v->lowlink == v->index)
  {
    w = stack[--(*stack_size)];
    w->contained = 0;

    if (v != w)
    {
      ctx->scc_id++;
      while (v != w)
      {
        w->scc_id = ctx->scc_id;
        w = stack[--(*stack_size)];
        w->contained = 0;
      }
      w->scc_id = ctx->scc_id;
    }
  }
}

/**
 * Detect all SCCs (Strongly Connected Components) inside the given automaton.
 * SCCs will be marked using the scc_id on each state.
 *
 * @param ctx context
 * @param a automaton
 */
static void
scc_tarjan (struct GNUNET_REGEX_Context *ctx, struct GNUNET_REGEX_Automaton *a)
{
  int index;
  struct GNUNET_REGEX_State *v;
  struct GNUNET_REGEX_State *stack[a->state_count];
  unsigned int stack_size;

  for (v = a->states_head; NULL != v; v = v->next)
  {
    v->contained = 0;
    v->index = -1;
    v->lowlink = -1;
  }

  stack_size = 0;
  index = 0;

  for (v = a->states_head; NULL != v; v = v->next)
  {
    if (v->index < 0)
      scc_tarjan_strongconnect (ctx, v, &index, stack, &stack_size);
  }
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
                      struct GNUNET_REGEX_State *from_state, const char label,
                      struct GNUNET_REGEX_State *to_state)
{
  int is_dup;
  struct Transition *t;

  if (NULL == from_state)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Could not create Transition.\n");
    return;
  }

  // Do not add duplicate state transitions
  is_dup = GNUNET_NO;
  for (t = from_state->transitions_head; NULL != t; t = t->next)
  {
    if (t->to_state == to_state && t->label == label &&
        t->from_state == from_state)
    {
      is_dup = GNUNET_YES;
      break;
    }
  }

  if (is_dup)
    return;

  t = GNUNET_malloc (sizeof (struct Transition));
  t->id = ctx->transition_id++;
  t->label = label;
  t->to_state = to_state;
  t->from_state = from_state;

  // Add outgoing transition to 'from_state'
  from_state->transition_count++;
  GNUNET_CONTAINER_DLL_insert (from_state->transitions_head,
                               from_state->transitions_tail, t);
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
 * @param edges all edges leaving 's'.
 *
 * @return number of edges.
 */
static unsigned int
state_get_edges (struct GNUNET_REGEX_State *s, struct GNUNET_REGEX_Edge *edges)
{
  struct Transition *t;
  unsigned int count;

  if (NULL == s)
    return 0;

  count = 0;

  for (t = s->transitions_head; NULL != t; t = t->next)
  {
    if (NULL != t->to_state)
    {
      edges[count].label = &t->label;
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
  int i;

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
    if (NULL != set->states)
      GNUNET_free (set->states);
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
  struct Transition *t;
  struct Transition *next_t;

  if (NULL == s)
    return;

  if (NULL != s->name)
    GNUNET_free (s->name);

  if (NULL != s->proof)
    GNUNET_free (s->proof);

  for (t = s->transitions_head; NULL != t; t = next_t)
  {
    next_t = t->next;
    GNUNET_CONTAINER_DLL_remove (s->transitions_head, s->transitions_tail, t);
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
  struct Transition *t_check;

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
  struct Transition *t_check;
  char *new_name;

  GNUNET_assert (NULL != ctx && NULL != a && NULL != s1 && NULL != s2);

  if (s1 == s2)
    return;

  // 1. Make all transitions pointing to s2 point to s1
  for (s_check = a->states_head; NULL != s_check; s_check = s_check->next)
  {
    for (t_check = s_check->transitions_head; NULL != t_check;
         t_check = t_check->next)
    {
      if (s2 == t_check->to_state)
        t_check->to_state = s1;
    }
  }

  // 2. Add all transitions from s2 to sX to s1
  for (t_check = s2->transitions_head; NULL != t_check; t_check = t_check->next)
  {
    if (t_check->to_state != s1)
      state_add_transition (ctx, s1, t_check->label, t_check->to_state);
  }

  // 3. Rename s1 to {s1,s2}
  new_name = GNUNET_strdup (s1->name);
  if (NULL != s1->name)
  {
    GNUNET_free (s1->name);
    s1->name = NULL;
  }
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
 * Function that is called with each state, when traversing an automaton.
 *
 * @param cls closure
 * @param s state
 */
typedef void (*GNUNET_REGEX_traverse_action) (void *cls,
                                              struct GNUNET_REGEX_State * s);

/**
 * Traverses all states that are reachable from state 's'. Expects the states to
 * be unmarked (s->marked == GNUNET_NO). Performs 'action' on each visited
 * state.
 *
 * @param cls closure.
 * @param s start state.
 * @param action action to be performed on each state.
 */
static void
automaton_state_traverse (void *cls, struct GNUNET_REGEX_State *s,
                          GNUNET_REGEX_traverse_action action)
{
  struct Transition *t;

  if (GNUNET_NO == s->marked)
  {
    s->marked = GNUNET_YES;

    if (action > 0)
      action (cls, s);

    for (t = s->transitions_head; NULL != t; t = t->next)
      automaton_state_traverse (cls, t->to_state, action);
  }
}

/**
 * Traverses the given automaton from it's start state, visiting all reachable
 * states and calling 'action' on each one of them.
 *
 * @param cls closure.
 * @param a automaton.
 * @param action action to be performed on each state.
 */
static void
automaton_traverse (void *cls, struct GNUNET_REGEX_Automaton *a,
                    GNUNET_REGEX_traverse_action action)
{
  struct GNUNET_REGEX_State *s;

  for (s = a->states_head; NULL != s; s = s->next)
    s->marked = GNUNET_NO;

  automaton_state_traverse (cls, a->start, action);
}

/**
 * Reverses all transitions of the given automaton.
 *
 * @param a automaton.
 */
static void
automaton_reverse (struct GNUNET_REGEX_Automaton *a)
{
  struct GNUNET_REGEX_State *s;
  struct Transition *t;
  struct Transition *t_next;
  struct GNUNET_REGEX_State *s_swp;

  for (s = a->states_head; NULL != s; s = s->next)
    for (t = s->transitions_head; NULL != t; t = t->next)
      t->mark = GNUNET_NO;

  for (s = a->states_head; NULL != s; s = s->next)
  {
    for (t = s->transitions_head; NULL != t; t = t_next)
    {
      t_next = t->next;

      if (GNUNET_YES == t->mark || t->from_state == t->to_state)
        continue;

      t->mark = GNUNET_YES;

      GNUNET_CONTAINER_DLL_remove (t->from_state->transitions_head,
                                   t->from_state->transitions_tail, t);
      t->from_state->transition_count--;
      GNUNET_CONTAINER_DLL_insert (t->to_state->transitions_head,
                                   t->to_state->transitions_tail, t);
      t->to_state->transition_count++;

      s_swp = t->from_state;
      t->from_state = t->to_state;
      t->to_state = s_swp;
    }
  }
}

/**
 * Create proof for the given state.
 *
 * @param cls closure.
 * @param s state.
 */
static void
automaton_create_proofs_step (void *cls, struct GNUNET_REGEX_State *s)
{
  struct Transition *t;
  int i;
  char *tmp;

  for (i = 0, t = s->transitions_head; NULL != t; t = t->next, i++)
  {
    if (t->to_state == s)
      GNUNET_asprintf (&tmp, "%c*", t->label);
    else if (i != s->transition_count - 1)
      GNUNET_asprintf (&tmp, "%c|", t->label);
    else
      GNUNET_asprintf (&tmp, "%c", t->label);

    if (NULL != s->proof)
      s->proof =
          GNUNET_realloc (s->proof, strlen (s->proof) + strlen (tmp) + 1);
    else
      s->proof = GNUNET_malloc (strlen (tmp) + 1);
    strcat (s->proof, tmp);
    GNUNET_free (tmp);
  }
}

/**
 * Create proofs for all states in the given automaton.
 *
 * @param a automaton.
 */
static void
automaton_create_proofs (struct GNUNET_REGEX_Automaton *a)
{
  struct GNUNET_REGEX_State *s;

  automaton_reverse (a);

  for (s = a->states_head; NULL != s; s = s->next)
    automaton_create_proofs_step (NULL, s);

  automaton_reverse (a);
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
  struct Transition *ctran;
  int insert = 1;
  struct Transition *t;
  int i;

  s = GNUNET_malloc (sizeof (struct GNUNET_REGEX_State));
  s->id = ctx->state_id++;
  s->accepting = 0;
  s->marked = 0;
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
      if (0 != ctran->label)
      {
        insert = 1;

        for (t = s->transitions_head; NULL != t; t = t->next)
        {
          if (t->label == ctran->label)
          {
            insert = 0;
            break;
          }
        }

        if (insert)
          state_add_transition (ctx, s, ctran->label, NULL);
      }
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
dfa_move (struct GNUNET_REGEX_State *s, const char label)
{
  struct Transition *t;
  struct GNUNET_REGEX_State *new_s;

  if (NULL == s)
    return NULL;

  new_s = NULL;

  for (t = s->transitions_head; NULL != t; t = t->next)
  {
    if (label == t->label)
    {
      new_s = t->to_state;
      break;
    }
  }

  return new_s;
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
  automaton_traverse (NULL, a, NULL);

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
 * not transition to any other state but themselfes.
 *
 * @param a DFA automaton
 */
static void
dfa_remove_dead_states (struct GNUNET_REGEX_Automaton *a)
{
  struct GNUNET_REGEX_State *s;
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
  int i;
  int table[a->state_count][a->state_count];
  struct GNUNET_REGEX_State *s1;
  struct GNUNET_REGEX_State *s2;
  struct Transition *t1;
  struct Transition *t2;
  struct GNUNET_REGEX_State *s1_next;
  struct GNUNET_REGEX_State *s2_next;
  int change;
  int num_equal_edges;

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
            if (t1->label == t2->label)
            {
              num_equal_edges++;
              if (0 != table[t1->to_state->marked][t2->to_state->marked] ||
                  0 != table[t2->to_state->marked][t1->to_state->marked])
              {
                table[s1->marked][s2->marked] = t1->label != 0 ? t1->label : 1;
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
  s->marked = 0;
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
 *                pass 0 for epsilon transition
 *
 * @return sorted nfa closure on 'label' (epsilon closure if 'label' is 0)
 */
static struct GNUNET_REGEX_StateSet *
nfa_closure_create (struct GNUNET_REGEX_Automaton *nfa,
                    struct GNUNET_REGEX_State *s, const char label)
{
  struct GNUNET_REGEX_StateSet *cls;
  struct GNUNET_REGEX_StateSet *cls_check;
  struct GNUNET_REGEX_State *clsstate;
  struct GNUNET_REGEX_State *currentstate;
  struct Transition *ctran;

  if (NULL == s)
    return NULL;

  cls = GNUNET_malloc (sizeof (struct GNUNET_REGEX_StateSet));
  cls_check = GNUNET_malloc (sizeof (struct GNUNET_REGEX_StateSet));

  for (clsstate = nfa->states_head; NULL != clsstate; clsstate = clsstate->next)
    clsstate->contained = 0;

  // Add start state to closure only for epsilon closure
  if (0 == label)
    GNUNET_array_append (cls->states, cls->len, s);

  GNUNET_array_append (cls_check->states, cls_check->len, s);
  while (cls_check->len > 0)
  {
    currentstate = cls_check->states[cls_check->len - 1];
    GNUNET_array_grow (cls_check->states, cls_check->len, cls_check->len - 1);

    for (ctran = currentstate->transitions_head; NULL != ctran;
         ctran = ctran->next)
    {
      if (NULL != ctran->to_state && label == ctran->label)
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
 *                pass 0 for epsilon transition
 *
 * @return sorted nfa closure on 'label' (epsilon closure if 'label' is 0)
 */
static struct GNUNET_REGEX_StateSet *
nfa_closure_set_create (struct GNUNET_REGEX_Automaton *nfa,
                        struct GNUNET_REGEX_StateSet *states, const char label)
{
  struct GNUNET_REGEX_State *s;
  struct GNUNET_REGEX_StateSet *sset;
  struct GNUNET_REGEX_StateSet *cls;
  int i;
  int j;
  int k;
  int contains;

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
  struct GNUNET_REGEX_Automaton *new;

  b = ctx->stack_tail;
  GNUNET_CONTAINER_DLL_remove (ctx->stack_head, ctx->stack_tail, b);
  a = ctx->stack_tail;
  GNUNET_CONTAINER_DLL_remove (ctx->stack_head, ctx->stack_tail, a);

  state_add_transition (ctx, a->end, 0, b->start);
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
  struct GNUNET_REGEX_State *start;
  struct GNUNET_REGEX_State *end;

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

  state_add_transition (ctx, start, 0, a->start);
  state_add_transition (ctx, start, 0, end);
  state_add_transition (ctx, a->end, 0, a->start);
  state_add_transition (ctx, a->end, 0, end);

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

  state_add_transition (ctx, a->end, 0, a->start);

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
  struct GNUNET_REGEX_Automaton *new;
  struct GNUNET_REGEX_State *start;
  struct GNUNET_REGEX_State *end;

  a = ctx->stack_tail;
  GNUNET_CONTAINER_DLL_remove (ctx->stack_head, ctx->stack_tail, a);

  if (NULL == a)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "nfa_add_question_op failed, because there was no element on the stack");
    return;
  }

  start = nfa_state_create (ctx, 0);
  end = nfa_state_create (ctx, 1);

  state_add_transition (ctx, start, 0, a->start);
  state_add_transition (ctx, start, 0, end);
  state_add_transition (ctx, a->end, 0, end);

  a->end->accepting = 0;

  new = nfa_fragment_create (start, end);
  nfa_add_states (new, a->states_head, a->states_tail);
  automaton_fragment_clear (a);

  GNUNET_CONTAINER_DLL_insert_tail (ctx->stack_head, ctx->stack_tail, new);
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
  struct GNUNET_REGEX_Automaton *new;
  struct GNUNET_REGEX_State *start;
  struct GNUNET_REGEX_State *end;

  b = ctx->stack_tail;
  GNUNET_CONTAINER_DLL_remove (ctx->stack_head, ctx->stack_tail, b);
  a = ctx->stack_tail;
  GNUNET_CONTAINER_DLL_remove (ctx->stack_head, ctx->stack_tail, a);

  start = nfa_state_create (ctx, 0);
  end = nfa_state_create (ctx, 1);
  state_add_transition (ctx, start, 0, a->start);
  state_add_transition (ctx, start, 0, b->start);

  state_add_transition (ctx, a->end, 0, end);
  state_add_transition (ctx, b->end, 0, end);

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
 * @param lit label for nfa transition
 */
static void
nfa_add_label (struct GNUNET_REGEX_Context *ctx, const char lit)
{
  struct GNUNET_REGEX_Automaton *n;
  struct GNUNET_REGEX_State *start;
  struct GNUNET_REGEX_State *end;

  GNUNET_assert (NULL != ctx);

  start = nfa_state_create (ctx, 0);
  end = nfa_state_create (ctx, 1);
  state_add_transition (ctx, start, lit, end);
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
  ctx->scc_id = 0;
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
    default:
      if (atomcount > 1)
      {
        --atomcount;
        nfa_add_concatenation (&ctx);
      }
      nfa_add_label (&ctx, *regexp);
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
  struct Transition *ctran;
  struct GNUNET_REGEX_State *state_iter;
  struct GNUNET_REGEX_State *new_dfa_state;
  struct GNUNET_REGEX_State *state_contains;
  struct GNUNET_REGEX_StateSet *tmp;
  struct GNUNET_REGEX_StateSet *nfa_set;

  for (ctran = dfa_state->transitions_head; NULL != ctran; ctran = ctran->next)
  {
    if (0 == ctran->label || NULL != ctran->to_state)
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

  // Create DFA start state from epsilon closure
  nfa_set = nfa_closure_create (nfa, nfa->start, 0);
  dfa->start = dfa_state_create (&ctx, nfa_set);
  automaton_add_state (dfa, dfa->start);

  construct_dfa_states (&ctx, nfa, dfa, dfa->start);

  GNUNET_REGEX_automaton_destroy (nfa);

  // Minimize DFA
  dfa_minimize (&ctx, dfa);

  // Calculate SCCs
  scc_tarjan (&ctx, dfa);

  // Create proofs for all states
  automaton_create_proofs (dfa);

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

  for (s = a->states_head; NULL != s;)
  {
    next_state = s->next;
    automaton_destroy_state (s);
    s = next_state;
  }

  GNUNET_free (a);
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
  struct GNUNET_REGEX_State *s;
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

  if (NULL == p)
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
      GNUNET_asprintf (&s_acc,
                       "\"%s\" [shape=doublecircle, color=\"0.%i 0.8 0.95\"];\n",
                       s->name, s->scc_id);
    }
    else
    {
      GNUNET_asprintf (&s_acc, "\"%s\" [color=\"0.%i 0.8 0.95\"];\n", s->name,
                       s->scc_id);
    }

    if (NULL == s_acc)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Could not print state %s\n",
                  s->name);
      return;
    }
    fwrite (s_acc, strlen (s_acc), 1, p);
    GNUNET_free (s_acc);
    s_acc = NULL;

    for (ctran = s->transitions_head; NULL != ctran; ctran = ctran->next)
    {
      if (NULL == ctran->to_state)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    "Transition from State %i has has no state for transitioning\n",
                    s->id);
        continue;
      }

      if (ctran->label == 0)
      {
        GNUNET_asprintf (&s_tran,
                         "\"%s\" -> \"%s\" [label = \"epsilon\", color=\"0.%i 0.8 0.95\"];\n",
                         s->name, ctran->to_state->name, s->scc_id);
      }
      else
      {
        GNUNET_asprintf (&s_tran,
                         "\"%s\" -> \"%s\" [label = \"%c\", color=\"0.%i 0.8 0.95\"];\n",
                         s->name, ctran->to_state->name, ctran->label,
                         s->scc_id);
      }

      if (NULL == s_tran)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Could not print state %s\n",
                    s->name);
        return;
      }

      fwrite (s_tran, strlen (s_tran), 1, p);
      GNUNET_free (s_tran);
      s_tran = NULL;
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
  struct GNUNET_REGEX_State *s;

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
  struct GNUNET_REGEX_State *s;
  struct GNUNET_REGEX_StateSet *sset;
  struct GNUNET_REGEX_StateSet *new_sset;
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
  sset = nfa_closure_create (a, a->start, 0);

  for (strp = string; NULL != strp && *strp; strp++)
  {
    new_sset = nfa_closure_set_create (a, sset, *strp);
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
 * Get the first key for the given 'input_string'. This hashes the first x bits
 * of the 'input_strings'.
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
                            GNUNET_HashCode * key)
{
  unsigned int size;

  size = string_len < initial_bits ? string_len : initial_bits;

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
 * @param proof partial regex
 * @param key hash
 *
 * @return GNUNET_OK if the proof is valid for the given key
 */
int
GNUNET_REGEX_check_proof (const char *proof, const GNUNET_HashCode * key)
{
  return GNUNET_OK;
}

/**
 * Iterate over all edges helper function starting from state 's', calling
 * iterator on for each edge.
 *
 * @param s state.
 * @param iterator iterator function called for each edge.
 * @param iterator_cls closure.
 */
static void
iterate_edge (struct GNUNET_REGEX_State *s, GNUNET_REGEX_KeyIterator iterator,
              void *iterator_cls)
{
  struct Transition *t;
  struct GNUNET_REGEX_Edge edges[s->transition_count];
  unsigned int num_edges;

  if (GNUNET_YES != s->marked)
  {
    s->marked = GNUNET_YES;

    num_edges = state_get_edges (s, edges);

    iterator (iterator_cls, &s->hash, s->proof, s->accepting, num_edges, edges);

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

  iterate_edge (a->start, iterator, iterator_cls);
}
