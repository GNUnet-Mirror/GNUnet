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

void
stack_push (struct GNUNET_CONTAINER_SList *stack, const void *buf, size_t len)
{
  GNUNET_CONTAINER_slist_add (stack, GNUNET_CONTAINER_SLIST_DISPOSITION_STATIC,
                              buf, len);
}

int
stack_empty (struct GNUNET_CONTAINER_SList *stack)
{
  return 0 == GNUNET_CONTAINER_slist_count (stack);
}

void *
stack_pop (struct GNUNET_CONTAINER_SList *stack, size_t length)
{
  struct GNUNET_CONTAINER_SList_Iterator it;
  void *val;
  size_t len;

  it = GNUNET_CONTAINER_slist_begin (stack);
  val = GNUNET_CONTAINER_slist_get (&it, &len);
  GNUNET_assert (length == len);
  GNUNET_CONTAINER_slist_erase (&it);
  GNUNET_CONTAINER_slist_iter_destroy (&it);

  return val;
}

void *
stack_top (struct GNUNET_CONTAINER_SList *stack, size_t * len)
{
  struct GNUNET_CONTAINER_SList_Iterator it;

  if (stack_empty (stack))
    return NULL;

  return GNUNET_CONTAINER_slist_get (&it, len);
}

struct State
{
  unsigned int id;
  int accepting;
  int marked;
  char *name;
  struct GNUNET_CONTAINER_SList *transitions;
  struct GNUNET_CONTAINER_SList *nfa_set;
};

struct GNUNET_REGEX_Automaton
{
  struct State *start;
  struct State *end;
  struct GNUNET_CONTAINER_SList *states;
};

struct Transition
{
  unsigned int id;
  char literal;
  struct State *state;
};

struct GNUNET_REGEX_Context
{
  unsigned int state_id;
  unsigned int transition_id;
  struct GNUNET_CONTAINER_SList *stack;
};

void
GNUNET_REGEX_context_init (struct GNUNET_REGEX_Context *ctx)
{
  if (NULL == ctx)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Context was NULL!");
    return;
  }
  ctx->state_id = 0;
  ctx->transition_id = 0;
  ctx->stack = GNUNET_CONTAINER_slist_create ();
}

void
GNUNET_REGEX_context_destroy (struct GNUNET_REGEX_Context *ctx)
{
  if (NULL != ctx->stack)
    GNUNET_CONTAINER_slist_destroy (ctx->stack);
}

void
debug_print_state (struct State *s)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "State %i: %s marked: %i accepting: %i\n", s->id, s->name,
              s->marked, s->accepting);
}

void
debug_print_states (struct GNUNET_CONTAINER_SList *states)
{
  struct GNUNET_CONTAINER_SList_Iterator it;
  struct State *s;

  for (it = GNUNET_CONTAINER_slist_begin (states);
       GNUNET_YES != GNUNET_CONTAINER_slist_end (&it);
       GNUNET_CONTAINER_slist_next (&it))
  {
    s = GNUNET_CONTAINER_slist_get (&it, NULL);
    debug_print_state (s);
  }
  GNUNET_CONTAINER_slist_iter_destroy (&it);
}

void
debug_print_transitions (struct State *s)
{
  struct GNUNET_CONTAINER_SList_Iterator it;
  struct Transition *t;
  char *state;
  char literal;

  for (it = GNUNET_CONTAINER_slist_begin (s->transitions);
       GNUNET_YES != GNUNET_CONTAINER_slist_end (&it);
       GNUNET_CONTAINER_slist_next (&it))
  {
    t = GNUNET_CONTAINER_slist_get (&it, NULL);

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

  GNUNET_CONTAINER_slist_iter_destroy (&it);
}

int
set_compare (const void *buf1, const size_t len1, const void *buf2,
             const size_t len2)
{
  int c1;
  int c2;
  struct GNUNET_CONTAINER_SList_Iterator it1;
  struct GNUNET_CONTAINER_SList_Iterator it2;
  struct State *s1;
  struct State *s2;
  struct GNUNET_CONTAINER_SList *l1;
  struct GNUNET_CONTAINER_SList *l2;
  const void *el1;
  const void *el2;
  size_t length1;
  size_t length2;
  int rslt;
  int contains;

  if (len1 != len2 && len1 != sizeof (struct State) &&
      len2 != sizeof (struct State))
    return 1;

  s1 = (struct State *) buf1;
  s2 = (struct State *) buf2;

  l1 = s1->nfa_set;
  l2 = s2->nfa_set;

  c1 = GNUNET_CONTAINER_slist_count (l1);
  c2 = GNUNET_CONTAINER_slist_count (l2);

  if (c1 != c2)
    return ((c1 > c2) ? 1 : -1);

  rslt = 0;

  for (it1 = GNUNET_CONTAINER_slist_begin (l1);
       GNUNET_YES != GNUNET_CONTAINER_slist_end (&it1);
       GNUNET_CONTAINER_slist_next (&it1))
  {
    el1 = GNUNET_CONTAINER_slist_get (&it1, &length1);
    contains = 0;

    for (it2 = GNUNET_CONTAINER_slist_begin (l2);
         GNUNET_YES != GNUNET_CONTAINER_slist_end (&it2);
         GNUNET_CONTAINER_slist_next (&it2))
    {
      el2 = GNUNET_CONTAINER_slist_get (&it2, &length2);

      if (length1 != length2)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "Comparing lists failed, element size mismatch\n");
        break;
      }
      if (((struct State *) el1)->id == ((struct State *) el2)->id)
      {
        contains = 1;
        break;
      }
    }
    GNUNET_CONTAINER_slist_iter_destroy (&it2);

    if (0 == contains)
    {
      rslt = 1;
      break;
    }
  }
  GNUNET_CONTAINER_slist_iter_destroy (&it1);

  return rslt;
}

int
transition_literal_compare (const void *buf1, const size_t len1,
                            const void *buf2, const size_t len2)
{
  struct Transition *t1;
  struct Transition *t2;

  if (len1 != len2 && len1 != sizeof (struct Transition) &&
      len2 != sizeof (struct Transition))
  {
    return 1;
  }

  t1 = (struct Transition *) buf1;
  t2 = (struct Transition *) buf2;

  if (t1->literal == t2->literal)
    return 0;
  else if (t1->literal > t2->literal)
    return 1;
  else
    return -1;
}

void
add_transition (struct GNUNET_REGEX_Context *ctx, struct State *from_state,
                const char literal, struct State *to_state)
{
  struct Transition t;

  if (NULL == from_state)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Could not create Transition.\n");
    return;
  }

  t.id = ctx->transition_id++;
  t.literal = literal;
  t.state = to_state;

  GNUNET_CONTAINER_slist_add (from_state->transitions,
                              GNUNET_CONTAINER_SLIST_DISPOSITION_TRANSIENT, &t,
                              sizeof t);
}

struct State *
dfa_create_state (struct GNUNET_REGEX_Context *ctx,
                  struct GNUNET_CONTAINER_SList *states)
{
  struct State *s;
  char *name;
  struct GNUNET_CONTAINER_SList_Iterator stateit;
  struct GNUNET_CONTAINER_SList_Iterator tranit;
  int len = 0;
  struct State *cstate;
  struct Transition *ctran;

  s = GNUNET_malloc (sizeof (struct State));
  s->id = ctx->state_id++;
  s->accepting = 0;
  s->transitions = GNUNET_CONTAINER_slist_create ();
  s->marked = 0;
  s->name = NULL;

  if (NULL == states)
    return s;

  s->nfa_set = states;

  if (0 == GNUNET_CONTAINER_slist_count (states))
    return s;


  // Create a name based on 'sset'
  s->name = GNUNET_malloc (sizeof (char) * 2);
  strcat (s->name, "{");
  name = NULL;

  for (stateit = GNUNET_CONTAINER_slist_begin (states);
       GNUNET_NO == GNUNET_CONTAINER_slist_end (&stateit);
       GNUNET_CONTAINER_slist_next (&stateit))
  {
    cstate = GNUNET_CONTAINER_slist_get (&stateit, NULL);
    GNUNET_CONTAINER_slist_iter_destroy (&tranit);
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
    for (tranit = GNUNET_CONTAINER_slist_begin (cstate->transitions);
         GNUNET_NO == GNUNET_CONTAINER_slist_end (&tranit);
         GNUNET_CONTAINER_slist_next (&tranit))
    {
      ctran = GNUNET_CONTAINER_slist_get (&tranit, NULL);
      if (0 != ctran->literal &&
          NULL == GNUNET_CONTAINER_slist_contains2 (s->transitions, ctran,
                                                    sizeof *ctran,
                                                    &transition_literal_compare))
      {
        add_transition (ctx, s, ctran->literal, NULL);
      }
    }

    if (cstate->accepting)
      s->accepting = 1;
  }
  GNUNET_CONTAINER_slist_iter_destroy (&stateit);

  s->name[strlen (s->name) - 1] = '}';

  return s;
}

void
dfa_clear_nfa_set (struct GNUNET_CONTAINER_SList *states)
{
  struct GNUNET_CONTAINER_SList_Iterator it;
  struct State *s;

  for (it = GNUNET_CONTAINER_slist_begin (states);
       GNUNET_YES != GNUNET_CONTAINER_slist_end (&it);
       GNUNET_CONTAINER_slist_next (&it))
  {
    s = GNUNET_CONTAINER_slist_get (&it, NULL);
    if (NULL != s->nfa_set) 
    {
      GNUNET_CONTAINER_slist_destroy (s->nfa_set);
      s->nfa_set = NULL;
    }
  }

  GNUNET_CONTAINER_slist_iter_destroy (&it);
}

struct GNUNET_REGEX_Automaton *
nfa_create (struct State *start, struct State *end)
{
  struct GNUNET_REGEX_Automaton *n;

  n = GNUNET_malloc (sizeof (struct GNUNET_REGEX_Automaton));

  n->start = NULL;
  n->end = NULL;
  n->states = GNUNET_CONTAINER_slist_create ();

  if (NULL == start && NULL == end)
    return n;

  GNUNET_CONTAINER_slist_add (n->states,
                              GNUNET_CONTAINER_SLIST_DISPOSITION_STATIC, end,
                              sizeof *end);

  GNUNET_CONTAINER_slist_add (n->states,
                              GNUNET_CONTAINER_SLIST_DISPOSITION_STATIC, start,
                              sizeof *start);

  n->start = start;
  n->end = end;

  return n;
}

void
nfa_add_states (struct GNUNET_REGEX_Automaton *n,
                struct GNUNET_CONTAINER_SList *states)
{
  // This isn't very pretty. Would be better to use GNUNET_CONTAINER_slist_append, but
  // this function adds to the beginning of dst, which currently breaks "pretty"
  // printing of the graph...
  struct GNUNET_CONTAINER_SList_Iterator i;
  struct State *s;

  for (i = GNUNET_CONTAINER_slist_begin (states);
       GNUNET_CONTAINER_slist_end (&i) != GNUNET_YES;
       GNUNET_CONTAINER_slist_next (&i))

  {
    s = GNUNET_CONTAINER_slist_get (&i, NULL);
    GNUNET_CONTAINER_slist_add_end (n->states,
                                    GNUNET_CONTAINER_SLIST_DISPOSITION_STATIC,
                                    s, sizeof *s);
  }
  GNUNET_CONTAINER_slist_iter_destroy (&i);
}

struct State *
nfa_create_state (struct GNUNET_REGEX_Context *ctx, int accepting)
{
  struct State *s;

  s = GNUNET_malloc (sizeof (struct State));
  s->id = ctx->state_id++;
  s->accepting = accepting;
  s->transitions = GNUNET_CONTAINER_slist_create ();
  s->marked = 0;
  s->name = NULL;
  GNUNET_asprintf (&s->name, "s%i", s->id);

  return s;
}

void
automaton_fragment_clear (struct GNUNET_REGEX_Automaton *a)
{
  GNUNET_CONTAINER_slist_destroy (a->states);
  a->start = NULL;
  a->end = NULL;
  GNUNET_free (a);
}

void
automaton_destroy_state (struct State *s)
{
  if (NULL != s->transitions)
    GNUNET_CONTAINER_slist_destroy (s->transitions);
  if (NULL != s->name)
    GNUNET_free (s->name);
  if (NULL != s->nfa_set)
    GNUNET_CONTAINER_slist_destroy (s->nfa_set);
  GNUNET_free (s);
}

void
mark_all_states (struct GNUNET_REGEX_Automaton *n, int marked)
{
  struct GNUNET_CONTAINER_SList_Iterator it;
  struct State *s;

  for (it = GNUNET_CONTAINER_slist_begin (n->states);
       GNUNET_YES != GNUNET_CONTAINER_slist_end (&it);
       GNUNET_CONTAINER_slist_next (&it))
  {
    s = GNUNET_CONTAINER_slist_get (&it, NULL);
    s->marked = marked;
  }

  GNUNET_CONTAINER_slist_iter_destroy (&it);
}

void
nfa_add_concatenation (struct GNUNET_REGEX_Context *ctx)
{
  struct GNUNET_REGEX_Automaton *a;
  struct GNUNET_REGEX_Automaton *b;
  struct GNUNET_REGEX_Automaton *new;

  b = stack_pop (ctx->stack, sizeof (struct GNUNET_REGEX_Automaton));
  a = stack_pop (ctx->stack, sizeof (struct GNUNET_REGEX_Automaton));

  add_transition (ctx, a->end, 0, b->start);
  a->end->accepting = 0;
  b->end->accepting = 1;

  new = nfa_create (NULL, NULL);
  nfa_add_states (new, a->states);
  nfa_add_states (new, b->states);
  new->start = a->start;
  new->end = b->end;
  automaton_fragment_clear (a);
  automaton_fragment_clear (b);

  stack_push (ctx->stack, new, sizeof *new);
}

void
nfa_add_star_op (struct GNUNET_REGEX_Context *ctx)
{
  struct GNUNET_REGEX_Automaton *a;
  struct GNUNET_REGEX_Automaton *new;
  struct State *start;
  struct State *end;

  a = stack_pop (ctx->stack, sizeof (struct GNUNET_REGEX_Automaton));

  if (NULL == a)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "nfa_add_star_op failed, because there was no element on the stack");
    return;
  }

  start = nfa_create_state (ctx, 0);
  end = nfa_create_state (ctx, 1);

  add_transition (ctx, start, 0, a->start);
  add_transition (ctx, start, 0, end);
  add_transition (ctx, a->end, 0, a->start);
  add_transition (ctx, a->end, 0, end);

  a->end->accepting = 0;
  end->accepting = 1;

  new = nfa_create (start, end);
  nfa_add_states (new, a->states);
  automaton_fragment_clear (a);

  stack_push (ctx->stack, new, sizeof *new);
}

void
nfa_add_plus_op (struct GNUNET_REGEX_Context *ctx)
{
  struct GNUNET_REGEX_Automaton *a;

  a = stack_pop (ctx->stack, sizeof (struct GNUNET_REGEX_Automaton));

  add_transition (ctx, a->end, 0, a->start);

  stack_push (ctx->stack, a, sizeof *a);
}

void
nfa_add_alternation (struct GNUNET_REGEX_Context *ctx)
{
  struct GNUNET_REGEX_Automaton *a;
  struct GNUNET_REGEX_Automaton *b;
  struct GNUNET_REGEX_Automaton *new;
  struct State *start;
  struct State *end;

  b = stack_pop (ctx->stack, sizeof (struct GNUNET_REGEX_Automaton));
  a = stack_pop (ctx->stack, sizeof (struct GNUNET_REGEX_Automaton));

  start = nfa_create_state (ctx, 0);
  end = nfa_create_state (ctx, 1);
  add_transition (ctx, start, 0, a->start);
  add_transition (ctx, start, 0, b->start);

  add_transition (ctx, a->end, 0, end);
  add_transition (ctx, b->end, 0, end);

  a->end->accepting = 0;
  b->end->accepting = 0;
  end->accepting = 1;

  new = nfa_create (start, end);
  nfa_add_states (new, a->states);
  nfa_add_states (new, b->states);
  automaton_fragment_clear (a);
  automaton_fragment_clear (b);

  stack_push (ctx->stack, new, sizeof *new);
}

void
nfa_add_literal (struct GNUNET_REGEX_Context *ctx, const char lit)
{
  struct GNUNET_REGEX_Automaton *n;
  struct State *start;
  struct State *end;

  start = nfa_create_state (ctx, 0);
  end = nfa_create_state (ctx, 1);
  add_transition (ctx, start, lit, end);
  n = nfa_create (start, end);
  stack_push (ctx->stack, n, sizeof *n);
}

/**
 * Calculates the closure set for the given set of states.
 *
 * @param states set of states for which to calculate the closure
 * @param count number of states in 'states'
 * @param literal for the transition
 *
 * @return set of states that can be reached from the given 'states' when
 *         using only 'literal' transitions
 */
struct GNUNET_CONTAINER_SList *
create_nfa_closure (struct GNUNET_CONTAINER_SList *states, const char literal)
{
  struct GNUNET_CONTAINER_SList_Iterator stateit;
  struct GNUNET_CONTAINER_SList_Iterator tranit;
  struct GNUNET_CONTAINER_SList *cls;
  struct GNUNET_CONTAINER_SList *cls_check;
  struct State *s;
  struct State *currentstate;
  struct Transition *currenttransition;
  struct State *clsstate;

  cls = GNUNET_CONTAINER_slist_create ();

  for (stateit = GNUNET_CONTAINER_slist_begin (states);
       GNUNET_YES != GNUNET_CONTAINER_slist_end (&stateit);
       GNUNET_CONTAINER_slist_next (&stateit))
  {
    s = GNUNET_CONTAINER_slist_get (&stateit, NULL);
    cls_check = GNUNET_CONTAINER_slist_create ();

    // Add start state to closure only for epsilon closure
    if (0 == literal)
    {
      GNUNET_CONTAINER_slist_add (cls,
                                  GNUNET_CONTAINER_SLIST_DISPOSITION_STATIC, s,
                                  sizeof *s);
    }

    stack_push (cls_check, s, sizeof *s);

    while (!stack_empty (cls_check))
    {
      currentstate = stack_pop (cls_check, sizeof (struct State));

      for (tranit = GNUNET_CONTAINER_slist_begin (currentstate->transitions);
           GNUNET_CONTAINER_slist_end (&tranit) != GNUNET_YES;
           GNUNET_CONTAINER_slist_next (&tranit))
      {
        currenttransition = GNUNET_CONTAINER_slist_get (&tranit, NULL);

        if (NULL != currenttransition->state &&
            literal == currenttransition->literal)
        {
          clsstate = currenttransition->state;

          if (NULL == clsstate)
            break;

          if (GNUNET_YES !=
              GNUNET_CONTAINER_slist_contains (cls, clsstate, sizeof *clsstate))
          {
            GNUNET_CONTAINER_slist_add (cls,
                                        GNUNET_CONTAINER_SLIST_DISPOSITION_STATIC,
                                        clsstate, sizeof *clsstate);
            stack_push (cls_check, clsstate, sizeof *clsstate);
          }
        }
      }
      GNUNET_CONTAINER_slist_iter_destroy (&tranit);
    }

    GNUNET_assert (stack_empty (cls_check));
    GNUNET_CONTAINER_slist_destroy (cls_check);
  }
  GNUNET_CONTAINER_slist_iter_destroy (&stateit);

  return cls;
}

struct GNUNET_CONTAINER_SList *
GNUNET_REGEX_move (struct GNUNET_REGEX_Automaton *a, struct State *s,
                   const char literal)
{
  struct GNUNET_CONTAINER_SList *l;
  struct GNUNET_CONTAINER_SList_Iterator it;
  struct Transition *ctran;

  if (!GNUNET_CONTAINER_slist_contains (a->states, s, sizeof *s))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "State %s is not part of the given automaton", s->name);
    return NULL;
  }

  l = GNUNET_CONTAINER_slist_create ();

  for (it = GNUNET_CONTAINER_slist_begin (s->transitions);
       GNUNET_YES != GNUNET_CONTAINER_slist_end (&it);
       GNUNET_CONTAINER_slist_next (&it))
  {
    ctran = GNUNET_CONTAINER_slist_get (&it, NULL);
    if (literal == ctran->literal)
      GNUNET_CONTAINER_slist_add (l, GNUNET_CONTAINER_SLIST_DISPOSITION_STATIC,
                                  ctran->state, sizeof *(ctran->state));
  }
  GNUNET_CONTAINER_slist_iter_destroy (&it);

  return l;
}

struct GNUNET_REGEX_Automaton *
GNUNET_REGEX_construct_nfa (const char *regex, const size_t len)
{
  struct GNUNET_REGEX_Context ctx;
  struct GNUNET_REGEX_Automaton *nfa;
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

  p = NULL;
  error_msg = NULL;
  altcount = 0;
  atomcount = 0;
  pcount = 0;

  for (count = 0; count < len && *regex; count++, regex++)
  {
    switch (*regex)
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
      regex++;
      count++;
    default:
      if (atomcount > 1)
      {
        --atomcount;
        nfa_add_concatenation (&ctx);
      }
      nfa_add_literal (&ctx, *regex);
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

  nfa = stack_pop (ctx.stack, sizeof (struct GNUNET_REGEX_Automaton));

  if (!stack_empty (ctx.stack))
  {
    error_msg = "Creating the NFA failed. NFA stack was not empty!";
    goto error;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Created NFA with %i States and a total of %i Transitions\n",
              GNUNET_CONTAINER_slist_count (nfa->states), ctx.transition_id);

  GNUNET_REGEX_context_destroy (&ctx);

  return nfa;

error:
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Could not parse regex\n");
  if (NULL != error_msg)
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "%s\n", error_msg);
  GNUNET_free (p);
  while (!stack_empty (ctx.stack))
    GNUNET_REGEX_destroy_automaton (stack_pop
                                    (ctx.stack,
                                     sizeof (struct GNUNET_REGEX_Automaton)));
  GNUNET_REGEX_context_destroy (&ctx);
  return NULL;
}

void
GNUNET_REGEX_destroy_automaton (struct GNUNET_REGEX_Automaton *a)
{
  struct GNUNET_CONTAINER_SList_Iterator it;

  if (NULL == a)
    return;

  for (it = GNUNET_CONTAINER_slist_begin (a->states);
       GNUNET_YES != GNUNET_CONTAINER_slist_end (&it);
       GNUNET_CONTAINER_slist_next (&it))
  {
    automaton_destroy_state (GNUNET_CONTAINER_slist_get (&it, NULL));
  }
  GNUNET_CONTAINER_slist_iter_destroy (&it);
  GNUNET_CONTAINER_slist_destroy (a->states);
  GNUNET_free (a);
}


struct GNUNET_REGEX_Automaton *
GNUNET_REGEX_construct_dfa (const char *regex, const size_t len)
{
  struct GNUNET_REGEX_Context ctx;
  struct GNUNET_REGEX_Automaton *dfa;
  struct GNUNET_REGEX_Automaton *nfa;
  struct GNUNET_CONTAINER_SList *tmp;
  struct GNUNET_CONTAINER_SList *nfa_set;
  struct GNUNET_CONTAINER_SList *sset;
  struct GNUNET_CONTAINER_SList *dfa_stack;
  struct GNUNET_CONTAINER_SList_Iterator tranit;
  struct Transition *currenttransition;
  struct State *dfa_state;
  struct State *new_dfa_state;
  struct State *state_contains;

  GNUNET_REGEX_context_init (&ctx);

  // Create NFA
  nfa = GNUNET_REGEX_construct_nfa (regex, len);

  dfa_stack = GNUNET_CONTAINER_slist_create ();

  // Initialize new dfa
  dfa = GNUNET_malloc (sizeof (struct GNUNET_REGEX_Automaton));
  dfa->states = GNUNET_CONTAINER_slist_create ();

  // Create DFA start state from epsilon closure
  sset = GNUNET_CONTAINER_slist_create ();
  GNUNET_CONTAINER_slist_add (sset, GNUNET_CONTAINER_SLIST_DISPOSITION_STATIC,
                              nfa->start, sizeof *(nfa->start));
  nfa_set = create_nfa_closure (sset, 0);
  GNUNET_CONTAINER_slist_destroy (sset);
  dfa->start = dfa_create_state (&ctx, nfa_set);
  GNUNET_CONTAINER_slist_add (dfa->states,
                              GNUNET_CONTAINER_SLIST_DISPOSITION_STATIC,
                              dfa->start, sizeof *(dfa->start));
  stack_push (dfa_stack, dfa->start, sizeof *(dfa->start));

  while (!stack_empty (dfa_stack))
  {
    dfa_state = stack_pop (dfa_stack, sizeof (struct State));

    for (tranit = GNUNET_CONTAINER_slist_begin (dfa_state->transitions);
         GNUNET_YES != GNUNET_CONTAINER_slist_end (&tranit);
         GNUNET_CONTAINER_slist_next (&tranit))
    {
      currenttransition = GNUNET_CONTAINER_slist_get (&tranit, NULL);

      if (0 != currenttransition->literal && NULL == currenttransition->state)
      {
        tmp = create_nfa_closure (dfa_state->nfa_set, 
                                  currenttransition->literal);
        nfa_set = create_nfa_closure (tmp, 0);
        new_dfa_state = dfa_create_state (&ctx, nfa_set);
        GNUNET_CONTAINER_slist_destroy (tmp);

        state_contains =
            GNUNET_CONTAINER_slist_contains2 (dfa->states, new_dfa_state,
                                              sizeof *new_dfa_state,
                                              &set_compare);
        if (NULL == state_contains)
        {
          GNUNET_CONTAINER_slist_add_end (dfa->states,
                                          GNUNET_CONTAINER_SLIST_DISPOSITION_STATIC,
                                          new_dfa_state, sizeof *new_dfa_state);
          stack_push (dfa_stack, new_dfa_state, sizeof *new_dfa_state);
          currenttransition->state = new_dfa_state;
        }
        else
          currenttransition->state = state_contains;
      }
    }

    GNUNET_CONTAINER_slist_iter_destroy (&tranit);
  }
  GNUNET_CONTAINER_slist_destroy (dfa_stack);
  GNUNET_REGEX_destroy_automaton (nfa);
  GNUNET_REGEX_context_destroy (&ctx);
  dfa_clear_nfa_set (dfa->states);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Created DFA with %i States\n",
              GNUNET_CONTAINER_slist_count (dfa->states));

  return dfa;
}

void
GNUNET_REGEX_save_nfa_graph (struct GNUNET_REGEX_Automaton *n,
                             const char *filename)
{
  struct GNUNET_CONTAINER_SList_Iterator stateit;
  struct GNUNET_CONTAINER_SList_Iterator tranit;
  struct State *s;
  struct Transition *ctran;
  char *s_acc = NULL;
  char *s_tran = NULL;
  char *start;
  char *end;
  FILE *p;

  if (NULL == n)
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

  for (stateit = GNUNET_CONTAINER_slist_begin (n->states);
       GNUNET_YES != GNUNET_CONTAINER_slist_end (&stateit);
       GNUNET_CONTAINER_slist_next (&stateit))
  {

    s = GNUNET_CONTAINER_slist_get (&stateit, NULL);

    if (s->accepting)
    {
      GNUNET_asprintf (&s_acc, "\"%s\" [shape=doublecircle];\n", s->name);
      fwrite (s_acc, strlen (s_acc), 1, p);
      GNUNET_free (s_acc);
    }

    s->marked = 1;

    for (tranit = GNUNET_CONTAINER_slist_begin (s->transitions);
         GNUNET_YES != GNUNET_CONTAINER_slist_end (&tranit);
         GNUNET_CONTAINER_slist_next (&tranit))
    {
      ctran = GNUNET_CONTAINER_slist_get (&tranit, NULL);

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
    GNUNET_CONTAINER_slist_iter_destroy (&tranit);
  }
  GNUNET_CONTAINER_slist_iter_destroy (&stateit);

  end = "\n}\n";
  fwrite (end, strlen (end), 1, p);
  fclose (p);
}
