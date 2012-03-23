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
#include "gnunet_regex_lib.h"
#include "regex.h"

struct Stack
{
  void *data;
  struct Stack *next;
};

static struct Stack *nfa_stack = NULL;

void
push (void *val, struct Stack **stack)
{
  struct Stack *new = GNUNET_malloc (sizeof (struct Stack *));

  if (NULL == new)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Could not push to stack\n");
    return;
  }
  new->data = val;
  new->next = *stack;
  *stack = new;
}

int
empty (struct Stack **stack)
{
  return (NULL == *stack || NULL == stack);
}

void *
pop (struct Stack **stack)
{
  struct Stack *top;
  void *val;

  if (empty (stack))
    return NULL;

  top = *stack;
  val = top->data;
  *stack = top->next;
  GNUNET_free (top);
  return val;
}

void *
top (struct Stack **stack)
{
  if (empty (stack))
    return NULL;

  return (*stack)->data;
}

struct State
{
  unsigned int id;
  int accepting;
  unsigned int tcnt;
  struct Transition *transitions;
  int marked;
  char *name;
};

struct StateSet
{
  struct State **states;
  unsigned int count;
};

struct GNUNET_REGEX_Automaton
{
  struct State *start;
  struct State *end;

  struct StateSet sset;
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
};

struct State *
dfa_create_state (struct GNUNET_REGEX_Context *ctx, struct StateSet *sset, int accepting)
{
  int i;
  struct State *s;
  char *name;

  s = GNUNET_malloc (sizeof (struct State));
  s->id = ctx->state_id++;
  s->accepting = accepting;
  s->tcnt = 0;
  s->transitions = NULL;
  s->marked = 0;
  s->name = NULL;

  if (0 == sset->count)
    return s;

  s->name = GNUNET_malloc ( strlen ("{"));
  strcat (s->name, "{");

  for (i=0; i<sset->count; i++)
  {
    name = GNUNET_malloc (sizeof (char));
    GNUNET_asprintf (&name, "%i,", sset->states[i]->id);
    s->name = GNUNET_realloc (s->name, strlen (s->name) + strlen (name) + 1);
    strcat (s->name, name);
    GNUNET_free (name);
  }
  s->name[strlen (s->name)-1] = '}';

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Created DFA state with name: %s\n", s->name);

  return s;
}

struct GNUNET_REGEX_Automaton *
nfa_create (struct State *start, struct State *end)
{
  struct GNUNET_REGEX_Automaton *n;
  struct StateSet sset;

  n = GNUNET_malloc (sizeof (struct GNUNET_REGEX_Automaton));

  if (NULL == start && NULL == end)
  {
    sset.states = NULL;
    sset.count = 0;
    n->sset = sset;
    n->start = NULL;
    n->end = NULL;

    return n;
  }

  sset.states = GNUNET_malloc ((sizeof (struct State *)) * 2);
  sset.states[0] = start;
  sset.states[1] = end;
  sset.count = 2;
  n->sset = sset;

  n->start = start;
  n->end = end;

  return n;
}


void
nfa_add_states (struct GNUNET_REGEX_Automaton *n, struct StateSet *sset)
{
  unsigned int i;
  unsigned int j;

  i = n->sset.count;
  GNUNET_array_grow (n->sset.states, n->sset.count, n->sset.count + sset->count);
  for (j = 0; i < n->sset.count && j < sset->count; i++, j++)
  {
    n->sset.states[i] = sset->states[j];
  }
}


struct State *
nfa_create_state (struct GNUNET_REGEX_Context *ctx, int accepting)
{
  struct State *s;

  s = GNUNET_malloc (sizeof (struct State));
  s->id = ctx->state_id++;
  s->accepting = accepting;
  s->tcnt = 0;
  s->transitions = NULL;
  s->marked = 0;
  s->name = NULL;
  GNUNET_asprintf (&s->name, "s%i", s->id);

  return s;
}

void
automaton_destroy_state (struct State *s)
{
  if (s->tcnt > 0)
    GNUNET_free (s->transitions);
  if (NULL != s->name)
    GNUNET_free (s->name);
  GNUNET_free (s);
}

void
nfa_add_transition (struct GNUNET_REGEX_Context *ctx, struct State *from_state, const char literal,
                    struct State *to_state)
{
  struct Transition t;

  if (NULL == from_state || NULL == to_state)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Could not create Transition.\n");
    return;
  }

  t.id = ctx->transition_id++;
  t.literal = literal;
  t.state = to_state;

  if (0 == from_state->tcnt)
    from_state->transitions = NULL;

  GNUNET_array_append (from_state->transitions, from_state->tcnt, t);
}

void
mark_all_states (struct GNUNET_REGEX_Automaton *n, int marked)
{
  int i;

  for (i = 0; i < n->sset.count; i++)
  {
    n->sset.states[i]->marked = marked;
  }
}

void
nfa_add_concatenation (struct GNUNET_REGEX_Context *ctx)
{
  struct GNUNET_REGEX_Automaton *A;
  struct GNUNET_REGEX_Automaton *B;
  struct GNUNET_REGEX_Automaton *new;

  B = pop (&nfa_stack);
  A = pop (&nfa_stack);

  if (NULL == A || NULL == B)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "nfa_add_concatenationenation failed, because there were not enough elements on the stack");
    return;
  }

  nfa_add_transition (ctx, A->end, 0, B->start);
  A->end->accepting = 0;
  B->end->accepting = 1;

  new = nfa_create (NULL, NULL);
  nfa_add_states (new, &A->sset);
  nfa_add_states (new, &B->sset);
  new->start = A->start;
  new->end = B->end;
  GNUNET_free (A);
  GNUNET_free (B);

  push (new, &nfa_stack);
}

void
nfa_add_star_op (struct GNUNET_REGEX_Context *ctx)
{
  struct GNUNET_REGEX_Automaton *A;
  struct GNUNET_REGEX_Automaton *new;
  struct State *start;
  struct State *end;

  A = pop (&nfa_stack);

  if (NULL == A)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "nfa_add_star_op failed, because there was no element on the stack");
    return;
  }

  start = nfa_create_state (ctx, 0);
  end = nfa_create_state (ctx, 1);

  nfa_add_transition (ctx, start, 0, A->start);
  nfa_add_transition (ctx, start, 0, end);
  nfa_add_transition (ctx, A->end, 0, A->start);
  nfa_add_transition (ctx, A->end, 0, end);

  A->end->accepting = 0;
  end->accepting = 1;

  new = nfa_create (start, end);
  nfa_add_states (new, &A->sset);
  GNUNET_free (A);

  push (new, &nfa_stack);
}

void
nfa_add_plus_op (struct GNUNET_REGEX_Context *ctx)
{
  struct GNUNET_REGEX_Automaton *A;

  A = pop (&nfa_stack);

  if (NULL == A)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "nfa_add_plus_op failed, because there was no element on the stack");
    return;
  }

  nfa_add_transition (ctx, A->end, 0, A->start);

  push (A, &nfa_stack);
}

void
nfa_add_alternation (struct GNUNET_REGEX_Context *ctx)
{
  struct GNUNET_REGEX_Automaton *A;
  struct GNUNET_REGEX_Automaton *B;
  struct GNUNET_REGEX_Automaton *new;
  struct State *start;
  struct State *end;

  B = pop (&nfa_stack);
  A = pop (&nfa_stack);

  if (NULL == A || NULL == B)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "alternation failed, because there were not enough elements on the stack");
    return;
  }

  start = nfa_create_state (ctx, 0);
  end = nfa_create_state (ctx, 1);
  nfa_add_transition (ctx, start, 0, A->start);
  nfa_add_transition (ctx, start, 0, B->start);

  nfa_add_transition (ctx, A->end, 0, end);
  nfa_add_transition (ctx, B->end, 0, end);

  A->end->accepting = 0;
  B->end->accepting = 0;
  end->accepting = 1;

  new = nfa_create (start, end);
  nfa_add_states (new, &A->sset);
  nfa_add_states (new, &B->sset);
  GNUNET_free (A);
  GNUNET_free (B);

  push (new, &nfa_stack);
}

void
nfa_add_literal (struct GNUNET_REGEX_Context *ctx, const char lit)
{
  struct GNUNET_REGEX_Automaton *n;
  struct State *start;
  struct State *end;

  start = nfa_create_state (ctx, 0);
  end = nfa_create_state (ctx, 1);
  nfa_add_transition (ctx, start, lit, end);
  n = nfa_create (start, end);
  push (n, &nfa_stack);
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
struct StateSet
nfa_closure (struct State **states, unsigned int count, const char literal)
{
  struct Stack *cls_check;
  unsigned int scnt;
  unsigned int tcnt;
  struct StateSet cls;
  struct State *s;
  struct State *currentstate;
  struct State *clsstate;


  for (scnt=0; scnt < count; scnt++)
  {
    s = states[scnt];
    cls_check = NULL;
    cls.states = NULL;
    cls.count = 0;

    // Add start state to closure
    GNUNET_array_append (cls.states, cls.count, s);
    push (s, &cls_check);

    while (!empty(&cls_check))
    {
      currentstate = pop(&cls_check);

      for (tcnt=0; tcnt<currentstate->tcnt; tcnt++)
      {
        if (NULL != currentstate->transitions[tcnt].state 
            && literal == currentstate->transitions[tcnt].literal)
        {
          clsstate = currentstate->transitions[tcnt].state;

          if (NULL == clsstate)
            break;

          GNUNET_array_append (cls.states, cls.count, clsstate);
          push (clsstate, &cls_check);
        }
      }
    }
  }

  return cls;
}

struct GNUNET_REGEX_Automaton *
GNUNET_REGEX_construct_nfa (const char *regex, size_t len)
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
  }*p;

  p = NULL;
  error_msg = NULL;
  altcount = 0;
  atomcount = 0;
  pcount = 0;
  ctx.state_id = 0;
  ctx.transition_id = 0;

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

  nfa = pop (&nfa_stack);

  if (!empty (&nfa_stack))
  {
    error_msg = "Creating the NFA failed. NFA stack was not empty!";
    goto error;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Created NFA with %i States and a total of %i Transitions\n",
              ctx.state_id, ctx.transition_id);

  return nfa;

error:
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Could not parse regex\n");
  if (NULL != error_msg)
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "%s\n", error_msg);
  GNUNET_free (p);
  while (!empty (&nfa_stack))
    GNUNET_REGEX_destroy_automaton (pop (&nfa_stack));
  return NULL;
}

void
GNUNET_REGEX_destroy_automaton (struct GNUNET_REGEX_Automaton *a)
{
  int i;

  if (NULL == a)
    return;

  for (i = 0; i < a->sset.count; i++)
  {
    automaton_destroy_state (a->sset.states[i]);
  }

  if (NULL != a->sset.states)
    GNUNET_free (a->sset.states);
  GNUNET_free (a);
}

void
GNUNET_REGEX_save_nfa_graph (struct GNUNET_REGEX_Automaton *n, const char *filename)
{
  struct State *s;
  char *start;
  char *end;
  FILE *p;
  int scnt;
  int tcnt;

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

  for (scnt = 0; scnt < n->sset.count; scnt++)
  {
    struct Transition *ctran;
    char *s_acc = NULL;
    char *s_tran = NULL;

    s = n->sset.states[scnt];

    if (s->accepting)
    {
      GNUNET_asprintf (&s_acc, "s%i [shape=doublecircle];\n", s->id);
      fwrite (s_acc, strlen (s_acc), 1, p);
      GNUNET_free (s_acc);
    }

    ctran = s->transitions;
    s->marked = 1;

    for (tcnt = 0; tcnt < s->tcnt && NULL != ctran; tcnt++)
    {
      if (NULL == ctran->state)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    "Transition from State %i has has no state for transitioning\n",
                    s->id);
      }

      if (ctran->literal == 0)
      {
        GNUNET_asprintf (&s_tran, "s%i -> s%i [label = \"epsilon\"];\n", s->id,
                         ctran->state->id);
      }
      else
      {
        GNUNET_asprintf (&s_tran, "s%i -> s%i [label = \"%c\"];\n", s->id,
                         ctran->state->id, ctran->literal);
      }

      fwrite (s_tran, strlen (s_tran), 1, p);

      ctran++;
    }
  }

  end = "\n}\n";
  fwrite (end, strlen (end), 1, p);
  fclose (p);
}

struct GNUNET_REGEX_Automaton *
GNUNET_REGEX_construct_dfa (const char *regex, size_t len)
{
  struct GNUNET_REGEX_Context ctx;
  struct GNUNET_REGEX_Automaton *dfa;
  struct GNUNET_REGEX_Automaton *nfa;
  struct StateSet dfa_start_set;
  struct State *dfa_start;

  ctx.state_id = 0;
  ctx.transition_id = 0;

  // Create NFA
  nfa = GNUNET_REGEX_construct_nfa (regex, len);

  // Create DFA start state from epsilon closure
  dfa_start_set = nfa_closure (&nfa->start, 1, 0);
  dfa_start = dfa_create_state (&ctx, &dfa_start_set, 0);

  // ecls (move (dfa_start, lit))

  return dfa;
}
