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

struct GNUNET_REGEX_Nfa
{
  struct State *start;
  struct State *end;

  unsigned int statecnt;
  struct State **states;
};

struct State
{
  unsigned int id;
  int accepting;
  unsigned int tcnt;
  struct Transition *transitions;
  int visited;
};

struct Transition
{
  unsigned int id;
  char literal;
  struct State *state;
};

static unsigned int state_id = 0;
static unsigned int transition_id = 0;

struct GNUNET_REGEX_Nfa *
nfa_create (struct State *start, struct State *end)
{
  struct GNUNET_REGEX_Nfa *n;

  n = GNUNET_malloc (sizeof (struct GNUNET_REGEX_Nfa));

  if (NULL == start && NULL == end)
  {
    n->states = NULL;
    n->statecnt = 0;
    n->start = NULL;
    n->end = NULL;

    return n;
  }

  n->states = GNUNET_malloc ((sizeof (struct State *)) * 2);
  n->states[0] = start;
  n->states[1] = end;
  n->statecnt = 2;

  n->start = start;
  n->end = end;

  return n;
}


void
nfa_add_states (struct GNUNET_REGEX_Nfa *n, struct State **states,
                unsigned int count)
{
  unsigned int i;
  unsigned int j;

  i = n->statecnt;
  GNUNET_array_grow (n->states, n->statecnt, n->statecnt + count);
  for (j = 0; i < n->statecnt && j < count; i++, j++)
  {
    n->states[i] = states[j];
  }
}


struct State *
nfa_create_state (int accepting)
{
  struct State *s;

  s = GNUNET_malloc (sizeof (struct State));
  s->id = state_id++;
  s->accepting = accepting;
  s->tcnt = 0;
  s->transitions = NULL;
  s->visited = 0;

  return s;
}

void
nfa_add_transition (struct State *from_state, const char literal,
                    struct State *to_state)
{
  struct Transition t;

  if (NULL == to_state)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Could not create Transition. to_state was NULL.\n");
    return;
  }

  t.id = transition_id++;
  t.literal = literal;
  t.state = to_state;

  if (0 == from_state->tcnt)
    from_state->transitions = NULL;

  GNUNET_array_append (from_state->transitions, from_state->tcnt, t);
}

void
mark_all_states (struct GNUNET_REGEX_Nfa *n, int visited)
{
  int i;

  for (i = 0; i < n->statecnt; i++)
  {
    n->states[i]->visited = visited;
  }
}

void
print_states (struct GNUNET_REGEX_Nfa *n, char **out_str)
{
  struct State *s;
  int i_s;
  int i_t;
  char *s_all;

  mark_all_states (n, 0);

  s_all = GNUNET_malloc (sizeof (char));
  *s_all = '\0';

  for (i_s = 0; i_s < n->statecnt; i_s++)
  {
    struct Transition *ctran;
    char *s_acc = NULL;
    char *s_tran = NULL;

    s = n->states[i_s];

    if (s->accepting)
    {
      GNUNET_asprintf (&s_acc, "s%i [shape=doublecircle];\n", s->id);

      s_all = GNUNET_realloc (s_all, strlen (s_all) + strlen (s_acc) + 1);
      strcat (s_all, s_acc);
      GNUNET_free (s_acc);
    }

    ctran = s->transitions;
    s->visited = 1;

    for (i_t = 0; i_t < s->tcnt && NULL != s->transitions; i_t++)
    {
      if (NULL == ctran)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "s->transitions was NULL\n");
      }

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

      s_all = GNUNET_realloc (s_all, strlen (s_all) + strlen (s_tran) + 1);
      strcat (s_all, s_tran);
      GNUNET_free (s_tran);

      ctran++;
    }
  }

  *out_str = s_all;
}

void
nfa_add_concatenation ()
{
  struct GNUNET_REGEX_Nfa *A;
  struct GNUNET_REGEX_Nfa *B;
  struct GNUNET_REGEX_Nfa *new;

  B = pop (&nfa_stack);
  A = pop (&nfa_stack);

  if (NULL == A || NULL == B)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "nfa_add_concatenationenation failed, because there were not enough elements on the stack");
    return;
  }

  nfa_add_transition (A->end, 0, B->start);
  A->end->accepting = 0;
  B->end->accepting = 1;

  new = nfa_create (NULL, NULL);
  nfa_add_states (new, A->states, A->statecnt);
  nfa_add_states (new, B->states, B->statecnt);
  new->start = A->start;
  new->end = B->end;
  GNUNET_free (A);
  GNUNET_free (B);

  push (new, &nfa_stack);
}

void
nfa_add_star_op ()
{
  struct GNUNET_REGEX_Nfa *A;
  struct GNUNET_REGEX_Nfa *new;
  struct State *start;
  struct State *end;

  A = pop (&nfa_stack);

  if (NULL == A)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "nfa_add_star_op failed, because there was no element on the stack");
    return;
  }

  start = nfa_create_state (0);
  end = nfa_create_state (1);

  nfa_add_transition (start, 0, A->start);
  nfa_add_transition (start, 0, end);
  nfa_add_transition (A->end, 0, A->start);
  nfa_add_transition (A->end, 0, end);

  A->end->accepting = 0;
  end->accepting = 1;

  new = nfa_create (start, end);
  nfa_add_states (new, A->states, A->statecnt);
  GNUNET_free (A);

  push (new, &nfa_stack);
}

void
nfa_add_plus_op ()
{
  struct GNUNET_REGEX_Nfa *A;

  A = pop (&nfa_stack);

  if (NULL == A)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "nfa_add_plus_op failed, because there was no element on the stack");
    return;
  }

  nfa_add_transition (A->end, 0, A->start);

  push (A, &nfa_stack);
}

void
nfa_add_alternation ()
{
  struct GNUNET_REGEX_Nfa *A;
  struct GNUNET_REGEX_Nfa *B;
  struct GNUNET_REGEX_Nfa *new;
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

  start = nfa_create_state (0);
  end = nfa_create_state (1);
  nfa_add_transition (start, 0, A->start);
  nfa_add_transition (start, 0, B->start);

  nfa_add_transition (A->end, 0, end);
  nfa_add_transition (B->end, 0, end);

  A->end->accepting = 0;
  B->end->accepting = 0;
  end->accepting = 1;

  new = nfa_create (start, end);
  nfa_add_states (new, A->states, A->statecnt);
  nfa_add_states (new, B->states, B->statecnt);
  GNUNET_free (A);
  GNUNET_free (B);

  push (new, &nfa_stack);
}

void
nfa_add_literal (const char lit)
{
  struct GNUNET_REGEX_Nfa *n;
  struct State *start;
  struct State *end;

  start = nfa_create_state (0);
  end = nfa_create_state (1);
  nfa_add_transition (start, lit, end);
  n = nfa_create (start, end);
  push (n, &nfa_stack);
}

struct GNUNET_REGEX_Nfa *
GNUNET_REGEX_construct_nfa (const char *regex, size_t len)
{
  struct GNUNET_REGEX_Nfa *nfa;
  unsigned int count;
  unsigned int altcount;
  unsigned int atomcount;
  unsigned int pcount;
  struct p_stage
  {
    int altcount;
    int atomcount;
  };
  struct p_stage *p;

  p = NULL;

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
        nfa_add_concatenation ();
      }
      GNUNET_array_grow (p, pcount, pcount + 1);
      p[pcount - 1].altcount = altcount;
      p[pcount - 1].atomcount = atomcount;
      altcount = 0;
      atomcount = 0;
      break;
    case '|':
      if (0 == atomcount)
        goto error;
      while (--atomcount > 0)
        nfa_add_concatenation ();
      altcount++;
      break;
    case ')':
      if (0 == pcount)
        goto error;
      if (atomcount == 0)
        goto error;
      while (--atomcount > 0)
        nfa_add_concatenation ();
      for (; altcount > 0; altcount--)
        nfa_add_alternation ();
      pcount--;
      altcount = p[pcount].altcount;
      atomcount = p[pcount].atomcount;
      atomcount++;
      break;
    case '*':
      if (atomcount == 0)
        goto error;
      nfa_add_star_op ();
      break;
    case '+':
      if (atomcount == 0)
        goto error;
      nfa_add_plus_op ();
      break;
    case 92:                   /* escape: \ */
      regex++;
      count++;
    default:
      if (atomcount > 1)
      {
        --atomcount;
        nfa_add_concatenation ();
      }
      nfa_add_literal (*regex);
      atomcount++;
      break;
    }
  }
  if (0 != pcount)
    goto error;
  while (--atomcount > 0)
    nfa_add_concatenation ();
  for (; altcount > 0; altcount--)
    nfa_add_alternation ();

  if (NULL != p)
    GNUNET_free (p);

  nfa = pop (&nfa_stack);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Created NFA with %i States and a total of %i Transitions\n",
              state_id, transition_id);

  return nfa;

error:
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Could not parse regex\n");
  GNUNET_free (p);
  while (!empty (&nfa_stack))
    GNUNET_REGEX_destroy_nfa (pop (&nfa_stack));
  return NULL;
}

void
GNUNET_REGEX_destroy_nfa (struct GNUNET_REGEX_Nfa *n)
{
  int i;

  for (i = 0; i < n->statecnt; i++)
  {
    GNUNET_free (n->states[i]);
  }
}

void
GNUNET_REGEX_save_nfa_graph (struct GNUNET_REGEX_Nfa *n, const char *filename)
{
  struct State *s;
  char *start;
  char *end;
  char *states;
  FILE *p;
  int i_s;
  int i_t;

  if (NULL == n)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Could not print NFA, was NULL!");
    return;
  }

  mark_all_states (n, 0);

  states = GNUNET_malloc (sizeof (char));
  *states = '\0';

  for (i_s = 0; i_s < n->statecnt; i_s++)
  {
    struct Transition *ctran;
    char *s_acc = NULL;
    char *s_tran = NULL;

    s = n->states[i_s];

    if (s->accepting)
    {
      GNUNET_asprintf (&s_acc, "s%i [shape=doublecircle];\n", s->id);

      states = GNUNET_realloc (states, strlen (states) + strlen (s_acc) + 1);
      strcat (states, s_acc);
      GNUNET_free (s_acc);
    }

    ctran = s->transitions;
    s->visited = 1;

    for (i_t = 0; i_t < s->tcnt && NULL != s->transitions; i_t++)
    {
      if (NULL == ctran)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "s->transitions was NULL\n");
      }

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

      states = GNUNET_realloc (states, strlen (states) + strlen (s_tran) + 1);
      strcat (states, s_tran);
      GNUNET_free (s_tran);

      ctran++;
    }
  }

  if (NULL == states)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Could not print NFA");
    return;
  }

  if (NULL == filename || strlen (filename) < 1)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "No Filename given!");
    GNUNET_free (states);
    return;
  }

  p = fopen (filename, "w");
  if (p == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Could not open file for writing: %s",
                filename);
    GNUNET_free (states);
    return;
  }

  start = "digraph G {\nrankdir=LR\n";
  end = "\n}\n";
  fwrite (start, strlen (start), 1, p);
  fwrite (states, strlen (states), 1, p);
  fwrite (end, strlen (end), 1, p);
  fclose (p);

  GNUNET_free (states);
}
