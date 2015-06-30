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
 * @file src/regex/regex_test_graph.c
 * @brief functions for creating .dot graphs from regexes
 * @author Maximilian Szengel
 */
#include "platform.h"
#include "regex_internal_lib.h"
#include "regex_test_lib.h"
#include "regex_internal.h"

/**
 * Context for graph creation. Passed as the cls to
 * REGEX_TEST_automaton_save_graph_step.
 */
struct REGEX_TEST_Graph_Context
{
  /**
   * File pointer to the dot file used for output.
   */
  FILE *filep;

  /**
   * Verbose flag, if it's set to GNUNET_YES additional info will be printed in
   * the graph.
   */
  int verbose;

  /**
   * Coloring flag, if set to GNUNET_YES SCCs will be colored.
   */
  int coloring;
};


/**
 * Recursive function doing DFS with 'v' as a start, detecting all SCCs inside
 * the subgraph reachable from 'v'. Used with scc_tarjan function to detect all
 * SCCs inside an automaton.
 *
 * @param scc_counter counter for numbering the sccs
 * @param v start vertex
 * @param index current index
 * @param stack stack for saving all SCCs
 * @param stack_size current size of the stack
 */
static void
scc_tarjan_strongconnect (unsigned int *scc_counter,
                          struct REGEX_INTERNAL_State *v, unsigned int *index,
                          struct REGEX_INTERNAL_State **stack,
                          unsigned int *stack_size)
{
  struct REGEX_INTERNAL_State *w;
  struct REGEX_INTERNAL_Transition *t;

  v->index = *index;
  v->lowlink = *index;
  (*index)++;
  stack[(*stack_size)++] = v;
  v->contained = 1;

  for (t = v->transitions_head; NULL != t; t = t->next)
  {
    w = t->to_state;

    if (NULL == w)
      continue;

    if (w->index < 0)
    {
      scc_tarjan_strongconnect (scc_counter, w, index, stack, stack_size);
      v->lowlink = (v->lowlink > w->lowlink) ? w->lowlink : v->lowlink;
    }
    else if (1 == w->contained)
      v->lowlink = (v->lowlink > w->index) ? w->index : v->lowlink;
  }

  if (v->lowlink == v->index)
  {
    (*scc_counter)++;
    do
    {
      w = stack[--(*stack_size)];
      w->contained = 0;
      w->scc_id = *scc_counter;
    }
    while (w != v);
  }
}


/**
 * Detect all SCCs (Strongly Connected Components) inside the given automaton.
 * SCCs will be marked using the scc_id on each state.
 *
 * @param a the automaton for which SCCs should be computed and assigned.
 */
static void
scc_tarjan (struct REGEX_INTERNAL_Automaton *a)
{
  unsigned int index;
  unsigned int scc_counter;
  struct REGEX_INTERNAL_State *v;
  struct REGEX_INTERNAL_State *stack[a->state_count];
  unsigned int stack_size;

  for (v = a->states_head; NULL != v; v = v->next)
  {
    v->contained = 0;
    v->index = -1;
    v->lowlink = -1;
  }

  stack_size = 0;
  index = 0;
  scc_counter = 0;

  for (v = a->states_head; NULL != v; v = v->next)
  {
    if (v->index < 0)
      scc_tarjan_strongconnect (&scc_counter, v, &index, stack, &stack_size);
  }
}


/**
 * Save a state to an open file pointer. cls is expected to be a file pointer to
 * an open file. Used only in conjunction with
 * REGEX_TEST_automaton_save_graph.
 *
 * @param cls file pointer.
 * @param count current count of the state, not used.
 * @param s state.
 */
void
REGEX_TEST_automaton_save_graph_step (void *cls, unsigned int count,
                                        struct REGEX_INTERNAL_State *s)
{
  struct REGEX_TEST_Graph_Context *ctx = cls;
  struct REGEX_INTERNAL_Transition *ctran;
  char *s_acc = NULL;
  char *s_tran = NULL;
  char *name;
  char *to_name;

  if (GNUNET_YES == ctx->verbose)
    GNUNET_asprintf (&name, "%i (%s) (%s) (%s)", s->dfs_id, s->name, s->proof,
                     GNUNET_h2s (&s->hash));
  else
    GNUNET_asprintf (&name, "%i", s->dfs_id);

  if (s->accepting)
  {
    if (GNUNET_YES == ctx->coloring)
    {
      GNUNET_asprintf (&s_acc,
                       "\"%s\" [shape=doublecircle, color=\"0.%i 0.8 0.95\"];\n",
                       name, s->scc_id * s->scc_id);
    }
    else
    {
      GNUNET_asprintf (&s_acc, "\"%s\" [shape=doublecircle];\n", name,
                       s->scc_id);
    }
  }
  else if (GNUNET_YES == ctx->coloring)
  {
    GNUNET_asprintf (&s_acc,
                     "\"%s\" [shape=circle, color=\"0.%i 0.8 0.95\"];\n", name,
                     s->scc_id * s->scc_id);
  }
  else
  {
    GNUNET_asprintf (&s_acc, "\"%s\" [shape=circle];\n", name, s->scc_id);
  }

  GNUNET_assert (NULL != s_acc);

  fwrite (s_acc, strlen (s_acc), 1, ctx->filep);
  GNUNET_free (s_acc);
  s_acc = NULL;

  for (ctran = s->transitions_head; NULL != ctran; ctran = ctran->next)
  {
    if (NULL == ctran->to_state)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Transition from State %i has no state for transitioning\n",
                  s->id);
      continue;
    }

    if (GNUNET_YES == ctx->verbose)
    {
      GNUNET_asprintf (&to_name, "%i (%s) (%s) (%s)", ctran->to_state->dfs_id,
                       ctran->to_state->name, ctran->to_state->proof,
                       GNUNET_h2s (&ctran->to_state->hash));
    }
    else
      GNUNET_asprintf (&to_name, "%i", ctran->to_state->dfs_id);

    if (NULL == ctran->label)
    {
      if (GNUNET_YES == ctx->coloring)
      {
        GNUNET_asprintf (&s_tran,
                         "\"%s\" -> \"%s\" [label = \"ε\", color=\"0.%i 0.8 0.95\"];\n",
                         name, to_name, s->scc_id * s->scc_id);
      }
      else
      {
        GNUNET_asprintf (&s_tran, "\"%s\" -> \"%s\" [label = \"ε\"];\n", name,
                         to_name, s->scc_id);
      }
    }
    else
    {
      if (GNUNET_YES == ctx->coloring)
      {
        GNUNET_asprintf (&s_tran,
                         "\"%s\" -> \"%s\" [label = \"%s\", color=\"0.%i 0.8 0.95\"];\n",
                         name, to_name, ctran->label, s->scc_id * s->scc_id);
      }
      else
      {
        GNUNET_asprintf (&s_tran, "\"%s\" -> \"%s\" [label = \"%s\"];\n", name,
                         to_name, ctran->label, s->scc_id);
      }
    }

    GNUNET_free (to_name);

    GNUNET_assert (NULL != s_tran);

    fwrite (s_tran, strlen (s_tran), 1, ctx->filep);
    GNUNET_free (s_tran);
    s_tran = NULL;
  }

  GNUNET_free (name);
}


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
                                   enum REGEX_TEST_GraphSavingOptions options)
{
  char *start;
  char *end;
  struct REGEX_TEST_Graph_Context ctx;

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

  ctx.filep = fopen (filename, "w");
  ctx.verbose =
      (0 == (options & REGEX_TEST_GRAPH_VERBOSE)) ? GNUNET_NO : GNUNET_YES;
  ctx.coloring =
      (0 == (options & REGEX_TEST_GRAPH_COLORING)) ? GNUNET_NO : GNUNET_YES;

  if (NULL == ctx.filep)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Could not open file for writing: %s",
                filename);
    return;
  }

  /* First add the SCCs to the automaton, so we can color them nicely */
  if (GNUNET_YES == ctx.coloring)
    scc_tarjan (a);

  start = "digraph G {\nrankdir=LR\n";
  fwrite (start, strlen (start), 1, ctx.filep);

  REGEX_INTERNAL_automaton_traverse (a, a->start, NULL, NULL,
                                   &REGEX_TEST_automaton_save_graph_step,
                                   &ctx);

  end = "\n}\n";
  fwrite (end, strlen (end), 1, ctx.filep);
  fclose (ctx.filep);
}
