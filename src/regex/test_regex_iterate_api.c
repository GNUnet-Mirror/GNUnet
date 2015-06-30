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
 * @file regex/test_regex_iterate_api.c
 * @brief test for regex.c
 * @author Maximilian Szengel
 */
#include <regex.h>
#include <time.h>
#include "platform.h"
#include "regex_internal_lib.h"
#include "regex_block_lib.h"
#include "regex_internal.h"

/**
 * Regex initial padding.
 */
#define INITIAL_PADDING "PADPADPADPADPADP"

/**
 * Set to GNUNET_YES to save a debug graph.
 */
#define REGEX_INTERNAL_ITERATE_SAVE_DEBUG_GRAPH GNUNET_NO

static unsigned int transition_counter;

struct IteratorContext
{
  int error;
  int should_save_graph;
  FILE *graph_filep;
  unsigned int string_count;
  char *const *strings;
  unsigned int match_count;
};

struct RegexStringPair
{
  char *regex;
  unsigned int string_count;
  char *strings[20];
};


static void
key_iterator (void *cls, const struct GNUNET_HashCode *key,
	      const char *proof,
              int accepting, unsigned int num_edges,
              const struct REGEX_BLOCK_Edge *edges)
{
  unsigned int i;
  struct IteratorContext *ctx = cls;
  char *out_str;
  char *state_id = GNUNET_strdup (GNUNET_h2s (key));

  GNUNET_assert (NULL != proof);
  if (GNUNET_YES == ctx->should_save_graph)
  {
    if (GNUNET_YES == accepting)
      GNUNET_asprintf (&out_str, "\"%s\" [shape=doublecircle]\n", state_id);
    else
      GNUNET_asprintf (&out_str, "\"%s\" [shape=circle]\n", state_id);
    fwrite (out_str, strlen (out_str), 1, ctx->graph_filep);
    GNUNET_free (out_str);

    for (i = 0; i < num_edges; i++)
    {
      transition_counter++;
      GNUNET_asprintf (&out_str, "\"%s\" -> \"%s\" [label = \"%s (%s)\"]\n",
                       state_id, GNUNET_h2s (&edges[i].destination),
                       edges[i].label, proof);
      fwrite (out_str, strlen (out_str), 1, ctx->graph_filep);

      GNUNET_free (out_str);
    }
  }
  else
  {
    for (i = 0; i < num_edges; i++)
      transition_counter++;
  }

  for (i = 0; i < ctx->string_count; i++)
  {
    if (0 == strcmp (proof, ctx->strings[i]))
      ctx->match_count++;
  }

  if (GNUNET_OK != REGEX_BLOCK_check_proof (proof, strlen (proof), key))
  {
    ctx->error++;
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Proof check failed: proof: %s key: %s\n", proof, state_id);
  }
  GNUNET_free (state_id);
}


int
main (int argc, char *argv[])
{
  GNUNET_log_setup ("test-regex", "WARNING", NULL);

  int error;
  struct REGEX_INTERNAL_Automaton *dfa;
  unsigned int i;
  unsigned int num_transitions;
  char *filename = NULL;
  struct IteratorContext ctx = { 0, 0, NULL, 0, NULL, 0 };

  error = 0;

  const struct RegexStringPair rxstr[13] = {
    {INITIAL_PADDING "ab(c|d)+c*(a(b|c)+d)+(bla)+", 2,
     {INITIAL_PADDING "abcdcdca", INITIAL_PADDING "abcabdbl"}},
    {INITIAL_PADDING
     "abcdefghixxxxxxxxxxxxxjklmnop*qstoisdjfguisdfguihsdfgbdsuivggsd", 1,
     {INITIAL_PADDING "abcdefgh"}},
    {INITIAL_PADDING "VPN-4-1(0|1)*", 2,
     {INITIAL_PADDING "VPN-4-10", INITIAL_PADDING "VPN-4-11"}},
    {INITIAL_PADDING "(a+X*y+c|p|R|Z*K*y*R+w|Y*6+n+h*k*w+V*F|W*B*e*)", 2,
     {INITIAL_PADDING "aaaaaaaa", INITIAL_PADDING "aaXXyyyc"}},
    {INITIAL_PADDING "a*", 1, {INITIAL_PADDING "aaaaaaaa"}},
    {INITIAL_PADDING "xzxzxzxzxz", 1, {INITIAL_PADDING "xzxzxzxz"}},
    {INITIAL_PADDING "xyz*", 1, {INITIAL_PADDING "xyzzzzzz"}},
    {INITIAL_PADDING
     "abcd:(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1):(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)",
     2, {INITIAL_PADDING "abcd:000", INITIAL_PADDING "abcd:101"}},
    {INITIAL_PADDING "(x*|(0|1|2)(a|b|c|d)+)", 2,
     {INITIAL_PADDING "xxxxxxxx", INITIAL_PADDING "0abcdbad"}},
    {INITIAL_PADDING "(0|1)(0|1)23456789ABC", 1, {INITIAL_PADDING "11234567"}},
    {INITIAL_PADDING "0*123456789ABC*", 3,
     {INITIAL_PADDING "00123456", INITIAL_PADDING "00000000",
      INITIAL_PADDING "12345678"}},
    {INITIAL_PADDING "0123456789A*BC", 1, {INITIAL_PADDING "01234567"}},
    {"GNUNETVPN000100000IPEX6-fc5a:4e1:c2ba::1", 1, {"GNUNETVPN000100000IPEX6-"}}
  };

  const char *graph_start_str = "digraph G {\nrankdir=LR\n";
  const char *graph_end_str = "\n}\n";

  for (i = 0; i < 13; i++)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Iterating DFA for regex %s\n",
                rxstr[i].regex);


    /* Create graph */
    if (GNUNET_YES == REGEX_INTERNAL_ITERATE_SAVE_DEBUG_GRAPH)
    {
      GNUNET_asprintf (&filename, "iteration_graph_%u.dot", i);
      ctx.graph_filep = fopen (filename, "w");
      if (NULL == ctx.graph_filep)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                    "Could not open file %s for saving iteration graph.\n",
                    filename);
        ctx.should_save_graph = GNUNET_NO;
      }
      else
      {
        ctx.should_save_graph = GNUNET_YES;
        fwrite (graph_start_str, strlen (graph_start_str), 1, ctx.graph_filep);
      }
      GNUNET_free (filename);
    }
    else
    {
      ctx.should_save_graph = GNUNET_NO;
      ctx.graph_filep = NULL;
    }

    /* Iterate over DFA edges */
    transition_counter = 0;
    ctx.string_count = rxstr[i].string_count;
    ctx.strings = rxstr[i].strings;
    ctx.match_count = 0;
    dfa =
        REGEX_INTERNAL_construct_dfa (rxstr[i].regex, strlen (rxstr[i].regex), 0);
    REGEX_INTERNAL_iterate_all_edges (dfa, key_iterator, &ctx);
    num_transitions =
        REGEX_INTERNAL_get_transition_count (dfa) - dfa->start->transition_count;

    if (transition_counter < num_transitions)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Automaton has %d transitions, iterated over %d transitions\n",
                  num_transitions, transition_counter);
      error += 1;
    }

    if (ctx.match_count < ctx.string_count)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Missing initial states for regex %s\n", rxstr[i].regex);
      error += (ctx.string_count - ctx.match_count);
    }
    else if (ctx.match_count > ctx.string_count)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Duplicate initial transitions for regex %s\n",
                  rxstr[i].regex);
      error += (ctx.string_count - ctx.match_count);
    }

    REGEX_INTERNAL_automaton_destroy (dfa);

    /* Finish graph */
    if (GNUNET_YES == ctx.should_save_graph)
    {
      fwrite (graph_end_str, strlen (graph_end_str), 1, ctx.graph_filep);
      fclose (ctx.graph_filep);
      ctx.graph_filep = NULL;
      ctx.should_save_graph = GNUNET_NO;
    }
  }


  for (i = 0; i < 13; i++)
  {
    ctx.string_count = rxstr[i].string_count;
    ctx.strings = rxstr[i].strings;
    ctx.match_count = 0;

    dfa =
        REGEX_INTERNAL_construct_dfa (rxstr[i].regex, strlen (rxstr[i].regex), 0);
    REGEX_INTERNAL_dfa_add_multi_strides (NULL, dfa, 2);
    REGEX_INTERNAL_iterate_all_edges (dfa, key_iterator, &ctx);

    if (ctx.match_count < ctx.string_count)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Missing initial states for regex %s\n", rxstr[i].regex);
      error += (ctx.string_count - ctx.match_count);
    }

    REGEX_INTERNAL_automaton_destroy (dfa);
  }

  error += ctx.error;

  return error;
}
