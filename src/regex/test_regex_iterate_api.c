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
 * @file regex/test_regex_iterate_api.c
 * @brief test for regex.c
 * @author Maximilian Szengel
 */
#include <regex.h>
#include <time.h>
#include "platform.h"
#include "gnunet_regex_lib.h"
#include "regex_internal.h"

#define GNUNET_REGEX_ITERATE_SAVE_DEBUG_GRAPH GNUNET_NO

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

void
key_iterator (void *cls, const struct GNUNET_HashCode *key, const char *proof,
              int accepting, unsigned int num_edges,
              const struct GNUNET_REGEX_Edge *edges)
{
  unsigned int i;
  struct IteratorContext *ctx = cls;
  char *out_str;
  char *state_id = GNUNET_strdup (GNUNET_h2s (key));

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

  GNUNET_free (state_id);

  for (i = 0; i < ctx->string_count; i++)
  {
    if (0 == strcmp (proof, ctx->strings[i]))
      ctx->match_count++;
  }

  ctx->error += (GNUNET_OK == GNUNET_REGEX_check_proof (proof, key)) ? 0 : 1;
}

int
main (int argc, char *argv[])
{
  GNUNET_log_setup ("test-regex",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);

  int error;
  struct GNUNET_REGEX_Automaton *dfa;
  unsigned int i;
  unsigned int num_transitions;
  struct IteratorContext ctx = { 0, 0, NULL };
  char *filename = NULL;

  error = 0;

  const struct RegexStringPair rxstr[10] = {
    {"ab(c|d)+c*(a(b|c)+d)+(bla)+", 2, {"abcdcdca", "abcabdbl"}},
    {"abcdefghijklmnop*qst", 1, {"abcdefgh"}},
    {"VPN-4-1(0|1)*", 2, {"VPN-4-10", "VPN-4-11"}},
    {"a+X*y+c|p|R|Z*K*y*R+w|Y*6+n+h*k*w+V*F|W*B*e*", 4,
     {"aaaaaaaa", "aaXXyyyc", "p", "Y"}},
    {"a*", 8,
     {"a", "aa", "aaa", "aaaa", "aaaaa", "aaaaaa", "aaaaaaa", "aaaaaaaa"}},
    {"xzxzxzxzxz", 1, {"xzxzxzxz"}},
    {"xyz*", 2, {"xy", "xyz"}},
    {"ab", 1, {"a"}},
    {"abcd:(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1):(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)(0|1)", 2, {"abcd:000", "abcd:101"}},
    {"x*|(0|1|2)(a|b|c|d)", 2, {"xxxxxxxx", "0a"}}
  };

  const char *graph_start_str = "digraph G {\nrankdir=LR\n";
  const char *graph_end_str = "\n}\n";

  for (i = 0; i < 10; i++)
  {
    // Create graph
    if (GNUNET_YES == GNUNET_REGEX_ITERATE_SAVE_DEBUG_GRAPH)
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
    }

    // Iterate over DFA edges
    transition_counter = 0;
    ctx.string_count = rxstr[i].string_count;
    ctx.strings = rxstr[i].strings;
    ctx.match_count = 0;
    dfa = GNUNET_REGEX_construct_dfa (rxstr[i].regex, strlen (rxstr[i].regex));
    GNUNET_REGEX_iterate_all_edges (dfa, key_iterator, &ctx);
    num_transitions = GNUNET_REGEX_get_transition_count (dfa);

    if (transition_counter < num_transitions)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Automaton has %d transitions, iterated over %d transitions\n",
                  num_transitions, transition_counter);
      error += 1;
      break;
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
                  "Doublicate initial transitions for regex %s\n",
                  rxstr[i].regex);
      error += (ctx.string_count - ctx.match_count);
    }

    GNUNET_REGEX_automaton_destroy (dfa);

    // Finish graph
    if (GNUNET_YES == ctx.should_save_graph)
    {
      fwrite (graph_end_str, strlen (graph_end_str), 1, ctx.graph_filep);
      fclose (ctx.graph_filep);
      ctx.graph_filep = NULL;
      ctx.should_save_graph = GNUNET_NO;
    }
  }


  for (i = 0; i < 10; i++)
  {
    dfa = GNUNET_REGEX_construct_dfa (rxstr[i].regex, strlen (rxstr[i].regex));
    GNUNET_REGEX_dfa_add_multi_strides (NULL, dfa, 2);
    GNUNET_REGEX_iterate_all_edges (dfa, key_iterator, &ctx);

    if (ctx.match_count < ctx.string_count)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Missing initial states for regex %s\n", rxstr[i].regex);
      error += (ctx.string_count - ctx.match_count);
    }

    GNUNET_REGEX_automaton_destroy (dfa);
  }

  error += ctx.error;

  return error;
}
