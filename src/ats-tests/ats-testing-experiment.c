/*
 This file is part of GNUnet.
 (C) 2010-2013 Christian Grothoff (and other contributing authors)

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
 * @file ats-tests/ats-testing-experiment.c
 * @brief ats benchmark: controlled experiment execution
 * @author Christian Grothoff
 * @author Matthias Wachs
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "ats-testing.h"

const char *
print_op (enum OperationType op)
{
  switch (op) {
    case START_SEND:
      return "START_SEND";
    case STOP_SEND:
      return "STOP_SEND";
    case START_PREFERENCE:
      return "START_PREFERENCE";
    case STOP_PREFERENCE:
      return "STOP_PREFERENCE";
    default:
      break;
  }
  return "";
}


static struct Experiment *
create_experiment ()
{
  struct Experiment *e;
  e = GNUNET_new (struct Experiment);
  e->name = NULL;
  e->num_masters = 0;
  e->num_slaves = 0;
  e->start = NULL;
  e->total_duration = GNUNET_TIME_UNIT_ZERO;
  return e;
}

static void
free_experiment (struct Experiment *e)
{
  struct Episode *cur;
  struct Episode *next;
  struct GNUNET_ATS_TEST_Operation *cur_o;
  struct GNUNET_ATS_TEST_Operation *next_o;

  next = e->start;
  for (cur = next; NULL != cur; cur = next)
  {
    next = cur->next;

    next_o = cur->head;
    for (cur_o = next_o; NULL != cur_o; cur_o = next_o)
    {
      next_o = cur_o->next;
      GNUNET_free (cur_o);
    }
    GNUNET_free (cur);
  }

  GNUNET_free_non_null (e->name);
  GNUNET_free_non_null (e->cfg_file);
  GNUNET_free (e);
}


static int
load_episode (struct Experiment *e,
              struct Episode *cur,
              struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_ATS_TEST_Operation *o;
  char *sec_name;
  char *op_name;
  char *op;
  char *type;
  char *pref;
  int op_counter = 0;

  fprintf (stderr, "Parsing episode %u\n",cur->id);
  GNUNET_asprintf (&sec_name, "episode-%u", cur->id);

  while (1)
  {
    /* Load operation */
    GNUNET_asprintf (&op_name, "op-%u-operation", op_counter);
    if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_string(cfg,
        sec_name, op_name, &op))
    {
      GNUNET_free (op_name);
      break;
    }
    o = GNUNET_new (struct GNUNET_ATS_TEST_Operation);
    /* operations = set_rate, start_send, stop_send, set_preference */
    if (0 == strcmp (op, "start_send"))
    {
      o->type = START_SEND;
    }
    else if (0 == strcmp (op, "stop_send"))
    {
      o->type = STOP_SEND;
    }
    else if (0 == strcmp (op, "start_preference"))
    {
      o->type = START_PREFERENCE;
    }
    else if (0 == strcmp (op, "stop_preference"))
    {
      o->type = STOP_PREFERENCE;
    }
    else
    {
      fprintf (stderr, "Invalid operation %u `%s' in episode %u\n",
          op_counter, op, cur->id);
      GNUNET_free (op);
      GNUNET_free (op_name);
      GNUNET_free (o);
      GNUNET_free (sec_name);
      return GNUNET_SYSERR;
    }
    GNUNET_free (op_name);

    /* Get source */
    GNUNET_asprintf(&op_name, "op-%u-src", op_counter);
    if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_number (cfg,
        sec_name, op_name, &o->src_id))
    {
      fprintf (stderr, "Missing src in operation %u `%s' in episode %u\n",
          op_counter, op, cur->id);
      GNUNET_free (op);
      GNUNET_free (op_name);
      GNUNET_free (o);
      GNUNET_free (sec_name);
      return GNUNET_SYSERR;
    }
    if (o->src_id > (e->num_masters - 1))
    {
      fprintf (stderr, "Invalid src %llu in operation %u `%s' in episode %u\n",
          o->src_id, op_counter, op, cur->id);
      GNUNET_free (op);
      GNUNET_free (op_name);
      GNUNET_free (o);
      GNUNET_free (sec_name);
      return GNUNET_SYSERR;
    }
    GNUNET_free (op_name);

    /* Get destination */
    GNUNET_asprintf(&op_name, "op-%u-dest", op_counter);
    if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_number (cfg,
        sec_name, op_name, &o->dest_id))
    {
      fprintf (stderr, "Missing src in operation %u `%s' in episode %u\n",
          op_counter, op, cur->id);
      GNUNET_free (op);
      GNUNET_free (op_name);
      GNUNET_free (o);
      GNUNET_free (sec_name);
      return GNUNET_SYSERR;
    }
    if (o->dest_id > (e->num_slaves - 1))
    {
      fprintf (stderr, "Invalid destination %llu in operation %u `%s' in episode %u\n",
          o->dest_id, op_counter, op, cur->id);
      GNUNET_free (op);
      GNUNET_free (op_name);
      GNUNET_free (o);
      GNUNET_free (sec_name);
      return GNUNET_SYSERR;
    }
    GNUNET_free (op_name);

    GNUNET_asprintf(&op_name, "op-%u-type", op_counter);
    if ( (GNUNET_SYSERR != GNUNET_CONFIGURATION_get_value_string(cfg,
            sec_name, op_name, &type)) &&
        ((STOP_SEND != o->type) || (STOP_PREFERENCE != o->type)))
    {
      /* Load arguments for set_rate, start_send, set_preference */
      if (0 == strcmp (type, "constant"))
      {
        o->gen_type = GNUNET_ATS_TEST_TG_CONSTANT;
      }
      else if (0 == strcmp (type, "linear"))
      {
        o->gen_type = GNUNET_ATS_TEST_TG_LINEAR;
      }
      else if (0 == strcmp (type, "sinus"))
      {
        o->gen_type = GNUNET_ATS_TEST_TG_SINUS;
      }
      else if (0 == strcmp (type, "random"))
      {
        o->gen_type = GNUNET_ATS_TEST_TG_RANDOM;
      }
      else
      {
        fprintf (stderr, "Invalid type %u `%s' in episode %u\n",
            op_counter, op, cur->id);
        GNUNET_free (type);
        GNUNET_free (op);
        GNUNET_free (op_name);
        GNUNET_free (sec_name);
        GNUNET_free (o);
        return GNUNET_SYSERR;
      }
      GNUNET_free (op_name);

      /* Get base rate */
      GNUNET_asprintf(&op_name, "op-%u-base-rate", op_counter);
      if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_number (cfg,
          sec_name, op_name, &o->base_rate))
      {
        fprintf (stderr, "Missing base rate in operation %u `%s' in episode %u\n",
            op_counter, op, cur->id);
        GNUNET_free (type);
        GNUNET_free (op);
        GNUNET_free (op_name);
        GNUNET_free (sec_name);
        GNUNET_free (o);
        return GNUNET_SYSERR;
      }
      GNUNET_free (op_name);

      /* Get max rate */
      GNUNET_asprintf(&op_name, "op-%u-max-rate", op_counter);
      if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_number (cfg,
          sec_name, op_name, &o->max_rate))
      {
        if ((GNUNET_ATS_TEST_TG_LINEAR == o->gen_type) ||
            (GNUNET_ATS_TEST_TG_RANDOM == o->gen_type) ||
            (GNUNET_ATS_TEST_TG_SINUS == o->gen_type))
        {
          fprintf (stderr, "Missing max rate in operation %u `%s' in episode %u\n",
              op_counter, op, cur->id);
          GNUNET_free (type);
          GNUNET_free (op_name);
          GNUNET_free (op);
          GNUNET_free (o);
          GNUNET_free (sec_name);
          return GNUNET_SYSERR;
        }
      }
      GNUNET_free (op_name);

      /* Get period */
      GNUNET_asprintf(&op_name, "op-%u-period", op_counter);
      if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_time (cfg,
          sec_name, op_name, &o->period))
      {
        o->period = cur->duration;
      }
      GNUNET_free (op_name);

      if (START_PREFERENCE == o->type)
      {
          /* Get frequency */
          GNUNET_asprintf(&op_name, "op-%u-frequency", op_counter);
          if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_time (cfg,
              sec_name, op_name, &o->frequency))
          {
              fprintf (stderr, "Missing frequency in operation %u `%s' in episode %u\n",
                  op_counter, op, cur->id);
              GNUNET_free (type);
              GNUNET_free (op_name);
              GNUNET_free (op);
              GNUNET_free (o);
              GNUNET_free (sec_name);
              return GNUNET_SYSERR;
          }
          GNUNET_free (op_name);

          /* Get preference */
          GNUNET_asprintf(&op_name, "op-%u-pref", op_counter);
          if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_string (cfg,
              sec_name, op_name, &pref))
          {
              fprintf (stderr, "Missing preference in operation %u `%s' in episode %u\n",
                  op_counter, op, cur->id);
              GNUNET_free (type);
              GNUNET_free (op_name);
              GNUNET_free (op);
              GNUNET_free_non_null (pref);
              GNUNET_free (o);
              GNUNET_free (sec_name);
              return GNUNET_SYSERR;
          }

          if (0 == strcmp(pref, "bandwidth"))
            o->pref_type = GNUNET_ATS_PREFERENCE_BANDWIDTH;
          else if (0 == strcmp(pref, "latency"))
            o->pref_type = GNUNET_ATS_PREFERENCE_LATENCY;
          else
          {
              fprintf (stderr, "Invalid preference in operation %u `%s' in episode %u\n",
                  op_counter, op, cur->id);
              GNUNET_free (type);
              GNUNET_free (op_name);
              GNUNET_free (op);
              GNUNET_free (pref);
              GNUNET_free_non_null (pref);
              GNUNET_free (o);
              GNUNET_free (sec_name);
              return GNUNET_SYSERR;
          }
          GNUNET_free (pref);
          GNUNET_free (op_name);
      }
    }

    /* Safety checks */
    if ((GNUNET_ATS_TEST_TG_LINEAR == o->gen_type) ||
        (GNUNET_ATS_TEST_TG_SINUS == o->gen_type))
    {
      if ((o->max_rate - o->base_rate) > o->base_rate)
      {
        /* This will cause an underflow */
        GNUNET_break (0);
      }
      fprintf (stderr, "Selected max rate and base rate cannot be used for desired traffic form!\n");
    }

    if ((START_SEND == o->type) || (START_PREFERENCE == o->type))
      fprintf (stderr, "Found operation %u in episode %u: %s [%llu]->[%llu] == %s, %llu -> %llu in %s\n",
        op_counter, cur->id, print_op (o->type), o->src_id,
        o->dest_id, (NULL != type) ? type : "",
        o->base_rate, o->max_rate,
        GNUNET_STRINGS_relative_time_to_string (o->period, GNUNET_YES));
    else
      fprintf (stderr, "Found operation %u in episode %u: %s [%llu]->[%llu]\n",
        op_counter, cur->id, print_op (o->type), o->src_id, o->dest_id);

    GNUNET_free_non_null (type);
    GNUNET_free (op);

    GNUNET_CONTAINER_DLL_insert (cur->head,cur->tail, o);
    op_counter++;
  }
  GNUNET_free (sec_name);

  return GNUNET_OK;
}


static int
load_episodes (struct Experiment *e, struct GNUNET_CONFIGURATION_Handle *cfg)
{
  int e_counter = 0;
  char *sec_name;
  struct GNUNET_TIME_Relative e_duration;
  struct Episode *cur;
  struct Episode *last;

  e_counter = 0;
  last = NULL;
  while (1)
  {
    GNUNET_asprintf(&sec_name, "episode-%u", e_counter);
    if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_time(cfg,
        sec_name, "duration", &e_duration))
    {
      GNUNET_free (sec_name);
      break;
    }

    cur = GNUNET_new (struct Episode);
    cur->duration = e_duration;
    cur->id = e_counter;

    if (GNUNET_OK != load_episode (e, cur, cfg))
    {
      GNUNET_free (sec_name);
      GNUNET_free (cur);
      return GNUNET_SYSERR;
    }

    fprintf (stderr, "Found episode %u with duration %s \n",
        e_counter,
        GNUNET_STRINGS_relative_time_to_string(cur->duration, GNUNET_YES));

    /* Update experiment */
    e->num_episodes ++;
    e->total_duration = GNUNET_TIME_relative_add(e->total_duration, cur->duration);
    /* Put in linked list */
    if (NULL == last)
      e->start = cur;
    else
    last->next = cur;

    GNUNET_free (sec_name);
    e_counter ++;
    last = cur;
  }
  return e_counter;
}

static void
timeout_experiment (void *cls, const struct GNUNET_SCHEDULER_TaskContext* tc)
{
  struct Experiment *e = cls;
  e->experiment_timeout_task = NULL;
  fprintf (stderr, "Experiment timeout!\n");

  if (NULL != e->episode_timeout_task)
  {
    GNUNET_SCHEDULER_cancel (e->episode_timeout_task);
    e->episode_timeout_task = NULL;
  }

  e->e_done_cb (e, GNUNET_TIME_absolute_get_duration(e->start_time),
      GNUNET_SYSERR);
}

static void
enforce_start_send (struct GNUNET_ATS_TEST_Operation *op)
{
  struct BenchmarkPeer *peer;
  struct BenchmarkPartner *partner;

  peer = GNUNET_ATS_TEST_get_peer (op->src_id);
  if (NULL == peer)
  {
    GNUNET_break (0);
    return;
  }

  partner = GNUNET_ATS_TEST_get_partner (op->src_id, op->dest_id);
  if (NULL == partner)
  {
    GNUNET_break (0);
    return;
  }

  fprintf (stderr, "Found master %llu slave %llu\n",op->src_id, op->dest_id);

  if (NULL != partner->tg)
  {
    fprintf (stderr, "Stopping traffic between master %llu slave %llu\n",op->src_id, op->dest_id);
    GNUNET_ATS_TEST_generate_traffic_stop(partner->tg);
    partner->tg = NULL;
  }

  partner->tg = GNUNET_ATS_TEST_generate_traffic_start(peer, partner,
      op->gen_type, op->base_rate, op->max_rate, op->period,
      GNUNET_TIME_UNIT_FOREVER_REL);
}

static void
enforce_stop_send (struct GNUNET_ATS_TEST_Operation *op)
{
  struct BenchmarkPartner *p;
  p = GNUNET_ATS_TEST_get_partner (op->src_id, op->dest_id);
  if (NULL == p)
  {
    GNUNET_break (0);
    return;
  }

  fprintf (stderr, "Found master %llu slave %llu\n",op->src_id, op->dest_id);

  if (NULL != p->tg)
  {
    fprintf (stderr, "Stopping traffic between master %llu slave %llu\n",
        op->src_id, op->dest_id);
    GNUNET_ATS_TEST_generate_traffic_stop(p->tg);
    p->tg = NULL;
  }
}


static void
enforce_start_preference (struct GNUNET_ATS_TEST_Operation *op)
{
  struct BenchmarkPeer *peer;
  struct BenchmarkPartner *partner;

  peer = GNUNET_ATS_TEST_get_peer (op->src_id);
  if (NULL == peer)
  {
    GNUNET_break (0);
    return;
  }

  partner = GNUNET_ATS_TEST_get_partner (op->src_id, op->dest_id);
  if (NULL == partner)
  {
    GNUNET_break (0);
    return;
  }

  fprintf (stderr, "Found master %llu slave %llu\n",op->src_id, op->dest_id);

  if (NULL != partner->pg)
  {
    fprintf (stderr, "Stopping traffic between master %llu slave %llu\n",
        op->src_id, op->dest_id);
    GNUNET_ATS_TEST_generate_preferences_stop(partner->pg);
    partner->pg = NULL;
  }

  partner->pg = GNUNET_ATS_TEST_generate_preferences_start(peer, partner,
      op->gen_type, op->base_rate, op->max_rate, op->period, op->frequency,
      op->pref_type);
}

static void
enforce_stop_preference (struct GNUNET_ATS_TEST_Operation *op)
{
  struct BenchmarkPartner *p;
  p = GNUNET_ATS_TEST_get_partner (op->src_id, op->dest_id);
  if (NULL == p)
  {
    GNUNET_break (0);
    return;
  }

  fprintf (stderr, "Found master %llu slave %llu\n",op->src_id, op->dest_id);

  if (NULL != p->pg)
  {
    fprintf (stderr, "Stopping preference between master %llu slave %llu\n",
        op->src_id, op->dest_id);
    GNUNET_ATS_TEST_generate_preferences_stop (p->pg);
    p->pg = NULL;
  }
}

static void enforce_episode (struct Episode *ep)
{
  struct GNUNET_ATS_TEST_Operation *cur;
  for (cur = ep->head; NULL != cur; cur = cur->next)
  {

    fprintf (stderr, "Enforcing operation: %s [%llu]->[%llu] == %llu\n",
        print_op (cur->type), cur->src_id, cur->dest_id, cur->base_rate);
    switch (cur->type) {
      case START_SEND:
        enforce_start_send (cur);
        break;
      case STOP_SEND:
        enforce_stop_send (cur);
        break;
      case START_PREFERENCE:
        enforce_start_preference (cur);
        break;
      case STOP_PREFERENCE:
        enforce_stop_preference (cur);
        break;
      default:
        break;
    }
  }
}

static void
timeout_episode (void *cls, const struct GNUNET_SCHEDULER_TaskContext* tc)
{
  struct Experiment *e = cls;
  e->episode_timeout_task = NULL;
  if (NULL != e->ep_done_cb)
    e->ep_done_cb (e->cur);

  /* Scheduling next */
  e->cur = e->cur->next;
  if (NULL == e->cur)
  {
    /* done */
    fprintf (stderr, "Last episode done!\n");
    if (NULL != e->experiment_timeout_task)
    {
      GNUNET_SCHEDULER_cancel (e->experiment_timeout_task);
      e->experiment_timeout_task = NULL;
    }
    e->e_done_cb (e, GNUNET_TIME_absolute_get_duration(e->start_time), GNUNET_OK);
    return;
  }

  fprintf (stderr, "Running episode %u with timeout %s\n",
      e->cur->id,
      GNUNET_STRINGS_relative_time_to_string(e->cur->duration, GNUNET_YES));
  enforce_episode(e->cur);

  e->episode_timeout_task = GNUNET_SCHEDULER_add_delayed (e->cur->duration,
      &timeout_episode, e);
}


void
GNUNET_ATS_TEST_experimentation_run (struct Experiment *e,
    GNUNET_ATS_TESTING_EpisodeDoneCallback ep_done_cb,
    GNUNET_ATS_TESTING_ExperimentDoneCallback e_done_cb)
{
  fprintf (stderr, "Running experiment `%s'  with timeout %s\n", e->name,
      GNUNET_STRINGS_relative_time_to_string(e->max_duration, GNUNET_YES));
  e->e_done_cb = e_done_cb;
  e->ep_done_cb = ep_done_cb;
  e->start_time = GNUNET_TIME_absolute_get();

  /* Start total time out */
  e->experiment_timeout_task = GNUNET_SCHEDULER_add_delayed (e->max_duration,
      &timeout_experiment, e);

  /* Start */
  e->cur = e->start;
  fprintf (stderr, "Running episode %u with timeout %s\n",
      e->cur->id,
      GNUNET_STRINGS_relative_time_to_string(e->cur->duration, GNUNET_YES));
  enforce_episode(e->cur);
  e->episode_timeout_task = GNUNET_SCHEDULER_add_delayed (e->cur->duration,
      &timeout_episode, e);


}


struct Experiment *
GNUNET_ATS_TEST_experimentation_load (char *filename)
{
  struct Experiment *e;
  struct GNUNET_CONFIGURATION_Handle *cfg;
  e = NULL;

  cfg = GNUNET_CONFIGURATION_create();
  if (GNUNET_SYSERR == GNUNET_CONFIGURATION_load (cfg, filename))
  {
    fprintf (stderr, "Failed to load `%s'\n", filename);
    GNUNET_CONFIGURATION_destroy (cfg);
    return NULL;
  }

  e = create_experiment ();

  if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_string(cfg, "experiment",
      "name", &e->name))
  {
    fprintf (stderr, "Invalid %s", "name");
    free_experiment (e);
    return NULL;
  }
  else
    fprintf (stderr, "Experiment name: `%s'\n", e->name);

  if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_filename (cfg, "experiment",
      "cfg_file", &e->cfg_file))
  {
    fprintf (stderr, "Invalid %s", "cfg_file");
    free_experiment (e);
    return NULL;
  }
  else
    fprintf (stderr, "Experiment name: `%s'\n", e->cfg_file);

  if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_number(cfg, "experiment",
      "masters", &e->num_masters))
  {
    fprintf (stderr, "Invalid %s", "masters");
    free_experiment (e);
    return NULL;
  }
  else
    fprintf (stderr, "Experiment masters: `%llu'\n",
        e->num_masters);

  if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_number(cfg, "experiment",
      "slaves", &e->num_slaves))
  {
    fprintf (stderr, "Invalid %s", "slaves");
    free_experiment (e);
    return NULL;
  }
  else
    fprintf (stderr, "Experiment slaves: `%llu'\n",
        e->num_slaves);

  if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_time(cfg, "experiment",
      "log_freq", &e->log_freq))
  {
    fprintf (stderr, "Invalid %s", "log_freq");
    free_experiment (e);
    return NULL;
  }
  else
    fprintf (stderr, "Experiment logging frequency: `%s'\n",
        GNUNET_STRINGS_relative_time_to_string (e->log_freq, GNUNET_YES));

  if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_time(cfg, "experiment",
      "max_duration", &e->max_duration))
  {
    fprintf (stderr, "Invalid %s", "max_duration");
    free_experiment (e);
    return NULL;
  }
  else
    fprintf (stderr, "Experiment duration: `%s'\n",
        GNUNET_STRINGS_relative_time_to_string (e->max_duration, GNUNET_YES));

  load_episodes (e, cfg);
  fprintf (stderr, "Loaded %u episodes with total duration %s\n",
      e->num_episodes,
      GNUNET_STRINGS_relative_time_to_string (e->total_duration, GNUNET_YES));

  GNUNET_CONFIGURATION_destroy (cfg);
  return e;
}

void
GNUNET_ATS_TEST_experimentation_stop (struct Experiment *e)
{
  if (NULL != e->experiment_timeout_task)
  {
    GNUNET_SCHEDULER_cancel (e->experiment_timeout_task);
    e->experiment_timeout_task = NULL;
  }
  if (NULL != e->episode_timeout_task)
  {
    GNUNET_SCHEDULER_cancel (e->episode_timeout_task);
    e->episode_timeout_task = NULL;
  }
  free_experiment (e);
}

/* end of file ats-testing-experiment.c*/

