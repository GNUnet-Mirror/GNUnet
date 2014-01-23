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

  next = e->start;
  for (cur = next; NULL != cur; cur = next)
  {
    next = cur->next;
    GNUNET_free (cur);
  }

  GNUNET_free_non_null (e->name);
  GNUNET_free_non_null (e->cfg_file);
  GNUNET_free (e);
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
  e->experiment_timeout_task = GNUNET_SCHEDULER_NO_TASK;
  fprintf (stderr, "Experiment timeout!\n");

  e->e_done_cb (e, GNUNET_SYSERR);
}

static void
timeout_episode (void *cls, const struct GNUNET_SCHEDULER_TaskContext* tc)
{
  struct Experiment *e = cls;
  e->episode_timeout_task = GNUNET_SCHEDULER_NO_TASK;
  e->ep_done_cb (e->cur);

  /* Scheduling next */
  e->cur = e->cur->next;
  if (NULL == e->cur)
  {
    /* done */
    fprintf (stderr, "Last episode done!\n");
    if (GNUNET_SCHEDULER_NO_TASK != e->experiment_timeout_task)
    {
      GNUNET_SCHEDULER_cancel (e->experiment_timeout_task);
      e->experiment_timeout_task = GNUNET_SCHEDULER_NO_TASK;
    }
    e->e_done_cb (e, GNUNET_OK);
    return;
  }

  fprintf (stderr, "Running episode %u with timeout %s\n",
      e->cur->id,
      GNUNET_STRINGS_relative_time_to_string(e->cur->duration, GNUNET_YES));
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

  /* Start total time out */
  e->experiment_timeout_task = GNUNET_SCHEDULER_add_delayed (e->max_duration,
      &timeout_experiment, e);

  /* Start */
  e->cur = e->start;
  fprintf (stderr, "Running episode %u with timeout %s\n",
      e->cur->id,
      GNUNET_STRINGS_relative_time_to_string(e->cur->duration, GNUNET_YES));
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
  if (GNUNET_SCHEDULER_NO_TASK != e->experiment_timeout_task)
  {
    GNUNET_SCHEDULER_cancel (e->experiment_timeout_task);
    e->experiment_timeout_task = GNUNET_SCHEDULER_NO_TASK;
  }
  free_experiment (e);
}

/* end of file ats-testing-experiment.c*/

