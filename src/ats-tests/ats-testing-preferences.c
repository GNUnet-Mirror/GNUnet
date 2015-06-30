/*
 This file is part of GNUnet.
 Copyright (C) 2010-2013 Christian Grothoff (and other contributing authors)

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
 * @file ats-tests/ats-testing-preferences.c
 * @brief ats benchmark: preference generator
 * @author Christian Grothoff
 * @author Matthias Wachs
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "ats-testing.h"

static struct PreferenceGenerator *pg_head;
static struct PreferenceGenerator *pg_tail;

extern struct GNUNET_ATS_TEST_Topology *top;

static double
get_preference (struct PreferenceGenerator *pg)
{
  struct GNUNET_TIME_Relative time_delta;
  double delta_value;
  double pref_value;

  /* Calculate the current preference value */
  switch (pg->type) {
    case GNUNET_ATS_TEST_TG_CONSTANT:
      pref_value = pg->base_value;
      break;
    case GNUNET_ATS_TEST_TG_LINEAR:
      time_delta = GNUNET_TIME_absolute_get_duration(pg->time_start);
      /* Calculate point of time in the current period */
      time_delta.rel_value_us = time_delta.rel_value_us %
          pg->duration_period.rel_value_us;
      delta_value = ((double) time_delta.rel_value_us  /
          pg->duration_period.rel_value_us) * (pg->max_value - pg->base_value);
      if ((pg->max_value < pg->base_value) &&
          ((pg->max_value - pg->base_value) > pg->base_value))
      {
        /* This will cause an underflow */
        GNUNET_break (0);
      }
      pref_value = pg->base_value + delta_value;
      break;
    case GNUNET_ATS_TEST_TG_RANDOM:
      delta_value =  (double) GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
          10000 * (pg->max_value - pg->base_value)) / 10000;
      pref_value = pg->base_value + delta_value;
      break;
    case GNUNET_ATS_TEST_TG_SINUS:
      time_delta = GNUNET_TIME_absolute_get_duration(pg->time_start);
      /* Calculate point of time in the current period */
      time_delta.rel_value_us = time_delta.rel_value_us %
          pg->duration_period.rel_value_us;
      if ((pg->max_value - pg->base_value) > pg->base_value)
      {
        /* This will cause an underflow for second half of sinus period,
         * will be detected in general when experiments are loaded */
        GNUNET_break (0);
      }
      delta_value = (pg->max_value - pg->base_value) *
          sin ( (2 * M_PI) / ((double) pg->duration_period.rel_value_us) *
              time_delta.rel_value_us);
      pref_value = pg->base_value + delta_value;
      break;
    default:
      pref_value = 0.0;
      break;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Current preference value is %f\n",
      pref_value);
  return pref_value;
}


static void
set_pref_task (void *cls,
                    const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct BenchmarkPartner *p = cls;
  double pref_value;
  p->pg->set_task = NULL;

  pref_value = get_preference (p->pg);

  GNUNET_log(GNUNET_ERROR_TYPE_INFO,
      "Setting preference for master [%u] and slave [%u] for %s to %f\n",
      p->me->no, p->dest->no,
      GNUNET_ATS_print_preference_type (p->pg->kind), pref_value);

  GNUNET_ATS_performance_change_preference(p->me->ats_perf_handle,
                                           &p->dest->id,
                                           p->pg->kind,
                                           pref_value,
                                           GNUNET_ATS_PREFERENCE_END);

  switch (p->pg->kind) {
    case GNUNET_ATS_PREFERENCE_BANDWIDTH:
      p->pref_bandwidth = pref_value;
      break;
    case GNUNET_ATS_PREFERENCE_LATENCY:
      p->pref_delay = pref_value;
      break;
    default:
      break;
  }

  p->pg->set_task = GNUNET_SCHEDULER_add_delayed (p->pg->frequency,
      set_pref_task, p);

}


/**
 * Generate between the source master and the partner and set preferences with a
 * value depending on the generator.
 *
 * @param src source
 * @param dest partner
 * @param type type of preferences to generate
 * @param base_value traffic base rate to send data with
 * @param value_rate  traffic maximum rate to send data with
 * @param period duration of a period of preferences generation (~ 1/frequency)
 * @param frequency how long to generate preferences
 * @param kind ATS preference to generate
 * @return the preference generator
 */
struct PreferenceGenerator *
GNUNET_ATS_TEST_generate_preferences_start (struct BenchmarkPeer *src,
    struct BenchmarkPartner *dest,
    enum GeneratorType type,
    long int base_value,
    long int value_rate,
    struct GNUNET_TIME_Relative period,
    struct GNUNET_TIME_Relative frequency,
    enum GNUNET_ATS_PreferenceKind kind)
{
  struct PreferenceGenerator *pg;

  if (NULL != dest->pg)
  {
    GNUNET_break (0);
    return NULL;
  }

  pg = GNUNET_new (struct PreferenceGenerator);
  GNUNET_CONTAINER_DLL_insert (pg_head, pg_tail, pg);
  pg->type = type;
  pg->src = src;
  pg->dest = dest;
  pg->kind = kind;
  pg->base_value = base_value;
  pg->max_value = value_rate;
  pg->duration_period = period;
  pg->frequency = frequency;
  pg->time_start = GNUNET_TIME_absolute_get();

  switch (type) {
    case GNUNET_ATS_TEST_TG_CONSTANT:
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
          "Setting up constant preference generator master[%u] `%s' and slave [%u] `%s' max %u Bips\n",
          dest->me->no, GNUNET_i2s (&dest->me->id),
          dest->dest->no, GNUNET_i2s (&dest->dest->id),
          base_value);
      break;
    case GNUNET_ATS_TEST_TG_LINEAR:
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
          "Setting up linear preference generator master[%u] `%s' and slave [%u] `%s' min %u Bips max %u Bips\n",
          dest->me->no, GNUNET_i2s (&dest->me->id),
          dest->dest->no, GNUNET_i2s (&dest->dest->id),
          base_value, value_rate);
      break;
    case GNUNET_ATS_TEST_TG_SINUS:
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
          "Setting up sinus preference generator master[%u] `%s' and slave [%u] `%s' baserate %u Bips, amplitude %u Bps\n",
          dest->me->no, GNUNET_i2s (&dest->me->id),
          dest->dest->no, GNUNET_i2s (&dest->dest->id),
          base_value, value_rate);
      break;
    case GNUNET_ATS_TEST_TG_RANDOM:
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
          "Setting up random preference generator master[%u] `%s' and slave [%u] `%s' min %u Bips max %u Bps\n",
          dest->me->no, GNUNET_i2s (&dest->me->id),
          dest->dest->no, GNUNET_i2s (&dest->dest->id),
          base_value, value_rate);
      break;
    default:
      break;
  }

  dest->pg = pg;
  pg->set_task = GNUNET_SCHEDULER_add_now (&set_pref_task, dest);
  return pg;
}


void
GNUNET_ATS_TEST_generate_preferences_stop (struct PreferenceGenerator *pg)
{
  GNUNET_CONTAINER_DLL_remove (pg_head, pg_tail, pg);
  pg->dest->pg = NULL;

  if (NULL != pg->set_task)
  {
    GNUNET_SCHEDULER_cancel (pg->set_task);
    pg->set_task = NULL;
  }

  GNUNET_free (pg);
}


/**
 * Stop all preferences generators
 */
void
GNUNET_ATS_TEST_generate_preferences_stop_all ()
{
  struct PreferenceGenerator *cur;
  struct PreferenceGenerator *next;
  next = pg_head;
  for (cur = next; NULL != cur; cur = next)
  {
      next = cur->next;
      GNUNET_ATS_TEST_generate_preferences_stop(cur);
  }
}

/* end of file ats-testing-preferences.c */
