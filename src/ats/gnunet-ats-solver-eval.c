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
#include "gnunet-ats-solver-eval.h"

#define BIG_M_STRING "unlimited"

static struct Experiment *e;

static struct LoggingHandle *l;

static struct SolverHandle *sh;

static struct TestPeer *peer_head;
static struct TestPeer *peer_tail;

/**
 * cmd option -e: experiment file
 */
static char *opt_exp_file;

static char *opt_solver;

/**
 * cmd option -l: enable logging
 */
static int opt_log;

/**
 * cmd option -p: enable plots
 */
static int opt_plot;

/**
 * cmd option -v: verbose logs
 */
static int opt_verbose;

/**
 * cmd option -p: print logs
 */
static int opt_print;

static int res;

static void
end_now ();

static char *
print_generator_type (enum GeneratorType g)
{
  switch (g) {
    case GNUNET_ATS_TEST_TG_CONSTANT:
      return "CONSTANT";
    case GNUNET_ATS_TEST_TG_LINEAR:
      return "LINEAR";
    case GNUNET_ATS_TEST_TG_RANDOM:
      return "RANDOM";
    case GNUNET_ATS_TEST_TG_SINUS:
      return "SINUS";
    default:
      return "INVALID";
      break;
  }
}

struct AddressLookupCtx
{
  struct ATS_Address *res;
  char *plugin;
  char *addr;
};


int find_address_it (void *cls,
                     const struct GNUNET_PeerIdentity *key,
                     void *value)
{
  struct AddressLookupCtx *ctx = cls;
  struct ATS_Address *addr = value;

  if ( (0 == strcmp (ctx->plugin, addr->plugin)) &&
       (0 == strcmp (ctx->addr, addr->addr)) )
  {
       ctx->res = addr;
       return GNUNET_NO;
  }
  return GNUNET_YES;
}

static struct TestPeer *
find_peer_by_id (int id)
{
  struct TestPeer *cur;
  for (cur = peer_head; NULL != cur; cur = cur->next)
    if (cur->id == id)
      return cur;
  return NULL;
}

static struct TestAddress *
find_address_by_id (struct TestPeer *peer, int aid)
{
  struct TestAddress *cur;
  for (cur = peer->addr_head; NULL != cur; cur = cur->next)
    if (cur->aid == aid)
      return cur;
  return NULL;
}



/**
 * Logging
 */

void
GNUNET_ATS_solver_logging_now (struct LoggingHandle *l)
{
  struct LoggingTimeStep *lts;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Logging\n");

  lts = GNUNET_new (struct LoggingTimeStep);
  lts->timestamp = GNUNET_TIME_absolute_get();

  /* Store logging data here */

  GNUNET_CONTAINER_DLL_insert_tail(l->head, l->tail, lts);

}

static void
logging_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct LoggingHandle *l = cls;
  l->logging_task = GNUNET_SCHEDULER_NO_TASK;

  GNUNET_ATS_solver_logging_now (l);

  l->logging_task = GNUNET_SCHEDULER_add_delayed (l->log_freq, &logging_task, l);

}

struct LoggingHandle *
GNUNET_ATS_solver_logging_start (struct GNUNET_TIME_Relative freq)
{
  struct LoggingHandle *l;
  l = GNUNET_new (struct LoggingHandle);

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Start logging every  %s\n",
      GNUNET_STRINGS_relative_time_to_string(freq, GNUNET_NO));

  /* Iterate over peers */

  l->log_freq = freq;
  l->logging_task = GNUNET_SCHEDULER_add_now (&logging_task, l);

  return l;
}

void
GNUNET_ATS_solver_logging_stop (struct LoggingHandle *l)
{
  if (GNUNET_SCHEDULER_NO_TASK != l->logging_task)
    GNUNET_SCHEDULER_cancel (l->logging_task);

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Stop logging\n");

  l->logging_task = GNUNET_SCHEDULER_NO_TASK;
}

void
GNUNET_ATS_solver_logging_eval (struct LoggingHandle *l)
{
  struct LoggingTimeStep *lts;

  for (lts = l->head; NULL != lts; lts = lts->next)
  {
    fprintf (stderr, "Log %llu: \n", (long long unsigned int) lts->timestamp.abs_value_us);
  }
}

void
GNUNET_ATS_solver_logging_free (struct LoggingHandle *l)
{
  struct LoggingTimeStep *cur;
  struct LoggingTimeStep *next;

  if (GNUNET_SCHEDULER_NO_TASK != l->logging_task)
    GNUNET_SCHEDULER_cancel (l->logging_task);
  l->logging_task = GNUNET_SCHEDULER_NO_TASK;

  next = l->head;
  while (NULL != (cur = next))
  {
    next = cur->next;
    GNUNET_CONTAINER_DLL_remove (l->head, l->tail, cur);
    GNUNET_free (cur);
  }

  GNUNET_free (l);
}

/**
 * Property Generators
 */

static struct PropertyGenerator *prop_gen_head;
static struct PropertyGenerator *prop_gen_tail;

static double
get_property (struct PropertyGenerator *pg)
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
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Current property value is %f\n",
      pref_value);
  return pref_value;
}


static void
set_prop_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct PropertyGenerator *pg = cls;
  double pref_value;
  struct GNUNET_ATS_Information atsi;

  pg->set_task = GNUNET_SCHEDULER_NO_TASK;

  if (GNUNET_NO == GNUNET_CONTAINER_multipeermap_contains_value (sh->addresses,
      &pg->test_peer->peer_id, pg->test_address->ats_addr))
  {
    GNUNET_break (0);
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
        "Setting property generation for unknown address [%u:%u]\n",
        pg->peer, pg->address_id);
    return;
  }

  pref_value = get_property (pg);

  GNUNET_log(GNUNET_ERROR_TYPE_INFO,
      "Setting property for peer [%u] address [%u] for %s to %f\n",
      pg->peer, pg->address_id,
      GNUNET_ATS_print_property_type (pg->ats_property), pref_value);


  atsi.type = htonl (pg->ats_property);
  atsi.value = htonl ((uint32_t) pref_value);

  /* set performance here! */
  sh->env.sf.s_bulk_start (sh->solver);
  GAS_normalization_normalize_property (sh->addresses,
      pg->test_address->ats_addr, &atsi, 1);
  sh->env.sf.s_bulk_stop (sh->solver);

  switch (pg->ats_property) {
    case GNUNET_ATS_PREFERENCE_BANDWIDTH:
      //p->pref_bandwidth = pref_value;
      break;
    case GNUNET_ATS_PREFERENCE_LATENCY:
      //p->pref_delay = pref_value;
      break;
    default:
      break;
  }

  pg->set_task = GNUNET_SCHEDULER_add_delayed (pg->frequency,
      &set_prop_task, pg);

}

static struct PropertyGenerator *
find_prop_gen (unsigned int peer, unsigned int address,
    uint32_t ats_property)
{
  struct PropertyGenerator *cur;
  for (cur = prop_gen_head; NULL != cur; cur = cur->next)
    if ((cur->peer == peer) && (cur->address_id == address) &&
        (cur->ats_property == ats_property))
      return cur;
  return NULL;
}

void
GNUNET_ATS_solver_generate_property_stop (struct PropertyGenerator *pg)
{
  GNUNET_CONTAINER_DLL_remove (prop_gen_head, prop_gen_tail, pg);

  if (GNUNET_SCHEDULER_NO_TASK != pg->set_task)
  {
    GNUNET_SCHEDULER_cancel (pg->set_task);
    pg->set_task = GNUNET_SCHEDULER_NO_TASK;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
      "Removing old up preference generator peer [%u] address [%u] `%s'\n",
      pg->peer, pg->address_id,
      GNUNET_ATS_print_property_type(pg->ats_property));

  GNUNET_free (pg);
}


/**
 * Generate between the source master and the partner and set property with a
 * value depending on the generator.
 *
 * @param peer source
 * @param address_id partner
 * @param test_peer the peer
 * @param test_address the address
 * @param type type of generator
 * @param base_value base value
 * @param value_rate maximum value
 * @param period duration of a period of generation (~ 1/frequency)
 * @param frequency how long to generate property
 * @param ats_property ATS property to generate
 * @return the property generator
 */
struct PropertyGenerator *
GNUNET_ATS_solver_generate_property_start (unsigned int peer,
    unsigned int address_id,
    struct TestPeer *test_peer,
    struct TestAddress *test_address,
    enum GeneratorType type,
    long int base_value,
    long int value_rate,
    struct GNUNET_TIME_Relative period,
    struct GNUNET_TIME_Relative frequency,
    uint32_t ats_property)
{
  struct PropertyGenerator *pg;

  pg = GNUNET_new (struct PropertyGenerator);
  GNUNET_CONTAINER_DLL_insert (prop_gen_head, prop_gen_tail, pg);
  pg->type = type;
  pg->peer = peer;
  pg->test_address = test_address;
  pg->test_peer = test_peer;
  pg->address_id = address_id;
  pg->ats_property = ats_property;
  pg->base_value = base_value;
  pg->max_value = value_rate;
  pg->duration_period = period;
  pg->frequency = frequency;
  pg->time_start = GNUNET_TIME_absolute_get();

  switch (type) {
    case GNUNET_ATS_TEST_TG_CONSTANT:
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
          "Setting up %s property generator peer [%u] address [%u] `%s'"\
          "max %u Bips\n",
          print_generator_type(type), pg->peer, pg->address_id,
          GNUNET_ATS_print_property_type (ats_property),
          base_value);
      break;
    case GNUNET_ATS_TEST_TG_LINEAR:
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
          "Setting up %s property generator peer [%u] address [%u] `%s' " \
          "min %u Bips max %u Bips\n",
          print_generator_type(type), pg->peer, pg->address_id,
          GNUNET_ATS_print_property_type(ats_property),
          base_value, value_rate);
      break;
    case GNUNET_ATS_TEST_TG_SINUS:
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
          "Setting up %s property generator peer [%u] address [%u] `%s' "\
          "baserate %u Bips, amplitude %u Bps\n",
          print_generator_type(type), pg->peer, pg->address_id,
          GNUNET_ATS_print_property_type(ats_property),
          base_value, value_rate);
      break;
    case GNUNET_ATS_TEST_TG_RANDOM:
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
          "Setting up %s property generator peer [%u] address [%u] `%s' "\
          "min %u Bips max %u Bps\n",
          print_generator_type(type), pg->peer, pg->address_id,
          GNUNET_ATS_print_property_type(ats_property),
          base_value, value_rate);
      break;
    default:
      break;
  }

  pg->set_task = GNUNET_SCHEDULER_add_now (&set_prop_task, pg);
  return pg;
}



/**
 * Stop all preferences generators
 */
void
GNUNET_ATS_solver_generate_property_stop_all ()
{
  struct PropertyGenerator *cur;
  struct PropertyGenerator *next;
  next = prop_gen_head;
  for (cur = next; NULL != cur; cur = next)
  {
      next = cur->next;
      GNUNET_ATS_solver_generate_property_stop (cur);
  }
}


/**
 * Preference Generators
 */

static struct PreferenceGenerator *pref_gen_head;
static struct PreferenceGenerator *pref_gen_tail;

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
  struct PreferenceGenerator *pg = cls;
  struct TestPeer *p;
  double pref_value;
  pg->set_task = GNUNET_SCHEDULER_NO_TASK;

  if (NULL == (p = find_peer_by_id (pg->peer)))
  {
    GNUNET_break (0);
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
        "Setting preference for unknown peer %u\n", pg->peer);
    return;
  }

  pref_value = get_preference (pg);

  GNUNET_log(GNUNET_ERROR_TYPE_INFO,
      "Setting preference for peer [%u] address [%u] for client %p pref %s to %f\n",
      pg->peer, pg->address_id, NULL + (pg->client_id),
      GNUNET_ATS_print_preference_type (pg->kind), pref_value);

  sh->env.sf.s_bulk_start (sh->solver);
  GAS_normalization_normalize_preference (NULL + (pg->client_id), &p->peer_id,
      pg->kind, pref_value);
  sh->env.sf.s_bulk_stop (sh->solver);

  switch (pg->kind) {
    case GNUNET_ATS_PREFERENCE_BANDWIDTH:
      //p->pref_bandwidth = pref_value;
      break;
    case GNUNET_ATS_PREFERENCE_LATENCY:
      //p->pref_delay = pref_value;
      break;
    default:
      break;
  }

  pg->set_task = GNUNET_SCHEDULER_add_delayed (pg->frequency,
      set_pref_task, pg);

}

static struct PreferenceGenerator *
find_pref_gen (unsigned int peer, unsigned int address,
    enum GNUNET_ATS_PreferenceKind kind)
{
  struct PreferenceGenerator *cur;
  for (cur = pref_gen_head; NULL != cur; cur = cur->next)
    if ((cur->peer == peer) && (cur->address_id == address) && (cur->kind == kind))
      return cur;
  return NULL;
}

void
GNUNET_ATS_solver_generate_preferences_stop (struct PreferenceGenerator *pg)
{
  GNUNET_CONTAINER_DLL_remove (pref_gen_head, pref_gen_tail, pg);

  if (GNUNET_SCHEDULER_NO_TASK != pg->set_task)
  {
    GNUNET_SCHEDULER_cancel (pg->set_task);
    pg->set_task = GNUNET_SCHEDULER_NO_TASK;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
      "Removing old up preference generator peer [%u] address [%u] `%s'\n",
      pg->peer, pg->address_id, GNUNET_ATS_print_preference_type(pg->kind));

  GNUNET_free (pg);
}


/**
 * Generate between the source master and the partner and set property with a
 * value depending on the generator.
 *
 * @param peer source
 * @param address_id partner
 * @param client_id the client
 * @param type type of generator
 * @param base_value base value
 * @param value_rate maximum value
 * @param period duration of a period of generation (~ 1/frequency)
 * @param frequency how long to generate property
 * @param kind ATS preference to generate
 * @return the preference generator
 */
struct PreferenceGenerator *
GNUNET_ATS_solver_generate_preferences_start (unsigned int peer,
    unsigned int address_id,
    unsigned int client_id,
    enum GeneratorType type,
    long int base_value,
    long int value_rate,
    struct GNUNET_TIME_Relative period,
    struct GNUNET_TIME_Relative frequency,
    enum GNUNET_ATS_PreferenceKind kind)
{
  struct PreferenceGenerator *pg;

  pg = GNUNET_new (struct PreferenceGenerator);
  GNUNET_CONTAINER_DLL_insert (pref_gen_head, pref_gen_tail, pg);
  pg->type = type;
  pg->peer = peer;
  pg->address_id = address_id;
  pg->client_id = client_id;
  pg->kind = kind;
  pg->base_value = base_value;
  pg->max_value = value_rate;
  pg->duration_period = period;
  pg->frequency = frequency;
  pg->time_start = GNUNET_TIME_absolute_get();

  switch (type) {
    case GNUNET_ATS_TEST_TG_CONSTANT:
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
          "Setting up %s preference generator peer [%u] address [%u] `%s' max %u Bips\n",
          print_generator_type (type), pg->peer, pg->address_id,
          GNUNET_ATS_print_preference_type(kind),
          base_value);
      break;
    case GNUNET_ATS_TEST_TG_LINEAR:
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
          "Setting up %s preference generator peer [%u] address [%u] `%s' min %u Bips max %u Bips\n",
          print_generator_type (type), pg->peer, pg->address_id, GNUNET_ATS_print_preference_type(kind),
          base_value, value_rate);
      break;
    case GNUNET_ATS_TEST_TG_SINUS:
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
          "Setting up %s preference generator peer [%u] address [%u] `%s' baserate %u Bips, amplitude %u Bps\n",
          print_generator_type (type), pg->peer, pg->address_id, GNUNET_ATS_print_preference_type(kind),
          base_value, value_rate);
      break;
    case GNUNET_ATS_TEST_TG_RANDOM:
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
          "Setting up %s preference generator peer [%u] address [%u] `%s' min %u Bips max %u Bps\n",
          print_generator_type (type), pg->peer, pg->address_id, GNUNET_ATS_print_preference_type(kind),
          base_value, value_rate);
      break;
    default:
      break;
  }

  pg->set_task = GNUNET_SCHEDULER_add_now (&set_pref_task, pg);
  return pg;
}



/**
 * Stop all preferences generators
 */
void
GNUNET_ATS_solver_generate_preferences_stop_all ()
{
  struct PreferenceGenerator *cur;
  struct PreferenceGenerator *next;
  next = pref_gen_head;
  for (cur = next; NULL != cur; cur = next)
  {
      next = cur->next;
      GNUNET_ATS_solver_generate_preferences_stop(cur);
  }
}



/**
 * Experiments
 */

const char *
print_op (enum OperationType op)
{
  switch (op) {
    case SOLVER_OP_ADD_ADDRESS:
      return "ADD_ADDRESS";
    case SOLVER_OP_DEL_ADDRESS:
      return "DEL_ADDRESS";
    case SOLVER_OP_START_SET_PREFERENCE:
      return "START_SET_PREFERENCE";
    case SOLVER_OP_STOP_SET_PREFERENCE:
      return "STOP_STOP_PREFERENCE";
    case SOLVER_OP_START_SET_PROPERTY:
      return "START_SET_PROPERTY";
    case SOLVER_OP_STOP_SET_PROPERTY:
      return "STOP_SET_PROPERTY";
    case SOLVER_OP_START_REQUEST:
      return "START_REQUEST";
    case SOLVER_OP_STOP_REQUEST:
      return "STOP_REQUEST";
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
      GNUNET_free_non_null (cur_o->address);
      GNUNET_free_non_null (cur_o->plugin);
      GNUNET_free (cur_o);
    }
    GNUNET_free (cur);
  }

  GNUNET_free_non_null (e->name);
  GNUNET_free_non_null (e->cfg_file);
  GNUNET_free (e);
}


static int
load_op_add_address (struct GNUNET_ATS_TEST_Operation *o,
    struct Episode *e,
    int op_counter,
    char *sec_name,
    const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  char *op_name;

  /* peer id */
  GNUNET_asprintf(&op_name, "op-%u-peer-id", op_counter);
  if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_number (cfg,
      sec_name, op_name, &o->peer_id))
  {
    fprintf (stderr, "Missing peer-id in operation %u `%s' in episode `%s'\n",
        op_counter, "ADD_ADDRESS", op_name);
    GNUNET_free (op_name);
    return GNUNET_SYSERR;
  }
  GNUNET_free (op_name);

  /* address id */
  GNUNET_asprintf(&op_name, "op-%u-address-id", op_counter);
  if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_number (cfg,
      sec_name, op_name, &o->address_id))
  {
    fprintf (stderr, "Missing address-id in operation %u `%s' in episode `%s'\n",
        op_counter, "ADD_ADDRESS", op_name);
    GNUNET_free (op_name);
    return GNUNET_SYSERR;
  }
  GNUNET_free (op_name);

  /* plugin */
  GNUNET_asprintf(&op_name, "op-%u-plugin", op_counter);
  if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_string (cfg,
      sec_name, op_name, &o->plugin))
  {
    fprintf (stderr, "Missing plugin in operation %u `%s' in episode `%s'\n",
        op_counter, "ADD_ADDRESS", op_name);
    GNUNET_free (op_name);
    return GNUNET_SYSERR;
  }
  GNUNET_free (op_name);

  /* address  */
  GNUNET_asprintf(&op_name, "op-%u-address", op_counter);
  if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_string (cfg,
      sec_name, op_name, &o->address))
  {
    fprintf (stderr, "Missing address in operation %u `%s' in episode `%s'\n",
        op_counter, "ADD_ADDRESS", op_name);
    GNUNET_free (op_name);
    return GNUNET_SYSERR;
  }
  GNUNET_free (op_name);

  /* session */
  GNUNET_asprintf(&op_name, "op-%u-address-session", op_counter);
  if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_number (cfg,
      sec_name, op_name, &o->address_session))
  {
    fprintf (stderr, "Missing address-session in operation %u `%s' in episode `%s'\n",
        op_counter, "ADD_ADDRESS", op_name);
    GNUNET_free (op_name);
    return GNUNET_SYSERR;
  }
  GNUNET_free (op_name);

  /* network */
  GNUNET_asprintf(&op_name, "op-%u-address-network", op_counter);
  if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_number (cfg,
      sec_name, op_name, &o->address_network))
  {
    fprintf (stderr, "Missing address-network in operation %u `%s' in episode `%s'\n",
        op_counter, "ADD_ADDRESS", op_name);
    GNUNET_free (op_name);
    return GNUNET_SYSERR;
  }
  GNUNET_free (op_name);

  fprintf (stderr,
      "Found operation %s: [%llu:%llu] address `%s' plugin `%s' \n",
      "ADD_ADDRESS", o->peer_id, o->address_id, o->address, o->plugin);

  return GNUNET_OK;
}

static int
load_op_del_address (struct GNUNET_ATS_TEST_Operation *o,
    struct Episode *e,
    int op_counter,
    char *sec_name,
    const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  char *op_name;

  /* peer id */
  GNUNET_asprintf(&op_name, "op-%u-peer-id", op_counter);
  if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_number (cfg,
      sec_name, op_name, &o->peer_id))
  {
    fprintf (stderr, "Missing peer-id in operation %u `%s' in episode `%s'\n",
        op_counter, "DEL_ADDRESS", op_name);
    GNUNET_free (op_name);
    return GNUNET_SYSERR;
  }
  GNUNET_free (op_name);

  /* address id */
  GNUNET_asprintf(&op_name, "op-%u-address-id", op_counter);
  if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_number (cfg,
      sec_name, op_name, &o->address_id))
  {
    fprintf (stderr, "Missing address-id in operation %u `%s' in episode `%s'\n",
        op_counter, "DEL_ADDRESS", op_name);
    GNUNET_free (op_name);
    return GNUNET_SYSERR;
  }
  GNUNET_free (op_name);

  /* plugin */
  GNUNET_asprintf(&op_name, "op-%u-plugin", op_counter);
  if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_string (cfg,
      sec_name, op_name, &o->plugin))
  {
    fprintf (stderr, "Missing plugin in operation %u `%s' in episode `%s'\n",
        op_counter, "DEL_ADDRESS", op_name);
    GNUNET_free (op_name);
    return GNUNET_SYSERR;
  }
  GNUNET_free (op_name);

  /* address  */
  GNUNET_asprintf(&op_name, "op-%u-address", op_counter);
  if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_string (cfg,
      sec_name, op_name, &o->address))
  {
    fprintf (stderr, "Missing address in operation %u `%s' in episode `%s'\n",
        op_counter, "DEL_ADDRESS", op_name);
    GNUNET_free (op_name);
    return GNUNET_SYSERR;
  }
  GNUNET_free (op_name);

  /* session */
  GNUNET_asprintf(&op_name, "op-%u-address-session", op_counter);
  if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_number (cfg,
      sec_name, op_name, &o->address_session))
  {
    fprintf (stderr, "Missing address-session in operation %u `%s' in episode `%s'\n",
        op_counter, "DEL_ADDRESS", op_name);
    GNUNET_free (op_name);
    return GNUNET_SYSERR;
  }
  GNUNET_free (op_name);

  /* network */
  GNUNET_asprintf(&op_name, "op-%u-address-network", op_counter);
  if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_number (cfg,
      sec_name, op_name, &o->address_network))
  {
    fprintf (stderr, "Missing address-network in operation %u `%s' in episode `%s'\n",
        op_counter, "DEL_ADDRESS", op_name);
    GNUNET_free (op_name);
    return GNUNET_SYSERR;
  }
  GNUNET_free (op_name);

  fprintf (stderr,
      "Found operation %s: [%llu:%llu] address `%s' plugin `%s' \n",
      "DEL_ADDRESS", o->peer_id, o->address_id, o->address, o->plugin);

  return GNUNET_OK;
}

static enum GNUNET_ATS_Property
parse_preference_string (const char * str)
{
  int c = 0;
  char *props[GNUNET_ATS_PreferenceCount] = GNUNET_ATS_PreferenceTypeString;

  for (c = 0; c < GNUNET_ATS_PreferenceCount; c++)
    if (0 == strcmp(str, props[c]))
      return c;
  return 0;
};

static int
load_op_start_set_preference (struct GNUNET_ATS_TEST_Operation *o,
    struct Episode *e,
    int op_counter,
    char *sec_name,
    const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  char *op_name;
  char *type;
  char *pref;

  /* peer id */
  GNUNET_asprintf(&op_name, "op-%u-peer-id", op_counter);
  if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_number (cfg,
      sec_name, op_name, &o->peer_id))
  {
    fprintf (stderr, "Missing peer-id in operation %u  `%s' in episode `%s'\n",
        op_counter, "START_SET_PREFERENCE", op_name);
    GNUNET_free (op_name);
    return GNUNET_SYSERR;
  }
  GNUNET_free (op_name);

  /* address id */
  GNUNET_asprintf(&op_name, "op-%u-address-id", op_counter);
  if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_number (cfg,
      sec_name, op_name, &o->address_id))
  {
    fprintf (stderr, "Missing address-id in operation %u `%s' in episode `%s'\n",
        op_counter, "START_SET_PREFERENCE", op_name);
    GNUNET_free (op_name);
    return GNUNET_SYSERR;
  }
  GNUNET_free (op_name);

  /* address id */
  GNUNET_asprintf(&op_name, "op-%u-client-id", op_counter);
  if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_number (cfg,
      sec_name, op_name, &o->client_id))
  {
    fprintf (stderr, "Missing client-id in operation %u `%s' in episode `%s'\n",
        op_counter, "START_SET_PREFERENCE", op_name);
    GNUNET_free (op_name);
    return GNUNET_SYSERR;
  }
  GNUNET_free (op_name);

  /* generator */
  GNUNET_asprintf(&op_name, "op-%u-gen-type", op_counter);
  if ( (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_string(cfg,
          sec_name, op_name, &type)) )
  {
    fprintf (stderr, "Missing type in operation %u `%s' in episode `%s'\n",
        op_counter, "START_SET_PREFERENCE", op_name);
    GNUNET_free (op_name);
    return GNUNET_SYSERR;
  }

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
    fprintf (stderr, "Invalid generator type %u `%s' in episode %u\n",
        op_counter, op_name, e->id);
    GNUNET_free (type);
    GNUNET_free (op_name);
    return GNUNET_SYSERR;
  }
  GNUNET_free (type);
  GNUNET_free (op_name);


  /* Get base rate */
  GNUNET_asprintf(&op_name, "op-%u-base-rate", op_counter);
  if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_number (cfg,
      sec_name, op_name, &o->base_rate))
  {
    fprintf (stderr, "Missing base rate in operation %u `%s' in episode %u\n",
        op_counter, op_name, e->id);
    GNUNET_free (op_name);
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
          op_counter, op_name, e->id);
      GNUNET_free (op_name);
      return GNUNET_SYSERR;
    }
  }
  GNUNET_free (op_name);

  /* Get period */
  GNUNET_asprintf(&op_name, "op-%u-period", op_counter);
  if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_time (cfg,
      sec_name, op_name, &o->period))
  {
    o->period = e->duration;
  }
  GNUNET_free (op_name);

  /* Get frequency */
  GNUNET_asprintf(&op_name, "op-%u-frequency", op_counter);
  if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_time (cfg,
      sec_name, op_name, &o->frequency))
  {
      fprintf (stderr, "Missing frequency in operation %u `%s' in episode %u\n",
          op_counter, op_name, e->id);
      GNUNET_free (op_name);
      return GNUNET_SYSERR;
  }
  GNUNET_free (op_name);

  /* Get preference */
  GNUNET_asprintf(&op_name, "op-%u-pref", op_counter);
  if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_string (cfg,
      sec_name, op_name, &pref))
  {
      fprintf (stderr, "Missing preference in operation %u `%s' in episode %u\n",
          op_counter, op_name, e->id);
      GNUNET_free (op_name);
      return GNUNET_SYSERR;
  }

  if (0 == (o->pref_type = parse_preference_string(pref)))
  {
      fprintf (stderr, "Invalid preference in operation %u `%s' in episode %u\n",
          op_counter, op_name, e->id);
      GNUNET_free (op_name);
      GNUNET_free (pref);
      return GNUNET_SYSERR;
  }
  GNUNET_free (pref);
  GNUNET_free (op_name);

  fprintf (stderr,
      "Found operation %s: [%llu:%llu]: %s = %llu\n",
      "START_SET_PREFERENCE", o->peer_id, o->address_id,
      GNUNET_ATS_print_preference_type(o->pref_type), o->base_rate);

  return GNUNET_OK;
}

static int
load_op_stop_set_preference (struct GNUNET_ATS_TEST_Operation *o,
    struct Episode *e,
    int op_counter,
    char *sec_name,
    const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  char *op_name;
  char *pref;

  /* peer id */
  GNUNET_asprintf(&op_name, "op-%u-peer-id", op_counter);
  if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_number (cfg,
      sec_name, op_name, &o->peer_id))
  {
    fprintf (stderr, "Missing peer-id in operation %u  `%s' in episode `%s'\n",
        op_counter, "STOP_SET_PREFERENCE", op_name);
    GNUNET_free (op_name);
    return GNUNET_SYSERR;
  }
  GNUNET_free (op_name);

  /* address id */
  GNUNET_asprintf(&op_name, "op-%u-address-id", op_counter);
  if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_number (cfg,
      sec_name, op_name, &o->address_id))
  {
    fprintf (stderr, "Missing address-id in operation %u `%s' in episode `%s'\n",
        op_counter, "STOP_SET_PREFERENCE", op_name);
    GNUNET_free (op_name);
    return GNUNET_SYSERR;
  }
  GNUNET_free (op_name);

  /* Get preference */
  GNUNET_asprintf(&op_name, "op-%u-pref", op_counter);
  if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_string (cfg,
      sec_name, op_name, &pref))
  {
    fprintf (stderr, "Missing preference in operation %u `%s' in episode `%s'\n",
        op_counter, "STOP_SET_PREFERENCE", op_name);
      GNUNET_free (op_name);
      return GNUNET_SYSERR;
  }

  if (0 == (o->pref_type = parse_preference_string(pref)))
  {
      fprintf (stderr, "Invalid preference in operation %u `%s' in episode %u\n",
          op_counter, op_name, e->id);
      GNUNET_free (op_name);
      GNUNET_free (pref);
      return GNUNET_SYSERR;
  }
  GNUNET_free (pref);
  GNUNET_free (op_name);

  fprintf (stderr,
      "Found operation %s: [%llu:%llu]: %s\n",
      "STOP_SET_PREFERENCE", o->peer_id, o->address_id,
      GNUNET_ATS_print_preference_type(o->pref_type));
  return GNUNET_OK;
}

static enum GNUNET_ATS_Property
parse_property_string (const char * str)
{
  int c = 0;
  char *props[GNUNET_ATS_PropertyCount] = GNUNET_ATS_PropertyStrings;

  for (c = 0; c < GNUNET_ATS_PropertyCount; c++)
    if (0 == strcmp(str, props[c]))
      return c;
  return 0;
};

static int
load_op_start_set_property(struct GNUNET_ATS_TEST_Operation *o,
    struct Episode *e,
    int op_counter,
    char *sec_name,
    const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  char *op_name;
  char *type;
  char *prop;

  /* peer id */
  GNUNET_asprintf(&op_name, "op-%u-peer-id", op_counter);
  if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_number (cfg,
      sec_name, op_name, &o->peer_id))
  {
    fprintf (stderr, "Missing peer-id in operation %u  `%s' in episode `%s'\n",
        op_counter, "START_SET_PROPERTY", op_name);
    GNUNET_free (op_name);
    return GNUNET_SYSERR;
  }
  GNUNET_free (op_name);

  /* address id */
  GNUNET_asprintf(&op_name, "op-%u-address-id", op_counter);
  if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_number (cfg,
      sec_name, op_name, &o->address_id))
  {
    fprintf (stderr, "Missing address-id in operation %u `%s' in episode `%s'\n",
        op_counter, "START_SET_PROPERTY", op_name);
    GNUNET_free (op_name);
    return GNUNET_SYSERR;
  }
  GNUNET_free (op_name);

  /* generator */
  GNUNET_asprintf(&op_name, "op-%u-gen-type", op_counter);
  if ( (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_string(cfg,
          sec_name, op_name, &type)) )
  {
    fprintf (stderr, "Missing type in operation %u `%s' in episode `%s'\n",
        op_counter, "START_SET_PROPERTY", op_name);
    GNUNET_free (op_name);
    return GNUNET_SYSERR;
  }

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
    fprintf (stderr, "Invalid generator type %u `%s' in episode %u\n",
        op_counter, op_name, e->id);
    GNUNET_free (type);
    GNUNET_free (op_name);
    return GNUNET_SYSERR;
  }
  GNUNET_free (type);
  GNUNET_free (op_name);


  /* Get base rate */
  GNUNET_asprintf(&op_name, "op-%u-base-rate", op_counter);
  if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_number (cfg,
      sec_name, op_name, &o->base_rate))
  {
    fprintf (stderr, "Missing base rate in operation %u `%s' in episode %u\n",
        op_counter, op_name, e->id);
    GNUNET_free (op_name);
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
          op_counter, op_name, e->id);
      GNUNET_free (op_name);
      return GNUNET_SYSERR;
    }
  }
  GNUNET_free (op_name);

  /* Get period */
  GNUNET_asprintf(&op_name, "op-%u-period", op_counter);
  if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_time (cfg,
      sec_name, op_name, &o->period))
  {
    o->period = e->duration;
  }
  GNUNET_free (op_name);

  /* Get frequency */
  GNUNET_asprintf(&op_name, "op-%u-frequency", op_counter);
  if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_time (cfg,
      sec_name, op_name, &o->frequency))
  {
      fprintf (stderr, "Missing frequency in operation %u `%s' in episode %u\n",
          op_counter, op_name, e->id);
      GNUNET_free (op_name);
      return GNUNET_SYSERR;
  }
  GNUNET_free (op_name);

  /* Get preference */
  GNUNET_asprintf(&op_name, "op-%u-property", op_counter);
  if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_string (cfg,
      sec_name, op_name, &prop))
  {
      fprintf (stderr, "Missing property in operation %u `%s' in episode %u\n",
          op_counter, op_name, e->id);
      GNUNET_free (op_name);
      GNUNET_free_non_null (prop);
      return GNUNET_SYSERR;
  }

  if (0 == (o->prop_type = parse_property_string(prop)))
  {
      fprintf (stderr, "Invalid property in operation %u `%s' in episode %u\n",
          op_counter, op_name, e->id);
      GNUNET_free (op_name);
      GNUNET_free (prop);
      return GNUNET_SYSERR;
  }

  GNUNET_free (prop);
  GNUNET_free (op_name);

  fprintf (stderr,
      "Found operation %s: [%llu:%llu] %s = %llu\n",
      "START_SET_PROPERTY", o->peer_id, o->address_id,
      GNUNET_ATS_print_property_type (o->prop_type), o->base_rate);

  return GNUNET_OK;
}

static int
load_op_stop_set_property (struct GNUNET_ATS_TEST_Operation *o,
    struct Episode *e,
    int op_counter,
    char *sec_name,
    const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  char *op_name;
  char *pref;

  /* peer id */
  GNUNET_asprintf(&op_name, "op-%u-peer-id", op_counter);
  if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_number (cfg,
      sec_name, op_name, &o->peer_id))
  {
    fprintf (stderr, "Missing peer-id in operation %u  `%s' in episode `%s'\n",
        op_counter, "STOP_SET_PROPERTY", op_name);
    GNUNET_free (op_name);
    return GNUNET_SYSERR;
  }
  GNUNET_free (op_name);

  /* address id */
  GNUNET_asprintf(&op_name, "op-%u-address-id", op_counter);
  if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_number (cfg,
      sec_name, op_name, &o->address_id))
  {
    fprintf (stderr, "Missing address-id in operation %u `%s' in episode `%s'\n",
        op_counter, "STOP_SET_PROPERTY", op_name);
    GNUNET_free (op_name);
    return GNUNET_SYSERR;
  }
  GNUNET_free (op_name);

  /* Get property */
  GNUNET_asprintf(&op_name, "op-%u-property", op_counter);
  if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_string (cfg,
      sec_name, op_name, &pref))
  {
    fprintf (stderr, "Missing property in operation %u `%s' in episode `%s'\n",
        op_counter, "STOP_SET_PROPERTY", op_name);
      GNUNET_free (op_name);
      GNUNET_free_non_null (pref);
      return GNUNET_SYSERR;
  }

  if (0 == (o->prop_type = parse_property_string(pref)))
  {
      fprintf (stderr, "Invalid property in operation %u `%s' in episode %u\n",
          op_counter, op_name, e->id);
      GNUNET_free (op_name);
      GNUNET_free_non_null (pref);
      return GNUNET_SYSERR;
  }

  GNUNET_free (pref);
  GNUNET_free (op_name);

  fprintf (stderr,
      "Found operation %s: [%llu:%llu] %s\n",
      "STOP_SET_PROPERTY", o->peer_id, o->address_id,
      GNUNET_ATS_print_property_type (o->prop_type));

  return GNUNET_OK;
}


static int
load_op_start_request (struct GNUNET_ATS_TEST_Operation *o,
    struct Episode *e,
    int op_counter,
    char *sec_name,
    const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  char *op_name;

  /* peer id */
  GNUNET_asprintf(&op_name, "op-%u-peer-id", op_counter);
  if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_number (cfg,
      sec_name, op_name, &o->peer_id))
  {
    fprintf (stderr, "Missing peer-id in operation %u  `%s' in episode `%s'\n",
        op_counter, "START_REQUEST", op_name);
    GNUNET_free (op_name);
    return GNUNET_SYSERR;
  }
  GNUNET_free (op_name);
  return GNUNET_OK;
}

static int
load_op_stop_request (struct GNUNET_ATS_TEST_Operation *o,
    struct Episode *e,
    int op_counter,
    char *sec_name,
    const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  char *op_name;

  /* peer id */
  GNUNET_asprintf(&op_name, "op-%u-peer-id", op_counter);
  if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_number (cfg,
      sec_name, op_name, &o->peer_id))
  {
    fprintf (stderr, "Missing peer-id in operation %u  `%s' in episode `%s'\n",
        op_counter, "STOP_REQUEST", op_name);
    GNUNET_free (op_name);
    return GNUNET_SYSERR;
  }
  GNUNET_free (op_name);
  return GNUNET_OK;
}


static int
load_episode (struct Experiment *e, struct Episode *cur,
    struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_ATS_TEST_Operation *o;
  char *sec_name;
  char *op_name;
  char *op;
  int op_counter = 0;
  int res;
  fprintf (stderr, "Parsing episode %u\n",cur->id);
  GNUNET_asprintf(&sec_name, "episode-%u", cur->id);

  while (1)
  {
    /* Load operation */
    GNUNET_asprintf(&op_name, "op-%u-operation", op_counter);
    if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_string(cfg,
        sec_name, op_name, &op))
    {
      GNUNET_free (op_name);
      break;
    }
    o = GNUNET_new (struct GNUNET_ATS_TEST_Operation);
    /* operations = set_rate, start_send, stop_send, set_preference */
    if (0 == strcmp (op, "address_add"))
    {
      o->type = SOLVER_OP_ADD_ADDRESS;
      res = load_op_add_address (o, cur,
          op_counter, sec_name, cfg);
    }
    else if (0 == strcmp (op, "address_del"))
    {
      o->type = SOLVER_OP_DEL_ADDRESS;
      res = load_op_del_address (o, cur,
          op_counter, sec_name, cfg);
    }
    else if (0 == strcmp (op, "start_set_property"))
    {
      o->type = SOLVER_OP_START_SET_PROPERTY;
      res = load_op_start_set_property (o, cur,
          op_counter, sec_name, cfg);
    }
    else if (0 == strcmp (op, "stop_set_property"))
    {
      o->type = SOLVER_OP_STOP_SET_PROPERTY;
      res = load_op_stop_set_property (o, cur,
          op_counter, sec_name, cfg);
    }
    else if (0 == strcmp (op, "start_set_preference"))
    {
      o->type = SOLVER_OP_START_SET_PREFERENCE;
      res =  load_op_start_set_preference (o, cur,
          op_counter, sec_name, cfg);
    }
    else if (0 == strcmp (op, "stop_set_preference"))
    {
      o->type = SOLVER_OP_STOP_SET_PREFERENCE;
      res =  load_op_stop_set_preference (o, cur,
          op_counter, sec_name, cfg);
    }
    else if (0 == strcmp (op, "start_request"))
    {
      o->type = SOLVER_OP_START_REQUEST;
      res = load_op_start_request (o, cur,
          op_counter, sec_name, cfg);
    }
    else if (0 == strcmp (op, "stop_request"))
    {
      o->type = SOLVER_OP_STOP_REQUEST;
      res = load_op_stop_request(o, cur,
          op_counter, sec_name, cfg);
    }
    else
    {
      fprintf (stderr, "Invalid operation %u `%s' in episode %u\n",
          op_counter, op, cur->id);
      res = GNUNET_SYSERR;
    }

    GNUNET_free (op);
    GNUNET_free (op_name);

    if (GNUNET_SYSERR == res)
    {
      GNUNET_free (o);
      GNUNET_free (sec_name);
      return GNUNET_SYSERR;
    }

    GNUNET_CONTAINER_DLL_insert_tail (cur->head,cur->tail, o);
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
      fprintf (stderr, "Missing duration in episode %u \n",e_counter);
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
  e->experiment_timeout_task = GNUNET_SCHEDULER_NO_TASK;
  fprintf (stderr, "Experiment timeout!\n");

  if (GNUNET_SCHEDULER_NO_TASK != e->episode_timeout_task)
  {
    GNUNET_SCHEDULER_cancel (e->episode_timeout_task);
    e->episode_timeout_task = GNUNET_SCHEDULER_NO_TASK;
  }

  e->e_done_cb (e, GNUNET_TIME_absolute_get_duration(e->start_time),
      GNUNET_SYSERR);
}

struct ATS_Address *
create_ats_address (const struct GNUNET_PeerIdentity *peer,
                const char *plugin_name,
                const void *plugin_addr, size_t plugin_addr_len,
                uint32_t session_id)
{
  struct ATS_Address *aa = NULL;

  aa = GNUNET_malloc (sizeof (struct ATS_Address) + plugin_addr_len + strlen (plugin_name) + 1);
  aa->peer = *peer;
  aa->addr_len = plugin_addr_len;
  aa->addr = &aa[1];
  aa->plugin = (char *) &aa[1] + plugin_addr_len;
  memcpy (&aa[1], plugin_addr, plugin_addr_len);
  memcpy (aa->plugin, plugin_name, strlen (plugin_name) + 1);
  aa->session_id = session_id;
  aa->active = GNUNET_NO;
  aa->used = GNUNET_NO;
  aa->solver_information = NULL;
  aa->assigned_bw_in = GNUNET_BANDWIDTH_value_init(0);
  aa->assigned_bw_out = GNUNET_BANDWIDTH_value_init(0);
  return aa;
}



static void
enforce_add_address (struct GNUNET_ATS_TEST_Operation *op)
{
  struct TestPeer *p;
  struct TestAddress *a;

  if (NULL == (p = find_peer_by_id (op->peer_id)))
  {
    p = GNUNET_new (struct TestPeer);
    p->id = op->peer_id;
    memset (&p->peer_id, op->peer_id, sizeof (p->peer_id));
    GNUNET_CONTAINER_DLL_insert (peer_head, peer_tail, p);
  }

  if (NULL != (find_address_by_id (p, op->address_id)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Duplicate address %u for peer %u\n",
        op->address_id, op->peer_id);
    return;
  }

  a = GNUNET_new (struct TestAddress);
  a->aid = op->address_id;
  a->ats_addr = create_ats_address (&p->peer_id, op->plugin, op->address,
      strlen (op->address) + 1, op->address_session);
  memset (&p->peer_id, op->peer_id, sizeof (p->peer_id));
  GNUNET_CONTAINER_DLL_insert (p->addr_head, p->addr_tail, a);

  GNUNET_CONTAINER_multipeermap_put (sh->addresses, &p->peer_id, a->ats_addr,
    GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Adding address %u for peer %u\n",
    op->address_id, op->peer_id);

  sh->env.sf.s_add (sh->solver, a->ats_addr, op->address_network);

}


static void
enforce_del_address (struct GNUNET_ATS_TEST_Operation *op)
{
  struct TestPeer *p;
  struct AddressLookupCtx ctx;

  if (NULL == (p = find_peer_by_id (op->peer_id)))
  {
    GNUNET_break (0);
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
        "Deleting address for unknown peer %u\n", op->peer_id);
    return;
  }

  ctx.plugin = op->plugin;
  ctx.addr = op->address;
  ctx.res = NULL;
  GNUNET_CONTAINER_multipeermap_get_multiple (sh->addresses, &p->peer_id,
      find_address_it, &ctx);
  if (NULL == ctx.res)
  {
    GNUNET_break (0);
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
        "Deleting unknown address for peer %u\n", op->peer_id);
    return;
  }

  if (NULL == (find_address_by_id (p, op->address_id)))
  {
    GNUNET_break (0);
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
        "Deleting address for unknown peer %u\n", op->peer_id);
    return;
  }

  GNUNET_CONTAINER_multipeermap_remove (sh->addresses, &p->peer_id, ctx.res);

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Removing address %u for peer %u\n",
      op->address_id, op->peer_id);

  sh->env.sf.s_del (sh->solver, ctx.res, GNUNET_NO);
  GNUNET_free (ctx.res);

}

static void
enforce_start_property (struct GNUNET_ATS_TEST_Operation *op)
{
  struct PropertyGenerator *pg;
  struct TestPeer *p;
  struct TestAddress *a;

  if (NULL != (pg = find_prop_gen (op->peer_id, op->address_id, op->prop_type)))
  {
    GNUNET_ATS_solver_generate_property_stop (pg);
    GNUNET_free (pg);
  }

  if (NULL == (p = find_peer_by_id (op->peer_id)))
  {
    GNUNET_break (0);
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
        "Starting property generation for unknown peer %u\n", op->peer_id);
    return;
  }

  if (NULL == (a = find_address_by_id (p, op->address_id)))
  {
    GNUNET_break (0);
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
        "Setting property for unknown address %u\n", op->peer_id);
    return;
  }

  GNUNET_ATS_solver_generate_property_start (op->peer_id,
    op->address_id,
    p, a,
    op->gen_type,
    op->base_rate,
    op->max_rate,
    op->period,
    op->frequency,
    op->prop_type);
}

static void
enforce_stop_property (struct GNUNET_ATS_TEST_Operation *op)
{
  struct PropertyGenerator *pg = find_prop_gen(op->peer_id, op->address_id,
      op->prop_type);
  if (NULL != pg)
      GNUNET_ATS_solver_generate_property_stop (pg);
}

static void
enforce_start_preference (struct GNUNET_ATS_TEST_Operation *op)
{
  struct PreferenceGenerator *pg;
  if (NULL != (pg = find_pref_gen (op->peer_id, op->address_id, op->pref_type)))
  {
    GNUNET_ATS_solver_generate_preferences_stop (pg);
    GNUNET_free (pg);
  }

  if (NULL == (find_peer_by_id (op->peer_id)))
  {
    GNUNET_break (0);
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
        "Starting preference generation for unknown peer %u\n", op->peer_id);
    return;
  }

  GNUNET_ATS_solver_generate_preferences_start (op->peer_id,
    op->address_id,
    op->client_id,
    op->gen_type,
    op->base_rate,
    op->max_rate,
    op->period,
    op->frequency,
    op->pref_type);
}

static void
enforce_stop_preference (struct GNUNET_ATS_TEST_Operation *op)
{
  struct PreferenceGenerator *pg = find_pref_gen(op->peer_id, op->address_id,
      op->pref_type);
  if (NULL != pg)
      GNUNET_ATS_solver_generate_preferences_stop (pg);
}


static void
enforce_start_request (struct GNUNET_ATS_TEST_Operation *op)
{
  struct TestPeer *p;
  const struct ATS_Address *res;

  if (NULL == (p = find_peer_by_id (op->peer_id)))
  {
    GNUNET_break (0);
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
        "Requesting address for unknown peer %u\n", op->peer_id);
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Requesting address for peer %u\n",
      op->peer_id);

  res = sh->env.sf.s_get (sh->solver, &p->peer_id);
  if (NULL != res)
  {

  }

}

static void
enforce_stop_request (struct GNUNET_ATS_TEST_Operation *op)
{
  struct TestPeer *p;

  if (NULL == (p = find_peer_by_id (op->peer_id)))
  {
    GNUNET_break (0);
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
        "Requesting address for unknown peer %u\n", op->peer_id);
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Stop requesting address for peer %u\n",
      op->peer_id);

  sh->env.sf.s_get_stop (sh->solver, &p->peer_id);
}

static void enforce_episode (struct Episode *ep)
{
  struct GNUNET_ATS_TEST_Operation *cur;
  for (cur = ep->head; NULL != cur; cur = cur->next)
  {
    switch (cur->type) {
      case SOLVER_OP_ADD_ADDRESS:
        fprintf (stderr, "Enforcing operation: %s [%llu:%llu]\n",
            print_op (cur->type), cur->peer_id, cur->address_id);
        enforce_add_address (cur);
        break;
      case SOLVER_OP_DEL_ADDRESS:
        fprintf (stderr, "Enforcing operation: %s [%llu:%llu]\n",
            print_op (cur->type), cur->peer_id, cur->address_id);
        enforce_del_address (cur);
        break;
      case SOLVER_OP_START_SET_PROPERTY:
        fprintf (stderr, "Enforcing operation: %s [%llu:%llu] == %llu\n",
            print_op (cur->type), cur->peer_id, cur->address_id, cur->base_rate);
        enforce_start_property (cur);
        break;
      case SOLVER_OP_STOP_SET_PROPERTY:
        fprintf (stderr, "Enforcing operation: %s [%llu:%llu] == %llu\n",
            print_op (cur->type), cur->peer_id, cur->address_id, cur->base_rate);
        enforce_stop_property (cur);
        break;
      case SOLVER_OP_START_SET_PREFERENCE:
        fprintf (stderr, "Enforcing operation: %s [%llu:%llu] == %llu\n",
            print_op (cur->type), cur->peer_id, cur->address_id, cur->base_rate);
        enforce_start_preference (cur);
        break;
      case SOLVER_OP_STOP_SET_PREFERENCE:
        fprintf (stderr, "Enforcing operation: %s [%llu:%llu] == %llu\n",
            print_op (cur->type), cur->peer_id, cur->address_id, cur->base_rate);
        enforce_stop_preference (cur);
        break;
      case SOLVER_OP_START_REQUEST:
        fprintf (stderr, "Enforcing operation: %s [%llu]\n",
            print_op (cur->type), cur->peer_id);
        enforce_start_request (cur);
        break;
      case SOLVER_OP_STOP_REQUEST:
        fprintf (stderr, "Enforcing operation: %s [%llu]\n",
            print_op (cur->type), cur->peer_id);
        enforce_stop_request (cur);
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
  e->episode_timeout_task = GNUNET_SCHEDULER_NO_TASK;
  if (NULL != e->ep_done_cb)
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
    e->e_done_cb (e, GNUNET_TIME_absolute_get_duration(e->start_time), GNUNET_OK);
    return;
  }

  fprintf (stderr, "Running episode %u with timeout %s\n",
      e->cur->id,
      GNUNET_STRINGS_relative_time_to_string(e->cur->duration, GNUNET_YES));
  e->episode_timeout_task = GNUNET_SCHEDULER_add_delayed (e->cur->duration,
      &timeout_episode, e);
  enforce_episode(e->cur);


}


void
GNUNET_ATS_solvers_experimentation_run (struct Experiment *e,
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
  if (NULL == e->start)
  {
    GNUNET_break (0);
    return;
  }
  e->cur = e->start;
  fprintf (stderr, "Running episode %u with timeout %s\n",
      e->cur->id,
      GNUNET_STRINGS_relative_time_to_string(e->cur->duration, GNUNET_YES));
  e->episode_timeout_task = GNUNET_SCHEDULER_add_delayed (e->cur->duration,
      &timeout_episode, e);
  enforce_episode(e->cur);

}

void
GNUNET_ATS_solvers_experimentation_stop (struct Experiment *e)
{
  if (GNUNET_SCHEDULER_NO_TASK != e->experiment_timeout_task)
  {
    GNUNET_SCHEDULER_cancel (e->experiment_timeout_task);
    e->experiment_timeout_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (GNUNET_SCHEDULER_NO_TASK != e->episode_timeout_task)
  {
    GNUNET_SCHEDULER_cancel (e->episode_timeout_task);
    e->episode_timeout_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (NULL != e->cfg)
  {
    GNUNET_CONFIGURATION_destroy(e->cfg);
    e->cfg = NULL;
  }
  free_experiment (e);
}


struct Experiment *
GNUNET_ATS_solvers_experimentation_load (char *filename)
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
  {
    fprintf (stderr, "Experiment configuration: `%s'\n", e->cfg_file);
    e->cfg = GNUNET_CONFIGURATION_create();
    if (GNUNET_SYSERR == GNUNET_CONFIGURATION_load (e->cfg, e->cfg_file))
    {
      fprintf (stderr, "Invalid configuration %s", "cfg_file");
      free_experiment (e);
      return NULL;
    }

  }

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

  if (GNUNET_SYSERR == load_episodes (e, cfg))
  {
    GNUNET_ATS_solvers_experimentation_stop (e);
    GNUNET_CONFIGURATION_destroy (cfg);
    e = NULL;
    fprintf (stderr, "Failed to load experiment\n");
    return NULL;
  }
  fprintf (stderr, "Loaded %u episodes with total duration %s\n",
      e->num_episodes,
      GNUNET_STRINGS_relative_time_to_string (e->total_duration, GNUNET_YES));

  GNUNET_CONFIGURATION_destroy (cfg);
  return e;
}



/**
 * Solver
 */

static int
free_all_it (void *cls,
    const struct GNUNET_PeerIdentity *key,
    void *value)
{
  struct ATS_Address *address = value;
  GNUNET_break (GNUNET_OK == GNUNET_CONTAINER_multipeermap_remove (sh->env.addresses,
      key, value));
  GNUNET_free (address);

  return GNUNET_OK;
}

void
GNUNET_ATS_solvers_solver_stop (struct SolverHandle *sh)
{
 GNUNET_STATISTICS_destroy ((struct GNUNET_STATISTICS_Handle *) sh->env.stats,
     GNUNET_NO);
 GNUNET_PLUGIN_unload (sh->plugin, sh->solver);
 GNUNET_CONTAINER_multipeermap_iterate (sh->addresses, &free_all_it, NULL);
 GNUNET_CONTAINER_multipeermap_destroy(sh->addresses);
 GNUNET_free (sh->plugin);
 GNUNET_free (sh);
}

/**
 * Load quotas for networks from configuration
 *
 * @param cfg configuration handle
 * @param out_dest where to write outbound quotas
 * @param in_dest where to write inbound quotas
 * @param dest_length length of inbound and outbound arrays
 * @return number of networks loaded
 */
unsigned int
GNUNET_ATS_solvers_load_quotas (const struct GNUNET_CONFIGURATION_Handle *cfg,
                                                 unsigned long long *out_dest,
                                                 unsigned long long *in_dest,
                                                 int dest_length)
{
  char *network_str[GNUNET_ATS_NetworkTypeCount] = GNUNET_ATS_NetworkTypeString;
  char * entry_in = NULL;
  char * entry_out = NULL;
  char * quota_out_str;
  char * quota_in_str;
  int c;
  int res;

  for (c = 0; (c < GNUNET_ATS_NetworkTypeCount) && (c < dest_length); c++)
  {
    in_dest[c] = 0;
    out_dest[c] = 0;
    GNUNET_asprintf (&entry_out, "%s_QUOTA_OUT", network_str[c]);
    GNUNET_asprintf (&entry_in, "%s_QUOTA_IN", network_str[c]);

    /* quota out */
    if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_string(cfg, "ats", entry_out, &quota_out_str))
    {
      res = GNUNET_NO;
      if (0 == strcmp(quota_out_str, BIG_M_STRING))
      {
        out_dest[c] = GNUNET_ATS_MaxBandwidth;
        res = GNUNET_YES;
      }
      if ((GNUNET_NO == res) && (GNUNET_OK == GNUNET_STRINGS_fancy_size_to_bytes (quota_out_str, &out_dest[c])))
        res = GNUNET_YES;
      if ((GNUNET_NO == res) && (GNUNET_OK == GNUNET_CONFIGURATION_get_value_number (cfg, "ats", entry_out,  &out_dest[c])))
         res = GNUNET_YES;

      if (GNUNET_NO == res)
      {
          GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("Could not load quota for network `%s':  `%s', assigning default bandwidth %llu\n"),
              network_str[c], quota_out_str, GNUNET_ATS_DefaultBandwidth);
          out_dest[c] = GNUNET_ATS_DefaultBandwidth;
      }
      else
      {
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, _("Outbound quota configure for network `%s' is %llu\n"),
              network_str[c], out_dest[c]);
      }
      GNUNET_free (quota_out_str);
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING, _("No outbound quota configured for network `%s', assigning default bandwidth %llu\n"),
          network_str[c], GNUNET_ATS_DefaultBandwidth);
      out_dest[c] = GNUNET_ATS_DefaultBandwidth;
    }

    /* quota in */
    if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_string(cfg, "ats", entry_in, &quota_in_str))
    {
      res = GNUNET_NO;
      if (0 == strcmp(quota_in_str, BIG_M_STRING))
      {
        in_dest[c] = GNUNET_ATS_MaxBandwidth;
        res = GNUNET_YES;
      }
      if ((GNUNET_NO == res) && (GNUNET_OK == GNUNET_STRINGS_fancy_size_to_bytes (quota_in_str, &in_dest[c])))
        res = GNUNET_YES;
      if ((GNUNET_NO == res) && (GNUNET_OK == GNUNET_CONFIGURATION_get_value_number (cfg, "ats", entry_in,  &in_dest[c])))
         res = GNUNET_YES;

      if (GNUNET_NO == res)
      {
          GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("Could not load quota for network `%s':  `%s', assigning default bandwidth %llu\n"),
              network_str[c], quota_in_str, GNUNET_ATS_DefaultBandwidth);
          in_dest[c] = GNUNET_ATS_DefaultBandwidth;
      }
      else
      {
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, _("Inbound quota configured for network `%s' is %llu\n"),
              network_str[c], in_dest[c]);
      }
      GNUNET_free (quota_in_str);
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING, _("No outbound quota configure for network `%s', assigning default bandwidth %llu\n"),
          network_str[c], GNUNET_ATS_DefaultBandwidth);
      out_dest[c] = GNUNET_ATS_DefaultBandwidth;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Loaded quota for network `%s' (in/out): %llu %llu\n", network_str[c], in_dest[c], out_dest[c]);
    GNUNET_free (entry_out);
    GNUNET_free (entry_in);
  }
  return GNUNET_ATS_NetworkTypeCount;
}

/**
 * Information callback for the solver
 *
 * @param cls the closure
 * @param op the solver operation
 * @param stat status of the solver operation
 * @param add additional solver information
 */
static void
solver_info_cb (void *cls,
    enum GAS_Solver_Operation op,
    enum GAS_Solver_Status stat,
    enum GAS_Solver_Additional_Information add)
{
  char *add_info;
  switch (add) {
    case GAS_INFO_NONE:
      add_info = "GAS_INFO_NONE";
      break;
    case GAS_INFO_FULL:
      add_info = "GAS_INFO_MLP_FULL";
      break;
    case GAS_INFO_UPDATED:
      add_info = "GAS_INFO_MLP_UPDATED";
      break;
    case GAS_INFO_PROP_ALL:
      add_info = "GAS_INFO_PROP_ALL";
      break;
    case GAS_INFO_PROP_SINGLE:
      add_info = "GAS_INFO_PROP_SINGLE";
      break;
    default:
      add_info = "INVALID";
      break;
  }

  switch (op)
  {
    case GAS_OP_SOLVE_START:
      GNUNET_log(GNUNET_ERROR_TYPE_INFO,
          "Solver notifies `%s' with result `%s' `%s'\n", "GAS_OP_SOLVE_START",
          (GAS_STAT_SUCCESS == stat) ? "SUCCESS" : "FAIL", add_info);
      return;
    case GAS_OP_SOLVE_STOP:
      GNUNET_log(GNUNET_ERROR_TYPE_INFO,
          "Solver notifies `%s' with result `%s'\n", "GAS_OP_SOLVE_STOP",
          (GAS_STAT_SUCCESS == stat) ? "SUCCESS" : "FAIL", add_info);
      return;

    case GAS_OP_SOLVE_SETUP_START:
      GNUNET_log(GNUNET_ERROR_TYPE_INFO,
          "Solver notifies `%s' with result `%s'\n", "GAS_OP_SOLVE_SETUP_START",
          (GAS_STAT_SUCCESS == stat) ? "SUCCESS" : "FAIL");
      return;

    case GAS_OP_SOLVE_SETUP_STOP:
      GNUNET_log(GNUNET_ERROR_TYPE_INFO,
          "Solver notifies `%s' with result `%s'\n", "GAS_OP_SOLVE_SETUP_STOP",
          (GAS_STAT_SUCCESS == stat) ? "SUCCESS" : "FAIL");
      return;

    case GAS_OP_SOLVE_MLP_LP_START:
      GNUNET_log(GNUNET_ERROR_TYPE_INFO,
          "Solver notifies `%s' with result `%s'\n", "GAS_OP_SOLVE_LP_START",
          (GAS_STAT_SUCCESS == stat) ? "SUCCESS" : "FAIL");
      return;
    case GAS_OP_SOLVE_MLP_LP_STOP:
      GNUNET_log(GNUNET_ERROR_TYPE_INFO,
          "Solver notifies `%s' with result `%s'\n", "GAS_OP_SOLVE_LP_STOP",
          (GAS_STAT_SUCCESS == stat) ? "SUCCESS" : "FAIL");
      return;

    case GAS_OP_SOLVE_MLP_MLP_START:
      GNUNET_log(GNUNET_ERROR_TYPE_INFO,
          "Solver notifies `%s' with result `%s'\n", "GAS_OP_SOLVE_MLP_START",
          (GAS_STAT_SUCCESS == stat) ? "SUCCESS" : "FAIL");
      return;
    case GAS_OP_SOLVE_MLP_MLP_STOP:
      GNUNET_log(GNUNET_ERROR_TYPE_INFO,
          "Solver notifies `%s' with result `%s'\n", "GAS_OP_SOLVE_MLP_STOP",
          (GAS_STAT_SUCCESS == stat) ? "SUCCESS" : "FAIL");
      return;
    case GAS_OP_SOLVE_UPDATE_NOTIFICATION_START:
      GNUNET_log(GNUNET_ERROR_TYPE_INFO,
          "Solver notifies `%s' with result `%s'\n", "GAS_OP_SOLVE_UPDATE_NOTIFICATION_START",
          (GAS_STAT_SUCCESS == stat) ? "SUCCESS" : "FAIL");
      return;
    case GAS_OP_SOLVE_UPDATE_NOTIFICATION_STOP:
      GNUNET_log(GNUNET_ERROR_TYPE_INFO,
          "Solver notifies `%s' with result `%s'\n", "GAS_OP_SOLVE_UPDATE_NOTIFICATION_STOP",
          (GAS_STAT_SUCCESS == stat) ? "SUCCESS" : "FAIL");
      return;
    default:
      break;
    }
}

static void
solver_bandwidth_changed_cb (void *cls, struct ATS_Address *address)
{
  if ( (0 == ntohl (address->assigned_bw_out.value__)) &&
       (0 == ntohl (address->assigned_bw_in.value__)) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Solver notified to disconnect peer `%s'\n",
                GNUNET_i2s (&address->peer));
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Bandwidth changed addresses %s %p to %u Bps out / %u Bps in\n",
              GNUNET_i2s (&address->peer),
              address,
              (unsigned int) ntohl (address->assigned_bw_out.value__),
              (unsigned int) ntohl (address->assigned_bw_in.value__));
  /*if (GNUNET_YES == ph.bulk_running)
    GNUNET_break (0);*/
  return;
}

const double *
get_preferences_cb (void *cls, const struct GNUNET_PeerIdentity *id)
{
  return GAS_normalization_get_preferences_by_peer (id);
}


const double *
get_property_cb (void *cls, const struct ATS_Address *address)
{
  return GAS_normalization_get_properties ((struct ATS_Address *) address);
}

static void
normalized_property_changed_cb (void *cls, struct ATS_Address *address,
    uint32_t type, double prop_rel)
{
  GNUNET_log(GNUNET_ERROR_TYPE_INFO,
      "Normalized property %s for peer `%s' changed to %.3f \n",
      GNUNET_ATS_print_property_type (type), GNUNET_i2s (&address->peer),
      prop_rel);

  sh->env.sf.s_address_update_property (sh->solver, address, type, 0, prop_rel);
}


static void
normalized_preference_changed_cb (void *cls,
    const struct GNUNET_PeerIdentity *peer,
    enum GNUNET_ATS_PreferenceKind kind,
    double pref_rel)
{
  GNUNET_log(GNUNET_ERROR_TYPE_INFO,
      "Normalized preference %s for peer `%s' changed to %.3f \n",
      GNUNET_ATS_print_preference_type (kind), GNUNET_i2s (peer),
      pref_rel);

  sh->env.sf.s_pref (sh->solver, peer, kind, pref_rel);
}


struct SolverHandle *
GNUNET_ATS_solvers_solver_start (enum GNUNET_ATS_Solvers type)
{
  struct SolverHandle *sh;
  char * solver_str;

  switch (type) {
    case GNUNET_ATS_SOLVER_PROPORTIONAL:
      solver_str = "proportional";
      break;
    case GNUNET_ATS_SOLVER_MLP:
      solver_str = "mlp";
      break;
    case GNUNET_ATS_SOLVER_RIL:
      solver_str = "ril";
      break;
    default:
      GNUNET_break (0);
      return NULL;
      break;
  }

  sh = GNUNET_new (struct SolverHandle);
  GNUNET_asprintf (&sh->plugin, "libgnunet_plugin_ats_%s", solver_str);

  sh->addresses = GNUNET_CONTAINER_multipeermap_create (128, GNUNET_NO);
  /* setup environment */
  sh->env.cfg = e->cfg;
  sh->env.stats = GNUNET_STATISTICS_create ("ats", e->cfg);
  sh->env.addresses = sh->addresses;
  sh->env.bandwidth_changed_cb = &solver_bandwidth_changed_cb;
  sh->env.get_preferences = &get_preferences_cb;
  sh->env.get_property = &get_property_cb;
  sh->env.network_count = GNUNET_ATS_NetworkTypeCount;
  sh->env.info_cb = &solver_info_cb;
  sh->env.info_cb_cls = NULL;


  /* start normalization */
  GAS_normalization_start (&normalized_preference_changed_cb, NULL,
      &normalized_property_changed_cb, NULL );

  /* load quotas */
  if (GNUNET_ATS_NetworkTypeCount != GNUNET_ATS_solvers_load_quotas (e->cfg,
      sh->env.out_quota, sh->env.in_quota, GNUNET_ATS_NetworkTypeCount))
  {
    GNUNET_break(0);
    GNUNET_free (sh->plugin);
    GNUNET_free (sh);
    end_now ();
    return NULL;
  }

  sh->solver = GNUNET_PLUGIN_load (sh->plugin, &sh->env);
  if (NULL == sh->solver)
  {
    fprintf (stderr, "Failed to load solver `%s'\n", sh->plugin);
    GNUNET_break(0);
    GNUNET_free (sh->plugin);
    GNUNET_free (sh);
    end_now ();
    return NULL;
  }
  return sh;
}

static void
done ()
{
  struct TestPeer *cur;
  struct TestPeer *next;

  struct TestAddress *cur_a;
  struct TestAddress *next_a;

  /* Stop logging */
  GNUNET_ATS_solver_logging_stop (l);

  /* Stop all preference generation */
  GNUNET_ATS_solver_generate_preferences_stop_all ();

  /* Stop all property generation */
  GNUNET_ATS_solver_generate_property_stop_all ();

  /* Clean up experiment */
  if (NULL != e)
  {
    GNUNET_ATS_solvers_experimentation_stop (e);
    e = NULL;
  }

  if (opt_print)
    GNUNET_ATS_solver_logging_eval (l);

  if (NULL != l)
  {
    GNUNET_ATS_solver_logging_free (l);
    l = NULL;
  }

  next = peer_head;
  while  (NULL != (cur = next))
  {
    next = cur->next;
    GNUNET_CONTAINER_DLL_remove (peer_head, peer_tail, cur);
    next_a = cur->addr_head;
    while  (NULL != (cur_a = next_a))
    {
      next_a = cur_a->next;
      GNUNET_CONTAINER_DLL_remove (cur->addr_head, cur->addr_tail, cur_a);
      GNUNET_free (cur_a);
    }
    GNUNET_free (cur);
  }
  if (NULL != sh)
  {
    GNUNET_ATS_solvers_solver_stop (sh);
    sh = NULL;
  }
  /* Shutdown */
  end_now();
}

static void
experiment_done_cb (struct Experiment *e, struct GNUNET_TIME_Relative duration,int success)
{
  if (GNUNET_OK == success)
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Experiment done successful in %s\n",
        GNUNET_STRINGS_relative_time_to_string (duration, GNUNET_YES));
  else
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Experiment failed \n");

  GNUNET_SCHEDULER_add_now (&done, NULL);
}

static void
episode_done_cb (struct Episode *ep)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Episode %u done\n", ep->id);
}



/**
 * Do shutdown
 */
static void
end_now ()
{
  if (NULL != e)
  {
    GNUNET_ATS_solvers_experimentation_stop (e);
    e = NULL;
  }
  if (NULL != sh)
  {
    GNUNET_ATS_solvers_solver_stop (sh);
    sh = NULL;
  }
}

static void
run (void *cls, char * const *args, const char *cfgfile,
    const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  enum GNUNET_ATS_Solvers solver;

  if (NULL == opt_exp_file)
  {
    fprintf (stderr, "No experiment given ...\n");
    res = 1;
    end_now ();
    return;
  }

  if (NULL == opt_solver)
  {
    fprintf (stderr, "No solver given ...\n");
    res = 1;
    end_now ();
    return;
  }

  if (0 == strcmp(opt_solver, "mlp"))
  {
    solver = GNUNET_ATS_SOLVER_MLP;
  }
  else if (0 == strcmp(opt_solver, "proportional"))
  {
    solver = GNUNET_ATS_SOLVER_PROPORTIONAL;
  }
  else if (0 == strcmp(opt_solver, "ril"))
  {
    solver = GNUNET_ATS_SOLVER_RIL;
  }
  else
  {
    fprintf (stderr, "No solver given ...");
    res = 1;
    end_now ();
    return;
  }

  /* load experiment */
  e = GNUNET_ATS_solvers_experimentation_load (opt_exp_file);
  if (NULL == e)
  {
    fprintf (stderr, "Failed to load experiment ...\n");
    res = 1;
    end_now ();
    return;
  }

  /* load solver */
  sh = GNUNET_ATS_solvers_solver_start (solver);
  if (NULL == sh)
  {
    fprintf (stderr, "Failed to start solver ...\n");
    end_now ();
    res = 1;
    return;
  }

  /* start logging */
  l = GNUNET_ATS_solver_logging_start (e->log_freq);

  /* run experiment */
  GNUNET_ATS_solvers_experimentation_run (e, episode_done_cb,
      experiment_done_cb);

  /* WAIT */
}


/**
 * Main function of the benchmark
 *
 * @param argc argument count
 * @param argv argument values
 */
int
main (int argc, char *argv[])
{
  opt_exp_file = NULL;
  opt_solver = NULL;
  opt_log = GNUNET_NO;
  opt_plot = GNUNET_NO;

  res = 0;

  static struct GNUNET_GETOPT_CommandLineOption options[] =
  {
    { 's', "solver", NULL,
        gettext_noop ("solver to use"),
        1, &GNUNET_GETOPT_set_string, &opt_solver},
    {  'e', "experiment", NULL,
      gettext_noop ("experiment to use"),
      1, &GNUNET_GETOPT_set_string, &opt_exp_file},
    {  'e', "experiment", NULL,
      gettext_noop ("experiment to use"),
      1, &GNUNET_GETOPT_set_one, &opt_verbose},
    {  'p', "print", NULL,
      gettext_noop ("print logging"),
      0, &GNUNET_GETOPT_set_one, &opt_print},
    GNUNET_GETOPT_OPTION_END
  };

  GNUNET_PROGRAM_run (argc, argv, "gnunet-ats-solver-eval",
      NULL, options, &run, argv[0]);

  return res;
}
/* end of file ats-testing-experiment.c*/

