/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2004, 2005, 2006, 2007, 2009 Christian Grothoff (and other contributing authors)

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
 * @file ats-tool/gnunet-ats.c
 * @brief ATS command line tool
 * @author Matthias Wachs
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_ats_service.h"
#include "gnunet_transport_service.h"

#define TIMEOUT GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 5)

#define BIG_M_STRING "unlimited"

/**
 * Final status code.
 */
static int ret;
static int results;
static int resolve_addresses_numeric;
static int receive_done;

/**
 * For which peer should we change preference values?
 */
static char *pid_str;

static char *type_str;
static unsigned int value;
static int pending;

/**
 * Print verbose ATS information
 */
static int verbose;

/**
 * List only addresses currently used (active)
 */
static int op_list_used;

/**
 * List all addresses
 */
static int op_list_all;

/**
 * List all addresses
 */
static int op_set_pref;

/**
 * Print quotas configured
 */
static int op_print_quotas;

/**
 * Monitor addresses used
 */
static int op_monitor;



static struct GNUNET_ATS_PerformanceHandle *ph;

struct GNUNET_ATS_AddressListHandle *alh;

static struct GNUNET_CONFIGURATION_Handle *cfg;

GNUNET_SCHEDULER_TaskIdentifier end_task;

struct PendingResolutions
{
  struct PendingResolutions *next;
  struct PendingResolutions *prev;

  struct GNUNET_HELLO_Address *address;
  struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out;
  struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in;

  struct GNUNET_ATS_Information *ats;
  uint32_t ats_count;

  struct GNUNET_TRANSPORT_AddressToStringContext * tats_ctx;
};

struct PendingResolutions *head;
struct PendingResolutions *tail;

void end (void *cls,
          const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct PendingResolutions * pr;
  struct PendingResolutions * next;
  unsigned int pending;

  if (NULL != alh)
  {
      GNUNET_ATS_performance_list_addresses_cancel (alh);
      alh = NULL;
  }

  if (NULL != ph)
  {
    GNUNET_ATS_performance_done (ph);
    ph = NULL;
  }

  pending = 0;
  next = head;
  while (NULL != (pr = next))
  {
      next = pr->next;
      GNUNET_CONTAINER_DLL_remove (head, tail, pr);
      GNUNET_TRANSPORT_address_to_string_cancel (pr->tats_ctx);
      GNUNET_free (pr->address);
      GNUNET_free (pr);
      pending ++;
  }
  if (0 < pending)
    fprintf (stderr, _("%u address resolutions had a timeout\n"), pending);

  fprintf (stderr, _("ATS returned results for %u addresses\n"), results);
  ret = 0;
}


void transport_addr_to_str_cb (void *cls, const char *address)
{
  struct PendingResolutions * pr = cls;
  char *ats_str;
  char *ats_tmp;
  char *ats_prop_arr[GNUNET_ATS_PropertyCount] = GNUNET_ATS_PropertyStrings;
  char *ats_prop_value;
  unsigned int c;
  uint32_t ats_type;
  uint32_t ats_value;
  uint32_t network;
  if (NULL != address)
  {
    ats_str = GNUNET_strdup("");


    for (c = 0; c < pr->ats_count; c++)
    {
        ats_tmp = ats_str;

        ats_type = ntohl(pr->ats[c].type);
        ats_value = ntohl(pr->ats[c].value);

        if (ats_type > GNUNET_ATS_PropertyCount)
        {
            GNUNET_break (0);
            continue;
        }

        switch (ats_type) {
          case GNUNET_ATS_NETWORK_TYPE:
            if (ats_value > GNUNET_ATS_NetworkTypeCount)
            {
                GNUNET_break (0);
                continue;
            }
            network = ats_value;
            GNUNET_asprintf (&ats_prop_value, "%s", GNUNET_ATS_print_network_type(ats_value));
            break;
          default:
            GNUNET_asprintf (&ats_prop_value, "%u", ats_value);
            break;
        }
        if ((verbose) && (ats_type < GNUNET_ATS_PropertyCount))
        {
          GNUNET_asprintf (&ats_str, "%s%s=%s, ", ats_tmp, ats_prop_arr[ats_type] , ats_prop_value);
          GNUNET_free (ats_tmp);
        }
        GNUNET_free (ats_prop_value);
		}

    fprintf (stderr, _("Peer `%s' plugin `%s', address `%s', `%s' bw out: %u Bytes/s, bw in %u Bytes/s, %s\n"),
      GNUNET_i2s (&pr->address->peer), pr->address->transport_name, address,
      GNUNET_ATS_print_network_type(network),
      ntohl (pr->bandwidth_out.value__), ntohl (pr->bandwidth_in.value__),ats_str);
    GNUNET_free (ats_str);
  }
  else
  {
    /* We're done */
    GNUNET_CONTAINER_DLL_remove (head, tail, pr);
    GNUNET_free (pr->address);
    GNUNET_free (pr);
    pending--;

    if ((GNUNET_YES == receive_done) && (0 == pending))
    {
        /* All messages received and no resolutions pending*/
        if (end_task != GNUNET_SCHEDULER_NO_TASK)
          GNUNET_SCHEDULER_cancel (end_task);
        end_task = GNUNET_SCHEDULER_add_now (end, NULL);
    }
  }
}

void ats_perf_cb (void *cls,
                  const struct
                  GNUNET_HELLO_Address *
                  address,
                  struct
                  GNUNET_BANDWIDTH_Value32NBO
                  bandwidth_out,
                  struct
                  GNUNET_BANDWIDTH_Value32NBO
                  bandwidth_in,
                  const struct
                  GNUNET_ATS_Information *
                  ats, uint32_t ats_count)
{
  struct PendingResolutions * pr;


  if (NULL != address)
  {
    pr = GNUNET_malloc (sizeof (struct PendingResolutions) +
                        ats_count * sizeof (struct GNUNET_ATS_Information));

    pr->ats_count = ats_count;
    pr->ats = (struct GNUNET_ATS_Information *) &pr[1];
    if (ats_count > 0)
      memcpy (pr->ats, ats, ats_count * sizeof (struct GNUNET_ATS_Information));
    pr->address = GNUNET_HELLO_address_copy (address);
    pr->bandwidth_in = bandwidth_in;
    pr->bandwidth_out = bandwidth_out;
    pr->tats_ctx = GNUNET_TRANSPORT_address_to_string(cfg, address,
                      resolve_addresses_numeric, GNUNET_TIME_UNIT_FOREVER_REL, transport_addr_to_str_cb, pr);
    GNUNET_CONTAINER_DLL_insert (head, tail, pr);
    results++;
    pending++;
  }
  else
  {
    /* All messages received */
    receive_done = GNUNET_YES;
    alh = NULL;
    if (0 == pending)
    {
      /* All messages received and no resolutions pending*/
      if (end_task != GNUNET_SCHEDULER_NO_TASK)
        GNUNET_SCHEDULER_cancel (end_task);
      end_task = GNUNET_SCHEDULER_add_now (end, NULL);
    }
  }
}

static unsigned int
print_quotas (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  char *network_str[GNUNET_ATS_NetworkTypeCount] = GNUNET_ATS_NetworkTypeString;
  char * entry_in = NULL;
  char * entry_out = NULL;
  char * quota_out_str;
  char * quota_in_str;
  unsigned long long int quota_out;
  unsigned long long int quota_in;
  int c;

  for (c = 0; (c < GNUNET_ATS_NetworkTypeCount); c++)
  {

    GNUNET_asprintf (&entry_out, "%s_QUOTA_OUT", network_str[c]);
    GNUNET_asprintf (&entry_in, "%s_QUOTA_IN", network_str[c]);

    /* quota out */
    if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_string(cfg, "ats", entry_out, &quota_out_str))
    {
      if (0 == strcmp(quota_out_str, BIG_M_STRING) ||
          (GNUNET_SYSERR == GNUNET_STRINGS_fancy_size_to_bytes (quota_out_str, &quota_out)))
        quota_out = UINT32_MAX;

      GNUNET_free (quota_out_str);
      GNUNET_asprintf (&quota_out_str, "%llu", quota_out);
    }
    else
    {
        fprintf (stderr, "Outbound quota for network `%11s' not configured!\n",
            network_str[c]);
        GNUNET_asprintf (&quota_out_str, "-");
    }
    GNUNET_free (entry_out);

    /* quota in */
    if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_string(cfg, "ats", entry_in, &quota_in_str))
    {
      if (0 == strcmp(quota_in_str, BIG_M_STRING) ||
          (GNUNET_SYSERR == GNUNET_STRINGS_fancy_size_to_bytes (quota_in_str, &quota_in)))
          quota_in = UINT32_MAX;
      GNUNET_free (quota_in_str);
      GNUNET_asprintf (&quota_in_str, "%llu", quota_in);
    }
    else
    {
        fprintf (stderr, "Inbound quota for network `%11s' not configured!\n",
            network_str[c]);
        GNUNET_asprintf (&quota_in_str, "-");
    }
    GNUNET_free (entry_in);

    fprintf (stderr, _("Quota for network `%11s' (in/out): %10s / %10s\n"), network_str[c], quota_in_str, quota_out_str );
    GNUNET_free (quota_out_str);
    GNUNET_free (quota_in_str);
  }
  return GNUNET_ATS_NetworkTypeCount;
}



void testservice_ats (void *cls,
               const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_PeerIdentity pid;
  struct GNUNET_CONFIGURATION_Handle *cfg = cls;
  unsigned int c;
  unsigned int type;

  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_TIMEOUT))
  {
      FPRINTF (stderr, _("Service `%s' is not running\n"), "ats");
      return;
  }

  results = 0;

  if (NULL != pid_str)
  {
      if (GNUNET_OK != GNUNET_CRYPTO_hash_from_string (pid_str, &pid.hashPubKey))
      {
        FPRINTF (stderr, _("Failed to parse peer identity `%s'\n"), pid_str);
        return;
      }
  }

  c = op_list_all + op_list_used + op_monitor + op_set_pref;
  if ((1 < c))
  {
      FPRINTF (stderr, _("Please select one operation : %s or %s or %s or %s or %s\n"),
               "--used", "--all", "--monitor", "--preference", "--quotas");
      return;
  }
  if ((0 == c))
    op_list_used = GNUNET_YES; /* set default */
    if (op_print_quotas)
    {
        ret = print_quotas (cfg);
        return;
    }
    if (op_list_all)
    {
        ph = GNUNET_ATS_performance_init (cfg, NULL, NULL);
        if (NULL == ph)
        {
          fprintf (stderr, _("Cannot connect to ATS service, exiting...\n"));
          return;
        }

        alh = GNUNET_ATS_performance_list_addresses (ph,
                                               (NULL == pid_str) ? NULL : &pid,
                                               GNUNET_YES, ats_perf_cb, NULL);
        if (NULL == alh)
        {
          fprintf (stderr, _("Cannot issue request to ATS service, exiting...\n"));
          end_task = GNUNET_SCHEDULER_add_now (&end, NULL);
          return;
        }
        end_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &end, NULL);
    }
    else if (op_list_used)
    {
        ph = GNUNET_ATS_performance_init (cfg, NULL, NULL);
        if (NULL == ph)
          fprintf (stderr, _("Cannot connect to ATS service, exiting...\n"));

        alh = GNUNET_ATS_performance_list_addresses (ph,
                                               (NULL == pid_str) ? NULL : &pid,
                                               GNUNET_NO, ats_perf_cb, NULL);
        if (NULL == alh)
        {
          fprintf (stderr, _("Cannot issue request to ATS service, exiting...\n"));
          end_task = GNUNET_SCHEDULER_add_now (&end, NULL);
          return;
        }
        end_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &end, NULL);
    }
    else if (op_monitor)
    {
        ph = GNUNET_ATS_performance_init (cfg, ats_perf_cb, NULL);
        if (NULL == ph)
          fprintf (stderr, _("Cannot connect to ATS service, exiting...\n"));
        end_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &end, NULL);

    }
    else if (op_set_pref)
    {
        for (c = 0; c<strlen(type_str); c++)
        {
          if (isupper (type_str[c]))
            type_str[c] = tolower (type_str[c]);
        }

        if (0 == strcasecmp("latency", type_str))
          type = GNUNET_ATS_PREFERENCE_LATENCY;
        else if (0 == strcasecmp("bandwidth", type_str))
          type = GNUNET_ATS_PREFERENCE_BANDWIDTH;
        else
        {
          FPRINTF (stderr, "%s", _("Type required\n"));
          return;
        }

            /* set */
            ph = GNUNET_ATS_performance_init (cfg, NULL, NULL);
            if (NULL == ph)
              fprintf (stderr, _("Cannot connect to ATS service, exiting...\n"));

            GNUNET_ATS_change_preference (ph, &pid, type, (double) value, GNUNET_ATS_PREFERENCE_END);

            end_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS, &end, NULL);
    }
  ret = 1;
}

/**
 * Main function that will be run by the scheduler.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param my_cfg configuration
 */
static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *my_cfg)
{
  cfg = (struct GNUNET_CONFIGURATION_Handle *) my_cfg;
  GNUNET_CLIENT_service_test ("ats", cfg,
                              TIMEOUT,
                              &testservice_ats,
                              (void *) cfg);
}


/**
 * The main function.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  int res;
  resolve_addresses_numeric = GNUNET_NO;
  op_monitor = GNUNET_NO;
  op_list_all = GNUNET_NO;
  op_list_used = GNUNET_NO;
  op_set_pref = GNUNET_NO;
  pending = 0;
  receive_done = GNUNET_NO;

  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
      {'u', "used", NULL,
       gettext_noop ("get list of active addresses currently used"),
       0, &GNUNET_GETOPT_set_one, &op_list_used},
       {'a', "all", NULL,
        gettext_noop ("get list of all active addresses"),
        0, &GNUNET_GETOPT_set_one, &op_list_all},
      {'n', "numeric", NULL,
       gettext_noop ("do not resolve IP addresses to hostnames"),
       0, &GNUNET_GETOPT_set_one, &resolve_addresses_numeric},
       {'m', "monitor", NULL,
        gettext_noop ("monitor mode"),
        0, &GNUNET_GETOPT_set_one, &op_monitor},
       {'p', "preference", NULL,
         gettext_noop ("set preference for the given peer"),
         0, &GNUNET_GETOPT_set_one, &op_set_pref},
       {'q', "quotas", NULL,
         gettext_noop ("print all configured quotas"),
         0, &GNUNET_GETOPT_set_one, &op_print_quotas},
       {'i', "id", "TYPE",
         gettext_noop ("peer id"),
         1, &GNUNET_GETOPT_set_string, &pid_str},
       {'t', "type", "TYPE",
         gettext_noop ("preference type to set: latency | bandwidth"),
         1, &GNUNET_GETOPT_set_string, &type_str},
       {'k', "value", "VALUE",
         gettext_noop ("preference value"),
         1, &GNUNET_GETOPT_set_uint, &value},
       {'V', "verbose", NULL,
        gettext_noop ("verbose output (include ATS address properties)"),
        0, &GNUNET_GETOPT_set_one, &verbose},
    GNUNET_GETOPT_OPTION_END
  };

  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;

  res = GNUNET_PROGRAM_run (argc, argv, "gnunet-ats",
                              gettext_noop ("Print information about ATS state"), options, &run,
                              NULL);
  GNUNET_free_non_null (pid_str);
  GNUNET_free_non_null (type_str);
  GNUNET_free ((void *) argv);

  if (GNUNET_OK == res)
    return ret;
  else
    return 1;

}

/* end of gnunet-ats.c */
