/*
   This file is part of GNUnet.
   Copyright (C) 2009--2015 GNUnet e.V.

   GNUnet is free software: you can redistribute it and/or modify it
   under the terms of the GNU Affero General Public License as published
   by the Free Software Foundation, either version 3 of the License,
   or (at your option) any later version.

   GNUnet is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Affero General Public License for more details.

   You should have received a copy of the GNU Affero General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
 */

/**
 * @file ats-tool/gnunet-ats.c
 * @brief ATS command line tool
 * @author Matthias Wachs
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_ats_service.h"
#include "gnunet_transport_service.h"

/**
 * String to respresent unlimited
 */
#define UNLIMITED_STRING "unlimited"


/**
 * CLI Opt:
 */
static int opt_resolve_addresses_numeric;

/**
 * CLI Opt: Print verbose ATS information
 */
static int opt_verbose;

/**
 * CLI Option: List only addresses currently used (active)
 */
static int opt_list_used;

/**
 * CLI Option: List all addresses
 */
static int opt_list_all;

/**
 * CLI Option: set preference
 */
static int opt_set_pref;

/**
 * CLI Option: print quotas configured
 */
static int opt_print_quotas;

/**
 * CLI Option: Monitor addresses used
 */
static int opt_monitor;

/**
 * CLI Option: use specific peer
 */
static char *opt_pid_str;

/**
 * CLI Option: preference type to set
 */
static char *opt_type_str;

/**
 * CLI Option: preference value to set
 */
static unsigned int opt_pref_value;

/**
 * Final status code.
 */
static int ret;

/**
 * Number of results returned from service
 */
static int stat_results;

/**
 * State: all pending receive operations done?
 */
static int stat_receive_done;

/**
 * State: number of pending operations
 */
static int stat_pending;

/**
 * Which peer should we connect to?
 */
static char *cpid_str;

/**
 * ATS performance handle used
 */
static struct GNUNET_ATS_PerformanceHandle *ph;

/**
 * Our connectivity handle.
 */
static struct GNUNET_ATS_ConnectivityHandle *ats_ch;

/**
 * Handle for address suggestion request.
 */
static struct GNUNET_ATS_ConnectivitySuggestHandle *ats_sh;

/**
 * ATS address list handle used
 */
static struct GNUNET_ATS_AddressListHandle *alh;

/**
 * Configuration handle
 */
static struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Shutdown task
 */
static struct GNUNET_SCHEDULER_Task *shutdown_task;

/**
 * Hashmap to store addresses
 */
static struct GNUNET_CONTAINER_MultiPeerMap *addresses;


/**
 * Structure used to remember all pending address resolutions.
 * We keep address information in here while we talk to transport
 * to map the address to a string.
 */
struct PendingResolutions
{
  /**
   * Kept in a DLL.
   */
  struct PendingResolutions *next;

  /**
   * Kept in a DLL.
   */
  struct PendingResolutions *prev;

  /**
   * Copy of the address we are resolving.
   */
  struct GNUNET_HELLO_Address *address;

  /**
   * Handle to the transport request to convert the address
   * to a string.
   */
  struct GNUNET_TRANSPORT_AddressToStringContext *tats_ctx;

  /**
   * Performance data.
   */
  struct GNUNET_ATS_Properties properties;

  /**
   * Amount of outbound bandwidth assigned by ATS.
   */
  struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out;

  /**
   * Amount of inbound bandwidth assigned by ATS.
   */
  struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in;

  /**
   * Is this an active address?
   */
  int active;
};


/**
 * Information we keep for an address.  Used to avoid
 * printing the same data multiple times.
 */
struct ATSAddress
{
  /**
   * Address information.
   */
  struct GNUNET_HELLO_Address *address;

  /**
   * Current outbound bandwidth.
   */
  struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out;

  /**
   * Current inbound bandwidth.
   */
  struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in;

  /**
   * Is this an active address?
   */
  int active;
};


/**
 * Head of list of pending resolution requests.
 */
static struct PendingResolutions *head;

/**
 * Tail of list of pending resolution requests.
 */
static struct PendingResolutions *tail;


/**
 * Free address corresponding to a given peer.
 *
 * @param cls NULL
 * @param key peer identity
 * @param value the `struct ATSAddress *` to be freed
 * @return #GNUNET_YES (always)
 */
static int
free_addr_it (void *cls, const struct GNUNET_PeerIdentity *key, void *value)
{
  struct ATSAddress *a = value;

  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multipeermap_remove (addresses, key, value));
  GNUNET_HELLO_address_free (a->address);
  GNUNET_free (a);
  return GNUNET_OK;
}


/**
 * Task run on shutdown.
 *
 * @param cls NULL
 */
static void
end (void *cls)
{
  struct PendingResolutions *pr;
  struct PendingResolutions *next;
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
    pending++;
  }
  GNUNET_CONTAINER_multipeermap_iterate (addresses, &free_addr_it, NULL);
  GNUNET_CONTAINER_multipeermap_destroy (addresses);
  addresses = NULL;

  if (0 < pending)
    fprintf (stdout, _ ("%u address resolutions had a timeout\n"), pending);
  if (opt_list_used || opt_list_all)
    fprintf (stdout,
             _ ("ATS returned stat_results for %u addresses\n"),
             stat_results);

  if (NULL != ats_sh)
  {
    GNUNET_ATS_connectivity_suggest_cancel (ats_sh);
    ats_sh = NULL;
  }
  if (NULL != ats_ch)
  {
    GNUNET_ATS_connectivity_done (ats_ch);
    ats_ch = NULL;
  }
  ret = 0;
}


/**
 * Function to call with a textual representation of an address.  This
 * function will be called several times with different possible
 * textual representations, and a last time with @a address being NULL
 * to signal the end of the iteration.  Note that @a address NULL
 * always is the last call, regardless of the value in @a res.
 *
 * @param cls closure, a `struct PendingResolutions *`
 * @param address NULL on end of iteration,
 *        otherwise 0-terminated printable UTF-8 string,
 *        in particular an empty string if @a res is #GNUNET_NO
 * @param res result of the address to string conversion:
 *        if #GNUNET_OK: conversion successful
 *        if #GNUNET_NO: address was invalid (or not supported)
 *        if #GNUNET_SYSERR: communication error (IPC error)
 */
static void
transport_addr_to_str_cb (void *cls, const char *address, int res)
{
  struct PendingResolutions *pr = cls;

  if (NULL == address)
  {
    /* We're done */
    GNUNET_CONTAINER_DLL_remove (head, tail, pr);
    GNUNET_free (pr->address);
    GNUNET_free (pr);
    stat_pending--;

    if ((GNUNET_YES == stat_receive_done) && (0 == stat_pending))
    {
      /* All messages received and no resolutions pending*/
      if (shutdown_task != NULL)
        GNUNET_SCHEDULER_cancel (shutdown_task);
      shutdown_task = GNUNET_SCHEDULER_add_now (&end, NULL);
    }
    return;
  }
  switch (res)
  {
  case GNUNET_SYSERR:
    fprintf (
      stderr,
      "Failed to convert address for peer `%s' plugin `%s' length %u to string (communication error)\n",
      GNUNET_i2s (&pr->address->peer),
      pr->address->transport_name,
      (unsigned int) pr->address->address_length);
    return;

  case GNUNET_NO:
    fprintf (
      stderr,
      "Failed to convert address for peer `%s' plugin `%s' length %u to string (address invalid or not supported)\n",
      GNUNET_i2s (&pr->address->peer),
      pr->address->transport_name,
      (unsigned int) pr->address->address_length);
    return;

  case GNUNET_OK:
    /* continues below */
    break;

  default:
    GNUNET_break (0);
    return;
  }

  fprintf (
    stdout,
    _ (
      "Peer `%s' plugin `%s', address `%s', `%s' bw out: %u Bytes/s, bw in %u Bytes/s, %s\n"),
    GNUNET_i2s (&pr->address->peer),
    pr->address->transport_name,
    address,
    GNUNET_NT_to_string (pr->properties.scope),
    ntohl (pr->bandwidth_out.value__),
    ntohl (pr->bandwidth_in.value__),
    pr->active ? _ ("active ") : _ ("inactive "));
}


/**
 * Closure for #find_address_it().
 */
struct AddressFindCtx
{
  /**
   * Address we are looking for.
   */
  const struct GNUNET_HELLO_Address *src;

  /**
   * Where to write the `struct ATSAddress` if we found one that matches.
   */
  struct ATSAddress *res;
};


/**
 * Find address corresponding to a given peer.
 *
 * @param cls the `struct AddressFindCtx *`
 * @param key peer identity
 * @param value the `struct ATSAddress *` for an existing address
 * @return #GNUNET_NO if we found a match, #GNUNET_YES if not
 */
static int
find_address_it (void *cls, const struct GNUNET_PeerIdentity *key, void *value)
{
  struct AddressFindCtx *actx = cls;
  struct ATSAddress *exist = value;

  if (0 == GNUNET_HELLO_address_cmp (actx->src, exist->address))
  {
    actx->res = exist;
    return GNUNET_NO;
  }
  return GNUNET_YES;
}


/**
 * Signature of a function that is called with QoS information about an address.
 *
 * @param cls closure (NULL)
 * @param address the address, NULL if ATS service was disconnected
 * @param active #GNUNET_YES if this address is actively used
 *        to maintain a connection to a peer;
 *        #GNUNET_NO if the address is not actively used;
 *        #GNUNET_SYSERR if this address is no longer available for ATS
 * @param bandwidth_out assigned outbound bandwidth for the connection
 * @param bandwidth_in assigned inbound bandwidth for the connection
 * @param prop performance data for the address (as far as known)
 */
static void
ats_perf_mon_cb (void *cls,
                 const struct GNUNET_HELLO_Address *address,
                 int active,
                 struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out,
                 struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in,
                 const struct GNUNET_ATS_Properties *prop)
{
  struct PendingResolutions *pr;
  struct PendingResolutions *cur;
  struct PendingResolutions *next;

  if (NULL == address)
  {
    /* ATS service temporarily disconnected, remove current state */
    next = head;
    for (cur = next; NULL != cur; cur = next)
    {
      next = cur->next;
      GNUNET_CONTAINER_DLL_remove (head, tail, cur);
      GNUNET_TRANSPORT_address_to_string_cancel (cur->tats_ctx);
      GNUNET_HELLO_address_free (cur->address);
      GNUNET_free (cur);
    }
    GNUNET_CONTAINER_multipeermap_iterate (addresses, &free_addr_it, NULL);
    return;
  }
  if (GNUNET_SYSERR == active)
  {
    /* remove address */
    struct AddressFindCtx actx;

    actx.src = address;
    actx.res = NULL;
    GNUNET_CONTAINER_multipeermap_get_multiple (addresses,
                                                &address->peer,
                                                &find_address_it,
                                                &actx);
    if (NULL == actx.res)
    {
      GNUNET_break (0);
      return;
    }
    GNUNET_break (GNUNET_OK ==
                  GNUNET_CONTAINER_multipeermap_remove (addresses,
                                                        &address->peer,
                                                        actx.res));
    fprintf (stdout,
             _ ("Removed address of peer `%s' with plugin `%s'\n"),
             GNUNET_i2s (&address->peer),
             actx.res->address->transport_name);
    GNUNET_HELLO_address_free (actx.res);
    return;
  }

  if (GNUNET_NO == opt_verbose)
  {
    struct AddressFindCtx actx;
    struct ATSAddress *a;

    actx.src = address;
    actx.res = NULL;
    GNUNET_CONTAINER_multipeermap_get_multiple (addresses,
                                                &address->peer,
                                                &find_address_it,
                                                &actx);
    if ((NULL != actx.res))
    {
      if ((bandwidth_in.value__ == actx.res->bandwidth_in.value__) &&
          (bandwidth_out.value__ == actx.res->bandwidth_out.value__) &&
          (active == actx.res->active))
      {
        return;       /* Nothing to do here */
      }
      else
      {
        actx.res->bandwidth_in = bandwidth_in;
        actx.res->bandwidth_out = bandwidth_out;
      }
    }
    else
    {
      a = GNUNET_new (struct ATSAddress);

      a->address = GNUNET_HELLO_address_copy (address);
      a->bandwidth_in = bandwidth_in;
      a->bandwidth_out = bandwidth_out;
      a->active = active;
      GNUNET_CONTAINER_multipeermap_put (
        addresses,
        &address->peer,
        a,
        GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
    }
  }

  pr = GNUNET_new (struct PendingResolutions);
  pr->properties = *prop;
  pr->address = GNUNET_HELLO_address_copy (address);
  pr->bandwidth_in = bandwidth_in;
  pr->bandwidth_out = bandwidth_out;
  pr->active = active;
  pr->tats_ctx = GNUNET_TRANSPORT_address_to_string (
    cfg,
    address,
    opt_resolve_addresses_numeric,
    GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10),
    &transport_addr_to_str_cb,
    pr);
  GNUNET_CONTAINER_DLL_insert (head, tail, pr);
  stat_results++;
  stat_pending++;
}


/**
 * Signature of a function that is called with QoS information about an address.
 *
 * @param cls closure (NULL)
 * @param address the address, NULL if ATS service was disconnected
 * @param active is this address actively used to maintain a connection
          to a peer
 * @param bandwidth_out assigned outbound bandwidth for the connection
 * @param bandwidth_in assigned inbound bandwidth for the connection
 * @param prop performance data for the address (as far as known)
 */
static void
ats_perf_cb (void *cls,
             const struct GNUNET_HELLO_Address *address,
             int active,
             struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out,
             struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in,
             const struct GNUNET_ATS_Properties *prop)
{
  struct PendingResolutions *pr;

  if (NULL == address)
  {
    /* All messages received */
    stat_receive_done = GNUNET_YES;
    alh = NULL;
    if (0 == stat_pending)
    {
      /* All messages received and no resolutions pending*/
      if (shutdown_task != NULL)
        GNUNET_SCHEDULER_cancel (shutdown_task);
      shutdown_task = GNUNET_SCHEDULER_add_now (&end, NULL);
    }
    return;
  }

  pr = GNUNET_new (struct PendingResolutions);
  pr->properties = *prop;
  pr->address = GNUNET_HELLO_address_copy (address);
  pr->bandwidth_in = bandwidth_in;
  pr->bandwidth_out = bandwidth_out;
  pr->active = active;
  pr->tats_ctx = GNUNET_TRANSPORT_address_to_string (
    cfg,
    address,
    opt_resolve_addresses_numeric,
    GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10),
    &transport_addr_to_str_cb,
    pr);
  GNUNET_CONTAINER_DLL_insert (head, tail, pr);
  stat_results++;
  stat_pending++;
}


/**
 * Print information about the quotas configured for the various
 * network scopes.
 *
 * @param cfg configuration to obtain quota information from
 * @return total number of ATS network types known
 */
static unsigned int
print_quotas (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  char *entry_in = NULL;
  char *entry_out = NULL;
  char *quota_out_str;
  char *quota_in_str;
  unsigned long long int quota_out;
  unsigned long long int quota_in;
  int c;

  for (c = 0; (c < GNUNET_NT_COUNT); c++)
  {
    GNUNET_asprintf (&entry_out, "%s_QUOTA_OUT", GNUNET_NT_to_string (c));
    GNUNET_asprintf (&entry_in, "%s_QUOTA_IN", GNUNET_NT_to_string (c));

    /* quota out */
    if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_string (cfg,
                                                            "ats",
                                                            entry_out,
                                                            &quota_out_str))
    {
      if ((0 == strcmp (quota_out_str, UNLIMITED_STRING)) ||
          (GNUNET_SYSERR ==
           GNUNET_STRINGS_fancy_size_to_bytes (quota_out_str, &quota_out)))
        quota_out = UINT32_MAX;

      GNUNET_free (quota_out_str);
      GNUNET_asprintf (&quota_out_str, "%llu", quota_out);
    }
    else
    {
      fprintf (stderr,
               "Outbound quota for network `%11s' not configured!\n",
               GNUNET_NT_to_string (c));
      GNUNET_asprintf (&quota_out_str, "-");
    }
    GNUNET_free (entry_out);

    /* quota in */
    if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_string (cfg,
                                                            "ats",
                                                            entry_in,
                                                            &quota_in_str))
    {
      if ((0 == strcmp (quota_in_str, UNLIMITED_STRING)) ||
          (GNUNET_SYSERR ==
           GNUNET_STRINGS_fancy_size_to_bytes (quota_in_str, &quota_in)))
        quota_in = UINT32_MAX;
      GNUNET_free (quota_in_str);
      GNUNET_asprintf (&quota_in_str, "%llu", quota_in);
    }
    else
    {
      fprintf (stderr,
               "Inbound quota for network `%11s' not configured!\n",
               GNUNET_NT_to_string (c));
      GNUNET_asprintf (&quota_in_str, "-");
    }
    GNUNET_free (entry_in);

    fprintf (stdout,
             _ ("Quota for network `%11s' (in/out): %10s / %10s\n"),
             GNUNET_NT_to_string (c),
             quota_in_str,
             quota_out_str);
    GNUNET_free (quota_out_str);
    GNUNET_free (quota_in_str);
  }
  return GNUNET_NT_COUNT;
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
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *my_cfg)
{
  struct GNUNET_PeerIdentity pid;
  struct GNUNET_PeerIdentity cpid;
  unsigned int c;
  unsigned int type;

  cfg = (struct GNUNET_CONFIGURATION_Handle *) my_cfg;
  addresses = GNUNET_CONTAINER_multipeermap_create (10, GNUNET_NO);
  stat_results = 0;

  c = 0;
  if (NULL != opt_pid_str)
  {
    if (GNUNET_OK !=
        GNUNET_CRYPTO_eddsa_public_key_from_string (opt_pid_str,
                                                    strlen (opt_pid_str),
                                                    &pid.public_key))
    {
      fprintf (stderr, _ ("Failed to parse peer identity `%s'\n"), opt_pid_str);
      return;
    }
  }
  if (NULL != cpid_str)
  {
    if (GNUNET_OK !=
        GNUNET_CRYPTO_eddsa_public_key_from_string (cpid_str,
                                                    strlen (cpid_str),
                                                    &cpid.public_key))
    {
      fprintf (stderr, _ ("Failed to parse peer identity `%s'\n"), cpid_str);
      return;
    }
    c++;
  }

  c += opt_list_all + opt_list_used + opt_monitor + opt_set_pref;

  if (1 < c)
  {
    fprintf (stderr,
             _ ("Please select one operation: %s or %s or %s or %s or %s\n"),
             "--used",
             "--all",
             "--monitor",
             "--preference",
             "--quotas");
    return;
  }
  if (0 == c)
    opt_list_used = GNUNET_YES; /* set default */
  if (opt_print_quotas)
  {
    ret = print_quotas (cfg);
    return;
  }
  if (opt_list_all)
  {
    ph = GNUNET_ATS_performance_init (cfg, NULL, NULL);
    if (NULL == ph)
    {
      fprintf (stderr, "%s", _ ("Cannot connect to ATS service, exiting...\n"));
      return;
    }
    alh = GNUNET_ATS_performance_list_addresses (ph,
                                                 (NULL == opt_pid_str) ? NULL
                                                 : &pid,
                                                 GNUNET_YES,
                                                 &ats_perf_cb,
                                                 NULL);
    if (NULL == alh)
    {
      fprintf (stderr,
               "%s",
               _ ("Cannot issue request to ATS service, exiting...\n"));
      shutdown_task = GNUNET_SCHEDULER_add_now (&end, NULL);
      return;
    }
    shutdown_task = GNUNET_SCHEDULER_add_shutdown (&end, NULL);
    return;
  }
  if (opt_list_used)
  {
    ph = GNUNET_ATS_performance_init (cfg, NULL, NULL);
    if (NULL == ph)
      fprintf (stderr, "%s", _ ("Cannot connect to ATS service, exiting...\n"));

    alh = GNUNET_ATS_performance_list_addresses (ph,
                                                 (NULL == opt_pid_str) ? NULL
                                                 : &pid,
                                                 GNUNET_NO,
                                                 &ats_perf_cb,
                                                 NULL);
    if (NULL == alh)
    {
      fprintf (stderr,
               "%s",
               _ ("Cannot issue request to ATS service, exiting...\n"));
      shutdown_task = GNUNET_SCHEDULER_add_now (&end, NULL);
      return;
    }
    shutdown_task = GNUNET_SCHEDULER_add_shutdown (&end, NULL);
    return;
  }
  if (opt_monitor)
  {
    ph = GNUNET_ATS_performance_init (cfg, &ats_perf_mon_cb, NULL);
    shutdown_task = GNUNET_SCHEDULER_add_shutdown (&end, NULL);
    if (NULL == ph)
    {
      fprintf (stderr, "%s", _ ("Cannot connect to ATS service, exiting...\n"));
      GNUNET_SCHEDULER_shutdown ();
    }
    return;
  }
  if (opt_set_pref)
  {
    if (NULL == opt_type_str)
    {
      fprintf (stderr, "%s", _ ("No preference type given!\n"));
      return;
    }
    if (NULL == opt_pid_str)
    {
      fprintf (stderr, "%s", _ ("No peer given!\n"));
      return;
    }

    for (c = 0; c < strlen (opt_type_str); c++)
    {
      if (isupper ((unsigned char) opt_type_str[c]))
        opt_type_str[c] = tolower ((unsigned char) opt_type_str[c]);
    }

    if (0 == strcasecmp ("latency", opt_type_str))
      type = GNUNET_ATS_PREFERENCE_LATENCY;
    else if (0 == strcasecmp ("bandwidth", opt_type_str))
      type = GNUNET_ATS_PREFERENCE_BANDWIDTH;
    else
    {
      fprintf (stderr, "%s", _ ("Valid type required\n"));
      return;
    }

    /* set */
    ph = GNUNET_ATS_performance_init (cfg, NULL, NULL);
    if (NULL == ph)
      fprintf (stderr, "%s", _ ("Cannot connect to ATS service, exiting...\n"));

    GNUNET_ATS_performance_change_preference (ph,
                                              &pid,
                                              type,
                                              (double) opt_pref_value,
                                              GNUNET_ATS_PREFERENCE_END);

    shutdown_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS, &end, NULL);
    return;
  }
  if (NULL != cpid_str)
  {
    ats_ch = GNUNET_ATS_connectivity_init (cfg);
    ats_sh = GNUNET_ATS_connectivity_suggest (ats_ch, &cpid, 1000);
    shutdown_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS, &end, NULL);
    return;
  }
  ret = 1;
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

  opt_resolve_addresses_numeric = GNUNET_NO;
  opt_monitor = GNUNET_NO;
  opt_list_all = GNUNET_NO;
  opt_list_used = GNUNET_NO;
  opt_set_pref = GNUNET_NO;
  stat_pending = 0;
  stat_receive_done = GNUNET_NO;
  opt_type_str = NULL;

  struct GNUNET_GETOPT_CommandLineOption options[] =
  { GNUNET_GETOPT_option_flag ('u',
                               "used",
                               gettext_noop (
                                 "get list of active addresses currently used"),
                               &opt_list_used),
    GNUNET_GETOPT_option_flag ('a',
                               "all",
                               gettext_noop (
                                 "get list of all active addresses"),
                               &opt_list_all),

    GNUNET_GETOPT_option_string ('C',
                                 "connect",
                                 NULL,
                                 gettext_noop ("connect to PEER"),
                                 &cpid_str),
    GNUNET_GETOPT_option_flag ('n',
                               "numeric",
                               gettext_noop (
                                 "do not resolve IP addresses to hostnames"),
                               &opt_resolve_addresses_numeric),

    GNUNET_GETOPT_option_flag ('m',
                               "monitor",
                               gettext_noop ("monitor mode"),
                               &opt_monitor),

    GNUNET_GETOPT_option_flag ('p',
                               "preference",
                               gettext_noop (
                                 "set preference for the given peer"),
                               &opt_set_pref),

    GNUNET_GETOPT_option_flag ('q',
                               "quotas",
                               gettext_noop ("print all configured quotas"),
                               &opt_print_quotas),
    GNUNET_GETOPT_option_string ('i',
                                 "id",
                                 "TYPE",
                                 gettext_noop ("peer id"),
                                 &opt_pid_str),

    GNUNET_GETOPT_option_string ('t',
                                 "type",
                                 "TYPE",
                                 gettext_noop (
                                   "preference type to set: latency | bandwidth"),
                                 &opt_type_str),

    GNUNET_GETOPT_option_uint ('k',
                               "value",
                               "VALUE",
                               gettext_noop ("preference value"),
                               &opt_pref_value),

    GNUNET_GETOPT_option_flag (
      'V',
      "verbose",
      gettext_noop ("verbose output (include ATS address properties)"),
      &opt_verbose),
    GNUNET_GETOPT_OPTION_END };

  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;

  res = GNUNET_PROGRAM_run (argc,
                            argv,
                            "gnunet-ats",
                            gettext_noop ("Print information about ATS state"),
                            options,
                            &run,
                            NULL);
  GNUNET_free_non_null (opt_pid_str);
  GNUNET_free_non_null (opt_type_str);
  GNUNET_free_nz ((void *) argv);

  if (GNUNET_OK == res)
    return ret;
  else
    return 1;
}


/* end of gnunet-ats.c */
