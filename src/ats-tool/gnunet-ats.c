/*
 This file is part of GNUnet.
 (C) 2009--2013 Christian Grothoff (and other contributing authors)

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
 * ATS performance handle used
 */
static struct GNUNET_ATS_PerformanceHandle *ph;

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
static GNUNET_SCHEDULER_TaskIdentifier shutdown_task;

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
   * Array of performance data.
   */
  struct GNUNET_ATS_Information *ats;

  /**
   * Length of the @e ats array.
   */
  uint32_t ats_count;

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
free_addr_it (void *cls,
              const struct GNUNET_PeerIdentity *key,
              void *value)
{
  struct ATSAddress *a = value;
  GNUNET_assert (GNUNET_OK == GNUNET_CONTAINER_multipeermap_remove (addresses, key, value));
  GNUNET_HELLO_address_free (a->address);
  GNUNET_free (a);
  return GNUNET_OK;
}


/**
 * Task run on shutdown.
 *
 * @param cls NULL
 * @param tc scheduler context
 */
static void
end (void *cls,
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
    GNUNET_CONTAINER_DLL_remove(head, tail, pr);
    GNUNET_TRANSPORT_address_to_string_cancel (pr->tats_ctx);
    GNUNET_free(pr->address);
    GNUNET_free(pr);
    pending++;
  }
  GNUNET_CONTAINER_multipeermap_iterate (addresses,
                                         &free_addr_it,
                                         NULL);
  GNUNET_CONTAINER_multipeermap_destroy (addresses);
  addresses = NULL;

  if (0 < pending)
    FPRINTF (stderr,
             _("%u address resolutions had a timeout\n"),
             pending);
  if (opt_list_used || opt_list_all)
    FPRINTF (stderr,
             _("ATS returned stat_results for %u addresses\n"),
             stat_results);
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
transport_addr_to_str_cb (void *cls,
                          const char *address,
                          int res)
{
  struct PendingResolutions *pr = cls;
  char *ats_str;
  char *ats_tmp;
  char *ats_prop_arr[GNUNET_ATS_PropertyCount] = GNUNET_ATS_PropertyStrings;
  char *ats_prop_value;
  unsigned int c;
  uint32_t ats_type;
  uint32_t ats_value;
  uint32_t network;

  if (NULL == address)
  {
    /* We're done */
    GNUNET_CONTAINER_DLL_remove(head, tail, pr);
    GNUNET_free(pr->address);
    GNUNET_free(pr);
    stat_pending--;

    if ((GNUNET_YES == stat_receive_done) && (0 == stat_pending))
    {
      /* All messages received and no resolutions pending*/
      if (shutdown_task != GNUNET_SCHEDULER_NO_TASK)
        GNUNET_SCHEDULER_cancel (shutdown_task);
      shutdown_task = GNUNET_SCHEDULER_add_now (end, NULL);
    }
    return;
  }
  switch (res)
  {
  case GNUNET_SYSERR:
    FPRINTF (stderr,
             "Failed to convert address for peer `%s' plugin `%s' length %u to string (communication error)\n",
             GNUNET_i2s (&pr->address->peer),
             pr->address->transport_name,
             (unsigned int) pr->address->address_length);
    return;
  case GNUNET_NO:
    FPRINTF (stderr,
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

  ats_str = GNUNET_strdup (pr->active ? _("active ") : _("inactive "));
  network = GNUNET_ATS_NET_UNSPECIFIED;
  for (c = 0; c < pr->ats_count; c++)
  {
    ats_tmp = ats_str;

    ats_type = ntohl (pr->ats[c].type);
    ats_value = ntohl (pr->ats[c].value);

    if (ats_type > GNUNET_ATS_PropertyCount)
    {
      FPRINTF (stderr,
               "Invalid ATS property type %u %u for address %s\n",
               ats_type,
               pr->ats[c].type,
               address);
      continue;
    }

    switch (ats_type)
    {
    case GNUNET_ATS_NETWORK_TYPE:
      if (ats_value > GNUNET_ATS_NetworkTypeCount)
      {
        GNUNET_break(0);
        continue;
      }
      network = ats_value;
      GNUNET_asprintf (&ats_prop_value,
                       "%s",
                       GNUNET_ATS_print_network_type (ats_value));
      break;
    default:
      GNUNET_asprintf (&ats_prop_value, "%u", ats_value);
      break;
    }
    if ((opt_verbose) && (ats_type < GNUNET_ATS_PropertyCount))
    {
      GNUNET_asprintf (&ats_str,
                       "%s%s=%s, ",
                       ats_tmp,
                       ats_prop_arr[ats_type],
                       ats_prop_value);
      GNUNET_free(ats_tmp);
    }
    GNUNET_free(ats_prop_value);
  }

  FPRINTF (stderr,
           _("Peer `%s' plugin `%s', address `%s', `%s' bw out: %u Bytes/s, bw in %u Bytes/s, %s\n"),
           GNUNET_i2s (&pr->address->peer),
           pr->address->transport_name,
           address,
           GNUNET_ATS_print_network_type (network),
           ntohl (pr->bandwidth_out.value__),
           ntohl (pr->bandwidth_in.value__),
           ats_str);
  GNUNET_free (ats_str);
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
find_address_it (void *cls,
                 const struct GNUNET_PeerIdentity *key,
                 void *value)
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
 * @param ats performance data for the address (as far as known)
 * @param ats_count number of performance records in @a ats
 */
static void
ats_perf_mon_cb (void *cls,
                 const struct GNUNET_HELLO_Address *address,
                 int active,
                 struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out,
                 struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in,
                 const struct GNUNET_ATS_Information *ats,
                 uint32_t ats_count)
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

    GNUNET_CONTAINER_multipeermap_iterate (addresses,
                                           &free_addr_it,
                                           NULL);
    return;
  }
  if (GNUNET_SYSERR == active)
  {
    /* remove address */
    struct AddressFindCtx actx;

    actx.src = address;
    actx.res = NULL;
    GNUNET_CONTAINER_multipeermap_get_multiple (addresses, &address->peer,
        &find_address_it, &actx);
    if (NULL == actx.res)
    {
      GNUNET_break (0);
      return;
    }
    GNUNET_break(
        GNUNET_OK == GNUNET_CONTAINER_multipeermap_remove (addresses, &address->peer, actx.res));
    FPRINTF (stderr,
             _("Removed address of peer `%s' with plugin `%s'\n"),
             GNUNET_i2s (&address->peer),
             actx.res->address->transport_name);
    GNUNET_HELLO_address_free (actx.res);
    GNUNET_free (actx.res);
    return;
  }

  if (GNUNET_NO == opt_verbose)
  {
    struct AddressFindCtx actx;
    struct ATSAddress *a;

    actx.src = address;
    actx.res = NULL;
    GNUNET_CONTAINER_multipeermap_get_multiple (addresses, &address->peer,
        &find_address_it, &actx);
    if ((NULL != actx.res))
    {
      if ((bandwidth_in.value__ == actx.res->bandwidth_in.value__) &&
          (bandwidth_out.value__ == actx.res->bandwidth_out.value__) &&
          (active == actx.res->active))
      {
        return; /* Nothing to do here */
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

      a->address = GNUNET_HELLO_address_copy(address);
      a->bandwidth_in = bandwidth_in;
      a->bandwidth_out = bandwidth_out;
      a->active = active;
      GNUNET_CONTAINER_multipeermap_put (addresses, &address->peer, a,
          GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
    }
  }

  pr = GNUNET_malloc (sizeof (struct PendingResolutions) +
      ats_count * sizeof (struct GNUNET_ATS_Information));

  pr->ats_count = ats_count;
  pr->ats = (struct GNUNET_ATS_Information *) &pr[1];
  if (ats_count > 0)
    memcpy (pr->ats, ats, ats_count * sizeof(struct GNUNET_ATS_Information));
  pr->address = GNUNET_HELLO_address_copy (address);
  pr->bandwidth_in = bandwidth_in;
  pr->bandwidth_out = bandwidth_out;
  pr->active = active;
  pr->tats_ctx = GNUNET_TRANSPORT_address_to_string (cfg, address,
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
 * @param ats performance data for the address (as far as known)
 * @param ats_count number of performance records in @a ats
 */
static void
ats_perf_cb (void *cls,
             const struct GNUNET_HELLO_Address *address,
             int active,
             struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out,
             struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in,
             const struct GNUNET_ATS_Information *ats,
             uint32_t ats_count)
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
      if (shutdown_task != GNUNET_SCHEDULER_NO_TASK)
        GNUNET_SCHEDULER_cancel (shutdown_task);
      shutdown_task = GNUNET_SCHEDULER_add_now (end, NULL);
    }
    return;
  }

  pr = GNUNET_malloc (sizeof (struct PendingResolutions) +
      ats_count * sizeof (struct GNUNET_ATS_Information));

  pr->ats_count = ats_count;
  pr->ats = (struct GNUNET_ATS_Information *) &pr[1];
  if (ats_count > 0)
    memcpy (pr->ats, ats, ats_count * sizeof(struct GNUNET_ATS_Information));
  pr->address = GNUNET_HELLO_address_copy (address);
  pr->bandwidth_in = bandwidth_in;
  pr->bandwidth_out = bandwidth_out;
  pr->active = active;
  pr->tats_ctx = GNUNET_TRANSPORT_address_to_string (cfg, address,
                                                     opt_resolve_addresses_numeric,
                                                     GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10),
                                                     &transport_addr_to_str_cb, pr);
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

    GNUNET_asprintf (&entry_out,
                     "%s_QUOTA_OUT",
                     network_str[c]);
    GNUNET_asprintf (&entry_in,
                     "%s_QUOTA_IN",
                     network_str[c]);

    /* quota out */
    if (GNUNET_OK ==
        GNUNET_CONFIGURATION_get_value_string (cfg,
                                               "ats",
                                               entry_out,
                                               &quota_out_str))
    {
      if (0 == strcmp (quota_out_str, UNLIMITED_STRING)
          || (GNUNET_SYSERR ==
              GNUNET_STRINGS_fancy_size_to_bytes (quota_out_str,
                                                  &quota_out)))
        quota_out = UINT32_MAX;

      GNUNET_free(quota_out_str);
      GNUNET_asprintf (&quota_out_str, "%llu", quota_out);
    }
    else
    {
      FPRINTF (stderr,
               "Outbound quota for network `%11s' not configured!\n",
               network_str[c]);
      GNUNET_asprintf (&quota_out_str, "-");
    }
    GNUNET_free(entry_out);

    /* quota in */
    if (GNUNET_OK ==
        GNUNET_CONFIGURATION_get_value_string (cfg,
                                               "ats",
                                               entry_in,
                                               &quota_in_str))
    {
      if (0 == strcmp (quota_in_str, UNLIMITED_STRING)
          || (GNUNET_SYSERR ==
              GNUNET_STRINGS_fancy_size_to_bytes (quota_in_str, &quota_in)))
        quota_in = UINT32_MAX;
      GNUNET_free(quota_in_str);
      GNUNET_asprintf (&quota_in_str, "%llu", quota_in);
    }
    else
    {
      FPRINTF (stderr,
               "Inbound quota for network `%11s' not configured!\n",
               network_str[c]);
      GNUNET_asprintf (&quota_in_str, "-");
    }
    GNUNET_free(entry_in);

    FPRINTF (stderr,
             _("Quota for network `%11s' (in/out): %10s / %10s\n"),
             network_str[c],
             quota_in_str,
             quota_out_str);
    GNUNET_free(quota_out_str);
    GNUNET_free(quota_in_str);
  }
  return GNUNET_ATS_NetworkTypeCount;
}


/**
 * Function called with the result from the test if ATS is
 * running.  Runs the actual main logic.
 *
 * @param cls the `struct GNUNET_CONFIGURATION_Handle *`
 * @param result result of the test, #GNUNET_YES if ATS is running
 */
static void
testservice_ats (void *cls,
                 int result)
{
  struct GNUNET_CONFIGURATION_Handle *cfg = cls;
  struct GNUNET_PeerIdentity pid;
  unsigned int c;
  unsigned int type;

  addresses = GNUNET_CONTAINER_multipeermap_create (10, GNUNET_NO);

  if (GNUNET_YES != result)
  {
    FPRINTF (stderr,
             _("Service `%s' is not running\n"),
             "ats");
    return;
  }

  stat_results = 0;

  if (NULL != opt_pid_str)
  {
    if (GNUNET_OK
        != GNUNET_CRYPTO_eddsa_public_key_from_string (opt_pid_str,
            strlen (opt_pid_str), &pid.public_key))
    {
      FPRINTF (stderr,
               _("Failed to parse peer identity `%s'\n"),
               opt_pid_str);
      return;
    }
  }

  c = opt_list_all + opt_list_used + opt_monitor + opt_set_pref;
  if ((1 < c))
  {
    FPRINTF (stderr,
             _("Please select one operation : %s or %s or %s or %s or %s\n"),
             "--used",
             "--all",
             "--monitor",
             "--preference",
             "--quotas");
    return;
  }
  if ((0 == c))
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
      FPRINTF (stderr,
               "%s",
               _("Cannot connect to ATS service, exiting...\n"));
      return;
    }

    alh = GNUNET_ATS_performance_list_addresses (ph,
                                                 (NULL == opt_pid_str) ? NULL : &pid,
                                                 GNUNET_YES,
                                                 &ats_perf_cb, NULL);
    if (NULL == alh)
    {
      FPRINTF (stderr,
               "%s",
               _("Cannot issue request to ATS service, exiting...\n"));
      shutdown_task = GNUNET_SCHEDULER_add_now (&end, NULL);
      return;
    }
    shutdown_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
                                             &end,
                                             NULL);
  }
  else if (opt_list_used)
  {
    ph = GNUNET_ATS_performance_init (cfg, NULL, NULL);
    if (NULL == ph)
      FPRINTF (stderr,
               "%s",
               _("Cannot connect to ATS service, exiting...\n"));

    alh = GNUNET_ATS_performance_list_addresses (ph,
                                                 (NULL == opt_pid_str)
                                                 ? NULL
                                                 : &pid,
                                                 GNUNET_NO,
                                                 &ats_perf_cb, NULL);
    if (NULL == alh)
    {
      FPRINTF (stderr,
               "%s",
               _("Cannot issue request to ATS service, exiting...\n"));
      shutdown_task = GNUNET_SCHEDULER_add_now (&end, NULL);
      return;
    }
    shutdown_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
                                             &end,
                                             NULL);
  }
  else if (opt_monitor)
  {
    ph = GNUNET_ATS_performance_init (cfg,
                                      &ats_perf_mon_cb,
                                      NULL);
    if (NULL == ph)
      FPRINTF (stderr,
               "%s",
               _("Cannot connect to ATS service, exiting...\n"));
    shutdown_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
                                             &end,
                                             NULL);

  }
  else if (opt_set_pref)
  {
    if (NULL == opt_type_str)
    {
      FPRINTF (stderr,
               "%s",
               _("No preference type given!\n"));
      return;
    }
    if (NULL == opt_pid_str)
    {
      FPRINTF (stderr,
               "%s",
               _("No peer given!\n"));
      return;
    }

    for (c = 0; c < strlen (opt_type_str); c++)
    {
      if (isupper (opt_type_str[c]))
        opt_type_str[c] = tolower (opt_type_str[c]);
    }

    if (0 == strcasecmp ("latency", opt_type_str))
      type = GNUNET_ATS_PREFERENCE_LATENCY;
    else if (0 == strcasecmp ("bandwidth", opt_type_str))
      type = GNUNET_ATS_PREFERENCE_BANDWIDTH;
    else
    {
      FPRINTF (stderr,
               "%s",
               _("Valid type required\n"));
      return;
    }

    /* set */
    ph = GNUNET_ATS_performance_init (cfg, NULL, NULL);
    if (NULL == ph)
      FPRINTF (stderr,
               "%s",
               _("Cannot connect to ATS service, exiting...\n"));

    GNUNET_ATS_performance_change_preference (ph, &pid, type, (double) opt_pref_value,
                                              GNUNET_ATS_PREFERENCE_END);

    shutdown_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
                                             &end,
                                             NULL);
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
run (void *cls,
     char * const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *my_cfg)
{
  cfg = (struct GNUNET_CONFIGURATION_Handle *) my_cfg;
  GNUNET_CLIENT_service_test ("ats", cfg,
      GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5),
      &testservice_ats, (void *) cfg);
}


/**
 * The main function.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc,
      char * const *argv)
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

  static const struct GNUNET_GETOPT_CommandLineOption options[] =
  {
  { 'u', "used", NULL,
      gettext_noop ("get list of active addresses currently used"), 0,
      &GNUNET_GETOPT_set_one, &opt_list_used },
  { 'a', "all", NULL, gettext_noop ("get list of all active addresses"), 0,
      &GNUNET_GETOPT_set_one, &opt_list_all },
  { 'n', "numeric", NULL,
      gettext_noop ("do not resolve IP addresses to hostnames"), 0,
      &GNUNET_GETOPT_set_one, &opt_resolve_addresses_numeric },
  { 'm', "monitor", NULL, gettext_noop ("monitor mode"), 0,
      &GNUNET_GETOPT_set_one, &opt_monitor },
  { 'p', "preference", NULL, gettext_noop ("set preference for the given peer"),
      0, &GNUNET_GETOPT_set_one, &opt_set_pref },
  { 'q', "quotas", NULL, gettext_noop ("print all configured quotas"), 0,
      &GNUNET_GETOPT_set_one, &opt_print_quotas },
  { 'i', "id", "TYPE", gettext_noop ("peer id"), 1, &GNUNET_GETOPT_set_string,
      &opt_pid_str },
  { 't', "type", "TYPE",
      gettext_noop ("preference type to set: latency | bandwidth"), 1,
      &GNUNET_GETOPT_set_string, &opt_type_str },
  { 'k', "value", "VALUE", gettext_noop ("preference value"), 1,
      &GNUNET_GETOPT_set_uint, &opt_pref_value },
  { 'V', "verbose", NULL,
      gettext_noop ("verbose output (include ATS address properties)"), 0,
      &GNUNET_GETOPT_set_one, &opt_verbose }, GNUNET_GETOPT_OPTION_END };

  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;

  res = GNUNET_PROGRAM_run (argc, argv, "gnunet-ats",
                            gettext_noop ("Print information about ATS state"),
                            options,
                            &run, NULL);
  GNUNET_free_non_null(opt_pid_str);
  GNUNET_free_non_null(opt_type_str);
  GNUNET_free((void *) argv);

  if (GNUNET_OK == res)
    return ret;
  else
    return 1;

}

/* end of gnunet-ats.c */
