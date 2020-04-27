/*
     This file is part of GNUnet.
     Copyright (C) 2012-2013, 2017-2018 GNUnet e.V.

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
 * @file gnunet-gns.c
 * @brief command line tool to access distributed GNS
 * @author Christian Grothoff
 */
#include "platform.h"
#if HAVE_LIBIDN2
#if HAVE_IDN2_H
#include <idn2.h>
#elif HAVE_IDN2_IDN2_H
#include <idn2/idn2.h>
#endif
#elif HAVE_LIBIDN
#if HAVE_IDNA_H
#include <idna.h>
#elif HAVE_IDN_IDNA_H
#include <idn/idna.h>
#endif
#endif
#include <gnunet_util_lib.h>
#include <gnunet_dnsparser_lib.h>
#include <gnunet_gnsrecord_lib.h>
#include <gnunet_namestore_service.h>
#include <gnunet_gns_service.h>


/**
 * Configuration we are using.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Handle to GNS service.
 */
static struct GNUNET_GNS_Handle *gns;

/**
 * GNS name to lookup. (-u option)
 */
static char *lookup_name;

/**
 * DNS IDNA name to lookup. (set if -d option is set)
 */
char *idna_name;

/**
 * DNS compatibility (name is given as DNS name, possible IDNA).
 */
static int dns_compat;

/**
 * record type to look up (-t option)
 */
static char *lookup_type;

/**
 * raw output
 */
static int raw;

/**
 * Desired record type.
 */
static uint32_t rtype;

/**
 * Timeout for lookup
 */
static struct GNUNET_TIME_Relative timeout;

/**
 * Timeout task
 */
static struct GNUNET_SCHEDULER_Task *to_task;

/**
 * Handle to lookup request
 */
static struct GNUNET_GNS_LookupWithTldRequest *lr;

/**
 * Global return value.
 * 0 on success (default),
 * 1 on internal failures
 * 2 on launch failure,
 * 4 if the name is not a GNS-supported TLD,
 */
static int global_ret;


/**
 * Task run on shutdown.  Cleans up everything.
 *
 * @param cls unused
 */
static void
do_shutdown (void *cls)
{
  (void) cls;
  if (NULL != to_task)
  {
    GNUNET_SCHEDULER_cancel (to_task);
    to_task = NULL;
  }
  if (NULL != lr)
  {
    GNUNET_GNS_lookup_with_tld_cancel (lr);
    lr = NULL;
  }
  if (NULL != gns)
  {
    GNUNET_GNS_disconnect (gns);
    gns = NULL;
  }
  if (NULL != idna_name)
  {
    GNUNET_free (idna_name);
    idna_name = NULL;
  }
}


/**
 * Task to run on timeout
 *
 * @param cls unused
 */
static void
do_timeout (void*cls)
{
  to_task = NULL;
  global_ret = 3; // Timeout
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Function called with the result of a GNS lookup.
 *
 * @param cls the 'const char *' name that was resolved
 * @param was_gns #GNUNET_NO if TLD did not indicate use of GNS
 * @param rd_count number of records returned
 * @param rd array of @a rd_count records with the results
 */
static void
process_lookup_result (void *cls,
                       int was_gns,
                       uint32_t rd_count,
                       const struct GNUNET_GNSRECORD_Data *rd)
{
  const char *name = cls;
  const char *typename;
  char *string_val;

  lr = NULL;
  if (GNUNET_NO == was_gns)
  {
    global_ret = 4;   /* not for GNS */
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  if (! raw)
  {
    if (0 == rd_count)
      printf ("No results.\n");
    else
      printf ("%s:\n", name);
  }
  for (uint32_t i = 0; i < rd_count; i++)
  {
    if ((rd[i].record_type != rtype) && (GNUNET_GNSRECORD_TYPE_ANY != rtype))
      continue;
    typename = GNUNET_GNSRECORD_number_to_typename (rd[i].record_type);
    string_val = GNUNET_GNSRECORD_value_to_string (rd[i].record_type,
                                                   rd[i].data,
                                                   rd[i].data_size);
    if (NULL == string_val)
    {
      fprintf (stderr,
               "Record %u of type %d malformed, skipping\n",
               (unsigned int) i,
               (int) rd[i].record_type);
      continue;
    }
    if (raw)
      printf ("%s\n", string_val);
    else
      printf ("Got `%s' record: %s%s\n",
              typename,
              string_val,
              (0 != (rd[i].flags & GNUNET_GNSRECORD_RF_SUPPLEMENTAL)) ?
              " (supplemental)" : "");
    GNUNET_free (string_val);
  }
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Main function that will be run.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param c configuration
 */
static void
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  (void) cls;
  (void) args;
  (void) cfgfile;

  cfg = c;
  to_task = NULL;
  {
    char *colon;

    if (NULL != (colon = strchr (lookup_name, ':')))
      *colon = '\0';
  }

  /**
   * If DNS compatibility is requested, we first verify that the
   * lookup_name is in a DNS format. If yes, we convert it to UTF-8.
   */
  if (GNUNET_YES == dns_compat)
  {
    Idna_rc rc;

    if (GNUNET_OK != GNUNET_DNSPARSER_check_name (lookup_name))
    {
      fprintf (stderr,
               _ ("`%s' is not a valid DNS domain name\n"),
               lookup_name);
      global_ret = 3;
      return;
    }
    if (IDNA_SUCCESS !=
        (rc = idna_to_unicode_8z8z (lookup_name, &idna_name,
                                    IDNA_ALLOW_UNASSIGNED)))
    {
      fprintf (stderr,
               _ ("Failed to convert DNS IDNA name `%s' to UTF-8: %s\n"),
               lookup_name,
               idna_strerror (rc));
      global_ret = 4;
      return;
    }
    lookup_name = idna_name;
  }

  if (GNUNET_YES !=
      GNUNET_CLIENT_test (cfg,
                          "arm"))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _ ("Cannot resolve using GNS: GNUnet peer not running\n"));
    global_ret = 2;
    return;
  }
  to_task = GNUNET_SCHEDULER_add_delayed (timeout,
                                          &do_timeout,
                                          NULL);
  gns = GNUNET_GNS_connect (cfg);
  if (NULL == gns)
  {
    fprintf (stderr,
             _ ("Failed to connect to GNS\n"));
    global_ret = 2;
    return;
  }
  GNUNET_SCHEDULER_add_shutdown (&do_shutdown,
                                 NULL);
  if (NULL != lookup_type)
    rtype = GNUNET_GNSRECORD_typename_to_number (lookup_type);
  else
    rtype = GNUNET_DNSPARSER_TYPE_A;
  if (UINT32_MAX == rtype)
  {
    fprintf (stderr,
             _ ("Invalid typename specified, assuming `ANY'\n"));
    rtype = GNUNET_GNSRECORD_TYPE_ANY;
  }
  lr = GNUNET_GNS_lookup_with_tld (gns,
                                   lookup_name,
                                   rtype,
                                   GNUNET_GNS_LO_DEFAULT,
                                   &process_lookup_result,
                                   lookup_name);
  if (NULL == lr)
  {
    global_ret = 2;
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
}


/**
 * The main function for gnunet-gns.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  timeout = GNUNET_TIME_UNIT_FOREVER_REL;
  struct GNUNET_GETOPT_CommandLineOption options[] =
  { GNUNET_GETOPT_option_mandatory (
      GNUNET_GETOPT_option_string ('u',
                                   "lookup",
                                   "NAME",
                                   gettext_noop (
                                     "Lookup a record for the given name"),
                                   &lookup_name)),
    GNUNET_GETOPT_option_string ('t',
                                 "type",
                                 "TYPE",
                                 gettext_noop (
                                   "Specify the type of the record to lookup"),
                                 &lookup_type),
    GNUNET_GETOPT_option_relative_time ('T',
                                        "timeout",
                                        "TIMEOUT",
                                        gettext_noop (
                                          "Specify a timeout for the lookup"),
                                        &timeout),
    GNUNET_GETOPT_option_flag ('r',
                               "raw",
                               gettext_noop ("No unneeded output"),
                               &raw),
    GNUNET_GETOPT_option_flag ('d',
                               "dns",
                               gettext_noop (
                                 "DNS Compatibility: Name is passed in IDNA instead of UTF-8"),
                               &dns_compat),
    GNUNET_GETOPT_OPTION_END };
  int ret;

  if (GNUNET_OK !=
      GNUNET_STRINGS_get_utf8_args (argc, argv,
                                    &argc, &argv))
    return 2;

  GNUNET_log_setup ("gnunet-gns", "WARNING", NULL);
  ret = GNUNET_PROGRAM_run (argc,
                            argv,
                            "gnunet-gns",
                            _ ("GNUnet GNS resolver tool"),
                            options,
                            &run,
                            NULL);
  GNUNET_free_nz ((void *) argv);
  if (GNUNET_OK != ret)
    return 1;
  return global_ret;
}


/* end of gnunet-gns.c */
