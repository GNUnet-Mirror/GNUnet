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

/**
 * Final status code.
 */
static int ret;
static int results;
static int resolve_addresses_numeric;
static int monitor;

static struct GNUNET_ATS_PerformanceHandle *ph;

static struct GNUNET_CONFIGURATION_Handle *cfg;

GNUNET_SCHEDULER_TaskIdentifier end_task;

struct PendingResolutions
{
  struct PendingResolutions *next;
  struct PendingResolutions *prev;

  struct GNUNET_HELLO_Address *address;
  struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out;
  struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in;

  struct GNUNET_TRANSPORT_AddressToStringContext * tats_ctx;
};

struct PendingResolutions *head;
struct PendingResolutions *tail;

void transport_addr_to_str_cb (void *cls, const char *address)
{
  struct PendingResolutions * pr = cls;
  if (NULL != address)
  {
      fprintf (stderr, _("Peer `%s' plugin `%s', address `%s', bandwidth out: %u Bytes/s, bandwidth in %u Bytes/s\n"),
        GNUNET_i2s (&pr->address->peer), pr->address->transport_name, address,
        ntohl (pr->bandwidth_out.value__), ntohl (pr->bandwidth_in.value__));
  }
  else if (NULL != pr)
  {
      /* We're done */
      GNUNET_CONTAINER_DLL_remove (head, tail, pr);
      GNUNET_free (pr->address);
      GNUNET_free (pr);
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

  pr = GNUNET_malloc (sizeof (struct PendingResolutions));
  pr->address = GNUNET_HELLO_address_copy (address);
  pr->bandwidth_in = bandwidth_in;
  pr->bandwidth_out = bandwidth_out;
  pr->tats_ctx = GNUNET_TRANSPORT_address_to_string(cfg, address,
                    resolve_addresses_numeric, GNUNET_TIME_UNIT_FOREVER_REL, transport_addr_to_str_cb, pr);
  GNUNET_CONTAINER_DLL_insert (head, tail, pr);
  results++;
}

void end (void *cls,
          const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct PendingResolutions * pr;
  struct PendingResolutions * next;
  unsigned int pending;

  GNUNET_ATS_performance_done (ph);
  ph = NULL;

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

void testservice_ats (void *cls,
               const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_CONFIGURATION_Handle *cfg = cls;

  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_TIMEOUT))
  {
      FPRINTF (stderr, _("Service `%s' is not running\n"), "ats");
      return;
  }

  results = 0;
  ph = GNUNET_ATS_performance_init (cfg, ats_perf_cb, NULL);
  if (NULL == ph)
    fprintf (stderr, _("Cannot connect to ATS service, exiting...\n"));

  if (GNUNET_NO == monitor)
    end_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT, &end, NULL);
  else
    end_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &end, NULL);
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
  monitor = GNUNET_NO;

  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
      {'n', "numeric", NULL,
       gettext_noop ("do not resolve hostnames"),
       0, &GNUNET_GETOPT_set_one, &resolve_addresses_numeric},
       {'m', "monitor", NULL,
        gettext_noop ("monitor mode"),
        0, &GNUNET_GETOPT_set_one, &monitor},
    GNUNET_GETOPT_OPTION_END
  };

  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;

  res = GNUNET_PROGRAM_run (argc, argv, "gnunet-ats",
                              gettext_noop ("Print information about ATS state"), options, &run,
                              NULL);
  GNUNET_free ((void *) argv);

  if (GNUNET_OK == res)
    return ret;
  else
    return 1;

}

/* end of gnunet-ats.c */
