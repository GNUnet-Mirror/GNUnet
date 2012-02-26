/*
     This file is part of GNUnet.
     (C) 2010,2011 Christian Grothoff (and other contributing authors)

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
 * @file ats/ats_api.c
 * @brief automatic transport selection API
 * @author Christian Grothoff
 * @author Matthias Wachs
 *
 * TODO:
 * - write test case
 * - extend API to get performance data
 * - implement simplistic strategy based on say 'lowest latency' or strict ordering
 * - extend API to get peer preferences, implement proportional bandwidth assignment
 * - re-implement API against a real ATS service (!)
 */
#include "platform.h"
#include "gnunet_ats_service.h"
#include "gnunet_transport_service.h"

#define VERBOSE GNUNET_NO

#define VERBOSE_ARM GNUNET_NO

#define START_ARM GNUNET_YES

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)

#define VALID GNUNET_TIME_absolute_get_forever ()

static struct GNUNET_ATS_SchedulingHandle *ats;

static struct GNUNET_ATS_SuggestionContext *asc;

static struct GNUNET_PeerIdentity peer;

static GNUNET_SCHEDULER_TaskIdentifier end_task;

static struct AllocationRecord *ar;

static int result;

struct ExpectedValues
{
  int expected_ats_count;

  int expected_ats_type;

  int expected_ats_value;

  int expected_in_index;
};

struct AllocationRecord
{

  /**
   * Performance information associated with this address (array).
   */
  struct GNUNET_ATS_Information *ats;

  /**
   * Name of the plugin
   */
  char *plugin_name;

  /**
   * Address this record represents, allocated at the end of this struct.
   */
  const void *plugin_addr;

  /**
   * Session associated with this record.
   */
  struct Session *session;

  /**
   * Number of bytes in plugin_addr.
   */
  size_t plugin_addr_len;

  /**
   * Number of entries in 'ats'.
   */
  uint32_t ats_count;
};

static void
end (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Shutdown\n");
  if (asc != NULL)
  {
    GNUNET_ATS_suggest_address_cancel (asc);
    asc = NULL;
  }
  GNUNET_ATS_shutdown (ats);

  GNUNET_array_grow (ar->ats, ar->ats_count, 0);
  GNUNET_free (ar);
}

void
suggest_cb (void *cls, const struct GNUNET_PeerIdentity *peer,
            const char *plugin_name, const void *plugin_addr,
            size_t plugin_addr_len, struct Session *session,
            struct GNUNET_BANDWIDTH_Value32NBO bandwidth,
            const struct GNUNET_ATS_Information *ats, uint32_t ats_count)
{
  struct ExpectedValues *ex = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "ATS suggested address for peer `%s': `%s' `%s'\n",
              GNUNET_i2s (peer), plugin_name, plugin_addr);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "ATS count %u\n", ats_count);

  int c = 0;

  while (c < ats_count)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "ats[%u]: type %u value %u\n", c,
                ntohl (ats[c].type), ntohl (ats[c].value));

    c++;
  }

  if (ex->expected_ats_count != GNUNET_SYSERR)
    GNUNET_assert (ex->expected_ats_count == ats_count);

  if ((ex->expected_ats_value != GNUNET_SYSERR) &&
      (ex->expected_in_index != GNUNET_SYSERR))
    GNUNET_assert (ex->expected_ats_value ==
                   ntohl (ats[ex->expected_in_index].value));

  if ((ex->expected_ats_type != GNUNET_SYSERR) &&
      (ex->expected_in_index != GNUNET_SYSERR))
    GNUNET_assert (ex->expected_ats_type ==
                   ntohl (ats[ex->expected_in_index].type));


}

static void
check (void *cls, char *const *args, const char *cfgfile,
       const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct ExpectedValues ex;

  GNUNET_CRYPTO_hash_create_random (GNUNET_CRYPTO_QUALITY_WEAK,
                                    &peer.hashPubKey);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Created peer identity `%s'\n",
              GNUNET_i2s (&peer));

  ats = GNUNET_ATS_init (cfg, NULL, NULL);
  GNUNET_assert (ats != NULL);

  end_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT, &end, NULL);

  ar = GNUNET_malloc (sizeof (struct AllocationRecord));

  ar->plugin_name = "test";
  ar->session = NULL;
  ar->plugin_addr = "address1";
  ar->plugin_addr_len = strlen (ar->plugin_addr) + 1;
  ar->ats = GNUNET_malloc (sizeof (struct GNUNET_ATS_Information));

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Initial ATS information\n");
  ar->ats_count = 1;
  ar->ats[0].type = htonl (0);
  ar->ats[0].value = htonl (0);

  ex.expected_ats_count = 1;
  ex.expected_ats_type = 0;
  ex.expected_ats_value = 0;
  ex.expected_in_index = 0;

  GNUNET_ATS_address_update (ats, &peer, VALID, ar->plugin_name, ar->session,
                             ar->plugin_addr, ar->plugin_addr_len, ar->ats,
                             ar->ats_count);
  asc = GNUNET_ATS_suggest_address (ats, &peer, &suggest_cb, &ex);

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Extending empty ATS information\n");

  GNUNET_array_grow (ar->ats, ar->ats_count, ar->ats_count + 1);
  ar->ats[0].type = htonl (1);
  ar->ats[0].value = htonl (1);
  ar->ats[1].type = htonl (0);
  ar->ats[1].value = htonl (0);

  ex.expected_ats_count = 2;
  ex.expected_ats_type = 1;
  ex.expected_ats_value = 1;
  ex.expected_in_index = 0;

  GNUNET_ATS_address_update (ats, &peer, VALID, ar->plugin_name, ar->session,
                             ar->plugin_addr, ar->plugin_addr_len, ar->ats,
                             ar->ats_count);
  asc = GNUNET_ATS_suggest_address (ats, &peer, &suggest_cb, &ex);

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Updating existing ATS information\n");

  ar->ats[0].type = htonl (1);
  ar->ats[0].value = htonl (2);
  ar->ats[1].type = htonl (0);
  ar->ats[1].value = htonl (0);

  ex.expected_ats_count = 2;
  ex.expected_ats_type = 1;
  ex.expected_ats_value = 2;
  ex.expected_in_index = 0;

  GNUNET_ATS_address_update (ats, &peer, VALID, ar->plugin_name, ar->session,
                             ar->plugin_addr, ar->plugin_addr_len, ar->ats,
                             ar->ats_count);
  asc = GNUNET_ATS_suggest_address (ats, &peer, &suggest_cb, &ex);

  /* Extending existing ATS information */
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Extending existing ATS information\n");


  ar->ats[0].type = htonl (2);
  ar->ats[0].value = htonl (2);
  ar->ats[1].type = htonl (0);
  ar->ats[1].value = htonl (0);

  ex.expected_ats_count = 3;
  ex.expected_ats_type = 2;
  ex.expected_ats_value = 2;
  ex.expected_in_index = 1;

  GNUNET_ATS_address_update (ats, &peer, VALID, ar->plugin_name, ar->session,
                             ar->plugin_addr, ar->plugin_addr_len, ar->ats,
                             ar->ats_count);
  asc = GNUNET_ATS_suggest_address (ats, &peer, &suggest_cb, &ex);

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Updating existing ATS information\n");

  ar->ats[0].type = htonl (2);
  ar->ats[0].value = htonl (3);
  ar->ats[1].type = htonl (0);
  ar->ats[1].value = htonl (0);

  ex.expected_ats_count = 3;
  ex.expected_ats_type = 2;
  ex.expected_ats_value = 3;
  ex.expected_in_index = 1;

  GNUNET_ATS_address_update (ats, &peer, VALID, ar->plugin_name, ar->session,
                             ar->plugin_addr, ar->plugin_addr_len, ar->ats,
                             ar->ats_count);
  asc = GNUNET_ATS_suggest_address (ats, &peer, &suggest_cb, &ex);

  if (end_task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (end_task);
  end_task = GNUNET_SCHEDULER_add_now (&end, NULL);
}

int
main (int argc, char *argv1[])
{
  static char *const argv[] = { "test_ats_api_update_address",
    "-c",
    "test_ats_api.conf",
#if VERBOSE
    "-L", "DEBUG",
#else
    "-L", "WARNING",
#endif
    NULL
  };

  static struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1, argv,
                      "test_ats_api_update_address", "nohelp", options, &check,
                      NULL);

  return result;
}
