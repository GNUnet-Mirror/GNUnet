/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

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
 * @file testing/test_transport_ats.c
 * @brief testcase for ats functionality without starting peers
 */
#include "platform.h"
#include "gnunet-service-transport_ats.h"
#include "gnunet_configuration_lib.h"
#include "gnunet_crypto_lib.h"

#define VERBOSE GNUNET_YES

static struct ATS_Handle *ats;

static struct GNUNET_CONFIGURATION_Handle *cfg;

static struct TransportConfiguration *tc;


static void
ats_result_cb ()
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "ATS Result callback\n");
}

struct TransportConfiguration
{
  int peers;
  int mechanisms;

  struct ATS_peer *p_head;
  struct ATS_peer *p_tail;

  struct ATS_mechanism *m_head;
  struct ATS_mechanism *m_tail;
};


static void
create_ats_information (struct ATS_peer **p, int *c_p, struct ATS_mechanism **m,
                        int *c_m)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "ATS needs addresses\n");

  (*p) = tc->p_head;
  (*c_p) = tc->mechanisms;
  (*m) = tc->m_head;
  (*c_m) = tc->mechanisms;
}


static int
run_ats ()
{
  int ret = 0;

  ats_calculate_bandwidth_distribution (ats);
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Running ATS: %s \n",
              (ret == 0) ? "SUCCESSFUL" : "FAILED");
  return ret;
}


static int
init_ats ()
{
  int ret = 0;

  ats =
      ats_init (1.0, 1.0, 1.0, 50000, 5, 10, ATS_MAX_EXEC_DURATION,
                create_ats_information, ats_result_cb);
  //GNUNET_assert (ats != NULL);

  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Initializing ATS: %s \n",
              (ret == 0) ? "SUCCESSFUL" : "FAILED");
  return ret;
}


static int
shutdown_ats ()
{
  int ret = 0;

  ats_delete_problem (ats);
  ats_shutdown (ats);
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Shutdown ATS: %s \n",
              (ret == 0) ? "SUCCESSFUL" : "FAILED");
  return ret;
}


/* To make compiler happy */
void
dummy ()
{
  struct ATS_quality_metric *q = qm;

  q = NULL;
  struct ATS_ressource *r = ressources;

  r = NULL;
  q++;
  r++;
}


static void
iterate_peer_values (void *cls, const char *section, const char *option,
                     const char *value)
{
  if (strcmp (option, "f") == 0)
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "\t %s %s\n", option, value);
}

static void
iterate_mech_values (void *cls, const char *section, const char *option,
                     const char *value)
{
  if (strcmp (option, "f") == 0)
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "\t %s %s\n", option, value);
}

static void
iterate_sections (void *cls, const char *section)
{
  struct TransportConfiguration *tc = cls;

  /* Peer definition */
  if (99 == strlen (section))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Peer '%s`\n", section);
    GNUNET_HashCode h;
    int res = GNUNET_CRYPTO_hash_from_string (section, &h);

    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "HASH '%s` %i\n", GNUNET_h2s (&h), res);
    GNUNET_CONFIGURATION_iterate_section_values (cfg, section,
                                                 iterate_peer_values, NULL);
    tc->peers++;
  }
  if (10 == strlen (section))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Mechanism '%s`\n", section);
    GNUNET_CONFIGURATION_iterate_section_values (cfg, section,
                                                 iterate_mech_values, NULL);
    tc->peers++;
  }
}


static struct TransportConfiguration *
load_transport_configuration (char *filename)
{
  struct TransportConfiguration *ret =
      GNUNET_malloc (sizeof (struct TransportConfiguration));

  cfg = GNUNET_CONFIGURATION_create ();
  GNUNET_assert (GNUNET_OK == GNUNET_CONFIGURATION_load (cfg, filename));
  GNUNET_CONFIGURATION_iterate_sections (cfg, iterate_sections, ret);
  GNUNET_CONFIGURATION_destroy (cfg);
  cfg = NULL;
  return ret;
}


int
main (int argc, char *argv[])
{
  int ret = 0;

  GNUNET_log_setup ("test-transport-ats",
#if VERBOSE
                    "DEBUG",
#else
                    "INFO",
#endif
                    NULL);
  tc = load_transport_configuration ("test_transport_ats.data");
  ats = NULL;
  ret += init_ats ();
  ret += run_ats ();
  ret += shutdown_ats ();
  return ret;

}

/* end of test_transport_ats.c*/
