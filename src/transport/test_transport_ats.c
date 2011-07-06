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
#include "transport_ats.h"
#include "gnunet_configuration_lib.h"

#define VERBOSE GNUNET_YES

struct GNUNET_CONFIGURATION_Handle *cfg;

static struct ATS_Handle * ats;


int init_ats (void)
{
  int ret = 0;

  //ats = ats_init(cfg);
  //GNUNET_assert (ats != NULL);

  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "Initializing ATS: %s \n", (ret==0)? "SUCCESFULL": "FAILED");
  return ret;
}


int shutdown_ats (void)
{
  int ret = 0;

  //ats_delete_problem (ats);
  //ats_shutdown (ats);
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "Shutdown ATS: %s \n", (ret==0)? "SUCCESFULL": "FAILED");
  return ret;
}

/* To make compiler happy */
void dummy(void)
{
  struct ATS_quality_metric * q = qm;
  q = NULL;
  struct ATS_ressource * r = ressources;
  r = NULL;
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
#if !HAVE_LIBGLPK
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "HAVE_LIBGLPK not set, exiting testcase\n");
#endif

#if !HAVE_LIBGLPK
  return ret;
#endif


  cfg = GNUNET_CONFIGURATION_create();
  GNUNET_CONFIGURATION_load(cfg, "test_transport_ats_1addr.conf");

  /* Testing */
  ats = NULL;
  ret += init_ats ();
  ret += shutdown_ats ();

  /* Shutdown */
  GNUNET_CONFIGURATION_destroy(cfg);
  return ret;

}

/* end of test_transport_ats.c*/
