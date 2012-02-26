/*
     This file is part of GNUnet.
     (C) 2009, 2011 Christian Grothoff (and other contributing authors)

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
 * @file arm/test_arm_api.c
 * @brief testcase for arm_api.c
 */
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_arm_service.h"
#include "gnunet_client_lib.h"
#include "gnunet_configuration_lib.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_program_lib.h"
#include "gnunet_resolver_service.h"

#define VERBOSE GNUNET_NO

#define START_ARM GNUNET_YES

#define START_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS, 1500)

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 15)

static const struct GNUNET_CONFIGURATION_Handle *cfg;

static struct GNUNET_ARM_Handle *arm;

static int ok = 1;

static void
arm_stopped (void *cls,  enum GNUNET_ARM_ProcessStatus success)
{
  GNUNET_break (success == GNUNET_ARM_PROCESS_DOWN);
  if (success != GNUNET_ARM_PROCESS_DOWN)
    ok = 3;
  else if (ok == 1)
    ok = 0;
}


static void
arm_notify_stop (void *cls, enum GNUNET_ARM_ProcessStatus success)
{
  GNUNET_break (success == GNUNET_ARM_PROCESS_DOWN);
#if START_ARM
  GNUNET_ARM_stop_service (arm, "arm", TIMEOUT, &arm_stopped, NULL);
#endif
}


static void
dns_notify (void *cls, const struct sockaddr *addr, socklen_t addrlen)
{
  if (addr == NULL)
    {
      if (ok != 0)
	{
	  GNUNET_break (0);
	  ok = 2;
	}
      GNUNET_ARM_stop_service (arm, "resolver", TIMEOUT, &arm_notify_stop,
			       NULL);
      return;
    }
  GNUNET_break (addr != NULL);
  ok = 0;
}


static void
resolver_notify (void *cls, enum GNUNET_ARM_ProcessStatus success)
{
  if (success != GNUNET_ARM_PROCESS_STARTING)
    {
      GNUNET_break (0);
      ok = 2;
#if START_ARM
      GNUNET_ARM_stop_service (arm, "arm", TIMEOUT, &arm_stopped, NULL);
#endif
      return;
    }
  GNUNET_RESOLVER_ip_get ("localhost", AF_INET, TIMEOUT, &dns_notify, NULL);
}


static void
arm_notify (void *cls, enum GNUNET_ARM_ProcessStatus success)
{
  if (success != GNUNET_ARM_PROCESS_STARTING)
    {
      GNUNET_break (0);
      ok = 2;
#if START_ARM
      GNUNET_ARM_stop_service (arm, "arm", TIMEOUT, &arm_stopped, NULL);
#endif
    }
  GNUNET_ARM_start_service (arm, "resolver", START_TIMEOUT, &resolver_notify,
			    NULL);
}


static void
task (void *cls, char *const *args, const char *cfgfile,
      const struct GNUNET_CONFIGURATION_Handle *c)
{
  cfg = c;
  arm = GNUNET_ARM_connect (cfg, NULL);
#if START_ARM
  GNUNET_ARM_start_service (arm, "arm", START_TIMEOUT, &arm_notify, NULL);
#else
  arm_notify (NULL, GNUNET_YES);
#endif
}



static int
check ()
{
  char *const argv[] = {
    "test-arm-api",
    "-c", "test_arm_api_data.conf",
#if VERBOSE
    "-L", "DEBUG",
#endif
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  GNUNET_assert (GNUNET_OK ==
		 GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1,
				     argv, "test-arm-api", "nohelp", options,
				     &task, NULL));
  return ok;
}

int
main (int argc, char *argv[])
{
  int ret;


  GNUNET_log_setup ("test-arm-api",
#if VERBOSE
		    "DEBUG",
#else
		    "WARNING",
#endif
		    NULL);
  ret = check ();

  return ret;
}

/* end of test_arm_api.c */
