/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
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
 * @file arm/test_gnunet_service_manager.c (A mockup testcase, not functionally complete)
 * @brief testcase for gnunet-service-manager.c
 */

#include "platform.h"
#include "gnunet_arm_service.h"
#include "gnunet_resolver_service.h"
#include "gnunet_program_lib.h"

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10)

/* Global Variables */
static int isOK = GNUNET_OK;

static void 
hostNameResolveCB(void *cls, 
				  const struct sockaddr *addr, 
				  socklen_t addrlen)
{
	if (NULL == addr)
		GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Name not resolved!\n");
}


static void
run(void *cls, 
	struct GNUNET_SCHEDULER_Handle *sched, 
	char * const *args,
    const char *cfgfile, 
    const struct GNUNET_CONFIGURATION_Handle *cfg)
{
	struct GNUNET_RESOLVER_RequestHandle *resolveRet;
	
	/* connect to the resolver service */
	resolveRet =
	GNUNET_RESOLVER_hostname_resolve (sched,
	                                  cfg, AF_UNSPEC,
	                                  TIMEOUT,
	                                  &hostNameResolveCB,
	                                  NULL);
	if (NULL == resolveRet) {
		GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Unable to resolve our own hostname!\n");
		isOK = GNUNET_NO;
	}
}


static int
check()
{
	char *const argv[] = {
	    "test-gnunet-service-manager",
	    "-c", "test_arm_api_data.conf",
	#if VERBOSE
	    "-L", "DEBUG",
	#endif
	    NULL
	  };
	  struct GNUNET_GETOPT_CommandLineOption options[] = {
	    GNUNET_GETOPT_OPTION_END
	  };
	  
	  /* Running ARM  and running the do_nothing task */
	  GNUNET_assert (GNUNET_OK ==
	                 GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1,
	                                     argv,
	                                     "test-gnunet-service-manager",
	                                     "nohelp", options, &run, NULL));
	  return isOK;
}


int
main (int argc, char *argv[])
{
  int ret;
  GNUNET_log_setup("test-gnunet-service-manager",
  #if VERBOSE
        "DEBUG",
  #else
        "WARNING",
  #endif
        NULL);
  ret = check();
  return ret;
}
