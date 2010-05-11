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
 * @file arm/test_exponential_backoff.c
 * @brief testcase for gnunet-service-arm.c
 */
#include "platform.h"
#include "gnunet_arm_service.h"
#include "gnunet_client_lib.h"
#include "gnunet_configuration_lib.h"
#include "gnunet_program_lib.h"

#define VERBOSE GNUNET_NO
#define START_ARM GNUNET_YES
#define LOG_BACKOFF GNUNET_NO
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10)
#define SERVICE_TEST_TIMEOUT GNUNET_TIME_UNIT_FOREVER_REL
#define FIVE_MILLISECONDS GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS, 5)

static struct GNUNET_SCHEDULER_Handle *sched;
static const struct GNUNET_CONFIGURATION_Handle *cfg;
static struct GNUNET_ARM_Handle *arm;
static int ok = 1;

static int trialCount;
static struct GNUNET_TIME_Absolute startedWaitingAt;
struct GNUNET_TIME_Relative waitedFor;

#if LOG_BACKOFF
static FILE *killLogFilePtr;
static char *killLogFileName;
#endif


static void
arm_notify_stop (void *cls, int success)
{
  GNUNET_assert (success == GNUNET_NO);
#if START_ARM
  GNUNET_ARM_stop_service (arm, "arm", TIMEOUT, NULL, NULL);
#endif
}


static void
kill_task (void *cbData,
	   const struct GNUNET_SCHEDULER_TaskContext *tc);


static void
do_nothing_notify (void *cls, int success)
{
  GNUNET_assert (success == GNUNET_YES);
  ok = 1;
  GNUNET_SCHEDULER_add_delayed (sched, GNUNET_TIME_UNIT_SECONDS, 
				&kill_task, NULL);
}


static void
arm_notify (void *cls, int success)
{ 
  GNUNET_assert (success == GNUNET_YES);
  GNUNET_ARM_start_service (arm, 
			    "do-nothing", TIMEOUT, 
			    &do_nothing_notify, NULL);
}


static void
kill_task (void *cbData,
		   const struct GNUNET_SCHEDULER_TaskContext *tc);


static void
do_nothing_restarted_notify_task (void *cls,
				  const struct GNUNET_SCHEDULER_TaskContext *tc)
{	
  static char a;
  
  trialCount++;

#if LOG_BACKOFF  
  if ((tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) != 0) 
    {
      fprintf(killLogFilePtr, 
	      "%d.Reason is shutdown!\n",
	      trialCount);
    } 
  else if ((tc->reason & GNUNET_SCHEDULER_REASON_TIMEOUT) != 0) 
    {
      fprintf(killLogFilePtr, 
	      "%d.Reason is timeout!\n", 
	      trialCount);
    }
  else if ((tc->reason & GNUNET_SCHEDULER_REASON_PREREQ_DONE) != 0) 
    {
      fprintf(killLogFilePtr, 
	      "%d.Service is running!\n", 
	      trialCount);
    }  
#endif
  GNUNET_SCHEDULER_add_now (sched, &kill_task, &a);
}


static void
do_test (void *cbData,
	 const struct GNUNET_SCHEDULER_TaskContext *tc)
{				      
  GNUNET_CLIENT_service_test(sched, "do-nothing", 
			     cfg, TIMEOUT,
			     &do_nothing_restarted_notify_task, NULL);
}


static void
shutdown_cont (void *cls, int reason)
{
  trialCount++;
  startedWaitingAt = GNUNET_TIME_absolute_get();
  GNUNET_SCHEDULER_add_delayed (sched,
                                waitedFor,
                                &do_test,
                                NULL);
}
static void
kill_task (void *cbData,
		   const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  static struct GNUNET_CLIENT_Connection * doNothingConnection = NULL;

  if (NULL != cbData) 
    {
      waitedFor = GNUNET_TIME_absolute_get_duration (startedWaitingAt);
      
#if LOG_BACKOFF
      fprintf(killLogFilePtr, 
	      "Waited for: %llu ms\n", 
	      (unsigned long long) waitedFor.value);
#endif
    }
  else
    {
      waitedFor.value = 0;
    }
  /* Connect to the doNothing task */
  doNothingConnection = GNUNET_CLIENT_connect (sched, "do-nothing", cfg);
#if LOG_BACKOFF
  if (NULL == doNothingConnection)
    fprintf(killLogFilePtr, 
	    "Unable to connect to do-nothing process!\n");
#endif  
  if (trialCount == 12) {
    GNUNET_ARM_stop_service (arm, 
			     "do-nothing", 
			     TIMEOUT,
			     &arm_notify_stop, NULL);
    ok = 0;
    return;
  }
  
  /* Use the created connection to kill the doNothingTask */
  GNUNET_CLIENT_service_shutdown(sched,
				 doNothingConnection, 
				 TIMEOUT, 
				 &shutdown_cont, NULL);
}

       
static void
task (void *cls,
      struct GNUNET_SCHEDULER_Handle *s,
      char *const *args,
      const char *cfgfile,
      const struct GNUNET_CONFIGURATION_Handle *c)
{
  cfg = c;
  sched = s;
  
  arm = GNUNET_ARM_connect (cfg, sched, NULL);
#if START_ARM
  GNUNET_ARM_start_service (arm, "arm", GNUNET_TIME_UNIT_ZERO, &arm_notify, NULL);
#else
  arm_do_nothing (NULL, GNUNET_YES);
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
  
  /* Running ARM  and running the do_nothing task */
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1,
                                     argv,
                                     "test-exponential-backoff",
                                     "nohelp", options, &task, NULL));
  
  
  return ok;
}

static int
init()
{
#if LOG_BACKOFF
  killLogFileName = GNUNET_DISK_mktemp("exponential-backoff-waiting.log");
  if (NULL == (killLogFilePtr = FOPEN(killLogFileName, "w"))) {
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "fopen", killLogFileName);
    GNUNET_free (killLogFileName);
    return GNUNET_SYSERR;
  }  
#endif
  return GNUNET_OK;
}


static void
houseKeep()
{
#if LOG_BACKOFF
  GNUNET_assert (0 == fclose (killLogFilePtr));
  GNUNET_free(killLogFileName);
#endif
}


int
main (int argc, char *argv[])
{
  int ret;

  GNUNET_log_setup ("test-exponential-backoff",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);
  
  init();
  ret = check ();
  houseKeep();
  return ret;
}

/* end of test_exponential_backoff.c */
