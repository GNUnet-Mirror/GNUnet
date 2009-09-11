/*
     This file is part of GNUnet.
     (C) 2004, 2005, 2006, 2007, 2009 Christian Grothoff (and other contributing authors)

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
/*
 * @file datastore/test_datastore_api.c
 * @brief Test for the basic datastore API.
 * @author Christian Grothoff
 *
 * TODO:
 * - test reservation failure
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_datastore_service.h"

#define VERBOSE GNUNET_NO

/**
 * How long until we give up on transmitting the message?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 15)

#define ITERATIONS 256

static struct GNUNET_DATASTORE_Handle *datastore;

static struct GNUNET_TIME_Absolute now;

static int ok;


static size_t
get_size (int i)
{
  return 8 * i;
}


static const void *
get_data (int i)
{
  static char buf[60000]; 
  memset (buf, i, 8 * i);
  return buf;
}


static int
get_type(int i)
{
  return i+1;
}


static int 
get_priority (int i)
{
  return i+1;
}


static int
get_anonymity(int i)
{
  return i;
}


static struct GNUNET_TIME_Absolute 
get_expiration (int i)
{
  struct GNUNET_TIME_Absolute av;

  av.value = now.value + 200000 - i * 1000;
  return av;
}

enum RunPhase
  {
    RP_DONE = 0,
    RP_PUT,
    RP_GET,
    RP_DEL,
    RP_DO_DEL,
    RP_DELVALIDATE,
    RP_RESERVE,
    RP_PUT_MULTIPLE,
    RP_PUT_MULTIPLE_NEXT,
    RP_GET_MULTIPLE,
    RP_GET_MULTIPLE_NEXT,
    RP_GET_MULTIPLE_DONE,
    RP_UPDATE,
    RP_UPDATE_VALIDATE,
    RP_UPDATE_DONE
  };


struct CpsRunContext
{
  GNUNET_HashCode key;
  int i;
  int rid;
  int *iptr;
  struct GNUNET_SCHEDULER_Handle *sched;
  const struct GNUNET_CONFIGURATION_Handle *cfg;
  void *data;
  size_t size;
  enum RunPhase phase;
  unsigned long long uid;
};


static void
run_continuation (void *cls,
		  const struct GNUNET_SCHEDULER_TaskContext *tc);


static void
check_success (void *cls,
	       int success,
	       const char *msg)
{
  struct CpsRunContext *crc = cls;
  if (GNUNET_OK != success)
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		"%s\n", msg);
  GNUNET_assert (GNUNET_OK == success);
  GNUNET_free_non_null (crc->data);
  crc->data = NULL;
  GNUNET_SCHEDULER_add_continuation (crc->sched,
				     GNUNET_NO,
				     &run_continuation,
				     crc,
				     GNUNET_SCHEDULER_REASON_PREREQ_DONE);
}


static void
get_reserved (void *cls,
	      int success,
	      const char *msg)
{
  struct CpsRunContext *crc = cls;
  if (0 >= success)
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		"%s\n", msg);
  GNUNET_assert (0 < success);
  crc->rid = success;
  GNUNET_SCHEDULER_add_continuation (crc->sched,
				     GNUNET_NO,
				     &run_continuation,
				     crc,
				     GNUNET_SCHEDULER_REASON_PREREQ_DONE);
}


static void 
check_value (void *cls,
	     const GNUNET_HashCode * key,
	     uint32_t size,
	     const void *data,
	     uint32_t type,
	     uint32_t priority,
	     uint32_t anonymity,
	     struct GNUNET_TIME_Absolute
	     expiration, uint64_t uid)
{
  struct CpsRunContext *crc = cls;
  int i;

  if (key == NULL)
    {
      if (crc->i == 0)
	{
	  crc->phase = RP_DEL;
	  crc->i = ITERATIONS;
	}
      GNUNET_SCHEDULER_add_continuation (crc->sched,
					 GNUNET_NO,
					 &run_continuation,
					 crc,
					 GNUNET_SCHEDULER_REASON_PREREQ_DONE);
      return;
    }
  i = crc->i;
  GNUNET_assert (size == get_size (i));
  GNUNET_assert (0 == memcmp (data, get_data(i), size));
  GNUNET_assert (type == get_type (i));
  GNUNET_assert (priority == get_priority (i));
  GNUNET_assert (anonymity == get_anonymity(i));
  GNUNET_assert (expiration.value == get_expiration(i).value);
  GNUNET_DATASTORE_get_next (datastore, GNUNET_YES);
}


static void 
delete_value (void *cls,
	     const GNUNET_HashCode * key,
	     uint32_t size,
	     const void *data,
	     uint32_t type,
	     uint32_t priority,
	     uint32_t anonymity,
	     struct GNUNET_TIME_Absolute
	     expiration, uint64_t uid)
{
  struct CpsRunContext *crc = cls;
  if (key == NULL)
    {
      crc->phase = RP_DO_DEL;
      GNUNET_SCHEDULER_add_continuation (crc->sched,
					 GNUNET_NO,
					 &run_continuation,
					 crc,
					 GNUNET_SCHEDULER_REASON_PREREQ_DONE);
      return;
    }
  GNUNET_assert (crc->data == NULL);
  crc->size = size;
  crc->key = *key;
  crc->data = GNUNET_malloc (size);
  memcpy (crc->data, data, size);
  GNUNET_DATASTORE_get_next (datastore, GNUNET_YES);
}


static void 
check_nothing (void *cls,
	     const GNUNET_HashCode * key,
	     uint32_t size,
	     const void *data,
	     uint32_t type,
	     uint32_t priority,
	     uint32_t anonymity,
	     struct GNUNET_TIME_Absolute
	     expiration, uint64_t uid)
{
  struct CpsRunContext *crc = cls;
  GNUNET_assert (key == NULL);
  if (crc->i == 0)
    {
      crc->phase = RP_RESERVE;	  
    }
  GNUNET_SCHEDULER_add_continuation (crc->sched,
				     GNUNET_NO,
				     &run_continuation,
				     crc,
				     GNUNET_SCHEDULER_REASON_PREREQ_DONE);
}


static void 
check_multiple (void *cls,
		const GNUNET_HashCode * key,
		uint32_t size,
		const void *data,
		uint32_t type,
		uint32_t priority,
		uint32_t anonymity,
		struct GNUNET_TIME_Absolute
		expiration, uint64_t uid)
{
  struct CpsRunContext *crc = cls;

  if (key == NULL)
    {
      GNUNET_assert (crc->phase == RP_GET_MULTIPLE_DONE);
      crc->phase = RP_UPDATE;
      GNUNET_SCHEDULER_add_continuation (crc->sched,
					 GNUNET_NO,
					 &run_continuation,
					 crc,
					 GNUNET_SCHEDULER_REASON_PREREQ_DONE);
      return;
    }
  crc->phase++;
  if (priority == get_priority (42))
    crc->uid = uid;
  GNUNET_DATASTORE_get_next (datastore, GNUNET_YES);
}


static void 
check_update (void *cls,
	      const GNUNET_HashCode * key,
	      uint32_t size,
	      const void *data,
	      uint32_t type,
	      uint32_t priority,
	      uint32_t anonymity,
	      struct GNUNET_TIME_Absolute
	      expiration, uint64_t uid)
{
  struct CpsRunContext *crc = cls;

  if (key == NULL)
    {
      GNUNET_assert (crc->phase == RP_UPDATE_DONE);
      crc->phase = RP_DONE;
      GNUNET_SCHEDULER_add_continuation (crc->sched,
					 GNUNET_NO,
					 &run_continuation,
					 crc,
					 GNUNET_SCHEDULER_REASON_PREREQ_DONE);
      return;
    }
  if ( (anonymity == get_anonymity (42)) &&
       (size == get_size (42)) &&
       (priority == get_priority (42) + 100) )
    {
      crc->phase = RP_UPDATE_DONE;
    }
  else
    GNUNET_assert (size == get_size (43));
  GNUNET_DATASTORE_get_next (datastore, GNUNET_YES);
}


static void
run_continuation (void *cls,
		  const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct CpsRunContext *crc = cls;
  ok = (int) crc->phase;
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Test in phase %u\n", crc->phase);
#endif
  switch (crc->phase)
    {
    case RP_PUT:
#if VERBOSE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Executing `%s' number %u\n",
		  "PUT",
		  crc->i);
#endif
      GNUNET_CRYPTO_hash (&crc->i, sizeof (int), &crc->key);
      GNUNET_DATASTORE_put (datastore,
			    0,
			    &crc->key,
			    get_size (crc->i),
			    get_data (crc->i),
			    get_type (crc->i),
			    get_priority (crc->i),
			    get_anonymity (crc->i),
			    get_expiration (crc->i),
			    TIMEOUT,
			    &check_success,
			    crc);
      crc->i++;
      if (crc->i == ITERATIONS)
	crc->phase = RP_GET;
      break;
    case RP_GET:
      crc->i--;
#if VERBOSE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Executing `%s' number %u\n",
		  "GET",
		  crc->i);
#endif
      GNUNET_CRYPTO_hash (&crc->i, sizeof (int), &crc->key);
      GNUNET_DATASTORE_get (datastore, 
			    &crc->key,
			    get_type (crc->i),
			    &check_value,
			    crc,
			    TIMEOUT);
      break;
    case RP_DEL:
      crc->i--;
#if VERBOSE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Executing `%s' number %u\n",
		  "DEL",
		  crc->i);
#endif
      GNUNET_CRYPTO_hash (&crc->i, sizeof (int), &crc->key);
      GNUNET_DATASTORE_get (datastore, 
			    &crc->key,
			    get_type (crc->i),
			    &delete_value,
			    crc,
			    TIMEOUT);
      break;
    case RP_DO_DEL:
#if VERBOSE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Executing `%s' number %u\n",
		  "DO_DEL",
		  crc->i);
#endif
      if (crc->i == 0)
	{
	  crc->i = ITERATIONS;	 
	  crc->phase = RP_DELVALIDATE;
	}      
      else
	{
	  crc->phase = RP_DEL;
	}
      GNUNET_DATASTORE_remove (datastore,
			       &crc->key,
			       crc->size,
			       crc->data,
			       &check_success,
			       crc,
			       TIMEOUT);
      break;   
    case RP_DELVALIDATE:
      crc->i--;
#if VERBOSE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Executing `%s' number %u\n",
		  "DEL-VALIDATE",
		  crc->i);
#endif
      GNUNET_CRYPTO_hash (&crc->i, sizeof (int), &crc->key);
      GNUNET_DATASTORE_get (datastore, 
			    &crc->key,
			    get_type (crc->i),
			    &check_nothing,
			    crc,
			    TIMEOUT);
      break;
    case RP_RESERVE:
      crc->phase = RP_PUT_MULTIPLE;
      GNUNET_DATASTORE_reserve (datastore,
				128*1024,
				2,
				&get_reserved,
				crc,
				TIMEOUT);
      break;
    case RP_PUT_MULTIPLE:
      crc->phase = RP_PUT_MULTIPLE_NEXT;
      GNUNET_DATASTORE_put (datastore,
			    crc->rid,
			    &crc->key,
			    get_size (42),
			    get_data (42),
			    get_type (42),
			    get_priority (42),
			    get_anonymity (42),
			    get_expiration (42),
			    TIMEOUT,
			    &check_success,
			    crc);
      break;
    case RP_PUT_MULTIPLE_NEXT:
      crc->phase = RP_GET_MULTIPLE;
      GNUNET_DATASTORE_put (datastore,
			    crc->rid,
			    &crc->key,
			    get_size (43),
			    get_data (43),
			    get_type (42),
			    get_priority (43),
			    get_anonymity (43),
			    get_expiration (43),
			    TIMEOUT,
			    &check_success,
			    crc);
      break;
    case RP_GET_MULTIPLE:
      GNUNET_DATASTORE_get (datastore,
			    &crc->key, 
			    get_type (42),
			    &check_multiple,
			    crc,
			    TIMEOUT);
      break;
    case RP_GET_MULTIPLE_NEXT:
    case RP_GET_MULTIPLE_DONE:
      GNUNET_assert (0);
      break;
    case RP_UPDATE:
      GNUNET_assert (crc->uid > 0);
      crc->phase = RP_UPDATE_VALIDATE;
      GNUNET_DATASTORE_update (datastore,
			       crc->uid,
			       100,
			       get_expiration (42),
			       &check_success,
			       crc,
			       TIMEOUT);
      break;
    case RP_UPDATE_VALIDATE:
      GNUNET_DATASTORE_get (datastore,
			    &crc->key, 
			    get_type (42),
			    &check_update,
			    crc,
			    TIMEOUT);   
      break;
    case RP_UPDATE_DONE:
      GNUNET_assert (0);
      break;
    case RP_DONE:
#if VERBOSE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Finished, disconnecting\n");
#endif
      GNUNET_DATASTORE_disconnect (datastore, GNUNET_YES);
      GNUNET_free (crc);
      ok = 0;
    }
}


static void
run (void *cls,
     struct GNUNET_SCHEDULER_Handle *sched,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct CpsRunContext *crc;

  crc = GNUNET_malloc(sizeof(struct CpsRunContext));
  crc->sched = sched;
  crc->cfg = cfg;
  crc->phase = RP_PUT;
  now = GNUNET_TIME_absolute_get ();
  datastore = GNUNET_DATASTORE_connect (cfg, sched);
  GNUNET_SCHEDULER_add_continuation (crc->sched,
				     GNUNET_NO,
				     &run_continuation,
				     crc,
				     GNUNET_SCHEDULER_REASON_PREREQ_DONE);

}



static int
check ()
{
  pid_t pid;
  char *const argv[] = { "test-datastore-api",
    "-c",
    "test_datastore_api_data.conf",
#if VERBOSE
    "-L", "DEBUG",
#endif
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  pid = GNUNET_OS_start_process ("gnunet-service-datastore",
                                 "gnunet-service-datastore",
#if VERBOSE
                                 "-L", "DEBUG",
#endif
                                 "-c", "test_datastore_api_data.conf", NULL);
  sleep (1);
  GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1,
                      argv, "test-datastore-api", "nohelp",
                      options, &run, NULL);
  if (0 != PLIBC_KILL (pid, SIGTERM))
    {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "kill");
      ok = 1;
    }
  GNUNET_OS_process_wait(pid);
  if (ok != 0)
    fprintf (stderr, "Missed some testcases: %u\n", ok);
  return ok;
}

int
main (int argc, char *argv[])
{
  int ret;
  
  GNUNET_DISK_directory_remove ("/tmp/test-gnunetd-datastore");
  GNUNET_log_setup ("test-datastore-api",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);
  ret = check ();
  GNUNET_DISK_directory_remove ("/tmp/test-gnunetd-datastore");

  return ret;
}



/* end of test_datastore_api.c */
