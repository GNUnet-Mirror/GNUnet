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
 * @file dht/test_dht_api.c
 * @brief base test case for dht api
 *
 * This test case tests DHT api to DUMMY DHT service communication.
 *
 */
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_hello_lib.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_os_lib.h"
#include "gnunet_program_lib.h"
#include "gnunet_scheduler_lib.h"
#include "gnunet_dht_service.h"
#include "gnunet_hello_lib.h"

#define VERBOSE GNUNET_NO

#define VERBOSE_ARM GNUNET_NO

#define START_ARM GNUNET_YES

/**
 * How long until we really give up on a particular testcase portion?
 */
#define TOTAL_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 600)

/**
 * How long until we give up on any particular operation (and retry)?
 */
#define BASE_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 3)

#define MTYPE 12345

struct RetryContext
{
  /**
   * When to really abort the operation.
   */
  struct GNUNET_TIME_Absolute real_timeout;

  /**
   * What timeout to set for the current attempt (increases)
   */
  struct GNUNET_TIME_Relative next_timeout;

  /**
   * The context of the peer we are dealing with.
   */
  struct PeerContext *peer_ctx;

  /**
   * The task identifier of the retry task, so it can be cancelled.
   */
  GNUNET_SCHEDULER_TaskIdentifier retry_task;

};

struct PeerContext
{
  struct GNUNET_CONFIGURATION_Handle *cfg;
  struct GNUNET_DHT_Handle *dht_handle;
  struct GNUNET_PeerIdentity id;
  struct GNUNET_DHT_GetHandle *get_handle;
#if START_ARM
  struct GNUNET_OS_Process *arm_proc;
#endif
};

static struct PeerContext p1;

struct RetryContext retry_context;


static int ok;

static GNUNET_SCHEDULER_TaskIdentifier die_task;

#if VERBOSE
#define OKPP do { ok++; FPRINTF (stderr, "Now at stage %u at %s:%u\n", ok, __FILE__, __LINE__); } while (0)
#else
#define OKPP do { ok++; } while (0)
#endif


static void
end (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_SCHEDULER_cancel (die_task);
  die_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_DHT_disconnect (p1.dht_handle);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "DHT disconnected, returning success!\n");
  ok = 0;
}

static void
stop_arm (struct PeerContext *p)
{
#if START_ARM
  if (0 != GNUNET_OS_process_kill (p->arm_proc, SIGTERM))
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "kill");
  GNUNET_OS_process_wait (p->arm_proc);
  GNUNET_OS_process_close (p->arm_proc);
  p->arm_proc = NULL;
#endif
  GNUNET_CONFIGURATION_destroy (p->cfg);
}


static void
end_badly ()
{
  /* do work here */
#if VERBOSE
  FPRINTF (stderr, "%s",  "Ending on an unhappy note.\n");
#endif

  if ((retry_context.peer_ctx != NULL) &&
      (retry_context.peer_ctx->get_handle != NULL))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Stopping get request!\n");
    GNUNET_DHT_get_stop (retry_context.peer_ctx->get_handle);
  }
  if (retry_context.retry_task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (retry_context.retry_task);
  GNUNET_DHT_disconnect (p1.dht_handle);
  ok = 1;
}


/**
 * Signature of the main function of a task.
 *
 * @param cls closure
 * @param tc context information (why was this task triggered now)
 */
static void
test_get_stop (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct PeerContext *peer = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Called test_get_stop!\n");
  if ((tc->reason & GNUNET_SCHEDULER_REASON_TIMEOUT) != 0)
  {
    GNUNET_break (0);
    GNUNET_SCHEDULER_cancel (die_task);
    die_task = GNUNET_SCHEDULER_add_now (&end_badly, NULL);
    return;
  }
  GNUNET_assert (peer->dht_handle != NULL);
  GNUNET_DHT_get_stop (peer->get_handle);
  peer->get_handle = NULL;
  GNUNET_SCHEDULER_add_now (&end, &p1);
}


static void
test_get_iterator (void *cls, struct GNUNET_TIME_Absolute exp,
                   const GNUNET_HashCode * key,
                   const struct GNUNET_PeerIdentity *get_path,
                   unsigned int get_path_length,
                   const struct GNUNET_PeerIdentity *put_path,
                   unsigned int put_path_length, enum GNUNET_BLOCK_Type type,
                   size_t size, const void *data)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "test_get_iterator called (we got a result), stopping get request!\n");

  GNUNET_SCHEDULER_add_continuation (&test_get_stop, &p1,
                                     GNUNET_SCHEDULER_REASON_PREREQ_DONE);
}

/**
 * Signature of the main function of a task.
 *
 * @param cls closure
 * @param tc context information (why was this task triggered now)
 */
static void
test_get (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct PeerContext *peer = cls;
  GNUNET_HashCode hash;

  memset (&hash, 42, sizeof (GNUNET_HashCode));

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Called test_get!\n");

  GNUNET_assert (peer->dht_handle != NULL);
  retry_context.real_timeout = GNUNET_TIME_relative_to_absolute (TOTAL_TIMEOUT);
  retry_context.next_timeout = BASE_TIMEOUT;

  peer->get_handle =
      GNUNET_DHT_get_start (peer->dht_handle, TOTAL_TIMEOUT,
                            GNUNET_BLOCK_TYPE_TEST, &hash, 1,
                            GNUNET_DHT_RO_NONE, NULL, 0, &test_get_iterator,
                            NULL);

  if (peer->get_handle == NULL)
  {
    GNUNET_break (0);
    GNUNET_SCHEDULER_cancel (die_task);
    die_task = GNUNET_SCHEDULER_add_now (&end_badly, &p1);
    return;
  }

  retry_context.peer_ctx = peer;
}

/**
 * Signature of the main function of a task.
 *
 * @param cls closure
 * @param tc context information (why was this task triggered now)
 */
static void
test_put (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct PeerContext *peer = cls;
  GNUNET_HashCode hash;
  char *data;
  size_t data_size = 42;

  memset (&hash, 42, sizeof (GNUNET_HashCode));
  data = GNUNET_malloc (data_size);
  memset (data, 43, data_size);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Called test_put!\n");
  peer->dht_handle = GNUNET_DHT_connect (peer->cfg, 100);

  GNUNET_assert (peer->dht_handle != NULL);

  GNUNET_DHT_put (peer->dht_handle, &hash, 1, GNUNET_DHT_RO_NONE,
                  GNUNET_BLOCK_TYPE_TEST, data_size, data,
                  GNUNET_TIME_relative_to_absolute (TOTAL_TIMEOUT),
                  TOTAL_TIMEOUT, &test_get, &p1);
  GNUNET_free (data);
}

static void
setup_peer (struct PeerContext *p, const char *cfgname)
{
  p->cfg = GNUNET_CONFIGURATION_create ();
#if START_ARM
  p->arm_proc =
    GNUNET_OS_start_process (GNUNET_YES, NULL, NULL, "gnunet-service-arm",
                               "gnunet-service-arm",
#if VERBOSE_ARM
                               "-L", "DEBUG",
#endif
                               "-c", cfgname, NULL);
#endif
  GNUNET_assert (GNUNET_OK == GNUNET_CONFIGURATION_load (p->cfg, cfgname));

}

static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  GNUNET_assert (ok == 1);
  OKPP;

  die_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                    (GNUNET_TIME_UNIT_MINUTES, 1), &end_badly,
                                    NULL);

  setup_peer (&p1, "test_dht_api_peer1.conf");

  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                (GNUNET_TIME_UNIT_SECONDS, 1), &test_put, &p1);
}

static int
check ()
{

  char *const argv[] = { "test-dht-api",
    "-c",
    "test_dht_api_data.conf",
#if VERBOSE
    "-L", "DEBUG",
#endif
    NULL
  };

  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  ok = 1;
  GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1, argv,
                      "test-dht-api", "nohelp", options, &run, &ok);
  stop_arm (&p1);
  return ok;
}


int
main (int argc, char *argv[])
{
  int ret;

  GNUNET_log_setup ("test-dht-api",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);
  ret = check ();

  GNUNET_DISK_directory_remove ("/tmp/test-gnunetd-dht-peer-1");

  return ret;
}

/* end of test_dht_api.c */
