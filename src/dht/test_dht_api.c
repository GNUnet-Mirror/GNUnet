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
#define TOTAL_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 50)

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
  struct GNUNET_DHT_FindPeerHandle *find_peer_handle;

#if START_ARM
  pid_t arm_pid;
#endif
};

static struct PeerContext p1;

struct RetryContext retry_context;

static struct GNUNET_SCHEDULER_Handle *sched;

static int ok;

GNUNET_SCHEDULER_TaskIdentifier die_task;

#if VERBOSE
#define OKPP do { ok++; fprintf (stderr, "Now at stage %u at %s:%u\n", ok, __FILE__, __LINE__); } while (0)
#else
#define OKPP do { ok++; } while (0)
#endif


static void
end (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  /* do work here */
  GNUNET_SCHEDULER_cancel (sched, die_task);

  GNUNET_DHT_disconnect (p1.dht_handle);

  die_task = GNUNET_SCHEDULER_NO_TASK;

  if (tc->reason == GNUNET_SCHEDULER_REASON_TIMEOUT)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "DHT disconnected, returning FAIL!\n");
      ok = 365;
    }
  else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "DHT disconnected, returning success!\n");
      ok = 0;
    }
}

static void
stop_arm (struct PeerContext *p)
{
#if START_ARM
  if (0 != PLIBC_KILL (p->arm_pid, SIGTERM))
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "kill");
  GNUNET_OS_process_wait (p->arm_pid);
#endif
  GNUNET_CONFIGURATION_destroy (p->cfg);
}


static void
end_badly ()
{
  /* do work here */
#if VERBOSE
  fprintf (stderr, "Ending on an unhappy note.\n");
#endif
  if (retry_context.peer_ctx->find_peer_handle != NULL)
    GNUNET_DHT_find_peer_stop(retry_context.peer_ctx->find_peer_handle, NULL, NULL);
  if (retry_context.retry_task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel(sched, retry_context.retry_task);
  GNUNET_DHT_disconnect (p1.dht_handle);

  ok = 1;
  return;
}

/**
 * Signature of the main function of a task.
 *
 * @param cls closure
 * @param tc context information (why was this task triggered now)
 */
void
test_find_peer_stop (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct PeerContext *peer = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Called test_find_peer_stop!\n");
  if (tc->reason == GNUNET_SCHEDULER_REASON_TIMEOUT)
    GNUNET_SCHEDULER_add_now (sched, &end_badly, NULL);

  GNUNET_assert (peer->dht_handle != NULL);

  GNUNET_DHT_find_peer_stop (peer->find_peer_handle, &end, &p1);

  //GNUNET_SCHEDULER_add_delayed(sched, GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 1), &end, &p1);

}


/**
 * Iterator called on each result obtained from a find peer
 * operation
 *
 * @param cls closure (NULL)
 * @param peer the peer we learned about
 * @param reply response
 */
void test_find_peer_processor (void *cls,
                               const struct GNUNET_HELLO_Message *hello)
{
  struct RetryContext *retry_ctx = cls;
  struct GNUNET_PeerIdentity peer;

  if (GNUNET_OK == GNUNET_HELLO_get_id(hello, &peer))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "test_find_peer_processor called (peer `%s'), stopping find peer request!\n", GNUNET_i2s(&peer));

      if (retry_ctx->retry_task != GNUNET_SCHEDULER_NO_TASK)
        {
          GNUNET_SCHEDULER_cancel(sched, retry_ctx->retry_task);
          retry_ctx->retry_task = GNUNET_SCHEDULER_NO_TASK;
        }

      GNUNET_SCHEDULER_add_continuation (sched, &test_find_peer_stop, &p1,
                                         GNUNET_SCHEDULER_REASON_PREREQ_DONE);
    }
  else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "received find peer request, but hello_get_id failed!\n");
    }

}

/**
 * Retry the find_peer task on timeout. (Forward declaration)
 *
 * @param cls closure
 * @param tc context information (why was this task triggered now?)
 */
void
retry_find_peer_stop (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);

/**
 * Retry the find_peer task on timeout.
 *
 * @param cls closure
 * @param tc context information (why was this task triggered now)
 */
void
retry_find_peer (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct RetryContext *retry_ctx = cls;
  GNUNET_HashCode hash;
  memset (&hash, 42, sizeof (GNUNET_HashCode));

  if (GNUNET_TIME_absolute_get_remaining(retry_ctx->real_timeout).value > 0)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "test_find_peer timed out, retrying!\n");
      retry_ctx->next_timeout = GNUNET_TIME_relative_multiply(retry_ctx->next_timeout, 2);
      retry_ctx->peer_ctx->find_peer_handle =
          GNUNET_DHT_find_peer_start (retry_ctx->peer_ctx->dht_handle, retry_ctx->next_timeout, 0, &hash,
                                      &test_find_peer_processor, retry_ctx, NULL, NULL);
    }
  else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "test_find_peer timed out for good, failing!\n");

      retry_ctx->peer_ctx->find_peer_handle = NULL;
    }

  if (retry_ctx->peer_ctx->find_peer_handle == NULL)
    GNUNET_SCHEDULER_add_now (sched, &end_badly, &p1);
  else
    retry_ctx->retry_task = GNUNET_SCHEDULER_add_delayed(sched, retry_ctx->next_timeout, &retry_find_peer_stop, retry_ctx);
}

/**
 * Retry the find_peer task on timeout.
 *
 * @param cls closure
 * @param tc context information (why was this task triggered now?)
 */
void
retry_find_peer_stop (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct RetryContext *retry_ctx = cls;
  GNUNET_HashCode hash;
  memset (&hash, 42, sizeof (GNUNET_HashCode));

  if (retry_ctx->peer_ctx->find_peer_handle != NULL)
    GNUNET_DHT_find_peer_stop(retry_ctx->peer_ctx->find_peer_handle, &retry_find_peer, retry_ctx);
  else
    GNUNET_SCHEDULER_add_now (sched, &retry_find_peer, retry_ctx);

}

/**
 * Entry point for test of find_peer functionality.
 *
 * @param cls closure
 * @param tc context information (why was this task triggered now)
 */
void
test_find_peer (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct PeerContext *peer = cls;
  GNUNET_HashCode hash;
  memset (&hash, 42, sizeof (GNUNET_HashCode));

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Called test_find_peer!\n");
  GNUNET_assert (peer->dht_handle != NULL);

  retry_context.real_timeout = GNUNET_TIME_relative_to_absolute(TOTAL_TIMEOUT);
  retry_context.next_timeout = BASE_TIMEOUT;
  retry_context.peer_ctx = peer;

  peer->find_peer_handle =
    GNUNET_DHT_find_peer_start (peer->dht_handle, retry_context.next_timeout, 0, &hash,
                                &test_find_peer_processor, &retry_context, NULL, NULL);

  if (peer->find_peer_handle == NULL)
    GNUNET_SCHEDULER_add_now (sched, &end_badly, &p1);
  else
    retry_context.retry_task = GNUNET_SCHEDULER_add_delayed(sched, retry_context.next_timeout, &retry_find_peer_stop, &retry_context);
}

/**
 * Signature of the main function of a task.
 *
 * @param cls closure
 * @param tc context information (why was this task triggered now)
 */
void
test_get_stop (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct PeerContext *peer = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Called test_get_stop!\n");
  if (tc->reason == GNUNET_SCHEDULER_REASON_TIMEOUT)
    GNUNET_SCHEDULER_add_now (sched, &end_badly, NULL);

  GNUNET_assert (peer->dht_handle != NULL);

  GNUNET_DHT_get_stop (peer->get_handle, &test_find_peer, &p1);

  //GNUNET_SCHEDULER_add_delayed(sched, GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 1), &test_put, &p1);

}

void
test_get_iterator (void *cls,
                   struct GNUNET_TIME_Absolute exp,
                   const GNUNET_HashCode * key,
                   uint32_t type, uint32_t size, const void *data)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "test_get_iterator called (we got a result), stopping get request!\n");

  GNUNET_SCHEDULER_add_continuation (sched, &test_get_stop, &p1,
                                     GNUNET_SCHEDULER_REASON_PREREQ_DONE);
}

/**
 * Signature of the main function of a task.
 *
 * @param cls closure
 * @param tc context information (why was this task triggered now)
 */
void
test_get (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct PeerContext *peer = cls;
  GNUNET_HashCode hash;
  memset (&hash, 42, sizeof (GNUNET_HashCode));

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Called test_get!\n");

  GNUNET_assert (peer->dht_handle != NULL);

  peer->get_handle =
    GNUNET_DHT_get_start (peer->dht_handle, TOTAL_TIMEOUT, 42, &hash,
                          &test_get_iterator, NULL, NULL, NULL);

  if (peer->get_handle == NULL)
    GNUNET_SCHEDULER_add_now (sched, &end_badly, &p1);
}

/**
 * Signature of the main function of a task.
 *
 * @param cls closure
 * @param tc context information (why was this task triggered now)
 */
void
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
  peer->dht_handle = GNUNET_DHT_connect (sched, peer->cfg, 100);

  GNUNET_assert (peer->dht_handle != NULL);

  GNUNET_DHT_put (peer->dht_handle, &hash, 42, data_size, data,
                  GNUNET_TIME_relative_to_absolute (TOTAL_TIMEOUT), TOTAL_TIMEOUT,
                  &test_get, &p1);
  GNUNET_free(data);
}

static void
setup_peer (struct PeerContext *p, const char *cfgname)
{
  p->cfg = GNUNET_CONFIGURATION_create ();
#if START_ARM
  p->arm_pid = GNUNET_OS_start_process (NULL, NULL, "gnunet-service-arm",
                                        "gnunet-service-arm",
#if VERBOSE_ARM
                                        "-L", "DEBUG",
#endif
                                        "-c", cfgname, NULL);
#endif
  GNUNET_assert (GNUNET_OK == GNUNET_CONFIGURATION_load (p->cfg, cfgname));

}

static void
run (void *cls,
     struct GNUNET_SCHEDULER_Handle *s,
     char *const *args,
     const char *cfgfile, const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  GNUNET_assert (ok == 1);
  OKPP;
  sched = s;

  die_task = GNUNET_SCHEDULER_add_delayed (sched,
                                           GNUNET_TIME_relative_multiply
                                           (GNUNET_TIME_UNIT_MINUTES, 1),
                                           &end_badly, NULL);

  setup_peer (&p1, "test_dht_api_peer1.conf");

  GNUNET_SCHEDULER_add_delayed (sched,
                                GNUNET_TIME_relative_multiply
                                (GNUNET_TIME_UNIT_SECONDS, 1), &test_put,
                                &p1);
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
  GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1,
                      argv, "test-dht-api", "nohelp", options, &run, &ok);
  stop_arm (&p1);
  return ok;
}


int
main (int argc, char *argv[])
{
  int ret;
#ifdef MINGW
  return GNUNET_SYSERR;
#endif

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
