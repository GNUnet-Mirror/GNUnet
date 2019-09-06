/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2010, 2015, 2016 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
*/
/**
 * @file core/test_core_quota_compliance.c
 * @brief testcase for core_api.c focusing quota compliance on core level
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_arm_service.h"
#include "gnunet_core_service.h"
#include "gnunet_util_lib.h"
#include "gnunet_ats_service.h"
#include "gnunet_transport_service.h"
#include "gnunet_transport_hello_service.h"
#include "gnunet_statistics_service.h"


#define SYMMETRIC 0
#define ASYMMETRIC_SEND_LIMITED 1
#define ASYMMETRIC_RECV_LIMITED 2

/**
 * Note that this value must not significantly exceed
 * 'MAX_PENDING' in 'gnunet-service-transport.c', otherwise
 * messages may be dropped even for a reliable transport.
 */
#define TOTAL_MSGS (60000 * 10)

/**
 * How long until we give up on transmitting the message?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 300)

/**
 * What delay do we request from the core service for transmission?
 */
#define FAST_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 150)

#define MTYPE 12345
#define MESSAGESIZE (1024 - 8)
#define MEASUREMENT_LENGTH GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 30)

static unsigned long long total_bytes_sent;
static unsigned long long total_bytes_recv;

static struct GNUNET_TIME_Absolute start_time;

static struct GNUNET_SCHEDULER_Task *err_task;

static struct GNUNET_SCHEDULER_Task *measure_task;


struct PeerContext
{
  struct GNUNET_CONFIGURATION_Handle *cfg;
  struct GNUNET_CORE_Handle *ch;
  struct GNUNET_MQ_Handle *mq;
  struct GNUNET_TRANSPORT_OfferHelloHandle *oh;
  struct GNUNET_PeerIdentity id;
  struct GNUNET_MessageHeader *hello;
  struct GNUNET_STATISTICS_Handle *stats;
  struct GNUNET_TRANSPORT_HelloGetHandle *ghh;
  struct GNUNET_ATS_ConnectivityHandle *ats;
  struct GNUNET_ATS_ConnectivitySuggestHandle *ats_sh;
  int connect_status;
  struct GNUNET_OS_Process *arm_proc;
};

static struct PeerContext p1;
static struct PeerContext p2;

static unsigned long long current_quota_p1_in;
static unsigned long long current_quota_p1_out;
static unsigned long long current_quota_p2_in;
static unsigned long long current_quota_p2_out;

static int ok;
static int test;
static int32_t tr_n;

static int running;


#if VERBOSE
#define OKPP do { ok++; GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Now at stage %u at %s:%u\n", ok, __FILE__, __LINE__); } while (0)
#else
#define OKPP do { ok++; } while (0)
#endif

struct TestMessage
{
  struct GNUNET_MessageHeader header;
  uint32_t num GNUNET_PACKED;
  uint8_t pad[MESSAGESIZE];
};


static void
terminate_peer (struct PeerContext *p)
{
  if (NULL != p->ch)
  {
    GNUNET_CORE_disconnect (p->ch);
    p->ch = NULL;
  }
  if (NULL != p->ghh)
  {
    GNUNET_TRANSPORT_hello_get_cancel (p->ghh);
    p->ghh = NULL;
  }
  if (NULL != p->oh)
  {
    GNUNET_TRANSPORT_offer_hello_cancel (p->oh);
    p->oh = NULL;
  }
  if (NULL != p->ats_sh)
  {
    GNUNET_ATS_connectivity_suggest_cancel (p->ats_sh);
    p->ats_sh = NULL;
  }
  if (NULL != p->ats)
  {
    GNUNET_ATS_connectivity_done (p->ats);
    p->ats = NULL;
  }
  if (NULL != p->stats)
  {
    GNUNET_STATISTICS_destroy (p->stats, GNUNET_NO);
    p->stats = NULL;
  }
  if (NULL != p->hello)
  {
    GNUNET_free (p->hello);
    p->hello = NULL;
  }
}


static void
shutdown_task (void *cls)
{
  if (NULL != err_task)
  {
    GNUNET_SCHEDULER_cancel (err_task);
    err_task = NULL;
  }
  if (NULL != measure_task)
  {
    GNUNET_SCHEDULER_cancel (measure_task);
    measure_task = NULL;
  }
  terminate_peer (&p1);
  terminate_peer (&p2);
}


static void
terminate_task_error (void *cls)
{
  err_task = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
	      "Testcase failed (timeout)!\n");
  GNUNET_SCHEDULER_shutdown ();
  ok = 42;
}


/**
 * Callback function to process statistic values.
 *
 * @param cls closure
 * @param subsystem name of subsystem that created the statistic
 * @param name the name of the datum
 * @param value the current value
 * @param is_persistent #GNUNET_YES if the value is persistent, #GNUNET_NO if not
 * @return #GNUNET_OK to continue, #GNUNET_SYSERR to abort iteration
 */
static int
print_stat (void *cls,
            const char *subsystem,
            const char *name,
            uint64_t value,
            int is_persistent)
{
  if (cls == &p1)
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Peer1 %50s = %12llu\n",
                name,
                (unsigned long long) value);
  if (cls == &p2)
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Peer2 %50s = %12llu\n",
                name,
                (unsigned long long) value);
  return GNUNET_OK;
}


static void
measurement_stop (void *cls)
{
  unsigned long long delta;
  unsigned long long throughput_out;
  unsigned long long throughput_in;
  unsigned long long max_quota_in;
  unsigned long long max_quota_out;
  unsigned long long quota_delta;
  enum GNUNET_ErrorType kind = GNUNET_ERROR_TYPE_DEBUG;

  measure_task = NULL;
  fprintf (stdout, "%s",  "\n");
  running = GNUNET_NO;

  delta = GNUNET_TIME_absolute_get_duration (start_time).rel_value_us;
  if (0 == delta)
    delta = 1;
  throughput_out = total_bytes_sent * 1000000LL / delta;     /* convert to bytes/s */
  throughput_in = total_bytes_recv * 1000000LL / delta;      /* convert to bytes/s */

  max_quota_in = GNUNET_MIN (current_quota_p1_in, current_quota_p2_in);
  max_quota_out = GNUNET_MIN (current_quota_p1_out, current_quota_p2_out);
  if (max_quota_out < max_quota_in)
    quota_delta = max_quota_in / 3;
  else
    quota_delta = max_quota_out / 3;

  if ((throughput_out > (max_quota_out + quota_delta)) ||
      (throughput_in > (max_quota_in + quota_delta)))
    ok = 1; /* fail */
  else
    ok = 0; /* pass */
  GNUNET_STATISTICS_get (p1.stats,
			 "core",
			 "# discarded CORE_SEND requests",
                         NULL,
			 &print_stat,
			 &p1);
  GNUNET_STATISTICS_get (p1.stats,
			 "core",
                         "# discarded CORE_SEND request bytes",
                         NULL,
			 &print_stat,
			 &p1);
  GNUNET_STATISTICS_get (p1.stats,
			 "core",
                         "# discarded lower priority CORE_SEND requests",
                         NULL,
			 &print_stat,
			 NULL);
  GNUNET_STATISTICS_get (p1.stats,
			 "core",
                         "# discarded lower priority CORE_SEND request bytes",
                         NULL,
			 &print_stat,
			 &p1);
  GNUNET_STATISTICS_get (p2.stats,
			 "core",
			 "# discarded CORE_SEND requests",
                         NULL,
			 &print_stat,
			 &p2);

  GNUNET_STATISTICS_get (p2.stats,
			 "core",
                         "# discarded CORE_SEND request bytes",
                         NULL,
			 &print_stat,
			 &p2);
  GNUNET_STATISTICS_get (p2.stats,
			 "core",
                         "# discarded lower priority CORE_SEND requests",
                         NULL,
			 &print_stat,
			 &p2);
  GNUNET_STATISTICS_get (p2.stats,
			 "core",
                         "# discarded lower priority CORE_SEND request bytes",
                         NULL,
			 &print_stat,
			 &p2);

  if (ok != 0)
    kind = GNUNET_ERROR_TYPE_ERROR;
  switch (test)
  {
  case SYMMETRIC:
    GNUNET_log (kind,
		"Core quota compliance test with symmetric quotas: %s\n",
                (0 == ok) ? "PASSED" : "FAILED");
    break;
  case ASYMMETRIC_SEND_LIMITED:
    GNUNET_log (kind,
                "Core quota compliance test with limited sender quota: %s\n",
                (0 == ok) ? "PASSED" : "FAILED");
    break;
  case ASYMMETRIC_RECV_LIMITED:
    GNUNET_log (kind,
                "Core quota compliance test with limited receiver quota: %s\n",
                (0 == ok) ? "PASSED" : "FAILED");
    break;
  };
  GNUNET_log (kind,
	      "Peer 1 send  rate: %llu b/s (%llu bytes in %llu ms)\n",
              throughput_out,
	      total_bytes_sent,
	      delta);
  GNUNET_log (kind,
	      "Peer 1 send quota: %llu b/s\n",
	      current_quota_p1_out);
  GNUNET_log (kind,
	      "Peer 2 receive  rate: %llu b/s (%llu bytes in %llu ms)\n",
              throughput_in,
	      total_bytes_recv,
	      delta);
  GNUNET_log (kind,
	      "Peer 2 receive quota: %llu b/s\n",
	      current_quota_p2_in);
/*
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Max. inbound  quota allowed: %llu b/s\n",max_quota_in );
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Max. outbound quota allowed: %llu b/s\n",max_quota_out);
*/
  GNUNET_SCHEDULER_shutdown ();
}


static void
do_transmit (void *cls)
{
  struct TestMessage *hdr;
  struct GNUNET_MQ_Envelope *env;

  env = GNUNET_MQ_msg (hdr,
                       MTYPE);
  hdr->num = htonl (tr_n);
  memset (&hdr->pad,
          tr_n,
          MESSAGESIZE);
  tr_n++;
  GNUNET_SCHEDULER_cancel (err_task);
  err_task =
      GNUNET_SCHEDULER_add_delayed (TIMEOUT,
				    &terminate_task_error,
				    NULL);
  total_bytes_sent += sizeof (struct TestMessage);
  GNUNET_MQ_send (p1.mq,
                  env);
}


static void *
connect_notify (void *cls,
		const struct GNUNET_PeerIdentity *peer,
                struct GNUNET_MQ_Handle *mq)
{
  struct PeerContext *pc = cls;

  if (0 == memcmp (&pc->id,
		   peer,
		   sizeof (struct GNUNET_PeerIdentity)))
    return NULL;                     /* loopback */
  GNUNET_assert (0 == pc->connect_status);
  pc->connect_status = 1;
  pc->mq = mq;
  if (pc == &p1)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Encrypted connection established to peer `%s'\n",
                GNUNET_i2s (peer));
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Asking core (1) for transmission to peer `%s'\n",
                GNUNET_i2s (&p2.id));
    GNUNET_SCHEDULER_cancel (err_task);
    err_task =
        GNUNET_SCHEDULER_add_delayed (TIMEOUT,
				      &terminate_task_error,
				      NULL);
    start_time = GNUNET_TIME_absolute_get ();
    running = GNUNET_YES;
    measure_task =
        GNUNET_SCHEDULER_add_delayed (MEASUREMENT_LENGTH,
				      &measurement_stop,
                                      NULL);
    do_transmit (NULL);
  }
  return pc;
}


static void
disconnect_notify (void *cls,
		   const struct GNUNET_PeerIdentity *peer,
                   void *internal_cls)
{
  struct PeerContext *pc = cls;

  if (NULL == internal_cls)
    return;                     /* loopback */
  pc->connect_status = 0;
  pc->mq = NULL;
  if (NULL != measure_task)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Measurement aborted due to disconnect!\n");
    GNUNET_SCHEDULER_cancel (measure_task);
    measure_task = NULL;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Encrypted connection to `%s' cut\n",
              GNUNET_i2s (peer));
}



static void
handle_test (void *cls,
             const struct TestMessage *hdr)
{
  static int n;

  total_bytes_recv += sizeof (struct TestMessage);
  if (ntohl (hdr->num) != n)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Expected message %u, got message %u\n",
                n,
		ntohl (hdr->num));
    GNUNET_SCHEDULER_cancel (err_task);
    err_task = GNUNET_SCHEDULER_add_now (&terminate_task_error,
					 NULL);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Got message %u\n",
              ntohl (hdr->num));
  n++;
  if (0 == (n % 10))
    fprintf (stderr, "%s",  ".");

  if (GNUNET_YES == running)
    do_transmit (NULL);
}


static void
init_notify (void *cls,
             const struct GNUNET_PeerIdentity *my_identity)
{
  struct PeerContext *p = cls;
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_fixed_size (test,
                             MTYPE,
                             struct TestMessage,
                             NULL),
    GNUNET_MQ_handler_end ()
  };

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Connection to CORE service of `%s' established\n",
              GNUNET_i2s (my_identity));
  GNUNET_assert (NULL != my_identity);
  p->id = *my_identity;
  if (cls == &p1)
  {
    GNUNET_assert (ok == 2);
    OKPP;
    /* connect p2 */
    p2.ch = GNUNET_CORE_connect (p2.cfg,
                                 &p2,
                                 &init_notify,
                                 &connect_notify,
                                 &disconnect_notify,
                                 handlers);
  }
  else
  {
    GNUNET_assert (ok == 3);
    OKPP;
    GNUNET_assert (cls == &p2);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Asking core (1) to connect to peer `%s' and vice-versa\n",
                GNUNET_i2s (&p2.id));
    p1.ats_sh = GNUNET_ATS_connectivity_suggest (p1.ats,
                                                 &p2.id,
                                                 1);
    p2.ats_sh = GNUNET_ATS_connectivity_suggest (p2.ats,
                                                 &p1.id,
                                                 1);
  }
}


static void
offer_hello_done (void *cls)
{
  struct PeerContext *p = cls;

  p->oh = NULL;
}


static void
process_hello (void *cls,
	       const struct GNUNET_MessageHeader *message)
{
  struct PeerContext *p = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received (my) HELLO from transport service\n");
  GNUNET_assert (message != NULL);
  p->hello = GNUNET_malloc (ntohs (message->size));
  GNUNET_memcpy (p->hello, message, ntohs (message->size));
  if ( (p == &p1) &&
       (NULL == p2.oh) )
    p2.oh = GNUNET_TRANSPORT_offer_hello (p2.cfg,
                                          message,
                                          &offer_hello_done,
                                          &p2);
  if ( (p == &p2) &&
       (NULL == p1.oh) )
    p1.oh = GNUNET_TRANSPORT_offer_hello (p1.cfg, message,
                                          &offer_hello_done,
                                          &p1);

  if ( (p == &p1) &&
       (NULL != p2.hello) &&
       (NULL == p1.oh) )
    p1.oh = GNUNET_TRANSPORT_offer_hello (p1.cfg,
                                          p2.hello,
                                          &offer_hello_done,
                                          &p1);
  if ( (p == &p2) &&
       (NULL != p1.hello) &&
       (NULL == p2.oh) )
    p2.oh = GNUNET_TRANSPORT_offer_hello (p2.cfg,
                                          p1.hello,
                                          &offer_hello_done,
                                          &p2);
}


static void
setup_peer (struct PeerContext *p,
	    const char *cfgname)
{
  char *binary;

  binary = GNUNET_OS_get_libexec_binary_path ("gnunet-service-arm");
  p->cfg = GNUNET_CONFIGURATION_create ();
  p->arm_proc =
    GNUNET_OS_start_process (GNUNET_YES,
			     GNUNET_OS_INHERIT_STD_OUT_AND_ERR,
                             NULL, NULL, NULL,
                             binary,
                             "gnunet-service-arm",
                             "-c",
			     cfgname,
			     NULL);
  GNUNET_assert (GNUNET_OK ==
		 GNUNET_CONFIGURATION_load (p->cfg,
					    cfgname));
  p->stats = GNUNET_STATISTICS_create ("core",
				       p->cfg);
  GNUNET_assert (NULL != p->stats);
  p->ats = GNUNET_ATS_connectivity_init (p->cfg);
  GNUNET_assert (NULL != p->ats);
  p->ghh = GNUNET_TRANSPORT_hello_get (p->cfg,
				       GNUNET_TRANSPORT_AC_ANY,
				       &process_hello,
				       p);
  GNUNET_free (binary);
}


static void
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_fixed_size (test,
                             MTYPE,
                             struct TestMessage,
                             NULL),
    GNUNET_MQ_handler_end ()
  };

  GNUNET_assert (ok == 1);
  OKPP;
  err_task =
      GNUNET_SCHEDULER_add_delayed (TIMEOUT,
				    &terminate_task_error,
				    NULL);
  GNUNET_SCHEDULER_add_shutdown (&shutdown_task,
				 NULL);
  if (test == SYMMETRIC)
  {
    setup_peer (&p1,
		"test_core_quota_peer1.conf");
    setup_peer (&p2,
		"test_core_quota_peer2.conf");
  }
  else if (test == ASYMMETRIC_SEND_LIMITED)
  {
    setup_peer (&p1,
		"test_core_quota_asymmetric_send_limit_peer1.conf");
    setup_peer (&p2,
		"test_core_quota_asymmetric_send_limit_peer2.conf");
  }
  else if (test == ASYMMETRIC_RECV_LIMITED)
  {
    setup_peer (&p1,
		"test_core_quota_asymmetric_recv_limited_peer1.conf");
    setup_peer (&p2,
		"test_core_quota_asymmetric_recv_limited_peer2.conf");
  }

  GNUNET_assert (test != -1);
  GNUNET_assert (GNUNET_SYSERR !=
                 GNUNET_CONFIGURATION_get_value_size (p1.cfg,
						      "ATS",
                                                      "WAN_QUOTA_IN",
                                                      &current_quota_p1_in));
  GNUNET_assert (GNUNET_SYSERR !=
                 GNUNET_CONFIGURATION_get_value_size (p2.cfg,
						      "ATS",
                                                      "WAN_QUOTA_IN",
                                                      &current_quota_p2_in));
  GNUNET_assert (GNUNET_SYSERR !=
                 GNUNET_CONFIGURATION_get_value_size (p1.cfg,
						      "ATS",
                                                      "WAN_QUOTA_OUT",
                                                      &current_quota_p1_out));
  GNUNET_assert (GNUNET_SYSERR !=
                 GNUNET_CONFIGURATION_get_value_size (p2.cfg,
						      "ATS",
                                                      "WAN_QUOTA_OUT",
                                                      &current_quota_p2_out));

  p1.ch = GNUNET_CORE_connect (p1.cfg,
                               &p1,
                               &init_notify,
                               &connect_notify,
                               &disconnect_notify,
                               handlers);
}


static void
stop_arm (struct PeerContext *p)
{
  if (0 != GNUNET_OS_process_kill (p->arm_proc,
				   GNUNET_TERM_SIG))
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING,
			 "kill");
  if (GNUNET_OK !=
      GNUNET_OS_process_wait (p->arm_proc))
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING,
			 "waitpid");
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "ARM process %u stopped\n",
              GNUNET_OS_process_get_pid (p->arm_proc));
  GNUNET_OS_process_destroy (p->arm_proc);
  p->arm_proc = NULL;
  GNUNET_CONFIGURATION_destroy (p->cfg);
}


static int
check ()
{
  char *const argv[] = {
    "test-core-quota-compliance",
    "-c",
    "test_core_api_data.conf",
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  ok = 1;
  GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1,
		      argv,
                      "test-core-quota-compliance",
		      "nohelp",
		      options,
		      &run,
                      &ok);
  stop_arm (&p1);
  stop_arm (&p2);
  return ok;
}


static void
cleanup_directory (int test)
{
  switch (test) {
  case SYMMETRIC:
    GNUNET_DISK_directory_remove ("/tmp/test-gnunet-core-quota-sym-peer-1/");
    GNUNET_DISK_directory_remove ("/tmp/test-gnunet-core-quota-sym-peer-2/");
    break;
  case ASYMMETRIC_SEND_LIMITED:
    GNUNET_DISK_directory_remove
        ("/tmp/test-gnunet-core-quota-asym-send-lim-peer-1/");
    GNUNET_DISK_directory_remove
        ("/tmp/test-gnunet-core-quota-asym-send-lim-peer-2/");
    break;
  case ASYMMETRIC_RECV_LIMITED:
    GNUNET_DISK_directory_remove
        ("/tmp/test-gnunet-core-quota-asym-recv-lim-peer-1/");
    GNUNET_DISK_directory_remove
        ("/tmp/test-gnunet-core-quota-asym-recv-lim-peer-2/");
    break;
  }
}


int
main (int argc,
      char *argv[])
{
  int ret;

  test = -1;
  if (NULL != strstr (argv[0],
		      "_symmetric"))
  {
    test = SYMMETRIC;
  }
  else if (NULL != strstr (argv[0],
			   "_asymmetric_send"))
  {
    test = ASYMMETRIC_SEND_LIMITED;
  }
  else if (NULL != strstr (argv[0],
			   "_asymmetric_recv"))
  {
    test = ASYMMETRIC_RECV_LIMITED;
  }
  GNUNET_assert (test != -1);
  cleanup_directory (test);
  GNUNET_log_setup ("test-core-quota-compliance",
                    "WARNING",
                    NULL);
  ret = check ();
  cleanup_directory (test);
  return ret;
}


/* end of test_core_quota_compliance.c */
