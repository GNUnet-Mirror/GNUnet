/*
     This file is part of GNUnet.
     (C) 2009, 2010 Christian Grothoff (and other contributing authors)

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
 * @file core/test_core_quota_compliance.c
 * @brief testcase for core_api.c focusing quota compliance on core level
 *
 * FIXME:
 * - make sure connect callback is invoked properly as well!
 */
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_constants.h"
#include "gnunet_arm_service.h"
#include "gnunet_core_service.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_os_lib.h"
#include "gnunet_program_lib.h"
#include "gnunet_scheduler_lib.h"
#include "gnunet_transport_service.h"
#include "gnunet_statistics_service.h"

#define VERBOSE GNUNET_YES

#define START_ARM GNUNET_YES
#define DEBUG_CONNECTIONS GNUNET_NO

/**
 * Note that this value must not significantly exceed
 * 'MAX_PENDING' in 'gnunet-service-transport.c', otherwise
 * messages may be dropped even for a reliable transport.
 */
#define TOTAL_MSGS (600 * 10)

#define MEASUREMENT_MSG_SIZE 10240
#define MEASUREMENT_MAX_QUOTA 1024 * 1024 * 1024
#define MEASUREMENT_MIN_QUOTA 1024
#define MEASUREMENT_INTERVALL GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)

/**
 * How long until we give up on transmitting the message?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 6000)

/**
 * What delay do we request from the core service for transmission?
 * Any value smaller than the CORK delay will disable CORKing, which
 * is what we want here.
 */
#define FAST_TIMEOUT GNUNET_TIME_relative_divide (GNUNET_CONSTANTS_MAX_CORK_DELAY, 2)

#define MTYPE 12345

static int is_asymmetric_send_constant;
static int is_asymmetric_recv_constant;
static unsigned long long current_quota_p1_in;
static unsigned long long current_quota_p1_out;
static unsigned long long current_quota_p2_in;
static unsigned long long current_quota_p2_out;

static unsigned long long total_bytes;
static unsigned long long total_bytes_sent;
static unsigned long long total_bytes_recv;

static struct GNUNET_TIME_Absolute start_time;

static GNUNET_SCHEDULER_TaskIdentifier err_task;

static GNUNET_SCHEDULER_TaskIdentifier send_task;

static GNUNET_SCHEDULER_TaskIdentifier measure_task;

struct PeerContext
{
  struct GNUNET_CONFIGURATION_Handle *cfg;
  struct GNUNET_STATISTICS_Handle *stats;
  struct GNUNET_CORE_Handle *ch;
  struct GNUNET_PeerIdentity id;   
  struct GNUNET_TRANSPORT_Handle *th;
  struct GNUNET_MessageHeader *hello;

  int connect_status;
#if START_ARM
  struct GNUNET_OS_Process *arm_proc;
#endif
};

static struct PeerContext p1;

static struct PeerContext p2;

static int ok;
static int measurement_running;

struct GNUNET_CORE_TransmitHandle * ch;

#if VERBOSE
#define OKPP do { ok++; fprintf (stderr, "Now at stage %u at %s:%u\n", ok, __FILE__, __LINE__); } while (0)
#else
#define OKPP do { ok++; } while (0)
#endif

struct TestMessage 
{
  struct GNUNET_MessageHeader header;
  uint32_t num;
};

static void
terminate_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  unsigned long long delta;

  GNUNET_CORE_disconnect (p1.ch);
  p1.ch = NULL;
  GNUNET_CORE_disconnect (p2.ch);
  p2.ch = NULL;
  GNUNET_TRANSPORT_disconnect (p1.th);
  p1.th = NULL;
  GNUNET_TRANSPORT_disconnect (p2.th);
  p2.th = NULL;
  delta = GNUNET_TIME_absolute_get_duration (start_time).rel_value;
  ok = 0;
}


static void
terminate_task_error (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_break (0);
  if (send_task != GNUNET_SCHEDULER_NO_TASK)
	  GNUNET_SCHEDULER_cancel (send_task);
  GNUNET_CORE_disconnect (p1.ch);
  p1.ch = NULL;
  GNUNET_CORE_disconnect (p2.ch);
  p2.ch = NULL;
  GNUNET_TRANSPORT_disconnect (p1.th);
  p1.th = NULL;
  GNUNET_TRANSPORT_disconnect (p2.th);
  p2.th = NULL;
  ok = 42;
}

static void
connect_notify (void *cls,
                const struct GNUNET_PeerIdentity *peer,
		struct GNUNET_TIME_Relative latency,
		uint32_t distance)
{
  struct PeerContext *pc = cls;
  GNUNET_assert (pc->connect_status == 0);
  pc->connect_status = 1;
#if DEBUG_CONNECTIONS
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Encrypted connection established to peer `%4s'\n",
              GNUNET_i2s (peer));
#endif
}


static void
disconnect_notify (void *cls,
                   const struct GNUNET_PeerIdentity *peer)
{
  struct PeerContext *pc = cls;
  pc->connect_status = 0;
#if DEBUG_CONNECTIONS
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Encrypted connection to `%4s' cut\n", GNUNET_i2s (peer));
#endif
}


static int
inbound_notify (void *cls,
                const struct GNUNET_PeerIdentity *other,
                const struct GNUNET_MessageHeader *message,
		const struct GNUNET_TRANSPORT_ATS_Information *atsi)
{
  total_bytes_recv += ntohs (message->size);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Core provides inbound data from `%4s' size %u.\n", GNUNET_i2s (other), ntohs (message->size));
#if DEBUG_CONNECTIONS
  #endif
  return GNUNET_OK;
}


static int
outbound_notify (void *cls,
                 const struct GNUNET_PeerIdentity *other,
                 const struct GNUNET_MessageHeader *message,
		 const struct GNUNET_TRANSPORT_ATS_Information *atsi)
{
#if DEBUG_CONNECTIONS
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Core notifies about outbound data for `%4s'.\n",
              GNUNET_i2s (other));
#endif
  return GNUNET_OK;
}

static void
next_fin (void *cls, int success)
{

}


static int
check_2 (void *cls,
         const char *subsystem,
         const char *name, uint64_t value, int is_persistent)
{
 fprintf(stderr, "%s %s %llu\n", subsystem, name, (long long unsigned int) value);
 return GNUNET_OK;
}

static void
measurement_end (void *cls,
	   const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_TIME_Relative duration;
  
  measure_task  = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;
  
  if (err_task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (err_task);
  if (send_task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (send_task);
  
  GNUNET_STATISTICS_get(p1.stats,"core","# discarded CORE_SEND requests",GNUNET_TIME_UNIT_SECONDS, &next_fin, &check_2, &p1);
  GNUNET_STATISTICS_get(p1.stats,"core","# discarded CORE_SEND requests",GNUNET_TIME_UNIT_SECONDS, &next_fin, &check_2, &p2);
  GNUNET_STATISTICS_get(p1.stats,"core","# discarded lower priority CORE_SEND requests",GNUNET_TIME_UNIT_SECONDS, &next_fin, &check_2, &p1);
  GNUNET_STATISTICS_get(p1.stats,"core","# discarded lower priority CORE_SEND requests",GNUNET_TIME_UNIT_SECONDS, &next_fin, &check_2, &p2);
  
  GNUNET_STATISTICS_get(p1.stats,"core","# discarded CORE_SEND request bytes",GNUNET_TIME_UNIT_SECONDS, &next_fin, &check_2, &p1);
  GNUNET_STATISTICS_get(p1.stats,"core","# discarded CORE_SEND request bytes",GNUNET_TIME_UNIT_SECONDS, &next_fin, &check_2, &p2);
  GNUNET_STATISTICS_get(p1.stats,"core","# discarded lower priority CORE_SEND request bytes",GNUNET_TIME_UNIT_SECONDS, &next_fin, &check_2, &p1);
  GNUNET_STATISTICS_get(p1.stats,"core","# discarded lower priority CORE_SEND request bytes",GNUNET_TIME_UNIT_SECONDS, &next_fin, &check_2, &p2);
  measurement_running = GNUNET_NO;
  duration = GNUNET_TIME_absolute_get_difference(start_time, GNUNET_TIME_absolute_get());
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
	      "\nQuota compliance: \n"			\
	      "Receive rate: %10llu kB/s\n"
	      "Send rate   : %10llu kB/s\n"			\
	      "Quota       : %10llu kB/s\n",
	      (total_bytes_recv/(duration.rel_value / 1000)/1024),
	      (total_bytes_sent/(duration.rel_value / 1000)/1024),
	      current_quota_p1_in/1024);
  GNUNET_SCHEDULER_add_now (&terminate_task, NULL);
}

static size_t
transmit_ready (void *cls, size_t size, void *buf);

static void
send_tsk (void *cls,
	   const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  send_task = GNUNET_SCHEDULER_NO_TASK;
  
  ch = GNUNET_CORE_notify_transmit_ready (p1.ch,
					  0,
					  FAST_TIMEOUT,
					  &p2.id,
					  sizeof (struct TestMessage) + MEASUREMENT_MSG_SIZE,
					  &transmit_ready, &p1);
}


static void 
measure (unsigned long long quota_p1, unsigned long long quota_p2)
{
#if VERBOSE
  if ((is_asymmetric_send_constant == GNUNET_YES) || (is_asymmetric_recv_constant == GNUNET_YES))
	  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Starting core level measurement for %u seconds receiving peer quota %llu kB/s, sending peer quota %llu kB/s\n", MEASUREMENT_INTERVALL.rel_value / 1000 , current_quota_p1_in / 1024, current_quota_p2_out / 1024);
  else
	  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Starting core level measurement for %u seconds, symmetric quota %llu kB/s\n", MEASUREMENT_INTERVALL.rel_value / 1000 , current_quota_p2_out / 1024);

#endif
#if DEBUG_CONNECTIONS
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Asking core (1) for transmission to peer `%4s'\n",
              GNUNET_i2s (&p2.id));
#endif
  err_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT,
			      &terminate_task_error,
			      NULL);
  measure_task = GNUNET_SCHEDULER_add_delayed (MEASUREMENT_INTERVALL,
			      &measurement_end,
			      NULL);
  start_time = GNUNET_TIME_absolute_get ();
  measurement_running = GNUNET_YES;
  total_bytes = 0;
  total_bytes_sent = 0;
  ch = GNUNET_CORE_notify_transmit_ready (p1.ch,
					  0,
					  TIMEOUT,
					  &p2.id,
					  sizeof (struct TestMessage) + MEASUREMENT_MSG_SIZE,
					  &transmit_ready, &p1);
}

static int tr_n;


static int
process_mtype (void *cls,
               const struct GNUNET_PeerIdentity *peer,
               const struct GNUNET_MessageHeader *message,
	       const struct GNUNET_TRANSPORT_ATS_Information *atsi)
{
  static int n;
  unsigned int s;
  const struct TestMessage *hdr;

  hdr = (const struct TestMessage*) message;
  s = sizeof (struct TestMessage) + MEASUREMENT_MSG_SIZE;
  if (MTYPE != ntohs (message->type))
    return GNUNET_SYSERR;

#if DEBUG_CONNECTIONS
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Got message %u of size %u\n",
	      ntohl (hdr->num),
	      ntohs (message->size));	      
#endif
  n++;
  if (0 == (n % (TOTAL_MSGS/100)))
    fprintf (stderr, ".");

  return GNUNET_OK;
}


static struct GNUNET_CORE_MessageHandler handlers[] = {
  {&process_mtype, MTYPE, 0},
  {NULL, 0, 0}
};


static size_t
transmit_ready (void *cls, size_t size, void *buf)
{
  char *cbuf = buf;
  struct TestMessage hdr;
  unsigned int s;
  unsigned int ret;

  if (measurement_running != GNUNET_YES)
	return 0;

  GNUNET_assert (size <= GNUNET_CONSTANTS_MAX_ENCRYPTED_MESSAGE_SIZE); 
  if (buf == NULL)
    {
      if (p1.ch != NULL)
      {
		ch = GNUNET_CORE_notify_transmit_ready (p1.ch,
							 0,
							 FAST_TIMEOUT,
							 &p2.id,
							 sizeof (struct TestMessage) + MEASUREMENT_MSG_SIZE,
							 &transmit_ready, &p1);
		GNUNET_break (NULL != ch);
      }
      return 0;
    }
  ret = 0;
  ch = NULL;
  s = sizeof (struct TestMessage) + MEASUREMENT_MSG_SIZE;

  GNUNET_assert (size >= s);
  GNUNET_assert (buf != NULL);
  cbuf = buf;
  do
    {
#if DEBUG_CONNECTIONS
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Sending message %u of size %u at offset %u\n",
		  tr_n,
		  s,
		  ret);
#endif
      hdr.header.size = htons (s);
      hdr.header.type = htons (MTYPE);
      hdr.num = htonl (tr_n);
      memcpy (&cbuf[ret], &hdr, sizeof (struct TestMessage));
      ret += sizeof (struct TestMessage);
      memset (&cbuf[ret], tr_n, s - sizeof (struct TestMessage));
      ret += s - sizeof (struct TestMessage);
      tr_n++;
      if (0 == GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, 16))
	break; /* sometimes pack buffer full, sometimes not */
    }
  while (size - ret >= s);
  GNUNET_SCHEDULER_cancel (err_task);
  err_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT,
				  &terminate_task_error, 
				  NULL);

  total_bytes += ret;
  total_bytes_sent += ret;
  if (send_task != GNUNET_SCHEDULER_NO_TASK)
	  GNUNET_SCHEDULER_cancel(send_task);
  send_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS, 20), &send_tsk, NULL);

  return ret;
}



static void
init_notify (void *cls,
             struct GNUNET_CORE_Handle *server,
             const struct GNUNET_PeerIdentity *my_identity,
             const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *publicKey)
{
  struct PeerContext *p = cls;
#if DEBUG_CONNECTIONS
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Connection to CORE service of `%4s' established\n",
              GNUNET_i2s (my_identity));
#endif
  GNUNET_assert (server != NULL);
  p->id = *my_identity;
  p->ch = server;
  if (cls == &p1)
    {
      GNUNET_assert (ok == 2);
      OKPP;
      /* connect p2 */
      GNUNET_CORE_connect (p2.cfg, 1,
                           &p2,
                           &init_notify,			 
                           &connect_notify,
                           &disconnect_notify,
			   NULL,
                           &inbound_notify,
                           GNUNET_YES,
                           &outbound_notify, GNUNET_YES, handlers);
    }
  else
    {
      GNUNET_assert (ok == 3);
      OKPP;
      GNUNET_assert (cls == &p2);

      measure (MEASUREMENT_MIN_QUOTA, MEASUREMENT_MIN_QUOTA);
    }
}


static void
process_hello (void *cls,
               const struct GNUNET_MessageHeader *message)
{
  struct PeerContext *p = cls;

  GNUNET_TRANSPORT_get_hello_cancel (p->th, &process_hello, p);
#if DEBUG_CONNECTIONS
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received (my) `%s' from transport service\n",
              "HELLO");
#endif
  GNUNET_assert (message != NULL);
  p->hello = GNUNET_malloc (ntohs (message->size));
  memcpy (p->hello, message, ntohs (message->size));
  if ((p == &p1) && (p2.th != NULL))
    GNUNET_TRANSPORT_offer_hello (p2.th, message);
  if ((p == &p2) && (p1.th != NULL))
    GNUNET_TRANSPORT_offer_hello (p1.th, message);

  if ((p == &p1) && (p2.hello != NULL))
    GNUNET_TRANSPORT_offer_hello (p1.th, p2.hello);
  if ((p == &p2) && (p1.hello != NULL))
    GNUNET_TRANSPORT_offer_hello (p2.th, p1.hello);
}



static void
setup_peer (struct PeerContext *p, const char *cfgname)
{
  p->cfg = GNUNET_CONFIGURATION_create ();
#if START_ARM
  p->arm_proc = GNUNET_OS_start_process (NULL, NULL, "gnunet-service-arm",
                                        "gnunet-service-arm",
#if VERBOSE
                                        "-L", "DEBUG",
#endif
                                        "-c", cfgname, NULL);
#endif
  GNUNET_assert (GNUNET_OK == GNUNET_CONFIGURATION_load (p->cfg, cfgname));
  p->stats = GNUNET_STATISTICS_create ("core", p->cfg);
  GNUNET_assert (p->stats != NULL);
  p->th = GNUNET_TRANSPORT_connect (p->cfg, NULL, p, NULL, NULL, NULL);
  GNUNET_assert (p->th != NULL);
  GNUNET_TRANSPORT_get_hello (p->th, &process_hello, p);
}


static void
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  GNUNET_assert (ok == 1);
  OKPP;
  setup_peer (&p1, "test_core_quota_peer1.conf");
  setup_peer (&p2, "test_core_quota_peer2.conf");
  GNUNET_CORE_connect (p1.cfg, 1,
                       &p1,
                       &init_notify,
                       &connect_notify,
                       &disconnect_notify,
                       NULL,
                       &inbound_notify,
                       GNUNET_YES, &outbound_notify, GNUNET_YES, handlers);

  GNUNET_assert (GNUNET_SYSERR != GNUNET_CONFIGURATION_get_value_number (p1.cfg,
                                         "CORE",
                                         "TOTAL_QUOTA_IN",
                                         &current_quota_p1_in));
  GNUNET_assert (GNUNET_SYSERR != GNUNET_CONFIGURATION_get_value_number (p2.cfg,
                                         "CORE",
                                         "TOTAL_QUOTA_IN",
                                         &current_quota_p2_in));
  GNUNET_assert (GNUNET_SYSERR != GNUNET_CONFIGURATION_get_value_number (p1.cfg,
                                         "CORE",
                                         "TOTAL_QUOTA_OUT",
                                         &current_quota_p1_out));
  GNUNET_assert (GNUNET_SYSERR != GNUNET_CONFIGURATION_get_value_number (p2.cfg,
                                         "CORE",
                                         "TOTAL_QUOTA_OUT",
                                         &current_quota_p2_out));
}


static void
stop_arm (struct PeerContext *p)
{
#if START_ARM
  if (0 != GNUNET_OS_process_kill (p->arm_proc, SIGTERM))
	GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "kill");
  if (GNUNET_OS_process_wait(p->arm_proc) != GNUNET_OK)
	GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "waitpid");

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"ARM process stopped\n");
  GNUNET_OS_process_close (p->arm_proc);
  p->arm_proc = NULL;
#endif
  GNUNET_STATISTICS_destroy (p->stats, 0);
  GNUNET_CONFIGURATION_destroy (p->cfg);
}

static int
check ()
{
  char *const argv[] = { "test-core-quota-compliance",
    "-c",
    "test_core_api_data.conf",
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
                      argv, "test_core_quota_compliance", "nohelp", options, &run, &ok);
  stop_arm (&p1);
  stop_arm (&p2);
  return ok;
}

int
main (int argc, char *argv[])
{
  int ret;

  GNUNET_log_setup ("test-core-quota-compliance",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);
  ret = check ();
  GNUNET_DISK_directory_remove ("/tmp/test-gnunet-core-quota-peer-2");
  GNUNET_DISK_directory_remove ("/tmp/test-gnunet-core-quota-peer-2");

  return ret;
}

/* end of test_core_quota_compliance.c */
