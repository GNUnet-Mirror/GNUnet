/*
     This file is part of GNUnet.
     (C) 2009, 2010, 2011 Christian Grothoff (and other contributing authors)

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
 * @file transport/test_quota_compliance.c
 * @brief base test case for transport implementations
 *
 * This test case tests quota compliance both on core and transport level
 */
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_hello_lib.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_os_lib.h"
#include "gnunet_program_lib.h"
#include "gnunet_scheduler_lib.h"
#include "gnunet_server_lib.h"
#include "gnunet_transport_service.h"
#include "transport.h"
#include "transport-testing.h"

#define VERBOSE GNUNET_NO

#define VERBOSE_ARM GNUNET_NO

#define START_ARM GNUNET_YES
#define DEBUG_MEASUREMENT GNUNET_NO
#define DEBUG_CONNECTIONS GNUNET_NO

#define MEASUREMENT_INTERVALL GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)
#define MEASUREMENT_MSG_SIZE 1024
#define MEASUREMENT_MSG_SIZE_BIG 32768
#define MEASUREMENT_MAX_QUOTA 1024 * 1024 * 1024
#define MEASUREMENT_MIN_QUOTA 1024
#define SEND_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10)
#define MEASUREMENT_SOFT_LIMIT 1024

/**
 * Testcase timeout
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 200)



#define MTYPE 11111

/**
 * Handle for a transmission-ready request.
 */
struct GNUNET_TRANSPORT_TransmitHandle
{

  /**
   * Neighbour for this handle, NULL for control-traffic.
   */
  struct NeighbourList *neighbour;

  /**
   * Function to call when notify_size bytes are available
   * for transmission.
   */
  GNUNET_CONNECTION_TransmitReadyNotify notify;

  /**
   * Closure for notify.
   */
  void *notify_cls;

  /**
   * transmit_ready task Id.  The task is used to introduce the
   * artificial delay that may be required to maintain the bandwidth
   * limits.  Later, this will be the ID of the "transmit_timeout"
   * task which is used to signal a timeout if the transmission could
   * not be done in a timely fashion.
   */
  GNUNET_SCHEDULER_TaskIdentifier notify_delay_task;

  /**
   * Timeout for this request.
   */
  struct GNUNET_TIME_Absolute timeout;

  /**
   * How many bytes is our notify callback waiting for?
   */
  size_t notify_size;

  /**
   * How important is this message?
   */
  unsigned int priority;

};

static struct PeerContext p1;

static struct PeerContext p2;

static int ok;

static int connected;
static int measurement_running;
static int send_running;
static int recv_running;

static unsigned long long total_bytes_sent;
static unsigned long long last_msg_sent;
static unsigned long long last_msg_recv;
static unsigned long long current_quota_p1;
static unsigned long long current_quota_p2;

static int is_tcp;
static int is_tcp_nat;
static int is_http;
static int is_https;
static int is_udp;
static int is_unix;
static int is_asymmetric_send_constant;
static int is_asymmetric_recv_constant;

static struct GNUNET_TIME_Absolute start_time;

static GNUNET_SCHEDULER_TaskIdentifier die_task;
static GNUNET_SCHEDULER_TaskIdentifier tct;
static GNUNET_SCHEDULER_TaskIdentifier measurement_task;
static GNUNET_SCHEDULER_TaskIdentifier measurement_counter_task;

static struct GNUNET_TRANSPORT_TransmitHandle * transmit_handle;

#define OKPP do { ok++; } while (0)


static void
end ()
{
  GNUNET_SCHEDULER_cancel (die_task);
  die_task = GNUNET_SCHEDULER_NO_TASK;
  
  if (measurement_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (measurement_task);
      measurement_task = GNUNET_SCHEDULER_NO_TASK;
    }
  if (measurement_counter_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (measurement_counter_task);
      measurement_counter_task = GNUNET_SCHEDULER_NO_TASK;
    }
  fprintf(stderr,"\n");
  GNUNET_SCHEDULER_shutdown ();
#if DEBUG_CONNECTIONS
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Disconnecting from transports!\n");
#endif
  GNUNET_TRANSPORT_disconnect (p1.th);
  GNUNET_TRANSPORT_disconnect (p2.th);
#if DEBUG_CONNECTIONS
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Transports disconnected, returning success!\n");
#endif
  GNUNET_SCHEDULER_shutdown ();
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
end_badly (void *cls,
	   const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (measurement_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (measurement_task);
    measurement_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (measurement_counter_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (measurement_counter_task);
      measurement_counter_task = GNUNET_SCHEDULER_NO_TASK;
    }
  GNUNET_break (0);
  if (GNUNET_SCHEDULER_NO_TASK != tct)
    {
      GNUNET_SCHEDULER_cancel (tct);
      tct = GNUNET_SCHEDULER_NO_TASK;
    }
  if (p1.th != NULL)
    GNUNET_TRANSPORT_disconnect (p1.th);
  if (p2.th != NULL)
    GNUNET_TRANSPORT_disconnect (p2.th);
  ok = 1;
}

struct TestMessage
{
  struct GNUNET_MessageHeader header;
  uint32_t num;
};


static unsigned int
get_size ()
{
  return MEASUREMENT_MSG_SIZE + sizeof (struct TestMessage);
}

static void
notify_receive_new (void *cls,
                const struct GNUNET_PeerIdentity *peer,
                const struct GNUNET_MessageHeader *message,
                const struct GNUNET_TRANSPORT_ATS_Information *ats, uint32_t ats_count)
{
  const struct TestMessage *hdr;

  GNUNET_assert (message != NULL);
  hdr = (const struct TestMessage*) message;
  if (measurement_running == GNUNET_NO)
	  return;
  if (MTYPE != ntohs (message->type))
    return;

#if DEBUG_MEASUREMENT
  if (ntohl(hdr->num) % 5000 == 0)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Got message %u of size %u\n",
                  ntohl (hdr->num),
                  ntohs (message->size));
    }
#endif
  /*
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Got message %u\n",
              ntohl (hdr->num));*/
  last_msg_recv = ntohl (hdr->num);
}


static size_t
notify_ready (void *cls, size_t size, void *buf)
{
  char *cbuf = buf;
  struct TestMessage hdr;
  unsigned int s;
  unsigned int ret;

  transmit_handle = NULL;
  if (measurement_task == GNUNET_SCHEDULER_NO_TASK)
    return 0;

  if (buf == NULL)
    {
      ok = 42;
      return 0;
    }
  if (measurement_running != GNUNET_YES)
    {
      send_running = GNUNET_NO;
      return 0;
    }
  send_running = GNUNET_YES;
  ret = 0;
  s = get_size ();
  GNUNET_assert (size >= s);
  GNUNET_assert (buf != NULL);
  last_msg_sent++;
  cbuf = buf;
  do
    {
      hdr.header.size = htons (s);
      hdr.header.type = htons (MTYPE);
      hdr.num = htonl (last_msg_sent);
      memcpy (&cbuf[ret], &hdr, sizeof (struct TestMessage));
      ret += sizeof (struct TestMessage);
      memset (&cbuf[ret], last_msg_sent, s - sizeof (struct TestMessage));
      ret += s - sizeof (struct TestMessage);
#if DEBUG_MEASUREMENT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Sending message %u\n",
		  last_msg_sent);
#endif
      s = get_size ();
      if (0 == GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, 16))
	break; /* sometimes pack buffer full, sometimes not */
    }
  while (size - ret >= s);
  transmit_handle = GNUNET_TRANSPORT_notify_transmit_ready (p2.th,
					    &p1.id,
					    s, 0, SEND_TIMEOUT,
					    &notify_ready,
					    NULL);
  total_bytes_sent += s;
  return ret;
}


static void
measure (unsigned long long quota_p1, unsigned long long quota_p2);

static void 
measurement_counter (void *cls,
		     const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  measurement_counter_task = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;
  
  fprintf(stderr,".");
  measurement_counter_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
							   &measurement_counter,
							   NULL);
}


static void
measurement_end (void *cls,
		 const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  static int strike_counter;
  static int failed_measurement_counter = 1;
  unsigned long long  quota_allowed = 0;
  int delta = 0;

  measurement_task  = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;

  measurement_running = GNUNET_NO;
  struct GNUNET_TIME_Relative duration
    = GNUNET_TIME_absolute_get_difference(start_time, GNUNET_TIME_absolute_get());


  if (measurement_counter_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (measurement_counter_task);
      measurement_counter_task = GNUNET_SCHEDULER_NO_TASK;
    }
  
  if (transmit_handle != NULL)
    {
      GNUNET_TRANSPORT_notify_transmit_ready_cancel(transmit_handle);
      transmit_handle = NULL;
    }
  
  if (current_quota_p1 < current_quota_p2)
    quota_allowed = current_quota_p1;
  else
    quota_allowed = current_quota_p2;
  
  
  if (MEASUREMENT_SOFT_LIMIT > (quota_allowed/3))
    delta = MEASUREMENT_SOFT_LIMIT;
  else
    delta = (quota_allowed/3);
  
  /* Throughput is far too slow. This is to prevent the test to exit with success when throughput is 0 */
  if ((total_bytes_sent/(duration.rel_value / 1000)) < 100)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  "\nQuota compliance failed: \n"			\
		  "Hard quota limit allowed: %10llu kB/s (%llu B/s)\n"	\
		  "Soft quota limit allowed: %10llu kB/s (%llu B/s)\n"	\
		  "Throughput              : %10llu kB/s (%llu B/s)\n",
		  (quota_allowed / (1024)), quota_allowed,
		  ((quota_allowed+delta) / (1024)),  quota_allowed+delta,
		  (total_bytes_sent/(duration.rel_value / 1000)/1024),
		  total_bytes_sent/(duration.rel_value / 1000));
      ok = 1;
      failed_measurement_counter--;
      if (failed_measurement_counter < 0)
	{
	  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		      "\nQuota measurement failed and no free strike: %i\n",
		      failed_measurement_counter);
	  end();
	  return;
	}
      else
	GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		    "\nQuota measurement failed and %i free strikes\n",
		    failed_measurement_counter);
    }
  
  /* Throughput is bigger than allowed quota + some extra*/
  if ((total_bytes_sent/(duration.rel_value / 1000)) > (quota_allowed + delta))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  "\nQuota compliance failed: \n"			\
		  "Hard quota limit allowed: %10llu kB/s (%llu B/s)\n"	\
		  "Soft quota limit allowed: %10llu kB/s (%llu B/s)\n"	\
		  "Throughput              : %10llu kB/s (%llu B/s)\n", 
		  (quota_allowed / (1024)), quota_allowed, 
		  ((quota_allowed+delta) / (1024)),  quota_allowed+delta, 
		  (total_bytes_sent/(duration.rel_value / 1000)/1024), 
		  total_bytes_sent/(duration.rel_value / 1000));
      ok = 1;
      failed_measurement_counter--;
      if (failed_measurement_counter < 0)
	{
	  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		      "\nQuota measurement failed and no free strike: %i\n",failed_measurement_counter);
	  end();
	  return;
	}
      else
	GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		    "\nQuota measurement failed and %i free strikes\n",failed_measurement_counter);
    }
  else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		  "\nQuota compliance ok: \n"			\
		  "Quota allowed: %10llu kB/s\n"			\
		  "Throughput   : %10llu kB/s\n",
		  (quota_allowed / (1024)), 
		  (total_bytes_sent/(duration.rel_value / 1000)/1024));
      if (failed_measurement_counter < 2)
	failed_measurement_counter++;
      ok = 0;
    }
  
  if ((quota_allowed) > (2 *(total_bytes_sent/(duration.rel_value / 1000))))
    {
      if (failed_measurement_counter < 2)
	failed_measurement_counter++;
      if (strike_counter == 2)
	{
	  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		      "Maximum transmission rate reached, stopping test\n");
	  end();
	  return;
	}
    }
  else
    {
      strike_counter = 0;
    }
  
  if (quota_allowed == MEASUREMENT_MAX_QUOTA)
    {
      end();
      return;
    }
  if (is_asymmetric_send_constant == GNUNET_YES)
    {
      if ((quota_allowed * 2) < MEASUREMENT_MAX_QUOTA)
	measure (current_quota_p1 * 2, MEASUREMENT_MAX_QUOTA);
      else
	measure (MEASUREMENT_MAX_QUOTA, MEASUREMENT_MAX_QUOTA);
    }
  else if (is_asymmetric_recv_constant == GNUNET_YES)
    {
      if ((quota_allowed * 2) < MEASUREMENT_MAX_QUOTA)
	measure (MEASUREMENT_MAX_QUOTA, current_quota_p2 * 2);
      else
	measure (MEASUREMENT_MAX_QUOTA, MEASUREMENT_MAX_QUOTA);
    }
  else
    {
      if ((quota_allowed * 2) < MEASUREMENT_MAX_QUOTA)
	measure ((current_quota_p1) * 2, (current_quota_p2) * 2);
      else
	measure (MEASUREMENT_MAX_QUOTA, MEASUREMENT_MAX_QUOTA);
    }
}

static void 
measure (unsigned long long quota_p1, unsigned long long quota_p2)
{
  current_quota_p1 = quota_p1;
  current_quota_p2 = quota_p2;
#if VERBOSE
  if ((is_asymmetric_send_constant == GNUNET_YES) || (is_asymmetric_recv_constant == GNUNET_YES))
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Starting transport level measurement for %u seconds, receiving peer quota %llu kB/s, sending peer quota %llu kB/s\n",
		MEASUREMENT_INTERVALL.rel_value / 1000 ,
		current_quota_p1 / 1024,
		current_quota_p2 / 1024);
  else
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Starting transport level measurement for %u seconds, symmetric quota %llu kB/s\n", 
		MEASUREMENT_INTERVALL.rel_value / 1000,
		current_quota_p2 / 1024);
  
#endif
  GNUNET_TRANSPORT_set_quota (p1.th,
			      &p2.id,
			      GNUNET_BANDWIDTH_value_init (current_quota_p1),
			      GNUNET_BANDWIDTH_value_init (current_quota_p1));
  GNUNET_TRANSPORT_set_quota (p2.th,
			      &p1.id,
			      GNUNET_BANDWIDTH_value_init (current_quota_p2),
			      GNUNET_BANDWIDTH_value_init (current_quota_p2));
  GNUNET_SCHEDULER_cancel (die_task);
  die_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT,
					   &end_badly,
					   NULL);
  if (measurement_counter_task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (measurement_counter_task);
  measurement_counter_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
							   &measurement_counter,
							   NULL);
  measurement_task = GNUNET_SCHEDULER_add_delayed (MEASUREMENT_INTERVALL,
						   &measurement_end,
						   NULL);
  total_bytes_sent = 0;
  last_msg_sent = 0;
  last_msg_recv = 0;
  measurement_running = GNUNET_YES;
  start_time = GNUNET_TIME_absolute_get ();
  
  if (transmit_handle != NULL)
    GNUNET_TRANSPORT_notify_transmit_ready_cancel(transmit_handle);
  transmit_handle = GNUNET_TRANSPORT_notify_transmit_ready (p2.th,
							    &p1.id,
							    get_size (), 0, SEND_TIMEOUT,
							    &notify_ready,
							    NULL);
}


static void
exchange_hello_last (void *cls,
                     const struct GNUNET_MessageHeader *message)
{
  struct PeerContext *me = cls;

  GNUNET_assert (message != NULL);
#if DEBUG_CONNECTIONS
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Exchanging HELLO of size %d with peer (%s)!\n", 
	      (int) GNUNET_HELLO_size((const struct GNUNET_HELLO_Message *)message),
	      GNUNET_i2s (&me->id));
#endif
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_HELLO_get_id ((const struct GNUNET_HELLO_Message *)
                                      message, &me->id));
  GNUNET_TRANSPORT_offer_hello (p1.th, message, NULL, NULL);
}



static void
exchange_hello (void *cls,
                const struct GNUNET_MessageHeader *message)
{
  struct PeerContext *me = cls;

  GNUNET_assert (message != NULL);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_HELLO_get_id ((const struct GNUNET_HELLO_Message *)
                                      message, &me->id));
#if DEBUG_CONNECTIONS
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Exchanging HELLO of size %d from peer %s!\n", 
	      (int) GNUNET_HELLO_size((const struct GNUNET_HELLO_Message *)message),
	      GNUNET_i2s (&me->id));
#endif
  GNUNET_TRANSPORT_offer_hello (p2.th, message, NULL, NULL);
}


static void
notify_connect (void *cls,
                const struct GNUNET_PeerIdentity *peer,
                const struct GNUNET_TRANSPORT_ATS_Information *ats, uint32_t ats_count)
{ 
  connected++;
 if (cls == &p1)
    {
#if DEBUG_CONNECTIONS
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Peer 1 `%4s' connected to us (%p)!\n", 
		  GNUNET_i2s (peer), 
		  cls);
#endif
    }
  else
    {
#if DEBUG_CONNECTIONS
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Peer 2 `%4s' connected to us (%p)!\n", 
		  GNUNET_i2s (peer), 
		  cls);
#endif
    }
  if (connected == 2)
    {
      GNUNET_SCHEDULER_cancel (tct);
      tct = GNUNET_SCHEDULER_NO_TASK;
      GNUNET_TRANSPORT_get_hello_cancel (p2.th, &exchange_hello_last, &p2);
      GNUNET_TRANSPORT_get_hello_cancel (p1.th, &exchange_hello, &p1);
      if (is_asymmetric_send_constant == GNUNET_YES)
	measure (MEASUREMENT_MIN_QUOTA, MEASUREMENT_MAX_QUOTA);
      else if (is_asymmetric_recv_constant == GNUNET_YES)
	measure (MEASUREMENT_MAX_QUOTA, MEASUREMENT_MIN_QUOTA);
      else
	measure (MEASUREMENT_MIN_QUOTA, MEASUREMENT_MIN_QUOTA);
    }
}


static void
notify_disconnect (void *cls, const struct GNUNET_PeerIdentity *peer)
{
  connected--;
#if DEBUG_CONNECTIONS
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Peer `%4s' disconnected (%p)!\n",
	      GNUNET_i2s (peer), cls);
#endif
}


static void
setup_peer (struct PeerContext *p, const char *cfgname)
{
  p->cfg = GNUNET_CONFIGURATION_create ();
  GNUNET_assert (GNUNET_OK == GNUNET_CONFIGURATION_load (p->cfg, cfgname));
  if (GNUNET_CONFIGURATION_have_value (p->cfg,"PATHS", "SERVICEHOME"))
    {
      GNUNET_CONFIGURATION_get_value_string (p->cfg, "PATHS", "SERVICEHOME", &p->servicehome);
      GNUNET_DISK_directory_remove (p->servicehome);
    }

#if START_ARM
  p->arm_proc = GNUNET_OS_start_process (NULL, NULL,
					"gnunet-service-arm",
                                        "gnunet-service-arm",
#if VERBOSE_ARM
                                        "-L", "DEBUG",
#endif
                                        "-c", cfgname, NULL);
#endif

  p->th = GNUNET_TRANSPORT_connect (p->cfg, NULL,
                                    p,
                                    &notify_receive_new,
                                    &notify_connect,
				    &notify_disconnect);
  GNUNET_assert (p->th != NULL);
}


static void
try_connect (void *cls,
	     const struct GNUNET_SCHEDULER_TaskContext *tc)
{
#if DEBUG_CONNECTIONS
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Asking peers to connect...\n");
#endif
  GNUNET_TRANSPORT_try_connect (p2.th,
				&p1.id);
  GNUNET_TRANSPORT_try_connect (p1.th,
				&p2.id);
  tct = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
				      &try_connect,
				      NULL);
}


static void
run (void *cls,
     char *const *args,
     const char *cfgfile, const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  GNUNET_assert (ok == 1);
  OKPP;

  die_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT,
					   &end_badly,
					   NULL);
  measurement_running = GNUNET_NO;
  send_running = GNUNET_NO;
  recv_running = GNUNET_NO;

  if (is_tcp)
    {
      if (is_asymmetric_recv_constant == GNUNET_YES)
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		    "Testing asymmetric quota compliance (receiver quota constant) for TCP transport plugin\n");
      else if (is_asymmetric_send_constant == GNUNET_YES)
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
		    "Testing asymmetric quota compliance (sender quota constant) for TCP transport plugin\n");
      else
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		    "Testing symmetric quota compliance for TCP transport plugin\n");
      setup_peer (&p1, "test_quota_compliance_tcp_peer1.conf");
      setup_peer (&p2, "test_quota_compliance_tcp_peer2.conf");
    }
  else if (is_http)
    {
      if (is_asymmetric_recv_constant == GNUNET_YES)
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
		    "Testing asymmetric quota compliance (receiver quota constant) for HTTP transport plugin\n");
      else if (is_asymmetric_send_constant == GNUNET_YES)
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
		    "Testing asymmetric quota compliance (sender quota constant) for HTTP transport plugin\n");
      else
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
		    "Testing symmetric quota compliance for HTTP transport plugin\n");
      setup_peer (&p1, "test_quota_compliance_http_peer1.conf");
      setup_peer (&p2, "test_quota_compliance_http_peer2.conf");
    }
  else if (is_https)
    {
      if (is_asymmetric_recv_constant == GNUNET_YES)
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
		    "Testing asymmetric quota compliance (receiver quota constant) for HTTPS transport plugin\n");
      else if (is_asymmetric_send_constant == GNUNET_YES)
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
		    "Testing asymmetric quota compliance (sender quota constant) for HTTPS transport plugin\n");
      else
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
		    "Testing symmetric quota compliance for HTTPS transport plugin\n");
      setup_peer (&p1, "test_quota_compliance_https_peer1.conf");
      setup_peer (&p2, "test_quota_compliance_https_peer2.conf");
    }
  else if (is_udp)
    {
      if (is_asymmetric_recv_constant == GNUNET_YES)
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
		    "Testing asymmetric quota compliance (receiver quota constant) for UDP transport plugin\n");
      else if (is_asymmetric_send_constant == GNUNET_YES)
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
		    "Testing asymmetric quota compliance (sender quota constant) for UDP transport plugin\n");
      else
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
		    "Testing symmetric quota compliance for UDP transport plugin\n");
      setup_peer (&p1, "test_quota_compliance_udp_peer1.conf");
      setup_peer (&p2, "test_quota_compliance_udp_peer2.conf");
    }
  else if (is_unix)
    {
      if (is_asymmetric_recv_constant == GNUNET_YES)
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
		    "Testing asymmetric quota compliance (receiver quota constant) for UNIX transport plugin\n");
      else if (is_asymmetric_send_constant == GNUNET_YES)
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
		    "Testing asymmetric quota compliance (sender quota constant) for UNIX transport plugin\n");
      else
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
		    "Testing symmetric quota compliance for UNIX transport plugin\n");
      setup_peer (&p1, "test_quota_compliance_unix_peer1.conf");
      setup_peer (&p2, "test_quota_compliance_unix_peer2.conf");
    }
  else if (is_tcp_nat)
    {
      if (is_asymmetric_recv_constant == GNUNET_YES)
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		    "Testing asymmetric quota compliance (receiver quota constant) for TCP NAT transport plugin\n");
      else if (is_asymmetric_send_constant == GNUNET_YES)
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
		    "Testing asymmetric quota compliance (sender quota constant) for TCP NAT transport plugin\n");
      else
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
		    "Testing symmetric quota compliance for TCP NAT transport plugin\n");
      setup_peer (&p1, "test_quota_compliance_tcp_peer1.conf");
      setup_peer (&p2, "test_quota_compliance_tcp_peer2.conf");
    }
  else
    GNUNET_assert (0);

  GNUNET_assert(p1.th != NULL);
  GNUNET_assert(p2.th != NULL);
  GNUNET_TRANSPORT_get_hello (p1.th, &exchange_hello, &p1);
  GNUNET_TRANSPORT_get_hello (p2.th, &exchange_hello_last, &p2);
  tct = GNUNET_SCHEDULER_add_now (&try_connect, NULL);
}


int
main (int argc, char *argv[])
{
  int ret = 0;
  if (strstr(argv[0], "tcp_nat") != NULL)
    {
      is_tcp_nat = GNUNET_YES;
    }
  else if (strstr(argv[0], "tcp") != NULL)
    {
      is_tcp = GNUNET_YES;
    }
  else if (strstr(argv[0], "https") != NULL)
    {
      is_https = GNUNET_YES;
    }
  else if (strstr(argv[0], "http") != NULL)
    {
      is_http = GNUNET_YES;
    }
  else if (strstr(argv[0], "udp") != NULL)
    {
      is_udp = GNUNET_YES;
    }
  else if (strstr(argv[0], "unix") != NULL)
    {
      is_unix = GNUNET_YES;
    }

  if (strstr(argv[0], "asymmetric_recv") != NULL)
  {
    is_asymmetric_recv_constant = GNUNET_YES;
  }
  else
    is_asymmetric_recv_constant = GNUNET_NO;
  if (strstr(argv[0], "asymmetric_send") != NULL)
    {
      is_asymmetric_send_constant = GNUNET_YES;
    }
  else
    is_asymmetric_send_constant = GNUNET_NO;
  
  char * logger;
  if (is_tcp == GNUNET_YES)
    {
      if (is_asymmetric_recv_constant == GNUNET_YES)
	GNUNET_asprintf(&logger, "test-quota-compliance-%s-%s","tcp","asymmetric_recv_constant");
      else if (is_asymmetric_send_constant == GNUNET_YES)
	GNUNET_asprintf(&logger, "test-quota-compliance-%s-%s","tcp","asymmetric_send_constant");
      else
	GNUNET_asprintf(&logger, "test-quota-compliance-%s-%s","tcp","symmetric");
    }
  else if (is_udp == GNUNET_YES)
    {
      if (is_asymmetric_recv_constant == GNUNET_YES)
	GNUNET_asprintf(&logger, "test-quota-compliance-%s-%s","udp","asymmetric_recv_constant");
      else if (is_asymmetric_send_constant == GNUNET_YES)
	GNUNET_asprintf(&logger, "test-quota-compliance-%s-%s","udp","asymmetric_send_constant");
      else
	GNUNET_asprintf(&logger, "test-quota-compliance-%s-%s","udp","symmetric");
    }
  else if (is_unix == GNUNET_YES)
    {
      if (is_asymmetric_recv_constant == GNUNET_YES)
	GNUNET_asprintf(&logger, "test-quota-compliance-%s-%s","unix","asymmetric_recv_constant");
      else if (is_asymmetric_send_constant == GNUNET_YES)
	GNUNET_asprintf(&logger, "test-quota-compliance-%s-%s","unix","asymmetric_send_constant");
      else
	GNUNET_asprintf(&logger, "test-quota-compliance-%s-%s","unix","symmetric");
    }
  else if (is_http == GNUNET_YES)
    {
      if (is_asymmetric_recv_constant == GNUNET_YES)
	GNUNET_asprintf(&logger, "test-quota-compliance-%s-%s","http","asymmetric_recv_constant");
      else if (is_asymmetric_send_constant == GNUNET_YES)
	GNUNET_asprintf(&logger, "test-quota-compliance-%s-%s","http","asymmetric_send_constant");
      else
	GNUNET_asprintf(&logger, "test-quota-compliance-%s-%s","http","symmetric");
    }
  else if (is_https == GNUNET_YES)
    {
      if (is_asymmetric_recv_constant == GNUNET_YES)
	GNUNET_asprintf(&logger, "test-quota-compliance-%s-%s","https","asymmetric_recv_constant");
      else if (is_asymmetric_send_constant == GNUNET_YES)
	GNUNET_asprintf(&logger, "test-quota-compliance-%s-%s","https","asymmetric_send_constant");
      else
	GNUNET_asprintf(&logger, "test-quota-compliance-%s-%s","https","symmetric");
    }
  else
    {
      GNUNET_asprintf(&logger, "test-quota-compliance-%s-%s","noplugin","none");
    }

  fprintf(stderr,  "Running `%s'\n", logger);
  GNUNET_log_setup ("test-quota-compliance",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);
  char *const argv1[] = { "test-quota-compliance",
    "-c",
    "test_quota_compliance_data.conf",
#if VERBOSE
    "-L", "DEBUG",
#endif
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  ok = 1;
  GNUNET_PROGRAM_run ((sizeof (argv1) / sizeof (char *)) - 1,
                      argv1, logger , "nohelp",
                      options, &run, &ok);
  ret = ok;
  stop_arm (&p1);
  stop_arm (&p2);

  if (p1.servicehome != NULL)
    {
      GNUNET_DISK_directory_remove (p1.servicehome);
      GNUNET_free(p1.servicehome);
    }
  if (p2.servicehome != NULL)
    {
      GNUNET_DISK_directory_remove (p2.servicehome);
      GNUNET_free(p2.servicehome);
    }
  GNUNET_free(logger);
  return ret;
}

/* end of test_quota_compliance.c */
