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
 * @file transport/test_transport_api_reliability.c
 * @brief base test case for transport implementations
 *
 * This test case serves as a base for tcp and http
 * transport test cases to check that the transports
 * achieve reliable message delivery.
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

#define VERBOSE GNUNET_NO

#define VERBOSE_ARM GNUNET_NO

#define START_ARM GNUNET_YES

/**
 * Note that this value must not significantly exceed
 * 'MAX_PENDING' in 'gnunet-service-transport.c', otherwise
 * messages may be dropped even for a reliable transport.
 */
#define TOTAL_MSGS (60000 * 2)

/**
 * How long until we give up on transmitting the message?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 150)

#define MTYPE 12345

struct PeerContext
{
  struct GNUNET_CONFIGURATION_Handle *cfg;
  struct GNUNET_TRANSPORT_Handle *th;
  struct GNUNET_PeerIdentity id;
#if START_ARM
  pid_t arm_pid;
#endif
};

static struct PeerContext p1;

static struct PeerContext p2;

static struct GNUNET_SCHEDULER_Handle *sched;

static int ok;

static int is_tcp;

static int is_tcp_nat;

static int is_http;

static int is_udp;

static int connected;

static unsigned long long total_bytes;

static struct GNUNET_TIME_Absolute start_time;

static GNUNET_SCHEDULER_TaskIdentifier die_task;

#if VERBOSE
#define OKPP do { ok++; fprintf (stderr, "Now at stage %u at %s:%u\n", ok, __FILE__, __LINE__); } while (0)
#else
#define OKPP do { ok++; } while (0)
#endif


static void
end ()
{
  unsigned long long delta;

  GNUNET_SCHEDULER_cancel (sched, die_task);
  die_task = GNUNET_SCHEDULER_NO_TASK;
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Disconnecting from transports!\n");
#endif
  GNUNET_TRANSPORT_disconnect (p1.th);
  GNUNET_TRANSPORT_disconnect (p2.th);
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Transports disconnected, returning success!\n");
#endif
  delta = GNUNET_TIME_absolute_get_duration (start_time).value;
  fprintf (stderr,
	   "\nThroughput was %llu kb/s\n",
	   total_bytes * 1000 / 1024 / delta);
  ok = 0;
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
end_badly (void *cls,
	   const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_break (0);
  GNUNET_TRANSPORT_disconnect (p1.th);
  GNUNET_TRANSPORT_disconnect (p2.th);
  ok = 1;
}


struct TestMessage 
{
  struct GNUNET_MessageHeader header;
  uint32_t num;
};


static unsigned int
get_size (unsigned int iter)
{
  unsigned int ret;

  if (iter < 60000)
    return iter + sizeof (struct TestMessage);
  ret = (iter * iter * iter);
  return sizeof (struct TestMessage) + (ret % 60000);
}


static void
notify_receive (void *cls,
                const struct GNUNET_PeerIdentity *peer,
                const struct GNUNET_MessageHeader *message,
                struct GNUNET_TIME_Relative latency,
		uint32_t distance)
{
  static int n;
  unsigned int s;
  char cbuf[GNUNET_SERVER_MAX_MESSAGE_SIZE - 1];
  const struct TestMessage *hdr;

  hdr = (const struct TestMessage*) message;
  s = get_size (n);
  if (MTYPE != ntohs (message->type))
    return;
  if (ntohs (message->size) != s)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  "Expected message %u of size %u, got %u bytes of message %u\n",
		  n, s,
		  ntohs (message->size),
		  ntohl (hdr->num));
      GNUNET_SCHEDULER_cancel (sched, die_task);
      die_task = GNUNET_SCHEDULER_add_now (sched, &end_badly, NULL);
      return;
    }
  if (ntohl (hdr->num) != n)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  "Expected message %u of size %u, got %u bytes of message %u\n",
		  n, s,
		  ntohs (message->size),
		  ntohl (hdr->num));
      GNUNET_SCHEDULER_cancel (sched, die_task);
      die_task = GNUNET_SCHEDULER_add_now (sched, &end_badly, NULL);
      return;
    }
  memset (cbuf, n, s - sizeof (struct TestMessage));
  if (0 != memcmp (cbuf,
		   &hdr[1],
		   s - sizeof (struct TestMessage)))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  "Expected message %u with bits %u, but body did not match\n",
		  n, (unsigned char) n);
      GNUNET_SCHEDULER_cancel (sched, die_task);
      die_task = GNUNET_SCHEDULER_add_now (sched, &end_badly, NULL);
      return;
    }
#if VERBOSE
  if (ntohl(hdr->num) % 5000 == 0)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Got message %u of size %u\n",
                  ntohl (hdr->num),
                  ntohs (message->size));
    }
#endif
  n++;
  if (0 == (n % (TOTAL_MSGS/100)))
    {
      fprintf (stderr, ".");
      GNUNET_SCHEDULER_cancel (sched, die_task);
      die_task = GNUNET_SCHEDULER_add_delayed (sched,
					       TIMEOUT,
					       &end_badly,
					       NULL);    
    }
  if (n == TOTAL_MSGS)
    end ();
}


static size_t
notify_ready (void *cls, size_t size, void *buf)
{
  static int n;
  char *cbuf = buf;
  struct TestMessage hdr;
  unsigned int s;
  unsigned int ret;

  if (buf == NULL)
    {
      GNUNET_break (0);
      ok = 42;
      return 0;
    }
  ret = 0;
  s = get_size (n);
  GNUNET_assert (size >= s);
  GNUNET_assert (buf != NULL);
  cbuf = buf;
  do
    {
      hdr.header.size = htons (s);
      hdr.header.type = htons (MTYPE);
      hdr.num = htonl (n);
      memcpy (&cbuf[ret], &hdr, sizeof (struct TestMessage));
      ret += sizeof (struct TestMessage);
      memset (&cbuf[ret], n, s - sizeof (struct TestMessage));
      ret += s - sizeof (struct TestMessage);
#if VERBOSE
      if (n % 5000 == 0)
        {
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "Sending message %u of size %u\n",
                      n,
                      s);
        }
#endif
      n++;
      s = get_size (n);
      if (0 == GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, 16))
	break; /* sometimes pack buffer full, sometimes not */
    }
  while (size - ret >= s);
  if (n < TOTAL_MSGS)
    GNUNET_TRANSPORT_notify_transmit_ready (p1.th,
					    &p2.id,
					    s, 0, TIMEOUT, 
					    &notify_ready,
					    NULL);
  if (n % 5000 == 0)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Returning total message block of size %u\n",
                  ret);
    }
  total_bytes += ret;
  return ret;
}


static void
notify_connect (void *cls,
                const struct GNUNET_PeerIdentity *peer,
                struct GNUNET_TIME_Relative latency,
		uint32_t distance)
{
  if (cls == &p1)
    {
      GNUNET_TRANSPORT_set_quota (p1.th,
				  &p2.id,
				  GNUNET_BANDWIDTH_value_init (1024 * 1024 * 1024),
				  GNUNET_BANDWIDTH_value_init (1024 * 1024 * 1024),
				  GNUNET_TIME_UNIT_FOREVER_REL,
				  NULL, NULL);
      start_time = GNUNET_TIME_absolute_get ();
      connected++;
    }
  else
    {
      GNUNET_TRANSPORT_set_quota (p2.th,
				  &p1.id,
				  GNUNET_BANDWIDTH_value_init (1024 * 1024 * 1024),
				  GNUNET_BANDWIDTH_value_init (1024 * 1024 * 1024),
				  GNUNET_TIME_UNIT_FOREVER_REL,
				  NULL, NULL);
      connected++;
    }

  if (connected == 2)
    {
      GNUNET_TRANSPORT_notify_transmit_ready (p1.th,
                                              &p2.id,
                                              get_size (0), 0, TIMEOUT,
                                              &notify_ready,
                                              NULL);
    }
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Peer `%4s' connected to us (%p)!\n", GNUNET_i2s (peer), cls);
#endif
}


static void
notify_disconnect (void *cls, const struct GNUNET_PeerIdentity *peer)
{
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Peer `%4s' disconnected (%p)!\n",
	      GNUNET_i2s (peer), cls);
#endif
}


static void
setup_peer (struct PeerContext *p, const char *cfgname)
{
  p->cfg = GNUNET_CONFIGURATION_create ();
#if START_ARM
  p->arm_pid = GNUNET_OS_start_process (NULL, NULL, 
					"gnunet-service-arm",
                                        "gnunet-service-arm",
#if VERBOSE_ARM
                                        "-L", "DEBUG",
#endif
                                        "-c", cfgname, NULL);
#endif
  GNUNET_assert (GNUNET_OK == GNUNET_CONFIGURATION_load (p->cfg, cfgname));
  p->th = GNUNET_TRANSPORT_connect (sched, p->cfg, NULL,
                                    p,
                                    &notify_receive,
                                    &notify_connect, 
				    &notify_disconnect);
  GNUNET_assert (p->th != NULL);
}


static void
exchange_hello_last (void *cls,
                     const struct GNUNET_MessageHeader *message)
{
  struct PeerContext *me = cls;

  GNUNET_TRANSPORT_get_hello_cancel (p2.th, &exchange_hello_last, me);
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Exchanging HELLO with peer (%p)!\n", cls);
#endif
  GNUNET_assert (ok >= 3);
  OKPP;
  GNUNET_assert (message != NULL);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_HELLO_get_id ((const struct GNUNET_HELLO_Message *)
                                      message, &me->id));
  /* both HELLOs exchanged, get ready to test transmission! */
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Finished exchanging HELLOs, now waiting for transmission!\n");
}


static void
exchange_hello (void *cls,
                const struct GNUNET_MessageHeader *message)
{
  struct PeerContext *me = cls;

  GNUNET_TRANSPORT_get_hello_cancel (p1.th, &exchange_hello, me);
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Exchanging HELLO with peer (%p)!\n", cls);
#endif
  GNUNET_assert (ok >= 2);
  OKPP;
  GNUNET_assert (message != NULL);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_HELLO_get_id ((const struct GNUNET_HELLO_Message *)
                                      message, &me->id));

#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received HELLO size %d\n", 
	      GNUNET_HELLO_size((const struct GNUNET_HELLO_Message *)message));
#endif
  GNUNET_TRANSPORT_offer_hello (p2.th, message);
  GNUNET_TRANSPORT_get_hello (p2.th, &exchange_hello_last, &p2);
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
					   TIMEOUT,
					   &end_badly,
					   NULL);
  if (is_tcp)
    {
      setup_peer (&p1, "test_transport_api_tcp_peer1.conf");
      setup_peer (&p2, "test_transport_api_tcp_peer2.conf");
    }
  else if (is_http)
    {
      setup_peer (&p1, "test_transport_api_rel_http_peer1.conf");
      setup_peer (&p2, "test_transport_api_rel_http_peer2.conf");
    }
  else if (is_udp)
    {
      setup_peer (&p1, "test_transport_api_udp_peer1.conf");
      setup_peer (&p2, "test_transport_api_udp_peer2.conf");
    }
  else if (is_tcp_nat)
    {
      setup_peer (&p1, "test_transport_api_tcp_nat_peer1.conf");
      setup_peer (&p2, "test_transport_api_tcp_nat_peer2.conf");
    }
  else
    GNUNET_assert (0);
  GNUNET_assert(p1.th != NULL);
  GNUNET_assert(p2.th != NULL);
  GNUNET_TRANSPORT_get_hello (p1.th, &exchange_hello, &p1);
}


static int
check ()
{
  char *const argv[] = { "test-transport-api-reliability",
    "-c",
    "test_transport_api_data.conf",
#if VERBOSE
    "-L", "DEBUG",
#endif
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

#if WRITECONFIG
  setTransportOptions("test_transport_api_data.conf");
#endif
  ok = 1;
  GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1,
                      argv, "test-transport-api-reliability", "nohelp",
                      options, &run, &ok);
  stop_arm (&p1);
  stop_arm (&p2);
  return ok;
}


int
main (int argc, char *argv[])
{
  int ret;
#ifdef MINGW
  return GNUNET_SYSERR;
#endif
  if (strstr(argv[0], "tcp_nat") != NULL)
    {
      is_tcp_nat = GNUNET_YES;
    }
  else if (strstr(argv[0], "tcp") != NULL)
    {
      is_tcp = GNUNET_YES;
    }
  else if (strstr(argv[0], "http") != NULL)
    {
      is_http = GNUNET_YES;
    }
  else if (strstr(argv[0], "udp") != NULL)
    {
      is_udp = GNUNET_YES;
    }
  GNUNET_log_setup ("test-transport-api-reliability",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);
  ret = check ();
  GNUNET_DISK_directory_remove ("/tmp/test-gnunetd-transport-peer-1");
  GNUNET_DISK_directory_remove ("/tmp/test-gnunetd-transport-peer-2");
  return ret;
}

/* end of test_transport_api_reliability.c */
