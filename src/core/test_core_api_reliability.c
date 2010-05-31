/*
     This file is part of GNUnet.
     (C) 2009, 2010 Christian Grothoff (and other contributing authors)

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
 * @file core/test_core_api_reliability.c
 * @brief testcase for core_api.c focusing on reliable transmission (with TCP)
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

#define VERBOSE GNUNET_NO

#define START_ARM GNUNET_YES

/**
 * How long until we give up on transmitting the message?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 60)

/**
 * What delay do we request from the core service for transmission?
 * Any value smaller than the CORK delay will disable CORKing, which
 * is what we want here.
 */
#define FAST_TIMEOUT GNUNET_TIME_relative_divide (GNUNET_CONSTANTS_MAX_CORK_DELAY, 2)

#define MTYPE 12345


static unsigned long long total_bytes;

static struct GNUNET_TIME_Absolute start_time;

/**
 * Note that this value must not significantly exceed
 * 'MAX_PENDING' in 'gnunet-service-transport.c', otherwise
 * messages may be dropped even for a reliable transport.
 */
#define TOTAL_MSGS (600 * 2)

struct PeerContext
{
  struct GNUNET_CONFIGURATION_Handle *cfg;
  struct GNUNET_CORE_Handle *ch;
  struct GNUNET_PeerIdentity id;   
  struct GNUNET_TRANSPORT_Handle *th;
  struct GNUNET_MessageHeader *hello;
  int connect_status;
#if START_ARM
  pid_t arm_pid;
#endif
};

static struct PeerContext p1;

static struct PeerContext p2;

static struct GNUNET_SCHEDULER_Handle *sched;

static int ok;

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
  delta = GNUNET_TIME_absolute_get_duration (start_time).value;
  fprintf (stderr,
	   "\nThroughput was %llu kb/s\n",
	   total_bytes * 1000 / 1024 / delta);
  ok = 0;
}


static void
terminate_task_error (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_break (0);
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
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Encrypted connection established to peer `%4s'\n",
              GNUNET_i2s (peer));
}


static void
disconnect_notify (void *cls,
                   const struct GNUNET_PeerIdentity *peer)
{
  struct PeerContext *pc = cls;
  pc->connect_status = 0;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Encrypted connection to `%4s' cut\n", GNUNET_i2s (peer));
}


static int
inbound_notify (void *cls,
                const struct GNUNET_PeerIdentity *other,
                const struct GNUNET_MessageHeader *message,
		struct GNUNET_TIME_Relative latency,
		uint32_t distance)
{
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Core provides inbound data from `%4s'.\n", GNUNET_i2s (other));
#endif
  return GNUNET_OK;
}


static int
outbound_notify (void *cls,
                 const struct GNUNET_PeerIdentity *other,
                 const struct GNUNET_MessageHeader *message,
		 struct GNUNET_TIME_Relative latency,
		 uint32_t distance)
{
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Core notifies about outbound data for `%4s'.\n",
              GNUNET_i2s (other));
#endif
  return GNUNET_OK;
}


static GNUNET_SCHEDULER_TaskIdentifier err_task;


static size_t
transmit_ready (void *cls, size_t size, void *buf);

static int tr_n;


static int
process_mtype (void *cls,
               const struct GNUNET_PeerIdentity *peer,
               const struct GNUNET_MessageHeader *message,
	       struct GNUNET_TIME_Relative latency,
	       uint32_t distance)
{
  static int n;
  unsigned int s;
  const struct TestMessage *hdr;

  hdr = (const struct TestMessage*) message;
  s = get_size (n);
  if (MTYPE != ntohs (message->type))
    return GNUNET_SYSERR;
  if (ntohs (message->size) != s)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  "Expected message %u of size %u, got %u bytes of message %u\n",
		  n, s,
		  ntohs (message->size),
		  ntohl (hdr->num));
      GNUNET_SCHEDULER_cancel (sched, err_task);
      err_task = GNUNET_SCHEDULER_add_now (sched, &terminate_task_error, NULL);
      return GNUNET_SYSERR;
    }
  if (ntohl (hdr->num) != n)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  "Expected message %u of size %u, got %u bytes of message %u\n",
		  n, s,
		  ntohs (message->size),
		  ntohl (hdr->num));
      GNUNET_SCHEDULER_cancel (sched, err_task);
      err_task = GNUNET_SCHEDULER_add_now (sched, &terminate_task_error, NULL);
      return GNUNET_SYSERR;
    }
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Got message %u of size %u\n",
	      ntohl (hdr->num),
	      ntohs (message->size));	      
#endif
  n++;
  if (0 == (n % (TOTAL_MSGS/100)))
    fprintf (stderr, ".");
  if (n == TOTAL_MSGS)
    {
      GNUNET_SCHEDULER_cancel (sched, err_task);
      GNUNET_SCHEDULER_add_now (sched, &terminate_task, NULL);
    }
  else
    {
      if (n == tr_n)
	GNUNET_break (NULL != 
		      GNUNET_CORE_notify_transmit_ready (p1.ch,
							 0,
							 FAST_TIMEOUT,
							 &p2.id,
							 sizeof (struct GNUNET_MessageHeader),
							 &transmit_ready, &p1));
    }
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

  GNUNET_assert (size <= GNUNET_CONSTANTS_MAX_ENCRYPTED_MESSAGE_SIZE); 
  if (buf == NULL)
    {
      if (p1.ch != NULL)
	GNUNET_break (NULL != 
		      GNUNET_CORE_notify_transmit_ready (p1.ch,
							 0,
							 FAST_TIMEOUT,
							 &p2.id,
							 sizeof (struct GNUNET_MessageHeader),
							 &transmit_ready, &p1));
      return 0;
    }
  GNUNET_assert (tr_n < TOTAL_MSGS);
  ret = 0;
  s = get_size (tr_n);
  GNUNET_assert (size >= s);
  GNUNET_assert (buf != NULL);
  cbuf = buf;
  do
    {
#if VERBOSE
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
      s = get_size (tr_n);
      if (0 == GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, 16))
	break; /* sometimes pack buffer full, sometimes not */
    }
  while (size - ret >= s);
  GNUNET_SCHEDULER_cancel (sched, err_task);
  err_task = 
    GNUNET_SCHEDULER_add_delayed (sched,
				  TIMEOUT,
				  &terminate_task_error, 
				  NULL);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Returning total message block of size %u\n",
	      ret);
  total_bytes += ret;
  return ret;
}



static void
init_notify (void *cls,
             struct GNUNET_CORE_Handle *server,
             const struct GNUNET_PeerIdentity *my_identity,
             const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *publicKey)
{
  struct PeerContext *p = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Connection to CORE service of `%4s' established\n",
              GNUNET_i2s (my_identity));
  GNUNET_assert (server != NULL);
  p->id = *my_identity;
  p->ch = server;
  if (cls == &p1)
    {
      GNUNET_assert (ok == 2);
      OKPP;
      /* connect p2 */
      GNUNET_CORE_connect (sched,
                           p2.cfg,
                           TIMEOUT,
                           &p2,
                           &init_notify,			 
                           &connect_notify,
                           &disconnect_notify,
                           &inbound_notify,
                           GNUNET_YES,
                           &outbound_notify, GNUNET_YES, handlers);
    }
  else
    {
      GNUNET_assert (ok == 3);
      OKPP;
      GNUNET_assert (cls == &p2);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Asking core (1) for transmission to peer `%4s'\n",
                  GNUNET_i2s (&p2.id));
      err_task = 
	GNUNET_SCHEDULER_add_delayed (sched,
				      TIMEOUT,
				      &terminate_task_error, 
				      NULL);
      start_time = GNUNET_TIME_absolute_get ();
      GNUNET_break (NULL != 
		    GNUNET_CORE_notify_transmit_ready (p1.ch,
						       0,
						       TIMEOUT,
						       &p2.id,
						       sizeof (struct GNUNET_MessageHeader),
						       &transmit_ready, &p1));
    }
}


static void
process_hello (void *cls,
               const struct GNUNET_MessageHeader *message)
{
  struct PeerContext *p = cls;

  GNUNET_TRANSPORT_get_hello_cancel (p->th, &process_hello, p);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received (my) `%s' from transport service\n",
              "HELLO");
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
  p->arm_pid = GNUNET_OS_start_process (NULL, NULL, "gnunet-service-arm",
                                        "gnunet-service-arm",
#if VERBOSE
                                        "-L", "DEBUG",
#endif
                                        "-c", cfgname, NULL);
#endif
  GNUNET_assert (GNUNET_OK == GNUNET_CONFIGURATION_load (p->cfg, cfgname));
  p->th = GNUNET_TRANSPORT_connect (sched, p->cfg, p, NULL, NULL, NULL);
  GNUNET_assert (p->th != NULL);
  GNUNET_TRANSPORT_get_hello (p->th, &process_hello, p);
}


static void
run (void *cls,
     struct GNUNET_SCHEDULER_Handle *s,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  GNUNET_assert (ok == 1);
  OKPP;
  sched = s;
  setup_peer (&p1, "test_core_api_peer1.conf");
  setup_peer (&p2, "test_core_api_peer2.conf");
  GNUNET_CORE_connect (sched,
                       p1.cfg,
                       TIMEOUT,
                       &p1,
                       &init_notify,
		       &connect_notify,
                       &disconnect_notify,
                       &inbound_notify,
                       GNUNET_YES, &outbound_notify, GNUNET_YES, handlers);
}


static void
stop_arm (struct PeerContext *p)
{
#if START_ARM
  if (0 != PLIBC_KILL (p->arm_pid, SIGTERM))
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "kill");
  if (GNUNET_OS_process_wait(p->arm_pid) != GNUNET_OK)
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "waitpid");
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "ARM process %u stopped\n", p->arm_pid);
#endif
  GNUNET_CONFIGURATION_destroy (p->cfg);
}

static int
check ()
{
  char *const argv[] = { "test-core-api-reliability",
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
                      argv, "test-core-api-reliability", "nohelp", options, &run, &ok);
  stop_arm (&p1);
  stop_arm (&p2);
  return ok;
}

int
main (int argc, char *argv[])
{
  int ret;

  GNUNET_log_setup ("test-core-api",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);
  ret = check ();
  GNUNET_DISK_directory_remove ("/tmp/test-gnunet-core-peer-1"); 
  GNUNET_DISK_directory_remove ("/tmp/test-gnunet-core-peer-2");

  return ret;
}

/* end of test_core_api_reliability.c */
