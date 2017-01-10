/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2010, 2015, 2016 GNUnet e.V.

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
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/
/**
 * @file core/test_core_api_reliability.c
 * @brief testcase for core_api.c focusing on reliable transmission (with TCP)
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_arm_service.h"
#include "gnunet_core_service.h"
#include "gnunet_util_lib.h"
#include "gnunet_ats_service.h"
#include "gnunet_transport_service.h"
#include "gnunet_transport_hello_service.h"
#include <gauger.h>

/**
 * Note that this value must not significantly exceed
 * 'MAX_PENDING' in 'gnunet-service-transport.c', otherwise
 * messages may be dropped even for a reliable transport.
 */
#define TOTAL_MSGS (600 * 10)

/**
 * How long until we give up on transmitting the message?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 600)

#define MTYPE 12345


static unsigned long long total_bytes;

static struct GNUNET_TIME_Absolute start_time;

static struct GNUNET_SCHEDULER_Task *err_task;


struct PeerContext
{
  struct GNUNET_CONFIGURATION_Handle *cfg;
  struct GNUNET_CORE_Handle *ch;
  struct GNUNET_MQ_Handle *mq;
  struct GNUNET_PeerIdentity id;
  struct GNUNET_TRANSPORT_OfferHelloHandle *oh;
  struct GNUNET_MessageHeader *hello;
  struct GNUNET_TRANSPORT_HelloGetHandle *ghh;
  struct GNUNET_ATS_ConnectivityHandle *ats;
  struct GNUNET_ATS_ConnectivitySuggestHandle *ats_sh;
  int connect_status;
  struct GNUNET_OS_Process *arm_proc;
};

static struct PeerContext p1;

static struct PeerContext p2;

static int ok;

static int32_t tr_n;


#define OKPP do { ok++; GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Now at stage %u at %s:%u\n", ok, __FILE__, __LINE__); } while (0)

struct TestMessage
{
  struct GNUNET_MessageHeader header;
  uint32_t num GNUNET_PACKED;
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
}


static void
terminate_task_error (void *cls)
{
  err_task = NULL;
  GNUNET_break (0);
  GNUNET_SCHEDULER_shutdown ();
  ok = 42;
}


static void
do_shutdown (void *cls)
{
  unsigned long long delta;

  delta = GNUNET_TIME_absolute_get_duration (start_time).rel_value_us;
  FPRINTF (stderr,
           "\nThroughput was %llu kb/s\n",
           total_bytes * 1000000LL / 1024 / delta);
  GAUGER ("CORE",
          "Core throughput/s",
          total_bytes * 1000000LL / 1024 / delta,
          "kb/s");
  if (NULL != err_task)
  {
    GNUNET_SCHEDULER_cancel (err_task);
    err_task = NULL;
  }
  terminate_peer (&p1);
  terminate_peer (&p2);

}


static void
send_message (struct GNUNET_MQ_Handle *mq,
	      int32_t num)
{
  struct GNUNET_MQ_Envelope *env;
  struct TestMessage *hdr;
  unsigned int s;

  GNUNET_assert (NULL != mq);
  GNUNET_assert (tr_n < TOTAL_MSGS);
  s = get_size (tr_n);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Sending message %u of size %u\n",
	      tr_n,
	      s);
  env = GNUNET_MQ_msg_extra (hdr,
			     s - sizeof (struct TestMessage),
			     MTYPE);
  hdr->num = htonl (tr_n);
  memset (&hdr[1],
	  tr_n,
	  s - sizeof (struct TestMessage));
  tr_n++;
  GNUNET_SCHEDULER_cancel (err_task);
  err_task =
      GNUNET_SCHEDULER_add_delayed (TIMEOUT,
                                    &terminate_task_error,
				    NULL);
  total_bytes += s;
  GNUNET_MQ_send (mq,
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
    return (void *) peer;
  pc->mq = mq;
  GNUNET_assert (0 == pc->connect_status);
  pc->connect_status = 1;
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
    send_message (mq,
		  0);
  }
  return (void *) peer;
}


static void
disconnect_notify (void *cls,
                   const struct GNUNET_PeerIdentity *peer,
		   void *internal_cls)
{
  struct PeerContext *pc = cls;

  if (0 == memcmp (&pc->id,
		   peer,
		   sizeof (struct GNUNET_PeerIdentity)))
    return;
  pc->mq = NULL;
  pc->connect_status = 0;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Encrypted connection to `%s' cut\n",
              GNUNET_i2s (peer));
}


static int
check_test (void *cls,
	    const struct TestMessage *hdr)
{
  return GNUNET_OK; /* accept all */
}


static void
handle_test (void *cls,
	     const struct TestMessage *hdr)
{
  static int n;
  unsigned int s;

  s = get_size (n);
  if (ntohs (hdr->header.size) != s)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Expected message %u of size %u, got %u bytes of message %u\n",
                n,
		s,
                ntohs (hdr->header.size),
                ntohl (hdr->num));
    GNUNET_SCHEDULER_cancel (err_task);
    err_task = GNUNET_SCHEDULER_add_now (&terminate_task_error,
                                         NULL);
    return;
  }
  if (ntohl (hdr->num) != n)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Expected message %u of size %u, got %u bytes of message %u\n",
                n,
		s,
                (unsigned int) ntohs (hdr->header.size),
                (unsigned int) ntohl (hdr->num));
    GNUNET_SCHEDULER_cancel (err_task);
    err_task = GNUNET_SCHEDULER_add_now (&terminate_task_error,
					 NULL);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Got message %u of size %u\n",
              (unsigned int) ntohl (hdr->num),
              (unsigned int) ntohs (hdr->header.size));
  n++;
  if (0 == (n % (TOTAL_MSGS / 100)))
    FPRINTF (stderr,
	     "%s",
	     ".");
  if (n == TOTAL_MSGS)
  {
    ok = 0;
    GNUNET_SCHEDULER_shutdown ();
  }
  else
  {
    if (n == tr_n)
    {
      send_message (p1.mq,
		    tr_n);
    }
  }
}


static void
init_notify (void *cls,
             const struct GNUNET_PeerIdentity *my_identity)
{
  struct PeerContext *p = cls;
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_var_size (test,
                           MTYPE,
                           struct TestMessage,
                           NULL),
    GNUNET_MQ_handler_end ()
  };

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Connection to CORE service of `%s' established\n",
              GNUNET_i2s (my_identity));
  p->id = *my_identity;
  if (cls == &p1)
  {
    GNUNET_assert (ok == 2);
    OKPP;
    /* connect p2 */
    GNUNET_assert (NULL !=
		   (p2.ch = GNUNET_CORE_connect (p2.cfg,
						 &p2,
						 &init_notify,
						 &connect_notify,
						 &disconnect_notify,
						 handlers)));
  }
  else
  {
    GNUNET_assert (ok == 3);
    OKPP;
    GNUNET_assert (cls == &p2);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Asking transport (1) to connect to peer `%s'\n",
                GNUNET_i2s (&p2.id));
    p1.ats_sh = GNUNET_ATS_connectivity_suggest (p1.ats,
                                                 &p2.id,
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
              "Received (my) `%s' from transport service\n", "HELLO");
  GNUNET_assert (message != NULL);
  p->hello = GNUNET_copy_message (message);
  if ((p == &p1) && (NULL == p2.oh))
    p2.oh = GNUNET_TRANSPORT_offer_hello (p2.cfg,
                                          message,
                                          &offer_hello_done,
                                          &p2);
  if ((p == &p2) && (NULL == p1.oh))
    p1.oh = GNUNET_TRANSPORT_offer_hello (p1.cfg,
                                          message,
                                          &offer_hello_done,
                                          &p1);

  if ((p == &p1) && (p2.hello != NULL) && (NULL == p1.oh) )
    p1.oh = GNUNET_TRANSPORT_offer_hello (p1.cfg,
                                          p2.hello,
                                          &offer_hello_done,
                                          &p1);
  if ((p == &p2) && (p1.hello != NULL) && (NULL == p2.oh) )
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
  p->arm_proc
    = GNUNET_OS_start_process (GNUNET_YES,
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
  setup_peer (&p1,
	      "test_core_api_peer1.conf");
  setup_peer (&p2,
	      "test_core_api_peer2.conf");
  err_task =
      GNUNET_SCHEDULER_add_delayed (TIMEOUT,
                                    &terminate_task_error,
                                    NULL);
  GNUNET_SCHEDULER_add_shutdown (&do_shutdown,
				 NULL);

  GNUNET_assert (NULL !=
		 (p1.ch = GNUNET_CORE_connect (p1.cfg,
					       &p1,
					       &init_notify,
					       &connect_notify,
					       &disconnect_notify,
					       handlers)));
}


static void
stop_arm (struct PeerContext *p)
{
  if (0 != GNUNET_OS_process_kill (p->arm_proc,
				   GNUNET_TERM_SIG))
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING,
                         "kill");
  if (GNUNET_OK != GNUNET_OS_process_wait (p->arm_proc))
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING,
                         "waitpid");
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "ARM process %u stopped\n",
              GNUNET_OS_process_get_pid (p->arm_proc));
  GNUNET_OS_process_destroy (p->arm_proc);
  p->arm_proc = NULL;
  GNUNET_CONFIGURATION_destroy (p->cfg);
}


int
main (int argc,
      char *argv1[])
{
  char *const argv[] = {
    "test-core-api-reliability",
    "-c",
    "test_core_api_data.conf",
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  ok = 1;
  GNUNET_log_setup ("test-core-api-reliability",
                    "WARNING",
                    NULL);
  GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1,
		      argv,
                      "test-core-api-reliability",
		      "nohelp",
		      options,
		      &run,
                      &ok);
  stop_arm (&p1);
  stop_arm (&p2);
  GNUNET_DISK_directory_remove ("/tmp/test-gnunet-core-peer-1");
  GNUNET_DISK_directory_remove ("/tmp/test-gnunet-core-peer-2");

  return ok;
}

/* end of test_core_api_reliability.c */
