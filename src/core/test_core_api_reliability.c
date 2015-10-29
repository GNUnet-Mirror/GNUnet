/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2010, 2015 Christian Grothoff (and other contributing authors)

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
 */
#include "platform.h"
#include "gnunet_arm_service.h"
#include "gnunet_core_service.h"
#include "gnunet_util_lib.h"
#include "gnunet_ats_service.h"
#include "gnunet_transport_service.h"
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

/**
 * What delay do we request from the core service for transmission?
 */
#define FAST_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)

#define MTYPE 12345


static unsigned long long total_bytes;

static struct GNUNET_TIME_Absolute start_time;

static struct GNUNET_SCHEDULER_Task *err_task;


struct PeerContext
{
  struct GNUNET_CONFIGURATION_Handle *cfg;
  struct GNUNET_CORE_Handle *ch;
  struct GNUNET_PeerIdentity id;
  struct GNUNET_TRANSPORT_Handle *th;
  struct GNUNET_MessageHeader *hello;
  struct GNUNET_TRANSPORT_GetHelloHandle *ghh;
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
terminate_peer (struct PeerContext *p)
{
  if (NULL != p->ch)
  {
    GNUNET_CORE_disconnect (p->ch);
    p->ch = NULL;
  }
  if (NULL != p->th)
  {
    GNUNET_TRANSPORT_get_hello_cancel (p->ghh);
    GNUNET_TRANSPORT_disconnect (p->th);
    p->th = NULL;
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
terminate_task (void *cls,
                const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  unsigned long long delta;

  terminate_peer (&p1);
  terminate_peer (&p2);
  delta = GNUNET_TIME_absolute_get_duration (start_time).rel_value_us;
  FPRINTF (stderr,
           "\nThroughput was %llu kb/s\n",
           total_bytes * 1000000LL / 1024 / delta);
  GAUGER ("CORE", "Core throughput/s", total_bytes * 1000000LL / 1024 / delta,
          "kb/s");
  ok = 0;
}


static void
terminate_task_error (void *cls,
                      const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_break (0);
  terminate_peer (&p1);
  terminate_peer (&p2);
  ok = 42;
}


static size_t
transmit_ready (void *cls, size_t size, void *buf)
{
  char *cbuf = buf;
  struct TestMessage hdr;
  unsigned int s;
  unsigned int ret;

  GNUNET_assert (size <= GNUNET_CONSTANTS_MAX_ENCRYPTED_MESSAGE_SIZE);
  if (NULL == buf)
  {
    if (NULL != p1.ch)
      GNUNET_break (NULL !=
                    GNUNET_CORE_notify_transmit_ready (p1.ch, GNUNET_NO,
                                                       GNUNET_CORE_PRIO_BEST_EFFORT,
                                                       FAST_TIMEOUT, &p2.id,
                                                       get_size (tr_n),
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
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Sending message %u of size %u at offset %u\n", tr_n, s, ret);
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
      break;                    /* sometimes pack buffer full, sometimes not */
  }
  while (size - ret >= s);
  GNUNET_SCHEDULER_cancel (err_task);
  err_task =
      GNUNET_SCHEDULER_add_delayed (TIMEOUT,
                                    &terminate_task_error, NULL);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Returning total message block of size %u\n", ret);
  total_bytes += ret;
  return ret;
}


static void
connect_notify (void *cls, const struct GNUNET_PeerIdentity *peer)
{
  struct PeerContext *pc = cls;

  if (0 == memcmp (&pc->id, peer, sizeof (struct GNUNET_PeerIdentity)))
    return;
  GNUNET_assert (pc->connect_status == 0);
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
        GNUNET_SCHEDULER_add_delayed (TIMEOUT, &terminate_task_error, NULL);
    start_time = GNUNET_TIME_absolute_get ();
    GNUNET_break (NULL !=
                  GNUNET_CORE_notify_transmit_ready (p1.ch, GNUNET_NO,
                                                     GNUNET_CORE_PRIO_BEST_EFFORT,
                                                     TIMEOUT, &p2.id,
                                                     get_size (0),
                                                     &transmit_ready, &p1));
  }
}


static void
disconnect_notify (void *cls, const struct GNUNET_PeerIdentity *peer)
{
  struct PeerContext *pc = cls;

  if (0 == memcmp (&pc->id, peer, sizeof (struct GNUNET_PeerIdentity)))
    return;
  pc->connect_status = 0;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Encrypted connection to `%s' cut\n",
              GNUNET_i2s (peer));
}


static int
inbound_notify (void *cls, const struct GNUNET_PeerIdentity *other,
                const struct GNUNET_MessageHeader *message)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Core provides inbound data from `%s'.\n", GNUNET_i2s (other));
  return GNUNET_OK;
}


static int
outbound_notify (void *cls, const struct GNUNET_PeerIdentity *other,
                 const struct GNUNET_MessageHeader *message)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Core notifies about outbound data for `%s'.\n",
              GNUNET_i2s (other));
  return GNUNET_OK;
}


static size_t
transmit_ready (void *cls, size_t size, void *buf);


static int
process_mtype (void *cls,
               const struct GNUNET_PeerIdentity *peer,
               const struct GNUNET_MessageHeader *message)
{
  static int n;
  unsigned int s;
  const struct TestMessage *hdr;

  hdr = (const struct TestMessage *) message;
  s = get_size (n);
  if (MTYPE != ntohs (message->type))
    return GNUNET_SYSERR;
  if (ntohs (message->size) != s)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Expected message %u of size %u, got %u bytes of message %u\n",
                n, s, ntohs (message->size), ntohl (hdr->num));
    GNUNET_SCHEDULER_cancel (err_task);
    err_task = GNUNET_SCHEDULER_add_now (&terminate_task_error, NULL);
    return GNUNET_SYSERR;
  }
  if (ntohl (hdr->num) != n)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Expected message %u of size %u, got %u bytes of message %u\n",
                n, s, ntohs (message->size), ntohl (hdr->num));
    GNUNET_SCHEDULER_cancel (err_task);
    err_task = GNUNET_SCHEDULER_add_now (&terminate_task_error, NULL);
    return GNUNET_SYSERR;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Got message %u of size %u\n",
              ntohl (hdr->num), ntohs (message->size));
  n++;
  if (0 == (n % (TOTAL_MSGS / 100)))
    FPRINTF (stderr, "%s",  ".");
  if (n == TOTAL_MSGS)
  {
    GNUNET_SCHEDULER_cancel (err_task);
    GNUNET_SCHEDULER_add_now (&terminate_task, NULL);
  }
  else
  {
    if (n == tr_n)
      GNUNET_break (NULL !=
                    GNUNET_CORE_notify_transmit_ready (p1.ch,
                                                       GNUNET_NO /* no cork */,
                                                       GNUNET_CORE_PRIO_BEST_EFFORT,
                                                       FAST_TIMEOUT /* ignored! */,
                                                       &p2.id,
                                                       get_size (tr_n),
                                                       &transmit_ready, &p1));
  }
  return GNUNET_OK;
}


static struct GNUNET_CORE_MessageHandler handlers[] = {
  {&process_mtype, MTYPE, 0},
  {NULL, 0, 0}
};


static void
init_notify (void *cls,
             const struct GNUNET_PeerIdentity *my_identity)
{
  struct PeerContext *p = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Connection to CORE service of `%s' established\n",
              GNUNET_i2s (my_identity));
  p->id = *my_identity;
  if (cls == &p1)
  {
    GNUNET_assert (ok == 2);
    OKPP;
    /* connect p2 */
    GNUNET_assert (NULL != (p2.ch = GNUNET_CORE_connect (p2.cfg, &p2,
                                                         &init_notify,
                                                         &connect_notify,
                                                         &disconnect_notify,
                                                         &inbound_notify, GNUNET_YES,
                                                         &outbound_notify, GNUNET_YES,
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
process_hello (void *cls, const struct GNUNET_MessageHeader *message)
{
  struct PeerContext *p = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received (my) `%s' from transport service\n", "HELLO");
  GNUNET_assert (message != NULL);
  p->hello = GNUNET_copy_message (message);
  if ((p == &p1) && (p2.th != NULL))
    GNUNET_TRANSPORT_offer_hello (p2.th, message, NULL, NULL);
  if ((p == &p2) && (p1.th != NULL))
    GNUNET_TRANSPORT_offer_hello (p1.th, message, NULL, NULL);

  if ((p == &p1) && (p2.hello != NULL))
    GNUNET_TRANSPORT_offer_hello (p1.th, p2.hello, NULL, NULL);
  if ((p == &p2) && (p1.hello != NULL))
    GNUNET_TRANSPORT_offer_hello (p2.th, p1.hello, NULL, NULL);
}


static void
setup_peer (struct PeerContext *p, const char *cfgname)
{
  char *binary;

  binary = GNUNET_OS_get_libexec_binary_path ("gnunet-service-arm");
  p->cfg = GNUNET_CONFIGURATION_create ();
  p->arm_proc =
    GNUNET_OS_start_process (GNUNET_YES, GNUNET_OS_INHERIT_STD_OUT_AND_ERR,
                             NULL, NULL, NULL,
                             binary,
                             "gnunet-service-arm",
                             "-c", cfgname, NULL);
  GNUNET_assert (GNUNET_OK == GNUNET_CONFIGURATION_load (p->cfg, cfgname));
  p->th = GNUNET_TRANSPORT_connect (p->cfg, NULL, p, NULL, NULL, NULL);
  GNUNET_assert (p->th != NULL);
  p->ats = GNUNET_ATS_connectivity_init (p->cfg);
  GNUNET_assert (NULL != p->ats);
  p->ghh = GNUNET_TRANSPORT_get_hello (p->th, &process_hello, p);
  GNUNET_free (binary);
}


static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  GNUNET_assert (ok == 1);
  OKPP;
  setup_peer (&p1, "test_core_api_peer1.conf");
  setup_peer (&p2, "test_core_api_peer2.conf");
  err_task =
      GNUNET_SCHEDULER_add_delayed (TIMEOUT, &terminate_task_error, NULL);

  GNUNET_assert (NULL != (p1.ch = GNUNET_CORE_connect (p1.cfg, &p1,
                                                       &init_notify,
                                                       &connect_notify,
                                                       &disconnect_notify,
                                                       &inbound_notify, GNUNET_YES,
                                                       &outbound_notify, GNUNET_YES,
                                                       handlers)));
}


static void
stop_arm (struct PeerContext *p)
{
  if (0 != GNUNET_OS_process_kill (p->arm_proc, GNUNET_TERM_SIG))
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "kill");
  if (GNUNET_OS_process_wait (p->arm_proc) != GNUNET_OK)
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "waitpid");
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "ARM process %u stopped\n",
              GNUNET_OS_process_get_pid (p->arm_proc));
  GNUNET_OS_process_destroy (p->arm_proc);
  p->arm_proc = NULL;
  GNUNET_CONFIGURATION_destroy (p->cfg);
}


int
main (int argc, char *argv1[])
{
  char *const argv[] = { "test-core-api-reliability",
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
  GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1, argv,
                      "test-core-api-reliability", "nohelp", options, &run,
                      &ok);
  stop_arm (&p1);
  stop_arm (&p2);
  GNUNET_DISK_directory_remove ("/tmp/test-gnunet-core-peer-1");
  GNUNET_DISK_directory_remove ("/tmp/test-gnunet-core-peer-2");

  return ok;
}

/* end of test_core_api_reliability.c */
