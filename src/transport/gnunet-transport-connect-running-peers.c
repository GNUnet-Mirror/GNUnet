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
 * @file transport/gnunet-transport-connect-running-peers.c
 * @brief utility to connect running peers
 *
 * This utility connects to running peers with each other
 * The peers have to be started before, for example in the debugger with
 * breakpoints set
 */
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_hello_lib.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_os_lib.h"
#include "gnunet_program_lib.h"
#include "gnunet_scheduler_lib.h"
#include "gnunet_transport_service.h"
#include "transport.h"
#include "transport-testing.h"

#define VERBOSE GNUNET_EXTRA_LOGGING

#define VERBOSE_ARM GNUNET_EXTRA_LOGGING

#define START_ARM GNUNET_YES

/**
 * How long until we give up on transmitting the message?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 300)

/**
 * How long until we give up on transmitting the message?
 */
#define TIMEOUT_TRANSMIT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 60)

#define MTYPE 12345

static int ok;

static GNUNET_SCHEDULER_TaskIdentifier die_task;

static GNUNET_SCHEDULER_TaskIdentifier send_task;

struct PeerContext *p1;

struct PeerContext *p2;

static GNUNET_TRANSPORT_TESTING_ConnectRequest cc;

struct GNUNET_TRANSPORT_TransmitHandle *th;

char *cfg_file_p1;

char *cfg_file_p2;

#if VERBOSE
#define OKPP do { ok++; fprintf (stderr, "Now at stage %u at %s:%u\n", ok, __FILE__, __LINE__); } while (0)
#else
#define OKPP do { ok++; } while (0)
#endif

void
disconnect_from_peer (struct PeerContext *p)
{
  GNUNET_assert (p != NULL);
  if (p->th != NULL)
    GNUNET_TRANSPORT_disconnect (p->th);

  if (p->cfg != NULL)
    GNUNET_CONFIGURATION_destroy (p->cfg);
  GNUNET_free (p);
  p = NULL;
}

static void
end (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Stopping peers\n");

  if (send_task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (send_task);

  if (die_task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (die_task);

  if (th != NULL)
    GNUNET_TRANSPORT_notify_transmit_ready_cancel (th);
  th = NULL;

  if (p1 != NULL)
    disconnect_from_peer (p1);
  if (p2 != NULL)
    disconnect_from_peer (p2);
}

static void
end_badly (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  die_task = GNUNET_SCHEDULER_NO_TASK;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Fail! Stopping peers\n");

  if (send_task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (send_task);

  if (cc != NULL)
    GNUNET_TRANSPORT_TESTING_connect_peers_cancel (cc);

  if (th != NULL)
    GNUNET_TRANSPORT_notify_transmit_ready_cancel (th);
  th = NULL;

  if (p1 != NULL)
    disconnect_from_peer (p1);
  if (p2 != NULL)
    disconnect_from_peer (p2);

  ok = GNUNET_SYSERR;
}


static size_t
notify_ready (void *cls, size_t size, void *buf)
{
  struct PeerContext *p = cls;
  struct GNUNET_MessageHeader *hdr;

  th = NULL;

  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "Transmitting message with %u bytes to peer %s\n",
              sizeof (struct GNUNET_MessageHeader), GNUNET_i2s (&p->id));
  GNUNET_assert (size >= 256);

  if (buf != NULL)
  {
    hdr = buf;
    hdr->size = htons (sizeof (struct GNUNET_MessageHeader));
    hdr->type = htons (MTYPE);
  }

  return sizeof (struct GNUNET_MessageHeader);
}

static void
sendtask (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  send_task = GNUNET_SCHEDULER_NO_TASK;
  static char t;

  if ((tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) != 0)
    return;

  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "Press <q> to quit or <1> to send from p1 to p2, <2> to send from p2 to p1, <enter> repeat\n");

read:
  t = getchar();
  if (t == '1')
  {
    th = GNUNET_TRANSPORT_notify_transmit_ready (p1->th, &p2->id, 256, 0, TIMEOUT,
                                                 &notify_ready, p1);
    return;
  }
  if (t == '2')
  {
    th = GNUNET_TRANSPORT_notify_transmit_ready (p2->th, &p1->id, 256, 0, TIMEOUT,
                                                 &notify_ready, p2);
    return;
  }
  if (t == 'q')
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Exiting %c!\n", t);
    GNUNET_SCHEDULER_add_now(&end, NULL);
    return;
  }
  goto read;
}

static void
notify_receive (void *cls, const struct GNUNET_PeerIdentity *peer,
                const struct GNUNET_MessageHeader *message,
                const struct GNUNET_ATS_Information *ats,
                uint32_t ats_count)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received message of type %d from peer %s!\n",
              ntohs (message->type), GNUNET_i2s (peer));

  if ((MTYPE == ntohs (message->type)) &&
      (sizeof (struct GNUNET_MessageHeader) == ntohs (message->size)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Successfully received message\n");

    send_task = GNUNET_SCHEDULER_add_now (&sendtask, NULL);
  }
}

static void
notify_connect (void *cls, const struct GNUNET_PeerIdentity *peer,
                const struct GNUNET_ATS_Information *ats,
                uint32_t ats_count)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Peer `%4s' connected to us (%p)!\n",
              GNUNET_i2s (peer), cls);
}


static void
notify_disconnect (void *cls, const struct GNUNET_PeerIdentity *peer)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Peer `%4s' disconnected (%p)!\n",
              GNUNET_i2s (peer), cls);
}




struct PeerContext *
connect_to_peer (const char *cfgname, GNUNET_TRANSPORT_ReceiveCallback rec,
                 GNUNET_TRANSPORT_NotifyConnect nc,
                 GNUNET_TRANSPORT_NotifyDisconnect nd, void *cb_cls)
{
  if (GNUNET_DISK_file_test (cfgname) == GNUNET_NO)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "File not found: `%s' \n", cfgname);
    return NULL;
  }

  struct PeerContext *p = GNUNET_malloc (sizeof (struct PeerContext));

  p->cfg = GNUNET_CONFIGURATION_create ();

  GNUNET_assert (GNUNET_OK == GNUNET_CONFIGURATION_load (p->cfg, cfgname));
  if (GNUNET_CONFIGURATION_have_value (p->cfg, "PATHS", "SERVICEHOME"))
    GNUNET_CONFIGURATION_get_value_string (p->cfg, "PATHS", "SERVICEHOME",
                                           &p->servicehome);
  if (NULL != p->servicehome)
    GNUNET_DISK_directory_remove (p->servicehome);
  /*
   * p->arm_proc =
   * GNUNET_OS_start_process (NULL, NULL, "gnunet-service-arm",
   * "gnunet-service-arm", "-c", cfgname,
   * #if VERBOSE_PEERS
   * "-L", "DEBUG",
   * #else
   * "-L", "ERROR",
   * #endif
   * NULL);
   */
  p->nc = nc;
  p->nd = nd;
  p->rec = rec;
  if (cb_cls != NULL)
    p->cb_cls = cb_cls;
  else
    p->cb_cls = p;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Connecting to transport service `%s'\n",
              p->servicehome);
  p->th =
      GNUNET_TRANSPORT_connect (p->cfg, NULL, p, &notify_receive,
                                &notify_connect, &notify_disconnect);
  GNUNET_assert (p->th != NULL);
  return p;
}

static void
testing_connect_cb (struct PeerContext *p1, struct PeerContext *p2, void *cls)
{
  cc = NULL;
  char *p1_c = GNUNET_strdup (GNUNET_i2s (&p1->id));

  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Peers connected: %s <-> %s\n", p1_c,
              GNUNET_i2s (&p2->id));
  GNUNET_free (p1_c);

  // FIXME: THIS IS REQUIRED! SEEMS TO BE A BUG!

  send_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS, &sendtask, NULL);
}

static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  die_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT, &end_badly, NULL);

  p1 = connect_to_peer (cfg_file_p1, &notify_receive, &notify_connect,
                        &notify_disconnect, NULL);
  p2 = connect_to_peer (cfg_file_p2, &notify_receive, &notify_connect,
                        &notify_disconnect, NULL);

  if ((p1 == NULL) || (p2 == NULL))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Fail! Could not start peers!\n");
    if (die_task != GNUNET_SCHEDULER_NO_TASK)
      GNUNET_SCHEDULER_cancel (die_task);
    die_task = GNUNET_SCHEDULER_add_now (&end_badly, NULL);
    return;
  }

  cc = GNUNET_TRANSPORT_TESTING_connect_peers (p1, p2, &testing_connect_cb,
                                               NULL);

}


static int
check ()
{
  static char *const argv[] = { "test-transport-api",
    "-c",
    "test_transport_api_data.conf",
#if VERBOSE
    "-L", "DEBUG",
#endif
    NULL
  };
  static struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

#if WRITECONFIG
  setTransportOptions ("test_transport_api_data.conf");
#endif
  send_task = GNUNET_SCHEDULER_NO_TASK;

  ok = 1;
  GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1, argv,
                      "util_connect_running_peers", "nohelp", options, &run,
                      &ok);

  return ok;
}

int
main (int argc, char *argv[])
{
  int ret;

  GNUNET_log_setup ("gnunet-transport-connect-running-peers",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);


  if (argc < 3)
  {
    fprintf (stderr,
             "usage gnunet-transport-connect-running-peers <cfg_peer1> <cfg_peer2>\n");
    return -1;
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Configuration file 1: `%s' \n",
                argv[1]);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Configuration file 2: `%s'\n",
                argv[2]);
  }

  if (GNUNET_DISK_file_test (argv[1]) == GNUNET_NO)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "File not found: `%s' \n", argv[1]);
    return -1;
  }
  if (GNUNET_DISK_file_test (argv[2]) == GNUNET_NO)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "File not found: `%s' \n", argv[2]);
    return -1;
  }

  GNUNET_asprintf (&cfg_file_p1, argv[1]);
  GNUNET_asprintf (&cfg_file_p2, argv[2]);

  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "Trying to connect peers, press control-d to stop... \n",
              argv[1]);

  ret = check ();

  GNUNET_free (cfg_file_p1);
  GNUNET_free (cfg_file_p2);
  return ret;
}

/* end of gnunet-transport-connect-running-peers.c */
