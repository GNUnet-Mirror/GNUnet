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
 * @file transport/test_transport_api_dv.c
 * @brief base test case for dv transport (separated from other transport
 * testcases for two reasons. 1) dv-service relies on core and other
 * transport plugins, dv plugin relies on dv-service, so dv-plugin needs
 * to live here, and 2) a dv plugin testcase is different from other
 * tranport plugin testcases because we need at least three peer to test
 * it.
 *
 * This test case tests DV functionality.  Specifically it starts three
 * peers connected in a line (1 <-> 2 <-> 3).  Then a message is transmitted
 * from peer 1 to peer 3.  Assuming that DV is working, peer 2 should have
 * gossiped about peer 3 to 1, and should then forward a message from one
 * to 3.
 */
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_hello_lib.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_os_lib.h"
#include "gnunet_program_lib.h"
#include "gnunet_scheduler_lib.h"
#include "gnunet_transport_service.h"
#include "../transport/transport.h"

#define VERBOSE GNUNET_YES

#define VERBOSE_ARM GNUNET_NO

#define START_ARM GNUNET_YES

/**
 * How long until we give up on transmitting the message?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 50)

#define MTYPE 12345

static int num_wanted = 2;

static int num_received = 0;

struct PeerContext
{
  struct GNUNET_CONFIGURATION_Handle *cfg;
  struct GNUNET_TRANSPORT_Handle *th;
  struct GNUNET_PeerIdentity id;
  const char *cfg_file;
  struct GNUNET_HELLO_Message *hello;
#if START_ARM
  pid_t arm_pid;
#endif
};

static struct PeerContext p1;

static struct PeerContext p2;

static struct PeerContext p3;

static struct PeerContext p4;

static struct GNUNET_SCHEDULER_Handle *sched;

static int ok;

GNUNET_SCHEDULER_TaskIdentifier die_task;

#if VERBOSE
#define OKPP do { ok++; fprintf (stderr, "Now at stage %u at %s:%u\n", ok, __FILE__, __LINE__); } while (0)
#else
#define OKPP do { ok++; } while (0)
#endif


static void
end ()
{
  /* do work here */
  GNUNET_SCHEDULER_cancel (sched, die_task);

  if (p1.th != NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Disconnecting from transport 1!\n");
      GNUNET_TRANSPORT_disconnect (p1.th);
      p1.th = NULL;
    }

  if (p2.th != NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Disconnecting from transport 2!\n");
      GNUNET_TRANSPORT_disconnect (p2.th);
      p2.th = NULL;
    }

  if (p3.th != NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Disconnecting from transport 3!\n");
      GNUNET_TRANSPORT_disconnect (p3.th);
      p3.th = NULL;
    }

  if (p4.th != NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Disconnecting from transport 4!\n");
      GNUNET_TRANSPORT_disconnect (p4.th);
      p4.th = NULL;
    }

  die_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Transports disconnected, returning success!\n");
  sleep(2);
  ok = 0;
}

static void
stop_arm (struct PeerContext *p)
{
#if START_ARM
  p->arm_pid = GNUNET_OS_start_process (NULL, NULL, "gnunet-arm",
                                        "gnunet-arm",
#if VERBOSE
                                        "-L", "DEBUG",
#endif
                                        "-c", p->cfg_file, "-e", "-q", NULL);

  GNUNET_OS_process_wait (p->arm_pid);
#endif
  GNUNET_CONFIGURATION_destroy (p->cfg);
}


static void
restart_transport (struct PeerContext *p)
{
#if START_ARM
  p->arm_pid = GNUNET_OS_start_process (NULL, NULL, "gnunet-arm",
                                        "gnunet-arm",
#if VERBOSE
                                        "-L", "DEBUG",
#endif
                                        "-c", p->cfg_file, "-k", "transport", "-q", NULL);

  GNUNET_OS_process_wait (p->arm_pid);
#endif

#if START_ARM
  p->arm_pid = GNUNET_OS_start_process (NULL, NULL, "gnunet-arm",
                                        "gnunet-arm",
#if VERBOSE
                                        "-L", "DEBUG",
#endif
                                        "-c", p->cfg_file, "-i", "transport", "-q", NULL);

  GNUNET_OS_process_wait (p->arm_pid);
#endif
}


static void
end_badly ()
{
  /* do work here */
#if VERBOSE
  fprintf(stderr, "Ending on an unhappy note.\n");
#endif

  if (p1.th != NULL)
    {
      GNUNET_TRANSPORT_disconnect (p1.th);
      p1.th = NULL;
    }

  if (p2.th != NULL)
    {
      GNUNET_TRANSPORT_disconnect (p2.th);
      p2.th = NULL;
    }

  if (p3.th != NULL)
    {
      GNUNET_TRANSPORT_disconnect (p3.th);
      p3.th = NULL;
    }

  if (p4.th != NULL)
    {
      GNUNET_TRANSPORT_disconnect (p4.th);
      p4.th = NULL;
    }
  sleep(2);
  ok = 1;
  return;
}

static void
notify_receive (void *cls,
                const struct GNUNET_PeerIdentity *peer,
                const struct GNUNET_MessageHeader *message,
                struct GNUNET_TIME_Relative latency,
		uint32_t distance)
{
  if (ntohs(message->type) != MTYPE)
    return;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received message of type %d from peer (%p) distance %d latency %u!\n",
                ntohs(message->type), cls, distance, latency.value);

  GNUNET_assert (MTYPE == ntohs (message->type));
  GNUNET_assert (sizeof (struct GNUNET_MessageHeader) ==
                 ntohs (message->size));
  num_received++;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received %d of %d messages.\n", num_received, num_wanted);

  if (num_wanted == num_received)
    {
      end ();
    }
}


static size_t
notify_ready (void *cls, size_t size, void *buf)
{
  struct GNUNET_MessageHeader *hdr;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Transmitting message to peer (%p) - %u!\n", cls, size);
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
notify_connect (void *cls,
                const struct GNUNET_PeerIdentity *peer,
                struct GNUNET_TIME_Relative latency,
		uint32_t distance)
{
  int peer_num = 0;
  int connect_num = 0;
  struct PeerContext *from_peer = cls;
  char *from_peer_str;

  if (cls == &p1)
    peer_num = 1;
  else if (cls == &p2)
    peer_num = 2;
  else if (cls == &p3)
    peer_num = 3;
  else if (cls == &p4)
    peer_num = 4;

  if (memcmp(peer, &p1.id, sizeof(struct GNUNET_PeerIdentity)) == 0)
    connect_num = 1;
  else if (memcmp(peer, &p2.id, sizeof(struct GNUNET_PeerIdentity)) == 0)
    connect_num = 2;
  else if (memcmp(peer, &p3.id, sizeof(struct GNUNET_PeerIdentity)) == 0)
    connect_num = 3;
  else if (memcmp(peer, &p4.id, sizeof(struct GNUNET_PeerIdentity)) == 0)
    connect_num = 4;
  else
    connect_num = -1;

  if ((cls == &p1) && (memcmp(peer, &p3.id, sizeof(struct GNUNET_PeerIdentity)) == 0))
    {
      GNUNET_TRANSPORT_notify_transmit_ready (p1.th,
					      &p3.id,
					      256, 0, TIMEOUT, &notify_ready,
					      &p1);
    }

  if ((cls == &p4) && (memcmp(peer, &p1.id, sizeof(struct GNUNET_PeerIdentity)) == 0))
    {

      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                 "Peer 4 notified about connection to peer 1, distance %u!\n", distance);

      GNUNET_TRANSPORT_notify_transmit_ready (p4.th,
                                              &p1.id,
                                              256, 0, TIMEOUT, &notify_ready,
                                              &p4);
    }

  GNUNET_asprintf(&from_peer_str, "%s", GNUNET_i2s(&from_peer->id));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Peer `%d' %4s connected to peer `%d' %4s distance %d!\n", peer_num, from_peer_str, connect_num, GNUNET_i2s(peer), distance);
}


static void
notify_disconnect (void *cls, const struct GNUNET_PeerIdentity *peer)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Peer `%4s' disconnected (%p)!\n",
	      GNUNET_i2s (peer), cls);
}


static void
setup_peer (struct PeerContext *p, const char *cfgname)
{
  p->cfg = GNUNET_CONFIGURATION_create ();
  p->cfg_file = strdup(cfgname);
#if START_ARM
  p->arm_pid = GNUNET_OS_start_process (NULL, NULL, "gnunet-arm",
                                        "gnunet-arm",
#if VERBOSE_ARM
                                        "-L", "DEBUG",
#endif
                                        "-c", cfgname, "-s", "-q", NULL);
#endif
  GNUNET_assert (GNUNET_OK == GNUNET_CONFIGURATION_load (p->cfg, cfgname));
}


static void blacklist_peer(struct GNUNET_DISK_FileHandle *file, struct PeerContext *peer)
{
  struct GNUNET_CRYPTO_HashAsciiEncoded peer_enc;
  char *buf;
  size_t size;

  GNUNET_CRYPTO_hash_to_enc(&peer->id.hashPubKey, &peer_enc);
  size = GNUNET_asprintf(&buf, "%s:%s\n", "tcp", (char *)&peer_enc);
  GNUNET_DISK_file_write(file, buf, size);
  GNUNET_free_non_null(buf);
}

static void
setup_blacklists (void *cls,
                  const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  char *blacklist_filename;
  struct GNUNET_DISK_FileHandle *file;
  int i;

  for (i = 1; i <= 4; i++)
    {
      GNUNET_asprintf(&blacklist_filename, "/tmp/test-gnunetd-transport-peer-%d/blacklist", i);
      if (blacklist_filename != NULL)
        {
          file = GNUNET_DISK_file_open(blacklist_filename, GNUNET_DISK_OPEN_WRITE | GNUNET_DISK_OPEN_TRUNCATE | GNUNET_DISK_OPEN_CREATE,
                                       GNUNET_DISK_PERM_USER_READ | GNUNET_DISK_PERM_USER_WRITE);
          GNUNET_free(blacklist_filename);

          if (file == NULL)
            {
              GNUNET_SCHEDULER_cancel(sched, die_task);
              GNUNET_SCHEDULER_add_now(sched, &end_badly, NULL);
              return;
            }
          switch (i)
          {
            case 1:
              blacklist_peer(file, &p3);
              blacklist_peer(file, &p4);
              break;
            case 2:
              blacklist_peer(file, &p4);
              break;
            case 3:
              blacklist_peer(file, &p1);
              break;
            case 4:
              blacklist_peer(file, &p1);
              blacklist_peer(file, &p2);
              break;
          }
        }
    }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Disconnecting transports...\n");

  if (p1.th != NULL)
    {
      GNUNET_TRANSPORT_disconnect (p1.th);
      p1.th = NULL;
    }

  if (p2.th != NULL)
    {
      GNUNET_TRANSPORT_disconnect (p2.th);
      p2.th = NULL;
    }

  if (p3.th != NULL)
    {
      GNUNET_TRANSPORT_disconnect (p3.th);
      p3.th = NULL;
    }

  if (p4.th != NULL)
    {
      GNUNET_TRANSPORT_disconnect (p4.th);
      p4.th = NULL;
    }

  sleep(1);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Restarting transport service (%p) with gnunet-arm -c %s -L DEBUG -k transport!\n", p1.arm_pid, p1.cfg_file);
  restart_transport(&p1);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Restarting transport service (%p) with gnunet-arm -c %s -L DEBUG -k transport!\n", p2.arm_pid, p2.cfg_file);
  restart_transport(&p2);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Restarting transport service (%p) with gnunet-arm -c %s -L DEBUG -k transport!\n", p3.arm_pid, p3.cfg_file);
  restart_transport(&p3);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Restarting transport service (%p) with gnunet-arm -c %s -L DEBUG -k transport!\n", p4.arm_pid, p4.cfg_file);
  restart_transport(&p4);

  p1.th = GNUNET_TRANSPORT_connect (sched, p1.cfg,
                                    &p1,
                                    &notify_receive,
                                    &notify_connect, &notify_disconnect);

  p2.th = GNUNET_TRANSPORT_connect (sched, p2.cfg,
                                    &p2,
                                    &notify_receive,
                                    &notify_connect, &notify_disconnect);

  p3.th = GNUNET_TRANSPORT_connect (sched, p3.cfg,
                                    &p3,
                                    &notify_receive,
                                    &notify_connect, &notify_disconnect);

  p4.th = GNUNET_TRANSPORT_connect (sched, p4.cfg,
                                    &p4,
                                    &notify_receive,
                                    &notify_connect, &notify_disconnect);
  GNUNET_assert(p1.th != NULL);
  GNUNET_assert(p2.th != NULL);
  GNUNET_assert(p3.th != NULL);
  GNUNET_assert(p4.th != NULL);

  GNUNET_TRANSPORT_offer_hello (p1.th, GNUNET_HELLO_get_header(p2.hello));
  GNUNET_TRANSPORT_offer_hello (p2.th, GNUNET_HELLO_get_header(p3.hello));
  GNUNET_TRANSPORT_offer_hello (p3.th, GNUNET_HELLO_get_header(p4.hello));

}


static void
get_hello_fourth (void *cls,
                const struct GNUNET_MessageHeader *message)
{
  struct PeerContext *me = cls;

  GNUNET_TRANSPORT_get_hello_cancel (me->th, &get_hello_fourth, me);

  GNUNET_assert (message != NULL);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_HELLO_get_id ((const struct GNUNET_HELLO_Message *)
                                      message, &me->id));

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received HELLO size %d\n", GNUNET_HELLO_size((const struct GNUNET_HELLO_Message *)message));

  me->hello = GNUNET_malloc(GNUNET_HELLO_size((const struct GNUNET_HELLO_Message *)message));
  memcpy(me->hello, message, GNUNET_HELLO_size((const struct GNUNET_HELLO_Message *)message));

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "All HELLO's received, setting up blacklists!\n");

  GNUNET_SCHEDULER_add_now(sched, &setup_blacklists, NULL);
}


static void
get_hello_third (void *cls,
                const struct GNUNET_MessageHeader *message)
{
  struct PeerContext *me = cls;

  GNUNET_TRANSPORT_get_hello_cancel (me->th, &get_hello_third, me);

  GNUNET_assert (message != NULL);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_HELLO_get_id ((const struct GNUNET_HELLO_Message *)
                                      message, &me->id));

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received HELLO size %d\n", GNUNET_HELLO_size((const struct GNUNET_HELLO_Message *)message));

  me->hello = GNUNET_malloc(GNUNET_HELLO_size((const struct GNUNET_HELLO_Message *)message));
  memcpy(me->hello, message, GNUNET_HELLO_size((const struct GNUNET_HELLO_Message *)message));

  GNUNET_TRANSPORT_get_hello (p4.th, &get_hello_fourth, &p4);
}


static void
get_hello_second (void *cls,
                const struct GNUNET_MessageHeader *message)
{
  struct PeerContext *me = cls;

  GNUNET_TRANSPORT_get_hello_cancel (me->th, &get_hello_second, me);

  GNUNET_assert (message != NULL);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_HELLO_get_id ((const struct GNUNET_HELLO_Message *)
                                      message, &me->id));

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received HELLO size %d\n", GNUNET_HELLO_size((const struct GNUNET_HELLO_Message *)message));

  me->hello = GNUNET_malloc(GNUNET_HELLO_size((const struct GNUNET_HELLO_Message *)message));
  memcpy(me->hello, message, GNUNET_HELLO_size((const struct GNUNET_HELLO_Message *)message));

  GNUNET_TRANSPORT_get_hello (p3.th, &get_hello_third, &p3);
}


static void
get_hello_first (void *cls,
                const struct GNUNET_MessageHeader *message)
{
  struct PeerContext *me = cls;

  GNUNET_TRANSPORT_get_hello_cancel (me->th, &get_hello_first, me);

  GNUNET_assert (message != NULL);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_HELLO_get_id ((const struct GNUNET_HELLO_Message *)
                                      message, &me->id));

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received HELLO size %d\n", GNUNET_HELLO_size((const struct GNUNET_HELLO_Message *)message));

  me->hello = GNUNET_malloc(GNUNET_HELLO_size((const struct GNUNET_HELLO_Message *)message));
  memcpy(me->hello, message, GNUNET_HELLO_size((const struct GNUNET_HELLO_Message *)message));

  GNUNET_TRANSPORT_get_hello (p2.th, &get_hello_second, &p2);
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
      GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MINUTES, 5), &end_badly, NULL);

  setup_peer (&p1, "test_transport_api_dv_peer1.conf");
  setup_peer (&p2, "test_transport_api_dv_peer2.conf");
  setup_peer (&p3, "test_transport_api_dv_peer3.conf");
  setup_peer (&p4, "test_transport_api_dv_peer4.conf");

  p1.th = GNUNET_TRANSPORT_connect (sched, p1.cfg,
                                    &p1,
                                    &notify_receive,
                                    &notify_connect, &notify_disconnect);

  p2.th = GNUNET_TRANSPORT_connect (sched, p2.cfg,
                                    &p2,
                                    &notify_receive,
                                    &notify_connect, &notify_disconnect);

  p3.th = GNUNET_TRANSPORT_connect (sched, p3.cfg,
                                    &p3,
                                    &notify_receive,
                                    &notify_connect, &notify_disconnect);

  p4.th = GNUNET_TRANSPORT_connect (sched, p4.cfg,
                                    &p4,
                                    &notify_receive,
                                    &notify_connect, &notify_disconnect);
  GNUNET_assert(p1.th != NULL);
  GNUNET_assert(p2.th != NULL);
  GNUNET_assert(p3.th != NULL);
  GNUNET_assert(p4.th != NULL);

  GNUNET_TRANSPORT_get_hello (p1.th, &get_hello_first, &p1);
}

static int
check ()
{

  char *const argv[] = { "test-transport-api",
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

  ok = 1;
  GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1,
                      argv, "test-transport-api", "nohelp",
                      options, &run, &ok);
  stop_arm (&p1);
  stop_arm (&p2);
  stop_arm (&p3);
  stop_arm (&p4);
  return ok;
}


int
main (int argc, char *argv[])
{
  int ret;
#ifdef MINGW
  return GNUNET_SYSERR;
#endif

  GNUNET_log_setup ("test-transport-api-dv",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);
  ret = check ();
  GNUNET_DISK_directory_remove ("/tmp/test-gnunetd-transport-peer-1");
  GNUNET_DISK_directory_remove ("/tmp/test-gnunetd-transport-peer-2");
  GNUNET_DISK_directory_remove ("/tmp/test-gnunetd-transport-peer-3");
  GNUNET_DISK_directory_remove ("/tmp/test-gnunetd-transport-peer-4");
  return ret;
}

/* end of test_transport_api_dv.c */

