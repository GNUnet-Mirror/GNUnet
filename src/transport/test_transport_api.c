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
 * @file transport/test_transport_api.c
 * @brief base test case for transport implementations
 *
 * This test case serves as a base for tcp, udp, and udp-nat
 * transport test cases.  Based on the executable being run
 * the correct test case will be performed.  Conservation of
 * C code apparently.
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

#define VERBOSE GNUNET_NO

#define VERBOSE_ARM GNUNET_NO

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

static  GNUNET_SCHEDULER_TaskIdentifier die_task;

struct PeerContext * p1;

struct PeerContext * p2;

struct GNUNET_TRANSPORT_TransmitHandle * th;

char * cfg_file_p1;

char * cfg_file_p2;

#if VERBOSE
#define OKPP do { ok++; fprintf (stderr, "Now at stage %u at %s:%u\n", ok, __FILE__, __LINE__); } while (0)
#else
#define OKPP do { ok++; } while (0)
#endif


static void
end ()
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Stopping peers\n");

  if (die_task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel(die_task);

  GNUNET_TRANSPORT_TESTING_stop_peer(p1);
  GNUNET_TRANSPORT_TESTING_stop_peer(p2);

  ok = 0;
}

static void
end_badly ()
{
  die_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Fail! Stopping peers\n");

  if (p1 != NULL)
    GNUNET_TRANSPORT_TESTING_stop_peer(p1);
  if (p2 != NULL)
    GNUNET_TRANSPORT_TESTING_stop_peer(p2);

  ok = GNUNET_SYSERR;
}


static void
notify_receive (void *cls,
                const struct GNUNET_PeerIdentity *peer,
                const struct GNUNET_MessageHeader *message,
                const struct GNUNET_TRANSPORT_ATS_Information *ats,
                uint32_t ats_count)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Received message of type %d from peer %s!\n",
	      ntohs(message->type), 
	      GNUNET_i2s (peer));

  GNUNET_assert (MTYPE == ntohs (message->type));
  GNUNET_assert (sizeof (struct GNUNET_MessageHeader) ==
                 ntohs (message->size));
  end ();
}


static size_t
notify_ready (void *cls, size_t size, void *buf)
{
  struct PeerContext *p = cls;
  struct GNUNET_MessageHeader *hdr;

  th = NULL;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Transmitting message with %u bytes to peer %s\n", 
	      sizeof (struct GNUNET_MessageHeader),
	      GNUNET_i2s (&p->id));
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
                const struct GNUNET_TRANSPORT_ATS_Information *ats,
                uint32_t ats_count)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Peer `%4s' connected to us (%p)!\n", 
	      GNUNET_i2s (peer), 
	      cls);
}


static void
notify_disconnect (void *cls,
		   const struct GNUNET_PeerIdentity *peer)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Peer `%4s' disconnected (%p)!\n",
	      GNUNET_i2s (peer), cls);
}

static void
sendtask ()
{
  th = GNUNET_TRANSPORT_notify_transmit_ready (p1->th,
                                              &p2->id,
                                              256, 0, TIMEOUT, &notify_ready,
                                              &p1);
}

static void
testing_connect_cb (struct PeerContext * p1, struct PeerContext * p2, void *cls)
{
  char * p1_c = strdup (GNUNET_i2s(&p1->id));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Peers connected: %s <-> %s\n",
       p1_c,
       GNUNET_i2s (&p2->id));

  // FIXME: THIS IS REQUIRED! SEEMS TO BE A BUG!
  GNUNET_SCHEDULER_add_delayed(GNUNET_TIME_UNIT_SECONDS, &sendtask, NULL);
}

static void
run (void *cls,
     char *const *args,
     const char *cfgfile, const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  die_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT,
					   &end_badly, NULL);

  p1 = GNUNET_TRANSPORT_TESTING_start_peer(cfg_file_p1,
      &notify_receive,
      &notify_connect,
      &notify_disconnect,
      NULL);
  p2 = GNUNET_TRANSPORT_TESTING_start_peer(cfg_file_p2,
      &notify_receive,
      &notify_connect,
      &notify_disconnect,
      NULL);

  GNUNET_TRANSPORT_TESTING_connect_peers(p1, p2, &testing_connect_cb, NULL);
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
  setTransportOptions("test_transport_api_data.conf");
#endif
  ok = 1;
  GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1,
                      argv, "test-transport-api", "nohelp",
                      options, &run, &ok);

  return ok;
}

/**
 * Return the actual path to a file found in the current
 * PATH environment variable.
 *
 * @param binary the name of the file to find
 */
static char *
get_path_from_PATH (char *binary)
{
  char *path;
  char *pos;
  char *end;
  char *buf;
  const char *p;

  p = getenv ("PATH");
  if (p == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("PATH environment variable is unset.\n"));
      return NULL;
    }
  path = GNUNET_strdup (p);     /* because we write on it */
  buf = GNUNET_malloc (strlen (path) + 20);
  pos = path;

  while (NULL != (end = strchr (pos, PATH_SEPARATOR)))
    {
      *end = '\0';
      sprintf (buf, "%s/%s", pos, binary);
      if (GNUNET_DISK_file_test (buf) == GNUNET_YES)
        {
          GNUNET_free (path);
          return buf;
        }
      pos = end + 1;
    }
  sprintf (buf, "%s/%s", pos, binary);
  if (GNUNET_DISK_file_test (buf) == GNUNET_YES)
    {
      GNUNET_free (path);
      return buf;
    }
  GNUNET_free (buf);
  GNUNET_free (path);
  return NULL;
}

/**
 * Check whether the suid bit is set on a file.
 * Attempts to find the file using the current
 * PATH environment variable as a search path.
 *
 * @param binary the name of the file to check
 *
 * @return GNUNET_YES if the binary is found and
 *         can be run properly, GNUNET_NO otherwise
 */
static int
check_gnunet_nat_binary(char *binary)
{
  struct stat statbuf;
  char *p;
#ifdef MINGW
  SOCKET rawsock;
#endif

#ifdef MINGW
  char *binaryexe;
  GNUNET_asprintf (&binaryexe, "%s.exe", binary);
  p = get_path_from_PATH (binaryexe);
  free (binaryexe);
#else
  p = get_path_from_PATH (binary);
#endif
  if (p == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("Could not find binary `%s' in PATH!\n"),
                  binary);
      return GNUNET_NO;
    }
  if (0 != STAT (p, &statbuf))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _("stat (%s) failed: %s\n"),
                  p,
                  STRERROR (errno));
      GNUNET_free (p);
      return GNUNET_SYSERR;
    }
  GNUNET_free (p);
#ifndef MINGW
  if ( (0 != (statbuf.st_mode & S_ISUID)) &&
       (statbuf.st_uid == 0) )
    return GNUNET_YES;
  return GNUNET_NO;
#else
  rawsock = socket (AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (INVALID_SOCKET == rawsock)
    {
      DWORD err = GetLastError ();
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "socket (AF_INET, SOCK_RAW, IPPROTO_ICMP) have failed! GLE = %d\n", err);
      return GNUNET_NO; /* not running as administrator */
    }
  closesocket (rawsock);
  return GNUNET_YES;
#endif
}

int
main (int argc, char *argv[])
{
  int ret;

  GNUNET_log_setup ("test-transport-api",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);

  char * pch = strdup(argv[0]);
  char * filename = NULL;
  char *dotexe;

  /* get executable filename */
  pch = strtok (pch,"/");
  while (pch != NULL)
  {
    pch = strtok (NULL, "/");
    if (pch != NULL)
      filename = pch;
  }

  /* remove "lt-" */

  filename = strstr(filename, "tes");
  if (NULL != (dotexe = strstr (filename, ".exe")))
    dotexe[0] = '\0';

  //filename = &filename[1];
  //GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
  //            "`%s'\n",filename);
  /* create cfg filename */
  GNUNET_asprintf(&cfg_file_p1, "%s_peer1.conf",filename);
  GNUNET_asprintf(&cfg_file_p2, "%s_peer2.conf", filename);

  if (strstr(argv[0], "tcp_nat") != NULL)
    {
      if (GNUNET_YES != check_gnunet_nat_binary("gnunet-nat-server"))
        {
          GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                      "`%s' not properly installed, cannot run NAT test!\n",
                      "gnunet-nat-server");
          return 0;
        }
    }
  else if (strstr(argv[0], "udp_nat") != NULL)
    {
      if (GNUNET_YES != check_gnunet_nat_binary("gnunet-nat-server"))
        {
          GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                      "`%s' not properly installed, cannot run NAT test!\n",
		      "gnunet-nat-server");
          return 0;
        }
    }

  ret = check ();

  GNUNET_free (cfg_file_p1);
  GNUNET_free (cfg_file_p2);

  return ret;
}

/* end of test_transport_api.c */
