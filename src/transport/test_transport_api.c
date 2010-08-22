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

static int is_udp;

static int is_udp_nat;

static int is_http;

static int is_https;

static  GNUNET_SCHEDULER_TaskIdentifier die_task;

static char * key_file_p1;
static char * cert_file_p1;

static char * key_file_p2;
static char * cert_file_p2;

#if VERBOSE
#define OKPP do { ok++; fprintf (stderr, "Now at stage %u at %s:%u\n", ok, __FILE__, __LINE__); } while (0)
#else
#define OKPP do { ok++; } while (0)
#endif


static void
end ()
{
  /* do work here */
  GNUNET_assert (ok == 6);
  GNUNET_SCHEDULER_cancel (sched, die_task);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Disconnecting from transports!\n");
  GNUNET_TRANSPORT_disconnect (p1.th);
  GNUNET_TRANSPORT_disconnect (p2.th);

  die_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Transports disconnected, returning success!\n");
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
end_badly ()
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Disconnecting from transports!\n");
  GNUNET_break (0);
  GNUNET_TRANSPORT_disconnect (p1.th);
  GNUNET_TRANSPORT_disconnect (p2.th);
  ok = 1;
}

static void
notify_receive (void *cls,
                const struct GNUNET_PeerIdentity *peer,
                const struct GNUNET_MessageHeader *message,
                struct GNUNET_TIME_Relative latency,
		uint32_t distance)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "ok is (%d)!\n",
              ok);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received message of type %d from peer (%p)!\n",
                ntohs(message->type), cls);

  GNUNET_assert (ok == 5);
  OKPP;

  GNUNET_assert (MTYPE == ntohs (message->type));
  GNUNET_assert (sizeof (struct GNUNET_MessageHeader) ==
                 ntohs (message->size));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received message from peer (%p)!\n",
              cls);
  end ();
}


static size_t
notify_ready (void *cls, size_t size, void *buf)
{
  struct GNUNET_MessageHeader *hdr;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Transmitting message to peer (%p) - %u!\n", cls, sizeof (struct GNUNET_MessageHeader));
  GNUNET_assert (size >= 256);
  GNUNET_assert (ok == 4);
  OKPP;

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
  if (cls == &p1)
    {
      GNUNET_SCHEDULER_cancel (sched, die_task);
      die_task = GNUNET_SCHEDULER_add_delayed (sched,
					       TIMEOUT_TRANSMIT,
					       &end_badly, NULL);

      GNUNET_TRANSPORT_notify_transmit_ready (p1.th,
					      &p2.id,
					      256, 0, TIMEOUT, &notify_ready,
					      &p1);
    }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Peer `%4s' connected to us (%p)!\n", GNUNET_i2s (peer), cls);
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
#if START_ARM
  p->arm_pid = GNUNET_OS_start_process (NULL, NULL, "gnunet-service-arm",
                                        "gnunet-service-arm",
#if VERBOSE_ARM
                                        "-L", "DEBUG",
#endif
                                        "-c", cfgname, NULL);
#endif
  GNUNET_assert (GNUNET_OK == GNUNET_CONFIGURATION_load (p->cfg, cfgname));

  if (is_https)
  {
	  struct stat sbuf;
	  if (p==&p1)
	  {
		  if (GNUNET_CONFIGURATION_have_value (p->cfg,
				  	  	  	  	  	  	  	   "transport-https", "KEY_FILE"))
				GNUNET_CONFIGURATION_get_value_string (p->cfg, "transport-https", "KEY_FILE", &key_file_p1);
		  else
			  GNUNET_asprintf(&key_file_p1,"https.key");
		  if (0 == stat (key_file_p1, &sbuf ))
		  {
			  if (0 == remove(key_file_p1))
			      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Successfully removed existing private key file `%s'\n",key_file_p1);
			  else
				  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Failed to remove private key file `%s'\n",key_file_p1);
		  }
		  if (GNUNET_CONFIGURATION_have_value (p->cfg,"transport-https", "CERT_FILE"))
			  GNUNET_CONFIGURATION_get_value_string (p->cfg, "transport-https", "CERT_FILE", &cert_file_p1);
		  else
			  GNUNET_asprintf(&cert_file_p1,"https.cert");
		  if (0 == stat (cert_file_p1, &sbuf ))
		  {
			  if (0 == remove(cert_file_p1))
			      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Successfully removed existing certificate file `%s'\n",cert_file_p1);
			  else
				  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Failed to remove existing certificate file `%s'\n",cert_file_p1);
		  }
	  }
	  else if (p==&p2)
	  {
		  if (GNUNET_CONFIGURATION_have_value (p->cfg,
				  	  	  	  	  	  	  	   "transport-https", "KEY_FILE"))
				GNUNET_CONFIGURATION_get_value_string (p->cfg, "transport-https", "KEY_FILE", &key_file_p2);
		  else
			  GNUNET_asprintf(&key_file_p2,"https.key");
		  if (0 == stat (key_file_p2, &sbuf ))
		  {
			  if (0 == remove(key_file_p2))
			      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Successfully removed existing private key file `%s'\n",key_file_p2);
			  else
				  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Failed to remove private key file `%s'\n",key_file_p2);
		  }
		  if (GNUNET_CONFIGURATION_have_value (p->cfg,"transport-https", "CERT_FILE"))
			  GNUNET_CONFIGURATION_get_value_string (p->cfg, "transport-https", "CERT_FILE", &cert_file_p2);
		  else
			  GNUNET_asprintf(&cert_file_p2,"https.cert");
		  if (0 == stat (cert_file_p2, &sbuf ))
		  {
			  if (0 == remove(cert_file_p2))
			      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Successfully removed existing certificate file `%s'\n",cert_file_p2);
			  else
				  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Failed to remove existing certificate file `%s'\n",cert_file_p2);
		  }
	  }
  }

  p->th = GNUNET_TRANSPORT_connect (sched, p->cfg,
                                    NULL, p,
                                    &notify_receive,
                                    &notify_connect, &notify_disconnect);
  GNUNET_assert (p->th != NULL);
}


static void
exchange_hello_last (void *cls,
                     const struct GNUNET_MessageHeader *message)
{
  struct PeerContext *me = cls;

  GNUNET_TRANSPORT_get_hello_cancel (p2.th, &exchange_hello_last, me);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Exchanging HELLO with peer (%p)!\n", cls);
  GNUNET_assert (ok >= 3);
  OKPP;
  GNUNET_assert (message != NULL);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_HELLO_get_id ((const struct GNUNET_HELLO_Message *)
                                      message, &me->id));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Finished exchanging HELLOs, now waiting for transmission!\n");
}

static void
exchange_hello (void *cls,
                const struct GNUNET_MessageHeader *message)
{
  struct PeerContext *me = cls;

  GNUNET_TRANSPORT_get_hello_cancel (p1.th, &exchange_hello, me);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Exchanging HELLO with peer (%p)!\n", cls);
  GNUNET_assert (ok >= 2);
  OKPP;
  GNUNET_assert (message != NULL);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_HELLO_get_id ((const struct GNUNET_HELLO_Message *)
                                      message, &me->id));

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received HELLO size %d\n", GNUNET_HELLO_size((const struct GNUNET_HELLO_Message *)message));

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
					   &end_badly, NULL);

  if (is_udp)
    {
      setup_peer (&p1, "test_transport_api_udp_peer1.conf");
      setup_peer (&p2, "test_transport_api_udp_peer2.conf");
    }
  else if (is_tcp)
    {
      setup_peer (&p1, "test_transport_api_tcp_peer1.conf");
      setup_peer (&p2, "test_transport_api_tcp_peer2.conf");
    }
  else if (is_tcp_nat)
    {
      setup_peer (&p1, "test_transport_api_tcp_nat_peer1.conf");
      setup_peer (&p2, "test_transport_api_tcp_nat_peer2.conf");
    }
  else if (is_udp_nat)
    {
      setup_peer (&p1, "test_transport_api_udp_nat_peer1.conf");
      setup_peer (&p2, "test_transport_api_udp_nat_peer2.conf");
    }
  else if (is_http)
    {
      setup_peer (&p1, "test_transport_api_http_peer1.conf");
      setup_peer (&p2, "test_transport_api_http_peer2.conf");
    }
  else if (is_https)
	{
	  setup_peer (&p1, "test_transport_api_https_peer1.conf");
	  setup_peer (&p2, "test_transport_api_https_peer2.conf");
	}
  GNUNET_assert(p1.th != NULL);
  GNUNET_assert(p2.th != NULL);

  GNUNET_TRANSPORT_get_hello (p1.th, &exchange_hello, &p1);
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
  stop_arm (&p1);
  stop_arm (&p2);

  if (is_https)
  {
	  struct stat sbuf;
	  if (0 == stat (cert_file_p1, &sbuf ))
	  {
		  if (0 == remove(cert_file_p1))
			  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Successfully removed existing certificate file `%s'\n",cert_file_p1);
		  else
			  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Failed to remove certfile `%s'\n",cert_file_p1);
	  }

	  if (0 == stat (key_file_p1, &sbuf ))
	  {
		  if (0 == remove(key_file_p1))
			  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Successfully removed private key file `%s'\n",key_file_p1);
		  else
			  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Failed to private key file `%s'\n",key_file_p1);
	  }

	  if (0 == stat (cert_file_p2, &sbuf ))
	  {
		  if (0 == remove(cert_file_p2))
			  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Successfully removed existing certificate file `%s'\n",cert_file_p2);
		  else
			  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Failed to remove certfile `%s'\n",cert_file_p2);
	  }

	  if (0 == stat (key_file_p2, &sbuf ))
	  {
		  if (0 == remove(key_file_p2))
			  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Successfully removed private key file `%s'\n",key_file_p2);
		  else
			  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Failed to private key file `%s'\n",key_file_p2);
	  }
	  GNUNET_free(key_file_p1);
	  GNUNET_free(key_file_p2);
	  GNUNET_free(cert_file_p1);
	  GNUNET_free(cert_file_p2);
  }
  return ok;
}


static char *
get_path_from_PATH ()
{
  char *path;
  char *pos;
  char *end;
  char *buf;
  const char *p;

  p = getenv ("PATH");
  if (p == NULL)
    return NULL;
  path = GNUNET_strdup (p);     /* because we write on it */
  buf = GNUNET_malloc (strlen (path) + 20);
  pos = path;

  while (NULL != (end = strchr (pos, ':')))
    {
      *end = '\0';
      sprintf (buf, "%s/%s", pos, "gnunet-nat-server");
      if (GNUNET_DISK_file_test (buf) == GNUNET_YES)
        {
          GNUNET_free (path);
          return buf;
        }
      pos = end + 1;
    }
  sprintf (buf, "%s/%s", pos, "gnunet-nat-server");
  GNUNET_free (path);
  if (GNUNET_DISK_file_test (buf) == GNUNET_YES)
    return buf;
  GNUNET_free (buf);
  return NULL;
}


static int
check_gnunet_nat_server()
{
  struct stat statbuf;
  char *p;

  p = get_path_from_PATH ();
  if (p == NULL)
    return GNUNET_NO;
  if (0 != STAT (p, &statbuf))
    {
      GNUNET_free (p);
      return GNUNET_SYSERR;
    }
  GNUNET_free (p);
  if ( (0 != (statbuf.st_mode & S_ISUID)) &&
       (statbuf.st_uid == 0) )
    return GNUNET_YES;
  return GNUNET_NO;
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
      if (check_gnunet_nat_server() != GNUNET_OK)
        {
          GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                      "`%s' not properly installed, cannot run NAT test!\n",
                      "gnunet-nat-server");
          return 0;
        }
    }
  else if (strstr(argv[0], "tcp") != NULL)
    {
      is_tcp = GNUNET_YES;
    }
  else if (strstr(argv[0], "udp_nat") != NULL)
    {
      is_udp_nat = GNUNET_YES;
      if (check_gnunet_nat_server() != GNUNET_OK)
        {
          GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                      "`%s' not properly installed, cannot run NAT test!\n",
		      "gnunet-nat-server");
          return 0;
        }
    }
  else if (strstr(argv[0], "udp") != NULL)
    {
      is_udp = GNUNET_YES;
    }
  else if (strstr(argv[0], "https") != NULL)
    {
      is_https = GNUNET_YES;
    }
  else if (strstr(argv[0], "http") != NULL)
    {
      is_http = GNUNET_YES;
    }

  GNUNET_log_setup ("test-transport-api",
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

/* end of test_transport_api.c */
