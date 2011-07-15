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
#include "gauger.h"
#include "transport.h"
#include "transport-testing.h"

#define VERBOSE GNUNET_NO

#define VERBOSE_ARM GNUNET_NO

#define START_ARM GNUNET_YES

/**
 * Note that this value must not significantly exceed
 * 'MAX_PENDING' in 'gnunet-service-transport.c', otherwise
 * messages may be dropped even for a reliable transport.
 */
#define TOTAL_MSGS (1024 * 2)

/**
 * How long until we give up on transmitting the message?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 1500)

#define MTYPE 12345

static struct PeerContext p1;

static struct PeerContext p2;

static int ok;

static int is_tcp;

static int is_tcp_nat;

static int is_http;

static int is_https;

static int is_udp;

static int is_unix;

static int is_wlan;

static int connected;

static int test_failed;

static unsigned long long total_bytes;

static struct GNUNET_TIME_Absolute start_time;

static GNUNET_SCHEDULER_TaskIdentifier die_task;

static GNUNET_SCHEDULER_TaskIdentifier tct;

struct GNUNET_TRANSPORT_TransmitHandle * th_p2;

static char * key_file_p1;
static char * cert_file_p1;

static char * key_file_p2;
static char * cert_file_p2;
static char *test_name;
static int msg_scheduled;
static int msg_sent;
static int msg_recv_expected;
static int msg_recv;

static int p1_hello_canceled;
static int p2_hello_canceled;

#if VERBOSE
#define OKPP do { ok++; fprintf (stderr, "Now at stage %u at %s:%u\n", ok, __FILE__, __LINE__); } while (0)
#else
#define OKPP do { ok++; } while (0)
#endif


static void
end ()
{
  unsigned long long delta;
  char *value_name;

  if (die_task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (die_task);
  die_task = GNUNET_SCHEDULER_NO_TASK;
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Disconnecting from transports!\n");
#endif

  if (th_p2 != NULL)
    GNUNET_TRANSPORT_notify_transmit_ready_cancel(th_p2);
  th_p2 = NULL;

  GNUNET_TRANSPORT_disconnect (p1.th);
  GNUNET_TRANSPORT_disconnect (p2.th);
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Transports disconnected, returning success!\n");
#endif
  delta = GNUNET_TIME_absolute_get_duration (start_time).rel_value;
  fprintf (stderr,
	   "\nThroughput was %llu kb/s\n",
	   total_bytes * 1000 / 1024 / delta);
  GNUNET_asprintf(&value_name, "reliable_%s", test_name);
  GAUGER ("TRANSPORT", value_name, (int)(total_bytes * 1000 / 1024 /delta), "kb/s");
  GNUNET_free(value_name);
  ok = 0;

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
  if (test_failed == GNUNET_NO)
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Testcase timeout\n");
    else
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "Reliability failed: Last message sent %u, Next message scheduled %u, Last message received %u, Message expected %u\n",
              msg_sent,
              msg_scheduled,
              msg_recv,
              msg_recv_expected);
  if (th_p2 != NULL)
    GNUNET_TRANSPORT_notify_transmit_ready_cancel(th_p2);
  th_p2 = NULL;

  GNUNET_break (0);
  GNUNET_TRANSPORT_disconnect (p1.th);
  GNUNET_TRANSPORT_disconnect (p2.th);
  if (GNUNET_SCHEDULER_NO_TASK != tct)
    {
      GNUNET_SCHEDULER_cancel (tct);
      tct = GNUNET_SCHEDULER_NO_TASK;
    }
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

  ret = (iter * iter * iter);
  return sizeof (struct TestMessage) + (ret % 60000);
}


static void
notify_receive (void *cls,
                const struct GNUNET_PeerIdentity *peer,
                const struct GNUNET_MessageHeader *message,
                const struct GNUNET_TRANSPORT_ATS_Information *ats,
                uint32_t ats_count)
{
  static int n;
  unsigned int s;
  char cbuf[GNUNET_SERVER_MAX_MESSAGE_SIZE - 1];
  const struct TestMessage *hdr;

  hdr = (const struct TestMessage*) message;
  s = get_size (n);
  if (MTYPE != ntohs (message->type))
    return;
  msg_recv_expected = n;
  msg_recv = ntohl(hdr->num);
  if (ntohs (message->size) != s)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  "Expected message %u of size %u, got %u bytes of message %u\n",
		  n, s,
		  ntohs (message->size),
		  ntohl (hdr->num));
      if (die_task != GNUNET_SCHEDULER_NO_TASK)
        GNUNET_SCHEDULER_cancel (die_task);
      test_failed = GNUNET_YES;
      die_task = GNUNET_SCHEDULER_add_now (&end_badly, NULL);
      return;
    }
  if (ntohl (hdr->num) != n)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  "Expected message %u of size %u, got %u bytes of message %u\n",
		  n, s,
		  ntohs (message->size),
		  ntohl (hdr->num));
      if (die_task != GNUNET_SCHEDULER_NO_TASK)
        GNUNET_SCHEDULER_cancel (die_task);
      test_failed = GNUNET_YES;
      die_task = GNUNET_SCHEDULER_add_now (&end_badly, NULL);
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
      if (die_task != GNUNET_SCHEDULER_NO_TASK)
        GNUNET_SCHEDULER_cancel (die_task);
      test_failed = GNUNET_YES;
      die_task = GNUNET_SCHEDULER_add_now (&end_badly, NULL);
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
      if (die_task != GNUNET_SCHEDULER_NO_TASK)
        GNUNET_SCHEDULER_cancel (die_task);
      die_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT,
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
  th_p2 = NULL;
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
      msg_sent = n;
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
  {
    if (th_p2 == NULL)
      th_p2 = GNUNET_TRANSPORT_notify_transmit_ready (p2.th,
					    &p1.id,
					    s, 0, TIMEOUT,
					    &notify_ready,
					    NULL);
    msg_scheduled = n;
  }
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
notify_disconnect (void *cls, const struct GNUNET_PeerIdentity *peer)
{
  connected--;
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Peer `%4s' disconnected (%p)!\n",
	      GNUNET_i2s (peer), cls);
#endif
  if (th_p2 != NULL)
    {
      GNUNET_TRANSPORT_notify_transmit_ready_cancel(th_p2);
      th_p2 = NULL;
    }
}


static void
exchange_hello_last (void *cls,
                     const struct GNUNET_MessageHeader *message)
{
  struct PeerContext *me = cls;

  GNUNET_assert (message != NULL);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Exchanging HELLO of size %d with peer (%s)!\n", 
	      (int) GNUNET_HELLO_size((const struct GNUNET_HELLO_Message *)message),
	      GNUNET_i2s (&me->id));
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
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Exchanging HELLO of size %d from peer %s!\n", 
	      (int) GNUNET_HELLO_size((const struct GNUNET_HELLO_Message *)message),
	      GNUNET_i2s (&me->id));
  GNUNET_TRANSPORT_offer_hello (p2.th, message, NULL, NULL);
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
  connected++;
  if (cls == &p1)
    {
      GNUNET_TRANSPORT_set_quota (p1.th,
				  &p2.id,
				  GNUNET_BANDWIDTH_value_init (1024 * 1024 * 1024),
				  GNUNET_BANDWIDTH_value_init (1024 * 1024 * 1024));
      start_time = GNUNET_TIME_absolute_get ();
    }
  else
    {
      GNUNET_TRANSPORT_set_quota (p2.th,
				  &p1.id,
				  GNUNET_BANDWIDTH_value_init (1024 * 1024 * 1024),
				  GNUNET_BANDWIDTH_value_init (1024 * 1024 * 1024));
    }
  if (2 == connected)
    {
      if (die_task != GNUNET_SCHEDULER_NO_TASK)
        GNUNET_SCHEDULER_cancel (die_task);
      if (tct != GNUNET_SCHEDULER_NO_TASK)
        GNUNET_SCHEDULER_cancel (tct);
      tct = GNUNET_SCHEDULER_NO_TASK;
      if (p2_hello_canceled == GNUNET_NO)
      {
        GNUNET_TRANSPORT_get_hello_cancel (p2.th, &exchange_hello_last, &p2);
        p2_hello_canceled = GNUNET_YES;
      }
      if (p1_hello_canceled == GNUNET_NO)
      {
        GNUNET_TRANSPORT_get_hello_cancel (p1.th, &exchange_hello, &p1);
        p1_hello_canceled = GNUNET_YES;
      }
      die_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT,
					       &end_badly, NULL);
      th_p2 = GNUNET_TRANSPORT_notify_transmit_ready (p2.th,
                                              &p1.id,
                                              get_size (0), 0, TIMEOUT,
                                              &notify_ready,
                                              NULL);
      
    }
}


static void
setup_peer (struct PeerContext *p, const char *cfgname)
{
  p->cfg = GNUNET_CONFIGURATION_create ();
  GNUNET_assert (GNUNET_OK == GNUNET_CONFIGURATION_load (p->cfg, cfgname));
  if (GNUNET_CONFIGURATION_have_value (p->cfg,"PATHS", "SERVICEHOME"))
      GNUNET_CONFIGURATION_get_value_string (p->cfg, "PATHS", "SERVICEHOME", &p->servicehome);
  GNUNET_DISK_directory_remove (p->servicehome);

#if START_ARM
  p->arm_proc = GNUNET_OS_start_process (NULL, NULL,
					"gnunet-service-arm",
                                        "gnunet-service-arm",
#if VERBOSE_ARM
                                        "-L", "DEBUG",
#endif
                                        "-c", cfgname, NULL);
#endif

  if (is_https)
    {
      struct stat sbuf;
      if (p==&p1)
	{
	  if (GNUNET_CONFIGURATION_have_value (p->cfg,
					       "transport-https", "KEY_FILE"))
	    GNUNET_CONFIGURATION_get_value_string (p->cfg, "transport-https", "KEY_FILE", &key_file_p1);
	  if (key_file_p1 == NULL)
	    GNUNET_asprintf(&key_file_p1,"https_p1.key");
	  if (0 == stat (key_file_p1, &sbuf ))
	    {
	      if (0 == remove(key_file_p1))
		GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
			    "Successfully removed existing private key file `%s'\n",
			    key_file_p1);
	      else
		GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
			    "Failed to remove private key file `%s'\n",
			    key_file_p1);
	    }
	  if (GNUNET_CONFIGURATION_have_value (p->cfg,"transport-https", "CERT_FILE"))
	    GNUNET_CONFIGURATION_get_value_string (p->cfg, "transport-https", "CERT_FILE", &cert_file_p1);
	  if (cert_file_p1 == NULL)
	    GNUNET_asprintf(&cert_file_p1,"https_p1.cert");
	  if (0 == stat (cert_file_p1, &sbuf ))
	    {
	      if (0 == remove(cert_file_p1))
		GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
			    "Successfully removed existing certificate file `%s'\n",
			    cert_file_p1);
	      else
		GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
			    "Failed to remove existing certificate file `%s'\n",
			    cert_file_p1);
	    }
	}
      else if (p==&p2)
	{
	  if (GNUNET_CONFIGURATION_have_value (p->cfg,
					       "transport-https", "KEY_FILE"))
	    GNUNET_CONFIGURATION_get_value_string (p->cfg, "transport-https", "KEY_FILE", &key_file_p2);
	  if (key_file_p2 == NULL)
	    GNUNET_asprintf(&key_file_p2,"https_p2.key");
	  if (0 == stat (key_file_p2, &sbuf ))
	    {
	      if (0 == remove(key_file_p2))
		GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
			    "Successfully removed existing private key file `%s'\n",
			    key_file_p2);
	      else
		GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
			    "Failed to remove private key file `%s'\n",
			    key_file_p2);
	    }
	  if (GNUNET_CONFIGURATION_have_value (p->cfg,"transport-https", "CERT_FILE"))
	    GNUNET_CONFIGURATION_get_value_string (p->cfg, "transport-https", "CERT_FILE", &cert_file_p2);
	  if (cert_file_p2 == NULL)
	    GNUNET_asprintf(&cert_file_p2,"https_p2.cert");
	  if (0 == stat (cert_file_p2, &sbuf ))
	    {
	      if (0 == remove(cert_file_p2))
		GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
			    "Successfully removed existing certificate file `%s'\n",
			    cert_file_p2);
	      else
		GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
			    "Failed to remove existing certificate file `%s'\n",
			    cert_file_p2);
	    }
	}
    }
  p->th = GNUNET_TRANSPORT_connect (p->cfg, NULL,
                                    p,
                                    &notify_receive,
                                    &notify_connect,
				    &notify_disconnect);
  GNUNET_assert (p->th != NULL);
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


static void
try_connect (void *cls,
	     const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Asking peers to connect...\n");
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
  else if (is_https)
    {
      setup_peer (&p1, "test_transport_api_rel_https_peer1.conf");
      setup_peer (&p2, "test_transport_api_rel_https_peer2.conf");
    }
  else if (is_udp)
    {
      setup_peer (&p1, "test_transport_api_udp_peer1.conf");
      setup_peer (&p2, "test_transport_api_udp_peer2.conf");
    }
  else if (is_unix)
    {
      setup_peer (&p1, "test_transport_api_unix_peer1.conf");
      setup_peer (&p2, "test_transport_api_unix_peer2.conf");
    }
  else if (is_tcp_nat)
    {
      setup_peer (&p1, "test_transport_api_tcp_nat_peer1.conf");
      setup_peer (&p2, "test_transport_api_tcp_nat_peer2.conf");
    }
  else if (is_wlan)
    {
      setup_peer (&p1, "test_transport_api_wlan_peer1.conf");
      setup_peer (&p2, "test_transport_api_wlan_peer2.conf");
    }
  else
    GNUNET_assert (0);
  GNUNET_assert(p1.th != NULL);
  GNUNET_assert(p2.th != NULL);
  GNUNET_TRANSPORT_get_hello (p1.th, &exchange_hello, &p1);
  p1_hello_canceled = GNUNET_NO;
  GNUNET_TRANSPORT_get_hello (p2.th, &exchange_hello_last, &p2);
  p2_hello_canceled = GNUNET_NO;
  tct = GNUNET_SCHEDULER_add_now (&try_connect, NULL);
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

  if ((GNUNET_YES == is_tcp_nat) && (check_gnunet_nat_binary("gnunet-nat-server") != GNUNET_YES))
    {
      GNUNET_log(GNUNET_ERROR_TYPE_WARNING,
		 "Not running NAT test case, binaries not properly installed.\n");
      return 0;
    }

  GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1,
                      argv, "test-transport-api-reliability", "nohelp",
                      options, &run, &ok);
  stop_arm (&p1);
  stop_arm (&p2);

  if (is_https)
  {
    struct stat sbuf;
    if (0 == stat (cert_file_p1, &sbuf ))
    {
      if (0 == remove(cert_file_p1))
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
		    "Successfully removed existing certificate file `%s'\n",
		    cert_file_p1);
      else
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR, 
		    "Failed to remove certfile `%s'\n",
		    cert_file_p1);
    }

    if (0 == stat (key_file_p1, &sbuf ))
    {
      if (0 == remove(key_file_p1))
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
		    "Successfully removed private key file `%s'\n",
		    key_file_p1);
      else
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR, 
		    "Failed to private key file `%s'\n",key_file_p1);
    }

    if (0 == stat (cert_file_p2, &sbuf ))
    {
      if (0 == remove(cert_file_p2))
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
		    "Successfully removed existing certificate file `%s'\n",
		    cert_file_p2);
      else
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR, 
		    "Failed to remove certfile `%s'\n",cert_file_p2);
    }

    if (0 == stat (key_file_p2, &sbuf ))
    {
      if (0 == remove(key_file_p2))
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
		    "Successfully removed private key file `%s'\n",
		    key_file_p2);
      else
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR, 
		    "Failed to private key file `%s'\n",
		    key_file_p2);
    }
    GNUNET_free(key_file_p1);
    GNUNET_free(key_file_p2);
    GNUNET_free(cert_file_p1);
    GNUNET_free(cert_file_p2);
    GNUNET_free(p1.servicehome);
    GNUNET_free(p2.servicehome);
  }

  return ok;
}


int
main (int argc, char *argv[])
{
  int ret;

  test_failed = GNUNET_NO;

  if (strstr(argv[0], "tcp_nat") != NULL)
    {
      is_tcp_nat = GNUNET_YES;
      GNUNET_asprintf(&test_name, "tcp_nat");
    }
  else if (strstr(argv[0], "tcp") != NULL)
    {
      is_tcp = GNUNET_YES;
      GNUNET_asprintf(&test_name, "tcp");
    }
  else if (strstr(argv[0], "https") != NULL)
    {
      is_https = GNUNET_YES;
      GNUNET_asprintf(&test_name, "https");
    }
  else if (strstr(argv[0], "http") != NULL)
    {
      is_http = GNUNET_YES;
      GNUNET_asprintf(&test_name, "http");
    }
  else if (strstr(argv[0], "udp") != NULL)
    {
      is_udp = GNUNET_YES;
      GNUNET_asprintf(&test_name, "udp");
    }
  else if (strstr(argv[0], "unix") != NULL)
    {
      is_unix = GNUNET_YES;
      GNUNET_asprintf(&test_name, "unix");
    }
  else if (strstr(argv[0], "wlan") != NULL)
    {
       is_wlan = GNUNET_YES;
    }
  GNUNET_log_setup ("test-transport-api-reliability",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);
  ret = check ();
  GNUNET_DISK_directory_remove (p1.servicehome);
  GNUNET_DISK_directory_remove (p2.servicehome);
  return ret;
}

/* end of test_transport_api_reliability.c */
