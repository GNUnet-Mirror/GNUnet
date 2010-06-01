/*
     This file is part of GNUnet.
     (C) 2010 Christian Grothoff (and other contributing authors)

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
 * @file transport/test_plugin_transport_http.c
 * @brief testcase for plugin_transport_http.c
 * @author Matthias Wachs
 */

#include "platform.h"
#include "gnunet_constants.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_hello_lib.h"
#include "gnunet_os_lib.h"
#include "gnunet_peerinfo_service.h"
#include "gnunet_plugin_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_program_lib.h"
#include "gnunet_signatures.h"
#include "gnunet_service_lib.h"
#include "plugin_transport.h"
#include "gnunet_statistics_service.h"
#include "transport.h"
#include <curl/curl.h>

#define VERBOSE GNUNET_NO
#define DEBUG GNUNET_NO
#define DEBUG_CURL GNUNET_NO

#define PLUGIN libgnunet_plugin_transport_template

/**
 * How long until we give up on transmitting the message?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 90)

/**
 * How long until we give up on transmitting the message?
 */
#define TEST_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10)

/**
 * How long between recieve and send?
 */
#define WAIT_INTERVALL GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 1)

/**
 *  Message to send using http
 */
struct HTTP_Message
{
  char *buf;
  size_t pos;
  size_t size;
  size_t len;
};

/**
 * Our public key.
 */
/* static struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded my_public_key; */

/**
 * Our public key.
 */
static struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded my_public_key;

/**
 * Our identity.
 */
static struct GNUNET_PeerIdentity my_identity;

/**
 * Our private key.
 */
static struct GNUNET_CRYPTO_RsaPrivateKey *my_private_key;


/**
 * Our scheduler.
 */
struct GNUNET_SCHEDULER_Handle *sched;

/**
 * Our statistics handle.
 */
struct GNUNET_STATISTICS_Handle *stats;


/**
 * Our configuration.
 */
const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Number of neighbours we'd like to have.
 */
static uint32_t max_connect_per_transport;

/**
 * Environment for this plugin.
 */
static struct GNUNET_TRANSPORT_PluginEnvironment env;

/**
 *handle for the api provided by this plugin
 */
static struct GNUNET_TRANSPORT_PluginFunctions *api;

/**
 * ID of the task controlling the testcase timeout
 */
static GNUNET_SCHEDULER_TaskIdentifier ti_timeout;

static GNUNET_SCHEDULER_TaskIdentifier ti_send;

const struct GNUNET_PeerIdentity * p;

/**
 *  Struct for plugin addresses
 */
struct Plugin_Address
{
  /**
   * Next field for linked list
   */
  struct Plugin_Address * next;

  /**
   * buffer containing data to send
   */
  void * addr;

  /**
   * amount of data to sent
   */
  size_t addrlen;
};

/**
 *  Struct for plugin addresses
 */
struct HTTP_Transfer
{
  /**
   * HTTP Header result for transfer
   */
  unsigned int http_result_code;

  /**
   * amount of bytes we recieved
   */
  size_t data_size;

  unsigned char buf[2048];

  /**
   * amount of bytes we recieved
   */
  size_t pos;

  size_t size;

  unsigned int test_failed;

};

struct Plugin_Address * addr_head;

/**
 * Did the test pass or fail?
 */
static int fail_notify_address;
/**
 * Did the test pass or fail?
 */
static int fail_notify_address_count;

/**
 * Did the test pass or fail?
 */
static int fail_pretty_printer;

/**
 * Did the test pass or fail?
 */
static int fail_pretty_printer_count;

/**
 * Did the test pass or fail?
 */
static int fail_addr_to_str;

/**
 * Did the test pass or fail?
 */
static struct HTTP_Transfer testtransfer_no_ident;



/**
 * Did the test pass or fail?
 */
static int fail;

/**
 * Recieved message already returned to sender?
 */
static int sent;

CURL *curl_handle;

/**
 * cURL Multihandle
 */
static CURLM *multi_handle;

/**
 * Test message to send
 */
struct HTTP_Message * msg;

/**
 * The task sending data
 */
static GNUNET_SCHEDULER_TaskIdentifier http_task_send;

/**
 * Shutdown testcase
 */
static void
shutdown_clean ()
{
  if ((fail_notify_address == GNUNET_NO) && (fail_pretty_printer == GNUNET_NO) && (fail_addr_to_str == GNUNET_NO) && (testtransfer_no_ident.test_failed == GNUNET_NO))
    fail = 0;
  else
    fail = 1;

  curl_multi_cleanup(multi_handle);

  if (NULL != curl_handle)
    curl_easy_cleanup (curl_handle);


  if (ti_send != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel(sched,ti_send);
    ti_send = GNUNET_SCHEDULER_NO_TASK;
  }

  if (http_task_send != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel(sched,http_task_send);
    http_task_send = GNUNET_SCHEDULER_NO_TASK;
  }

  if (ti_timeout != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel(sched,ti_timeout);
    ti_timeout = GNUNET_SCHEDULER_NO_TASK;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Unloading http plugin\n");
  GNUNET_assert (NULL == GNUNET_PLUGIN_unload ("libgnunet_plugin_transport_http", api));

  GNUNET_SCHEDULER_shutdown(sched);

  GNUNET_free(msg->buf);
  GNUNET_free(msg);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Exiting testcase\n");
  exit(fail);
  return;
}

/**
 * Continuation called after plugin send message
 * @cls closure
 * @target target
 * @result GNUNET_OK or GNUNET_SYSERR
 */
static void task_send_cont (void *cls,
                            const struct GNUNET_PeerIdentity * target,
                            int result)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Message was sent!\n");
  fail = GNUNET_NO;
  shutdown_clean();
}

/**
 * Task sending recieved message back to peer
 * @cls closure
 * @tc task context
 */
static void
task_send (void *cls,
            const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  ti_timeout = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;

  if (GNUNET_YES==sent)
    return;

  struct GNUNET_MessageHeader * msg = cls;
  unsigned int len = ntohs(msg->size);
  const char * msgc = (const char *) msg;

  api->send(api->cls, p, msgc, len, 0, TIMEOUT, NULL,NULL, 0, GNUNET_NO, &task_send_cont, NULL);
  sent = GNUNET_YES;

}

/**
 * Recieves messages from plugin, in real world transport
 */
static struct GNUNET_TIME_Relative
receive (void *cls,
         const struct GNUNET_PeerIdentity * peer,
         const struct GNUNET_MessageHeader * message,
         uint32_t distance,
         struct Session *session,
         const char *sender_address,
         uint16_t sender_address_len)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Testcase recieved new message from peer `%s' with type %u and length %u\n",  GNUNET_i2s(peer),ntohs(message->type),ntohs(message->size));

  /* take recieved message and send it back to peer */
  p = peer;
  void * c = (void *) message;
  ti_send =GNUNET_SCHEDULER_add_delayed (sched, WAIT_INTERVALL, &task_send, c);

  return GNUNET_TIME_UNIT_ZERO;
}

 int done;
static size_t
putBuffer (void *stream, size_t size, size_t nmemb, void *ptr)
{
  unsigned int len;
  struct HTTP_Message  * cbc = ptr;

  len = cbc->len;

  if (( cbc->pos == len) && (len < (size * nmemb)))
    return 0;
  memcpy(stream, cbc->buf, len);
  cbc->pos = len;
  return len;
}

static size_t copyBuffer (void *ptr, size_t size, size_t nmemb, void *ctx)
{
  struct HTTP_Transfer * res = (struct HTTP_Transfer *) ctx;

  res->data_size = size * nmemb;

  if (res->pos + size * nmemb > res->size)
    return 0;                   /* overflow */
  memcpy (&res->buf[res->pos], ptr, size * nmemb);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Send completed. %s\n",res->buf);
  res->pos += size * nmemb;
  return size * nmemb;
}

static size_t header_function( void *ptr, size_t size, size_t nmemb, void *stream)
{
  struct HTTP_Transfer * res = (struct HTTP_Transfer *) stream;
  char * tmp;
  unsigned int len = size * nmemb;

  tmp = GNUNET_malloc (  len+1 );
  memcpy(tmp,ptr,len);
  if (tmp[len-2] == 13)
    tmp[len-2]= '\0';
  if (0==strcmp (tmp,"HTTP/1.1 404 Not Found"))
    {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "404\n");
    res->http_result_code=404;
    }

  GNUNET_free (tmp);
  return size * nmemb;
}

static size_t send_prepare( struct HTTP_Transfer * result);

static void send_execute (void *cls,
             const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct HTTP_Transfer *res;

  int running;
  struct CURLMsg *msg;
  CURLMcode mret;

  res = (struct HTTP_Transfer *) cls;
  http_task_send = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;

  do
    {
      running = 0;
      mret = curl_multi_perform (multi_handle, &running);
      if (running == 0)
        {
          do
            {

              msg = curl_multi_info_read (multi_handle, &running);
              GNUNET_break (msg != NULL);
              if (msg == NULL)
                break;
              /* get session for affected curl handle */
              //cs = find_session_by_curlhandle (msg->easy_handle);
              //GNUNET_assert ( cs != NULL );
              switch (msg->msg)
                {

                case CURLMSG_DONE:
                  if ( (msg->data.result != CURLE_OK) &&
                       (msg->data.result != CURLE_GOT_NOTHING) )
                    {

                    GNUNET_log(GNUNET_ERROR_TYPE_INFO,
                               _("curl failed for `%s' at %s:%d: `%s'\n"),
                               "curl_multi_perform",
                               __FILE__,
                               __LINE__,
                               curl_easy_strerror (msg->data.result));
                    /* sending msg failed*/
                    }
                  else
                    {
                    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Send completed with code %u\n", res->data_size);
                    /* sending completed */
                    }
                  if ( (cls == &testtransfer_no_ident) && (res->http_result_code==404) && (res->data_size==208))
                      res->test_failed = GNUNET_NO;

                  curl_easy_cleanup(curl_handle);
                  curl_handle=NULL;
                  shutdown_clean();
                  return;
                default:
                  break;
                }

            }
          while ( (running > 0) );
        }
    }
  while (mret == CURLM_CALL_MULTI_PERFORM);
  send_prepare(cls);
}

/**
 * Function setting up file descriptors and scheduling task to run
 * @param ses session to send data to
 * @return bytes sent to peer
 */
static size_t send_prepare( struct HTTP_Transfer * result)
{
  fd_set rs;
  fd_set ws;
  fd_set es;
  int max;
  struct GNUNET_NETWORK_FDSet *grs;
  struct GNUNET_NETWORK_FDSet *gws;
  long to;
  CURLMcode mret;

  max = -1;
  FD_ZERO (&rs);
  FD_ZERO (&ws);
  FD_ZERO (&es);
  mret = curl_multi_fdset (multi_handle, &rs, &ws, &es, &max);
  if (mret != CURLM_OK)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("%s failed at %s:%d: `%s'\n"),
                  "curl_multi_fdset", __FILE__, __LINE__,
                  curl_multi_strerror (mret));
      return -1;
    }
  mret = curl_multi_timeout (multi_handle, &to);
  if (mret != CURLM_OK)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("%s failed at %s:%d: `%s'\n"),
                  "curl_multi_timeout", __FILE__, __LINE__,
                  curl_multi_strerror (mret));
      return -1;
    }

  grs = GNUNET_NETWORK_fdset_create ();
  gws = GNUNET_NETWORK_fdset_create ();
  GNUNET_NETWORK_fdset_copy_native (grs, &rs, max + 1);
  GNUNET_NETWORK_fdset_copy_native (gws, &ws, max + 1);
  http_task_send = GNUNET_SCHEDULER_add_select (sched,
                                   GNUNET_SCHEDULER_PRIORITY_DEFAULT,
                                   GNUNET_SCHEDULER_NO_TASK,
                                   GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 0),
                                   grs,
                                   gws,
                                   &send_execute,
                                   result);
  GNUNET_NETWORK_fdset_destroy (gws);
  GNUNET_NETWORK_fdset_destroy (grs);

  /* FIXME: return bytes REALLY sent */
  return 0;
}

/**
 * function to send data to server
 */
static int send_data(struct HTTP_Message *msg, struct HTTP_Transfer * result, char * url)
{

  curl_handle = curl_easy_init();
  if( NULL == curl_handle)
  {
    printf("easy_init failed \n");
    return GNUNET_SYSERR;
  }
#if DEBUG_CURL
  curl_easy_setopt(curl_handle, CURLOPT_VERBOSE, 1L);
#endif
  curl_easy_setopt(curl_handle, CURLOPT_URL, url);
  curl_easy_setopt(curl_handle, CURLOPT_PUT, 1L);
  curl_easy_setopt (curl_handle, CURLOPT_HEADERFUNCTION, &header_function);
  curl_easy_setopt (curl_handle, CURLOPT_WRITEHEADER, result);
  curl_easy_setopt (curl_handle, CURLOPT_WRITEFUNCTION, &copyBuffer);
  curl_easy_setopt (curl_handle, CURLOPT_WRITEDATA, result);
  curl_easy_setopt (curl_handle, CURLOPT_READFUNCTION, &putBuffer);
  curl_easy_setopt (curl_handle, CURLOPT_READDATA, msg);
  curl_easy_setopt(curl_handle, CURLOPT_INFILESIZE_LARGE, (curl_off_t) msg->len);
  curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT, 30);
  curl_easy_setopt(curl_handle, CURLOPT_CONNECTTIMEOUT, 20);

  curl_multi_add_handle(multi_handle, curl_handle);

  send_prepare(result);

  return GNUNET_OK;
}

/**
 * Network format for IPv4 addresses.
 */
struct IPv4HttpAddress
{
  /**
   * IPv4 address, in network byte order.
   */
  uint32_t ipv4_addr;

  /**
   * Port number, in network byte order.
   */
  uint16_t u_port;

};


/**
 * Network format for IPv6 addresses.
 */
struct IPv6HttpAddress
{
  /**
   * IPv6 address.
   */
  struct in6_addr ipv6_addr;

  /**
   * Port number, in network byte order.
   */
  uint16_t u6_port;

};

/**
 * Plugin notifies transport (aka testcase) about its addresses
 */
void
notify_address (void *cls,
                const char *name,
                const void *addr,
                uint16_t addrlen,
                struct GNUNET_TIME_Relative expires)
{
  char address[INET6_ADDRSTRLEN];
  unsigned int port;
  struct Plugin_Address * pl_addr;
  struct Plugin_Address * cur;

  if (addrlen == (sizeof (struct IPv4HttpAddress)))
    {
      inet_ntop(AF_INET, (struct in_addr *) addr,address,INET_ADDRSTRLEN);
      port = ntohs(((struct IPv4HttpAddress *) addr)->u_port);
    }
  if (addrlen == (sizeof (struct IPv6HttpAddress)))
    {
      inet_ntop(AF_INET6, (struct in6_addr *) addr,address,INET6_ADDRSTRLEN);
      port = ntohs(((struct IPv6HttpAddress *) addr)->u6_port);
    }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      _("Transport plugin notification for address: `%s':%u\n"),
	      address,
	      port);
  pl_addr = GNUNET_malloc (sizeof (struct Plugin_Address) );
  pl_addr->addrlen = addrlen;
  pl_addr->addr = GNUNET_malloc(addrlen);
  memcpy(pl_addr->addr,addr,addrlen);
  pl_addr->next = NULL;

  if ( NULL == addr_head)
    {
      addr_head = pl_addr;
    }
  else
    {
      cur = addr_head;
      while (NULL != cur->next)
	{
	  cur = cur->next;
	}
      cur->next = pl_addr;
    }
  fail_notify_address_count++;
  fail_notify_address = GNUNET_NO;
}

/**
 * Setup plugin environment
 */
static void
setup_plugin_environment ()
{
  env.cfg = cfg;
  env.sched = sched;
  env.stats = stats;
  env.my_identity = &my_identity;
  env.cls = &env;
  env.receive = &receive;
  env.notify_address = &notify_address;
  env.max_connections = max_connect_per_transport;
}


/**
 * Task shutting down testcase if it a timeout occurs
 */
static void
task_timeout (void *cls,
            const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  ti_timeout = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Testcase timeout\n");
  fail = GNUNET_YES;
  shutdown_clean();
  return;
}

static void pretty_printer_cb (void *cls,
                               const char *address)
{
  if (NULL==address)
    return;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Plugin returned pretty address: `%s'\n",address);
  fail_pretty_printer_count++;
}


/**
 * Runs the test.
 *
 * @param cls closure
 * @param s scheduler to use
 * @param c configuration to use
 */
static void
run (void *cls,
     struct GNUNET_SCHEDULER_Handle *s,
     char *const *args,
     const char *cfgfile, const struct GNUNET_CONFIGURATION_Handle *c)
{
  char * libname;
  sched = s;
  cfg = c;
  char *keyfile;
  unsigned long long tneigh;
  struct Plugin_Address * cur;
  struct Plugin_Address * tmp;
  const char * addr_str;
  unsigned int count_str_addr;
  unsigned int suggest_res;
  unsigned int res;

  fail_pretty_printer = GNUNET_YES;
  fail_notify_address = GNUNET_YES;
  fail_addr_to_str = GNUNET_YES;

  addr_head = NULL;
  count_str_addr = 0;
  /* parse configuration */
  if ((GNUNET_OK !=
       GNUNET_CONFIGURATION_get_value_number (c,
                                              "TRANSPORT",
                                              "NEIGHBOUR_LIMIT",
                                              &tneigh)) ||
      (GNUNET_OK !=
       GNUNET_CONFIGURATION_get_value_filename (c,
                                                "GNUNETD",
                                                "HOSTKEY", &keyfile)))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _
                  ("Transport service is lacking key configuration settings.  Exiting.\n"));
      GNUNET_SCHEDULER_shutdown (s);
      fail = 1;
      return;
    }
  max_connect_per_transport = (uint32_t) tneigh;
  my_private_key = GNUNET_CRYPTO_rsa_key_create_from_file (keyfile);
  GNUNET_free (keyfile);
  if (my_private_key == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("Transport service could not access hostkey.  Exiting.\n"));
      GNUNET_SCHEDULER_shutdown (s);
      fail = 1;
      return;
    }
  GNUNET_CRYPTO_rsa_key_get_public (my_private_key, &my_public_key);
  GNUNET_CRYPTO_hash (&my_public_key,
                      sizeof (my_public_key), &my_identity.hashPubKey);

  /* load plugins... */
  setup_plugin_environment ();
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Loading HTTP transport plugin `%s'\n"),"libgnunet_plugin_transport_http");
  GNUNET_asprintf (&libname, "libgnunet_plugin_transport_http");
  api = GNUNET_PLUGIN_load (libname, &env);
  GNUNET_free (libname);
  if (api == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Failed to load transport plugin for http\n"));
    fail = 1;
    return;
  }

  ti_timeout = GNUNET_SCHEDULER_add_delayed (sched, TEST_TIMEOUT, &task_timeout, NULL);

  /* testing plugin functionality */
  GNUNET_assert (0!=fail_notify_address_count);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Transport plugin returned %u addresses to connect to\n"),  fail_notify_address_count);

  /* testing pretty printer with all addresses obtained from the plugin*/
  while (addr_head != NULL)
  {
    cur = addr_head;

    api->address_pretty_printer (NULL,"http",cur->addr,cur->addrlen,GNUNET_NO,TEST_TIMEOUT,&pretty_printer_cb,NULL);
    addr_str = api->address_to_string (NULL,cur->addr,cur->addrlen);
    suggest_res = api->check_address (NULL,cur->addr,cur->addrlen);

    GNUNET_assert (GNUNET_OK == suggest_res);
    GNUNET_assert (NULL != addr_str);
    count_str_addr++;

    tmp = addr_head->next;
    GNUNET_free (addr_head->addr);
    GNUNET_free (addr_head);
    GNUNET_free ((char *) addr_str);
    addr_head=tmp;
  }
  GNUNET_assert (fail_pretty_printer_count==fail_notify_address_count);
  GNUNET_assert (fail_pretty_printer_count==count_str_addr);
  fail_pretty_printer=GNUNET_NO;
  fail_addr_to_str=GNUNET_NO;

  /* Suggesting addresses with wrong port*/
  struct IPv4HttpAddress failing_addr;
  failing_addr.ipv4_addr = INADDR_LOOPBACK;
  failing_addr.u_port = 0;
  suggest_res = api->check_address (NULL,&failing_addr,sizeof (struct IPv4HttpAddress));
  GNUNET_assert (GNUNET_SYSERR == suggest_res);

  /* Suggesting addresses with wrong size*/
  failing_addr.ipv4_addr = INADDR_LOOPBACK;
  failing_addr.u_port = 0;
  suggest_res = api->check_address (NULL,&failing_addr,sizeof (struct IPv6HttpAddress));
  GNUNET_assert (GNUNET_SYSERR == suggest_res);

  /* Suggesting addresses with wrong address*/
  failing_addr.ipv4_addr = 0;
  failing_addr.u_port = 12389;
  suggest_res = api->check_address (NULL,&failing_addr,sizeof (struct IPv4HttpAddress));
  GNUNET_assert (GNUNET_SYSERR == suggest_res);

  /* test sending to client */
  multi_handle = curl_multi_init();

  /*building messages */
  msg = GNUNET_malloc (sizeof (struct HTTP_Message));
  msg->size = 2048;
  msg->pos = 0;
  msg->buf = GNUNET_malloc (2048);
  testtransfer_no_ident.size=2048;
  testtransfer_no_ident.test_failed = GNUNET_YES;

  /* Connecting to peer without identification */
  res = send_data (msg, &testtransfer_no_ident, "http://localhost:12389/");

  /* Add more tests */

  /* testing finished */
  return;
}


/**
 * The main function for the transport service.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{

  static struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  int ret;
  char *const argv_prog[] = {
    "test_plugin_transport_http",
    "-c",
    "test_plugin_transport_data_http.conf",
    "-L",
#if VERBOSE
    "DEBUG",
#else
    "WARNING",
#endif
    NULL
  };
  GNUNET_log_setup ("test_plugin_transport_http",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);

  ret = (GNUNET_OK ==
         GNUNET_PROGRAM_run (5,
                             argv_prog,
                             "test_plugin_transport_http",
                             "testcase", options, &run, NULL)) ? GNUNET_NO : GNUNET_YES;

    GNUNET_DISK_directory_remove ("/tmp/test_plugin_transport_http");

  return fail;
}

/* end of test_plugin_transport_http.c */
