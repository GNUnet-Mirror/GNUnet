/*
     This file is part of GNUnet.
     Copyright (C) 2011, 2017 GNUnet e.V.

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
 * @file src/nat/gnunet-nat-server.c
 * @brief Daemon to run on 'gnunet.org' to help test NAT traversal code
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_nat_service.h"
#include "gnunet_protocols.h"
#include "nat-auto.h"


/**
 * Information we track per client.
 */
struct ClientData
{
  /**
   * Timeout task.
   */
  struct GNUNET_SCHEDULER_Task *tt;

  /**
   * Client handle.
   */
  struct GNUNET_SERVICE_Client *client;
};


/**
 * Our configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;


/**
 * Try contacting the peer using autonomous NAT traveral method.
 *
 * @param dst_ipv4 IPv4 address to send the fake ICMP message
 * @param dport destination port to include in ICMP message
 * @param is_tcp mark for TCP (#GNUNET_YES)  or UDP (#GNUNET_NO)
 */
static void
try_anat (uint32_t dst_ipv4,
          uint16_t dport,
          int is_tcp)
{
  struct GNUNET_NAT_Handle *h;
  struct sockaddr_in lsa;
  struct sockaddr_in rsa;
  const struct sockaddr *sa;
  socklen_t sa_len;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Asking for connection reversal with %x and code %u\n",
              (unsigned int) dst_ipv4,
              (unsigned int) dport);
  memset (&lsa, 0, sizeof (lsa));
  lsa.sin_family = AF_INET;
#if HAVE_SOCKADDR_IN_SIN_LEN
  lsa.sin_len = sizeof (sa);
#endif
  lsa.sin_addr.s_addr = 0;
  lsa.sin_port = htons (dport);
  memset (&rsa, 0, sizeof (rsa));
  rsa.sin_family = AF_INET;
#if HAVE_SOCKADDR_IN_SIN_LEN
  rsa.sin_len = sizeof (sa);
#endif
  rsa.sin_addr.s_addr = dst_ipv4;
  rsa.sin_port = htons (dport);
  sa_len = sizeof (lsa);
  sa = (const struct sockaddr *) &lsa;
  h = GNUNET_NAT_register (cfg,
			   "none",
                           is_tcp ? IPPROTO_TCP : IPPROTO_UDP,
                           1,
			   &sa,
			   &sa_len,
                           NULL, NULL, NULL);
  GNUNET_NAT_request_reversal (h,
			       &lsa,
			       &rsa);
  GNUNET_NAT_unregister (h);
}


/**
 * Closure for #tcp_send.
 */
struct TcpContext
{
  /**
   * TCP  socket.
   */
  struct GNUNET_NETWORK_Handle *s;

  /**
   * Data to transmit.
   */
  uint16_t data;
};


/**
 * Task called by the scheduler once we can do the TCP send
 * (or once we failed to connect...).
 *
 * @param cls the `struct TcpContext`
 */
static void
tcp_send (void *cls)
{
  struct TcpContext *ctx = cls;
  const struct GNUNET_SCHEDULER_TaskContext *tc;

  tc = GNUNET_SCHEDULER_get_task_context ();
  if ((NULL != tc->write_ready) &&
      (GNUNET_NETWORK_fdset_isset (tc->write_ready, ctx->s)))
  {
    if (-1 ==
        GNUNET_NETWORK_socket_send (ctx->s, &ctx->data, sizeof (ctx->data)))
    {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_DEBUG, "send");
    }
    GNUNET_NETWORK_socket_shutdown (ctx->s, SHUT_RDWR);
  }
  GNUNET_NETWORK_socket_close (ctx->s);
  GNUNET_free (ctx);
}


/**
 * Try to send @a data to the
 * IP @a dst_ipv4' at port @a dport via TCP.
 *
 * @param dst_ipv4 target IP
 * @param dport target port
 * @param data data to send
 */
static void
try_send_tcp (uint32_t dst_ipv4,
              uint16_t dport,
              uint16_t data)
{
  struct GNUNET_NETWORK_Handle *s;
  struct sockaddr_in sa;
  struct TcpContext *ctx;

  s = GNUNET_NETWORK_socket_create (AF_INET,
                                    SOCK_STREAM,
                                    0);
  if (NULL == s)
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING,
                         "socket");
    return;
  }
  memset (&sa, 0, sizeof (sa));
  sa.sin_family = AF_INET;
#if HAVE_SOCKADDR_IN_SIN_LEN
  sa.sin_len = sizeof (sa);
#endif
  sa.sin_addr.s_addr = dst_ipv4;
  sa.sin_port = htons (dport);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending TCP message to `%s'\n",
              GNUNET_a2s ((struct sockaddr *) &sa,
                          sizeof (sa)));
  if ( (GNUNET_OK !=
        GNUNET_NETWORK_socket_connect (s,
                                       (const struct sockaddr *) &sa,
                                       sizeof (sa))) &&
       (errno != EINPROGRESS) )
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING,
                         "connect");
    GNUNET_NETWORK_socket_close (s);
    return;
  }
  ctx = GNUNET_new (struct TcpContext);
  ctx->s = s;
  ctx->data = data;
  GNUNET_SCHEDULER_add_write_net (GNUNET_TIME_UNIT_SECONDS,
                                  s,
                                  &tcp_send,
                                  ctx);
}


/**
 * Try to send @a data to the
 * IP @a dst_ipv4 at port @a dport via UDP.
 *
 * @param dst_ipv4 target IP
 * @param dport target port
 * @param data data to send
 */
static void
try_send_udp (uint32_t dst_ipv4,
              uint16_t dport,
              uint16_t data)
{
  struct GNUNET_NETWORK_Handle *s;
  struct sockaddr_in sa;

  s = GNUNET_NETWORK_socket_create (AF_INET,
                                    SOCK_DGRAM,
                                    0);
  if (NULL == s)
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING,
                         "socket");
    return;
  }
  memset (&sa, 0, sizeof (sa));
  sa.sin_family = AF_INET;
#if HAVE_SOCKADDR_IN_SIN_LEN
  sa.sin_len = sizeof (sa);
#endif
  sa.sin_addr.s_addr = dst_ipv4;
  sa.sin_port = htons (dport);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending UDP packet to `%s'\n",
              GNUNET_a2s ((struct sockaddr *) &sa,
                          sizeof (sa)));
  if (-1 ==
      GNUNET_NETWORK_socket_sendto (s,
                                    &data,
                                    sizeof (data),
                                    (const struct sockaddr *) &sa,
                                    sizeof (sa)))
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING,
                         "sendto");
  GNUNET_NETWORK_socket_close (s);
}


/**
 * We've received a request to probe a NAT
 * traversal. Do it.
 *
 * @param cls handle to client (we always close)
 * @param msg message with details about what to test
 */
static void
handle_test (void *cls,
             const struct GNUNET_NAT_AUTO_TestMessage *tm)
{
  struct ClientData *cd = cls;
  uint16_t dport;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received test request\n");
  dport = ntohs (tm->dport);
  if (0 == dport)
    try_anat (tm->dst_ipv4,
              ntohs (tm->data),
              (int) ntohl (tm->is_tcp));
  else if (GNUNET_YES == ntohl (tm->is_tcp))
    try_send_tcp (tm->dst_ipv4,
                  dport,
                  tm->data);
  else
    try_send_udp (tm->dst_ipv4,
                  dport,
                  tm->data);
  GNUNET_SERVICE_client_drop (cd->client);
}


/**
 * Main function that will be run.
 *
 * @param cls closure
 * @param c configuration
 * @param srv service handle
 */
static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *c,
     struct GNUNET_SERVICE_Handle *srv)
{
  cfg = c;
}


/**
 * Forcefully drops client after 1s.
 *
 * @param cls our `struct ClientData` of a client to drop
 */
static void
force_timeout (void *cls)
{
  struct ClientData *cd = cls;

  cd->tt = NULL;
  GNUNET_SERVICE_client_drop (cd->client);
}



/**
 * Callback called when a client connects to the service.
 *
 * @param cls closure for the service
 * @param c the new client that connected to the service
 * @param mq the message queue used to send messages to the client
 * @return our `struct ClientData`
 */
static void *
client_connect_cb (void *cls,
		   struct GNUNET_SERVICE_Client *c,
		   struct GNUNET_MQ_Handle *mq)
{
  struct ClientData *cd;

  cd = GNUNET_new (struct ClientData);
  cd->client = c;
  cd->tt = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
                                         &force_timeout,
                                         cd);
  return cd;
}


/**
 * Callback called when a client disconnected from the service
 *
 * @param cls closure for the service
 * @param c the client that disconnected
 * @param internal_cls our `struct ClientData`
 */
static void
client_disconnect_cb (void *cls,
		      struct GNUNET_SERVICE_Client *c,
		      void *internal_cls)
{
  struct ClientData *cd = internal_cls;

  if (NULL != cd->tt)
    GNUNET_SCHEDULER_cancel (cd->tt);
  GNUNET_free (cd);
}


/**
 * Define "main" method using service macro.
 */
GNUNET_SERVICE_MAIN
("nat-server",
 GNUNET_SERVICE_OPTION_NONE,
 &run,
 &client_connect_cb,
 &client_disconnect_cb,
 NULL,
 GNUNET_MQ_hd_fixed_size (test,
			  GNUNET_MESSAGE_TYPE_NAT_TEST,
			  struct GNUNET_NAT_AUTO_TestMessage,
			  NULL),
 GNUNET_MQ_handler_end ());


#if defined(LINUX) && defined(__GLIBC__)
#include <malloc.h>

/**
 * MINIMIZE heap size (way below 128k) since this process doesn't need much.
 */
void __attribute__ ((constructor))
GNUNET_ARM_memory_init ()
{
  mallopt (M_TRIM_THRESHOLD, 4 * 1024);
  mallopt (M_TOP_PAD, 1 * 1024);
  malloc_trim (0);
}
#endif




/* end of gnunet-nat-server.c */
