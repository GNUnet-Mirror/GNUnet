/*
     This file is part of GNUnet.
     (C) 2011 Christian Grothoff (and other contributing authors)

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
 * @file src/nat/gnunet-nat-server.c
 * @brief Daemon to run on 'gnunet.org' to help test NAT traversal code
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_nat_lib.h"
#include "gnunet_protocols.h"
#include "nat.h"


/**
 * Our server.
 */
static struct GNUNET_SERVER_Handle *server;

/**
 * Our configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;


/**
 * Try contacting the peer using autonomous
 * NAT traveral method.
 *
 * @param dst_ipv4 IPv4 address to send the fake ICMP message
 * @param dport destination port to include in ICMP message
 * @param is_tcp mark for TCP (GNUNET_YES)  or UDP (GNUNET_NO)
 */
static void
try_anat (uint32_t dst_ipv4, uint16_t dport, int is_tcp)
{
  struct GNUNET_NAT_Handle *h;
  struct sockaddr_in sa;

#if DEBUG_NAT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Asking for connection reversal with %x and code %u\n",
              (unsigned int) dst_ipv4, (unsigned int) dport);
#endif
  h = GNUNET_NAT_register (cfg, is_tcp, dport, 0, NULL, NULL, NULL, NULL, NULL);
  memset (&sa, 0, sizeof (sa));
  sa.sin_family = AF_INET;
#if HAVE_SOCKADDR_IN_SIN_LEN
  sa.sin_len = sizeof (sa);
#endif
  sa.sin_addr.s_addr = dst_ipv4;
  GNUNET_NAT_run_client (h, &sa);
  GNUNET_NAT_unregister (h);
}


/**
 * Closure for 'tcp_send'.
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
 * @param cls the 'struct TcpContext'
 * @param tc scheduler context
 */
static void
tcp_send (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct TcpContext *ctx = cls;

  if ((NULL != tc->write_ready) &&
      (GNUNET_NETWORK_fdset_isset (tc->write_ready, ctx->s)))
  {
    if (-1 ==
        GNUNET_NETWORK_socket_send (ctx->s, &ctx->data, sizeof (ctx->data)))
    {
#if DEBUG_NAT
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_DEBUG, "send");
#endif
    }
    GNUNET_NETWORK_socket_shutdown (ctx->s, SHUT_RDWR);
  }
  GNUNET_NETWORK_socket_close (ctx->s);
  GNUNET_free (ctx);
}


/**
 * Try to send 'data' to the
 * IP 'dst_ipv4' at port 'dport' via TCP.
 *
 * @param dst_ipv4 target IP
 * @param dport target port
 * @param data data to send
 */
static void
try_send_tcp (uint32_t dst_ipv4, uint16_t dport, uint16_t data)
{
  struct GNUNET_NETWORK_Handle *s;
  struct sockaddr_in sa;
  struct TcpContext *ctx;

  s = GNUNET_NETWORK_socket_create (AF_INET, SOCK_STREAM, 0);
  if (NULL == s)
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "socket");
    return;
  }
  memset (&sa, 0, sizeof (sa));
  sa.sin_family = AF_INET;
#if HAVE_SOCKADDR_IN_SIN_LEN
  sa.sin_len = sizeof (sa);
#endif
  sa.sin_addr.s_addr = dst_ipv4;
  sa.sin_port = htons (dport);
#if DEBUG_NAT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending TCP message to `%s'\n",
              GNUNET_a2s ((struct sockaddr *) &sa, sizeof (sa)));
#endif
  if ((GNUNET_OK !=
       GNUNET_NETWORK_socket_connect (s, (const struct sockaddr *) &sa,
                                      sizeof (sa))) && (errno != EINPROGRESS))
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "connect");
    GNUNET_NETWORK_socket_close (s);
    return;
  }
  ctx = GNUNET_malloc (sizeof (struct TcpContext));
  ctx->s = s;
  ctx->data = data;
  GNUNET_SCHEDULER_add_write_net (GNUNET_TIME_UNIT_SECONDS, s, &tcp_send, ctx);
}


/**
 * Try to send 'data' to the
 * IP 'dst_ipv4' at port 'dport' via UDP.
 *
 * @param dst_ipv4 target IP
 * @param dport target port
 * @param data data to send
 */
static void
try_send_udp (uint32_t dst_ipv4, uint16_t dport, uint16_t data)
{
  struct GNUNET_NETWORK_Handle *s;
  struct sockaddr_in sa;

  s = GNUNET_NETWORK_socket_create (AF_INET, SOCK_DGRAM, 0);
  if (NULL == s)
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "socket");
    return;
  }
  memset (&sa, 0, sizeof (sa));
  sa.sin_family = AF_INET;
#if HAVE_SOCKADDR_IN_SIN_LEN
  sa.sin_len = sizeof (sa);
#endif
  sa.sin_addr.s_addr = dst_ipv4;
  sa.sin_port = htons (dport);
#if DEBUG_NAT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending UDP packet to `%s'\n",
              GNUNET_a2s ((struct sockaddr *) &sa, sizeof (sa)));
#endif
  if (-1 ==
      GNUNET_NETWORK_socket_sendto (s, &data, sizeof (data),
                                    (const struct sockaddr *) &sa, sizeof (sa)))
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "sendto");
  GNUNET_NETWORK_socket_close (s);
}


/**
 * We've received a request to probe a NAT
 * traversal. Do it.
 *
 * @param cls unused
 * @param client handle to client (we always close)
 * @param msg message with details about what to test
 */
static void
test (void *cls, struct GNUNET_SERVER_Client *client,
      const struct GNUNET_MessageHeader *msg)
{
  const struct GNUNET_NAT_TestMessage *tm;
  uint16_t dport;

#if DEBUG_NAT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received test request\n");
#endif
  tm = (const struct GNUNET_NAT_TestMessage *) msg;
  dport = ntohs (tm->dport);
  if (0 == dport)
    try_anat (tm->dst_ipv4, ntohs (tm->data), (int) ntohl (tm->is_tcp));
  else if (GNUNET_YES == ntohl (tm->is_tcp))
    try_send_tcp (tm->dst_ipv4, dport, tm->data);
  else
    try_send_udp (tm->dst_ipv4, dport, tm->data);
  GNUNET_SERVER_receive_done (client, GNUNET_NO);
}


/**
 * Task run during shutdown.
 *
 * @param cls unused
 * @param tc scheduler context
 */
static void
shutdown_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_SERVER_destroy (server);
  server = NULL;
}


/**
 * Main function that will be run.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param c configuration
 */
static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  static const struct GNUNET_SERVER_MessageHandler handlers[] = {
    {&test, NULL, GNUNET_MESSAGE_TYPE_NAT_TEST,
     sizeof (struct GNUNET_NAT_TestMessage)},
    {NULL, NULL, 0, 0}
  };
  unsigned int port;
  struct sockaddr_in in4;
  struct sockaddr_in6 in6;

  socklen_t slen[] = {
    sizeof (in4),
    sizeof (in6),
    0
  };
  struct sockaddr *sa[] = {
    (struct sockaddr *) &in4,
    (struct sockaddr *) &in6,
    NULL
  };

  cfg = c;
  if ((args[0] == NULL) || (1 != SSCANF (args[0], "%u", &port)) || (0 == port)
      || (65536 <= port))
  {
    FPRINTF (stderr,
             _
             ("Please pass valid port number as the first argument! (got `%s')\n"),
             args[0]);
    return;
  }
  memset (&in4, 0, sizeof (in4));
  memset (&in6, 0, sizeof (in6));
  in4.sin_family = AF_INET;
  in4.sin_port = htons ((uint16_t) port);
  in6.sin6_family = AF_INET6;
  in6.sin6_port = htons ((uint16_t) port);
#if HAVE_SOCKADDR_IN_SIN_LEN
  in4.sin_len = sizeof (in4);
  in6.sin6_len = sizeof (in6);
#endif
  server =
      GNUNET_SERVER_create (NULL, NULL, (struct sockaddr * const *) sa, slen,
                            GNUNET_TIME_UNIT_SECONDS, GNUNET_YES);
  GNUNET_SERVER_add_handlers (server, handlers);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &shutdown_task,
                                NULL);
}


/**
 * Main function of gnunet-nat-server.
 *
 * @param argc number of command-line arguments
 * @param argv command line
 * @return 0 on success, -1 on error
 */
int
main (int argc, char *const argv[])
{
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  if (GNUNET_OK !=
      GNUNET_PROGRAM_run (argc, argv, "gnunet-nat-server [options] PORT",
                          _("GNUnet NAT traversal test helper daemon"), options,
                          &run, NULL))
    return 1;
  return 0;
}


/* end of gnunet-nat-server.c */
