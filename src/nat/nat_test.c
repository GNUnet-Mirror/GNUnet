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
 * @file nat/nat_test.c
 * @brief functions to test if the NAT configuration is successful at achieving NAT traversal (with the help of a gnunet-nat-server)
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_nat_lib.h"
#include "nat.h"

#define LOG(kind,...) GNUNET_log_from (kind, "nat", __VA_ARGS__)

/**
 * Entry we keep for each incoming connection.
 */
struct NatActivity
{
  /**
   * This is a doubly-linked list.
   */
  struct NatActivity *next;

  /**
   * This is a doubly-linked list.
   */
  struct NatActivity *prev;

  /**
   * Socket of the incoming connection.
   */
  struct GNUNET_NETWORK_Handle *sock;

  /**
   * Handle of the master context.
   */
  struct GNUNET_NAT_Test *h;

  /**
   * Task reading from the incoming connection.
   */
  GNUNET_SCHEDULER_TaskIdentifier rtask;
};


/**
 * Entry we keep for each connection to the gnunet-nat-service.
 */
struct ClientActivity
{
  /**
   * This is a doubly-linked list.
   */
  struct ClientActivity *next;

  /**
   * This is a doubly-linked list.
   */
  struct ClientActivity *prev;

  /**
   * Socket of the incoming connection.
   */
  struct GNUNET_CLIENT_Connection *client;

};


/**
 * Handle to a NAT test.
 */
struct GNUNET_NAT_Test
{

  /**
   * Configuration used
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Function to call with success report
   */
  GNUNET_NAT_TestCallback report;

  /**
   * Closure for 'report'.
   */
  void *report_cls;

  /**
   * Handle to NAT traversal in use
   */
  struct GNUNET_NAT_Handle *nat;

  /**
   * Handle to listen socket, or NULL
   */
  struct GNUNET_NETWORK_Handle *lsock;

  /**
   * Head of list of nat activities.
   */
  struct NatActivity *na_head;

  /**
   * Tail of list of nat activities.
   */
  struct NatActivity *na_tail;

  /**
   * Head of list of client activities.
   */
  struct ClientActivity *ca_head;

  /**
   * Tail of list of client activities.
   */
  struct ClientActivity *ca_tail;

  /**
   * Identity of task for the listen socket (if any)
   */
  GNUNET_SCHEDULER_TaskIdentifier ltask;

  /**
   * GNUNET_YES if we're testing TCP
   */
  int is_tcp;

  /**
   * Data that should be transmitted or source-port.
   */
  uint16_t data;

  /**
   * Advertised port to the other peer.
   */
  uint16_t adv_port;

};


/**
 * Function called from GNUNET_NAT_register whenever someone asks us
 * to do connection reversal.
 *
 * @param cls closure, our 'struct GNUNET_NAT_Handle'
 * @param addr public IP address of the other peer
 * @param addrlen actual lenght of the address
 */
static void
reversal_cb (void *cls, const struct sockaddr *addr, socklen_t addrlen)
{
  struct GNUNET_NAT_Test *h = cls;
  const struct sockaddr_in *sa;

  if (addrlen != sizeof (struct sockaddr_in))
    return;
  sa = (const struct sockaddr_in *) addr;
  if (h->data != sa->sin_port)
  {
#if DEBUG_NAT
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Received connection reversal request for wrong port\n");
#endif
    return;                     /* wrong port */
  }
  /* report success */
  h->report (h->report_cls, GNUNET_OK);
}


/**
 * Activity on our incoming socket.  Read data from the
 * incoming connection.
 *
 * @param cls the 'struct NatActivity'
 * @param tc scheduler context
 */
static void
do_udp_read (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_NAT_Test *tst = cls;
  uint16_t data;

  tst->ltask =
      GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL, tst->lsock,
                                     &do_udp_read, tst);
  if ((NULL != tc->write_ready) &&
      (GNUNET_NETWORK_fdset_isset (tc->read_ready, tst->lsock)) &&
      (sizeof (data) ==
       GNUNET_NETWORK_socket_recv (tst->lsock, &data, sizeof (data))))
  {
    if (data == tst->data)
      tst->report (tst->report_cls, GNUNET_OK);
#if DEBUG_NAT
    else
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Received data mismatches expected value\n");
#endif
  }
#if DEBUG_NAT
  else
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Failed to receive data from inbound connection\n");
#endif
}


/**
 * Activity on our incoming socket.  Read data from the
 * incoming connection.
 *
 * @param cls the 'struct NatActivity'
 * @param tc scheduler context
 */
static void
do_read (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct NatActivity *na = cls;
  struct GNUNET_NAT_Test *tst;
  uint16_t data;

  na->rtask = GNUNET_SCHEDULER_NO_TASK;
  tst = na->h;
  GNUNET_CONTAINER_DLL_remove (tst->na_head, tst->na_tail, na);
  if ((NULL != tc->write_ready) &&
      (GNUNET_NETWORK_fdset_isset (tc->read_ready, na->sock)) &&
      (sizeof (data) ==
       GNUNET_NETWORK_socket_recv (na->sock, &data, sizeof (data))))
  {
    if (data == tst->data)
      tst->report (tst->report_cls, GNUNET_OK);
#if DEBUG_NAT
    else
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Received data mismatches expected value\n");
#endif
  }
#if DEBUG_NAT
  else
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Failed to receive data from inbound connection\n");
#endif
  GNUNET_NETWORK_socket_close (na->sock);
  GNUNET_free (na);
}


/**
 * Activity on our listen socket. Accept the
 * incoming connection.
 *
 * @param cls the 'struct GNUNET_NAT_Test'
 * @param tc scheduler context
 */
static void
do_accept (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_NAT_Test *tst = cls;
  struct GNUNET_NETWORK_Handle *s;
  struct NatActivity *wl;

  tst->ltask = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;
  tst->ltask =
      GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL, tst->lsock,
                                     &do_accept, tst);
  s = GNUNET_NETWORK_socket_accept (tst->lsock, NULL, NULL);
  if (NULL == s)
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_INFO, "accept");
    return;                     /* odd error */
  }
#if DEBUG_NAT
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Got an inbound connection, waiting for data\n");
#endif
  wl = GNUNET_malloc (sizeof (struct NatActivity));
  wl->sock = s;
  wl->h = tst;
  wl->rtask =
      GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL, wl->sock,
                                     &do_read, wl);
  GNUNET_CONTAINER_DLL_insert (tst->na_head, tst->na_tail, wl);
}


/**
 * Address-callback, used to send message to gnunet-nat-server.
 *
 * @param cls closure
 * @param add_remove GNUNET_YES to mean the new public IP address, GNUNET_NO to mean
 *     the previous (now invalid) one
 * @param addr either the previous or the new public IP address
 * @param addrlen actual lenght of the address
 */
static void
addr_cb (void *cls, int add_remove, const struct sockaddr *addr,
         socklen_t addrlen)
{
  struct GNUNET_NAT_Test *h = cls;
  struct ClientActivity *ca;
  struct GNUNET_CLIENT_Connection *client;
  struct GNUNET_NAT_TestMessage msg;
  const struct sockaddr_in *sa;

  if (GNUNET_YES != add_remove)
    return;
  if (addrlen != sizeof (struct sockaddr_in))
    return;                     /* ignore IPv6 here */
#if DEBUG_NAT
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Asking gnunet-nat-server to connect to `%s'\n",
       GNUNET_a2s (addr, addrlen));
#endif
  sa = (const struct sockaddr_in *) addr;
  msg.header.size = htons (sizeof (struct GNUNET_NAT_TestMessage));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_NAT_TEST);
  msg.dst_ipv4 = sa->sin_addr.s_addr;
  msg.dport = sa->sin_port;
  msg.data = h->data;
  msg.is_tcp = htonl ((uint32_t) h->is_tcp);

  client = GNUNET_CLIENT_connect ("gnunet-nat-server", h->cfg);
  if (NULL == client)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Failed to connect to `gnunet-nat-server'\n"));
    return;
  }
  ca = GNUNET_malloc (sizeof (struct ClientActivity));
  ca->client = client;
  GNUNET_CONTAINER_DLL_insert (h->ca_head, h->ca_tail, ca);
  GNUNET_break (GNUNET_OK ==
                GNUNET_CLIENT_transmit_and_get_response (client, &msg.header,
                                                         GNUNET_TIME_UNIT_SECONDS,
                                                         GNUNET_YES, NULL,
                                                         NULL));
}


/**
 * Start testing if NAT traversal works using the
 * given configuration (IPv4-only).
 *
 * @param cfg configuration for the NAT traversal
 * @param is_tcp GNUNET_YES to test TCP, GNUNET_NO to test UDP
 * @param bnd_port port to bind to, 0 for connection reversal
 * @param adv_port externally advertised port to use
 * @param report function to call with the result of the test
 * @param report_cls closure for report
 * @return handle to cancel NAT test
 */
struct GNUNET_NAT_Test *
GNUNET_NAT_test_start (const struct GNUNET_CONFIGURATION_Handle *cfg,
                       int is_tcp, uint16_t bnd_port, uint16_t adv_port,
                       GNUNET_NAT_TestCallback report, void *report_cls)
{
  struct GNUNET_NAT_Test *ret;
  struct sockaddr_in sa;
  const struct sockaddr *addrs[] = { (const struct sockaddr *) &sa };
  const socklen_t addrlens[] = { sizeof (sa) };

  memset (&sa, 0, sizeof (sa));
  sa.sin_family = AF_INET;
  sa.sin_port = htons (bnd_port);
#if HAVE_SOCKADDR_IN_SIN_LEN
  sa.sin_len = sizeof (sa);
#endif

  ret = GNUNET_malloc (sizeof (struct GNUNET_NAT_Test));
  ret->cfg = cfg;
  ret->is_tcp = is_tcp;
  ret->data = bnd_port;
  ret->adv_port = adv_port;
  ret->report = report;
  ret->report_cls = report_cls;
  if (bnd_port == 0)
  {
    ret->nat =
        GNUNET_NAT_register (cfg, is_tcp, 0, 0, NULL, NULL, &addr_cb,
                             &reversal_cb, ret);
  }
  else
  {
    ret->lsock =
        GNUNET_NETWORK_socket_create (AF_INET,
                                      (is_tcp ==
                                       GNUNET_YES) ? SOCK_STREAM : SOCK_DGRAM,
                                      0);
    if ((ret->lsock == NULL) ||
        (GNUNET_OK !=
         GNUNET_NETWORK_socket_bind (ret->lsock, (const struct sockaddr *) &sa,
                                     sizeof (sa))))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _
                  ("Failed to create listen socket bound to `%s' for NAT test: %s\n"),
                  GNUNET_a2s ((const struct sockaddr *) &sa, sizeof (sa)),
                  STRERROR (errno));
      if (NULL != ret->lsock)
        GNUNET_NETWORK_socket_close (ret->lsock);
      GNUNET_free (ret);
      return NULL;
    }
    if (GNUNET_YES == is_tcp)
    {
      GNUNET_break (GNUNET_OK == GNUNET_NETWORK_socket_listen (ret->lsock, 5));
      ret->ltask =
          GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                         ret->lsock, &do_accept, ret);
    }
    else
    {
      ret->ltask =
          GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                         ret->lsock, &do_udp_read, ret);
    }
    ret->nat =
        GNUNET_NAT_register (cfg, is_tcp, adv_port, 1, addrs, addrlens,
                             &addr_cb, NULL, ret);
  }
  return ret;
}


/**
 * Stop an active NAT test.
 *
 * @param tst test to stop.
 */
void
GNUNET_NAT_test_stop (struct GNUNET_NAT_Test *tst)
{
  struct NatActivity *pos;
  struct ClientActivity *cpos;

  while (NULL != (cpos = tst->ca_head))
  {
    GNUNET_CONTAINER_DLL_remove (tst->ca_head, tst->ca_tail, cpos);
    GNUNET_CLIENT_disconnect (cpos->client, GNUNET_NO);
    GNUNET_free (cpos);
  }
  while (NULL != (pos = tst->na_head))
  {
    GNUNET_CONTAINER_DLL_remove (tst->na_head, tst->na_tail, pos);
    GNUNET_SCHEDULER_cancel (pos->rtask);
    GNUNET_NETWORK_socket_close (pos->sock);
    GNUNET_free (pos);
  }
  if (GNUNET_SCHEDULER_NO_TASK != tst->ltask)
    GNUNET_SCHEDULER_cancel (tst->ltask);
  if (NULL != tst->lsock)
    GNUNET_NETWORK_socket_close (tst->lsock);
  GNUNET_NAT_unregister (tst->nat);
  GNUNET_free (tst);
}

/* end of nat_test.c */
