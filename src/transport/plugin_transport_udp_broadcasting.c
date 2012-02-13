/*
     This file is part of GNUnet
     (C) 2010, 2011 Christian Grothoff (and other contributing authors)

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
 * @file transport/plugin_transport_udp_broadcasting.c
 * @brief Neighbour discovery with UDP
 * @author Christian Grothoff
 * @author Matthias Wachs
 */
#include "platform.h"
#include "plugin_transport_udp.h"
#include "gnunet_hello_lib.h"
#include "gnunet_util_lib.h"
#include "gnunet_fragmentation_lib.h"
#include "gnunet_nat_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_resolver_service.h"
#include "gnunet_signatures.h"
#include "gnunet_constants.h"
#include "gnunet_statistics_service.h"
#include "gnunet_transport_service.h"
#include "gnunet_transport_plugin.h"
#include "transport.h"

#define LOG(kind,...) GNUNET_log_from (kind, "transport-udp", __VA_ARGS__)


struct UDP_Beacon_Message
{
 /**
  * Message header.
  */
  struct GNUNET_MessageHeader header;

 /**
  * What is the identity of the sender
  */
  struct GNUNET_PeerIdentity sender;
};


struct BroadcastAddress
{
  struct BroadcastAddress *next;
  struct BroadcastAddress *prev;

  void *addr;
  socklen_t addrlen;
};


struct Mstv4Context
{
  struct Plugin *plugin;

  struct IPv4UdpAddress addr;
  /**
   * ATS network type in NBO
   */
  uint32_t ats_address_network_type;
};

struct Mstv6Context
{
  struct Plugin *plugin;

  struct IPv6UdpAddress addr;
  /**
   * ATS network type in NBO
   */
  uint32_t ats_address_network_type;
};



void
broadcast_ipv6_mst_cb (void *cls, void *client,
                       const struct GNUNET_MessageHeader *message)
{

  struct Plugin *plugin = cls;
  struct Mstv6Context *mc = client;
  const struct GNUNET_MessageHeader *hello;
  struct UDP_Beacon_Message *msg;

  msg = (struct UDP_Beacon_Message *) message;

  if (GNUNET_MESSAGE_TYPE_TRANSPORT_BROADCAST_BEACON !=
      ntohs (msg->header.type))
    return;
#if DEBUG_UDP_BROADCASTING
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received beacon with %u bytes from peer `%s' via address `%s'\n",
       ntohs (msg->header.size), GNUNET_i2s (&msg->sender),
       udp_address_to_string (NULL, &mc->addr, sizeof (mc->addr)));
#endif
  struct GNUNET_ATS_Information atsi[2];

  /* setup ATS */
  atsi[0].type = htonl (GNUNET_ATS_QUALITY_NET_DISTANCE);
  atsi[0].value = htonl (1);
  atsi[1].type = htonl (GNUNET_ATS_NETWORK_TYPE);
  atsi[1].value = mc->ats_address_network_type;
  GNUNET_break (ntohl(mc->ats_address_network_type) != GNUNET_ATS_NET_UNSPECIFIED);

  hello = (struct GNUNET_MessageHeader *) &msg[1];
  plugin->env->receive (plugin->env->cls, &msg->sender, hello,
                        (const struct GNUNET_ATS_Information *) &atsi, 2, NULL,
                        (const char *) &mc->addr, sizeof (mc->addr));

  GNUNET_STATISTICS_update (plugin->env->stats,
                            _
                            ("# IPv6 multicast HELLO beacons received via udp"),
                            1, GNUNET_NO);
  GNUNET_free (mc);
}

void
broadcast_ipv4_mst_cb (void *cls, void *client,
                       const struct GNUNET_MessageHeader *message)
{
  struct Plugin *plugin = cls;
  struct Mstv4Context *mc = client;
  const struct GNUNET_MessageHeader *hello;
  struct UDP_Beacon_Message *msg;

  msg = (struct UDP_Beacon_Message *) message;

  if (GNUNET_MESSAGE_TYPE_TRANSPORT_BROADCAST_BEACON !=
      ntohs (msg->header.type))
    return;
#if DEBUG_UDP_BROADCASTING
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received beacon with %u bytes from peer `%s' via address `%s'\n",
       ntohs (msg->header.size), GNUNET_i2s (&msg->sender),
       udp_address_to_string (NULL, &mc->addr, sizeof (mc->addr)));
#endif

  struct GNUNET_ATS_Information atsi[2];

  /* setup ATS */
  atsi[0].type = htonl (GNUNET_ATS_QUALITY_NET_DISTANCE);
  atsi[0].value = htonl (1);
  atsi[1].type = htonl (GNUNET_ATS_NETWORK_TYPE);
  atsi[1].value = mc->ats_address_network_type;
  GNUNET_break (ntohl(mc->ats_address_network_type) != GNUNET_ATS_NET_UNSPECIFIED);

  hello = (struct GNUNET_MessageHeader *) &msg[1];
  plugin->env->receive (plugin->env->cls, &msg->sender, hello,
                        (const struct GNUNET_ATS_Information *) &atsi, 2, NULL,
                        (const char *) &mc->addr, sizeof (mc->addr));

  GNUNET_STATISTICS_update (plugin->env->stats,
                            _
                            ("# IPv4 broadcast HELLO beacons received via udp"),
                            1, GNUNET_NO);
  GNUNET_free (mc);
}

void
udp_broadcast_receive (struct Plugin *plugin, const char * buf, ssize_t size, struct sockaddr *addr, size_t addrlen)
{
  struct GNUNET_ATS_Information ats;

  if (addrlen == sizeof (struct sockaddr_in))
  {
#if DEBUG_UDP_BROADCASTING
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Received IPv4 HELLO beacon broadcast with %i bytes from address %s\n",
         size, GNUNET_a2s ((const struct sockaddr *) addr, addrlen));
#endif
    struct Mstv4Context *mc;

    mc = GNUNET_malloc (sizeof (struct Mstv4Context));
    struct sockaddr_in *av4 = (struct sockaddr_in *) addr;

    mc->addr.ipv4_addr = av4->sin_addr.s_addr;
    mc->addr.u4_port = av4->sin_port;
    ats = plugin->env->get_address_type (plugin->env->cls, (const struct sockaddr *) addr, addrlen);
    mc->ats_address_network_type = ats.value;
    if (GNUNET_OK !=
        GNUNET_SERVER_mst_receive (plugin->broadcast_ipv4_mst, mc, buf, size,
                                   GNUNET_NO, GNUNET_NO))
      GNUNET_free (mc);
  }
  else if (addrlen == sizeof (struct sockaddr_in6))
  {
#if DEBUG_UDP_BROADCASTING
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Received IPv6 HELLO beacon broadcast with %i bytes from address %s\n",
         size, GNUNET_a2s ((const struct sockaddr *) &addr, addrlen));
#endif
    struct Mstv6Context *mc;

    mc = GNUNET_malloc (sizeof (struct Mstv6Context));
    struct sockaddr_in6 *av6 = (struct sockaddr_in6 *) addr;

    mc->addr.ipv6_addr = av6->sin6_addr;
    mc->addr.u6_port = av6->sin6_port;
    ats = plugin->env->get_address_type (plugin->env->cls, (const struct sockaddr *) addr, addrlen);
    mc->ats_address_network_type = ats.value;

    if (GNUNET_OK !=
        GNUNET_SERVER_mst_receive (plugin->broadcast_ipv6_mst, mc, buf, size,
                                   GNUNET_NO, GNUNET_NO))
      GNUNET_free (mc);
  }
}

static void
udp_ipv4_broadcast_send (void *cls,
                         const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Plugin *plugin = cls;
  int sent;
  uint16_t msg_size;
  uint16_t hello_size;
  char buf[65536];

  const struct GNUNET_MessageHeader *hello;
  struct UDP_Beacon_Message *msg;
  struct BroadcastAddress *baddr;

  plugin->send_ipv4_broadcast_task = GNUNET_SCHEDULER_NO_TASK;

  hello = plugin->env->get_our_hello ();
  hello_size = GNUNET_HELLO_size ((struct GNUNET_HELLO_Message *) hello);
  msg_size = hello_size + sizeof (struct UDP_Beacon_Message);

  if (hello_size < (sizeof (struct GNUNET_MessageHeader)) ||
      (msg_size > (UDP_MTU)))
    return;

  msg = (struct UDP_Beacon_Message *) buf;
  msg->sender = *(plugin->env->my_identity);
  msg->header.size = ntohs (msg_size);
  msg->header.type = ntohs (GNUNET_MESSAGE_TYPE_TRANSPORT_BROADCAST_BEACON);
  memcpy (&msg[1], hello, hello_size);
  sent = 0;

  baddr = plugin->ipv4_broadcast_head;
  /* just IPv4 */
  while ((baddr != NULL) && (baddr->addrlen == sizeof (struct sockaddr_in)))
  {
    struct sockaddr_in *addr = (struct sockaddr_in *) baddr->addr;

    addr->sin_port = htons (plugin->port);

    sent =
        GNUNET_NETWORK_socket_sendto (plugin->sockv4, msg, msg_size,
                                      (const struct sockaddr *) addr,
                                      baddr->addrlen);
    if (sent == GNUNET_SYSERR)
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "sendto");
    else
    {
#if DEBUG_UDP_BROADCASTING
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Sent HELLO beacon broadcast with  %i bytes to address %s\n", sent,
           GNUNET_a2s (baddr->addr, baddr->addrlen));
#endif
    }
    baddr = baddr->next;
  }

  plugin->send_ipv4_broadcast_task =
      GNUNET_SCHEDULER_add_delayed (plugin->broadcast_interval,
                                    &udp_ipv4_broadcast_send, plugin);
}

static void
udp_ipv6_broadcast_send (void *cls,
                         const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Plugin *plugin = cls;
  int sent;
  uint16_t msg_size;
  uint16_t hello_size;
  char buf[65536];

  const struct GNUNET_MessageHeader *hello;
  struct UDP_Beacon_Message *msg;

  plugin->send_ipv6_broadcast_task = GNUNET_SCHEDULER_NO_TASK;

  hello = plugin->env->get_our_hello ();
  hello_size = GNUNET_HELLO_size ((struct GNUNET_HELLO_Message *) hello);
  msg_size = hello_size + sizeof (struct UDP_Beacon_Message);

  if (hello_size < (sizeof (struct GNUNET_MessageHeader)) ||
      (msg_size > (UDP_MTU)))
    return;

  msg = (struct UDP_Beacon_Message *) buf;
  msg->sender = *(plugin->env->my_identity);
  msg->header.size = ntohs (msg_size);
  msg->header.type = ntohs (GNUNET_MESSAGE_TYPE_TRANSPORT_BROADCAST_BEACON);
  memcpy (&msg[1], hello, hello_size);
  sent = 0;

  sent =
      GNUNET_NETWORK_socket_sendto (plugin->sockv6, msg, msg_size,
                                    (const struct sockaddr *)
                                    &plugin->ipv6_multicast_address,
                                    sizeof (struct sockaddr_in6));
  if (sent == GNUNET_SYSERR)
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "sendto");
  else
  {
#if DEBUG_UDP_BROADCASTING
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Sending IPv6 HELLO beacon broadcast with  %i bytes to address %s\n",
         sent,
         GNUNET_a2s ((const struct sockaddr *) &plugin->ipv6_multicast_address,
                     sizeof (struct sockaddr_in6)));
#endif
  }


  plugin->send_ipv6_broadcast_task =
      GNUNET_SCHEDULER_add_delayed (plugin->broadcast_interval,
                                    &udp_ipv6_broadcast_send, plugin);
}


static int
iface_proc (void *cls, const char *name, int isDefault,
            const struct sockaddr *addr, const struct sockaddr *broadcast_addr,
            const struct sockaddr *netmask, socklen_t addrlen)
{
  struct Plugin *plugin = cls;

  if (addr != NULL)
  {
#if DEBUG_UDP_BROADCASTING
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "address %s for interface %s %p\n ",
                GNUNET_a2s (addr, addrlen), name, addr);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "broadcast address %s for interface %s %p\n ",
                GNUNET_a2s (broadcast_addr, addrlen), name, broadcast_addr);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "netmask %s for interface %s %p\n ",
                GNUNET_a2s (netmask, addrlen), name, netmask);
#endif

    /* Collecting broadcast addresses */
    if (broadcast_addr != NULL)
    {
      struct BroadcastAddress *ba =
          GNUNET_malloc (sizeof (struct BroadcastAddress));
      ba->addr = GNUNET_malloc (addrlen);
      memcpy (ba->addr, broadcast_addr, addrlen);
      ba->addrlen = addrlen;
      GNUNET_CONTAINER_DLL_insert (plugin->ipv4_broadcast_head,
                                   plugin->ipv4_broadcast_tail, ba);
    }
  }
  return GNUNET_OK;
}


void
setup_broadcast (struct Plugin *plugin, struct sockaddr_in6 *serverAddrv6, struct sockaddr_in *serverAddrv4)
{
  /* create IPv4 broadcast socket */
  plugin->broadcast_ipv4 = GNUNET_NO;
  if (plugin->sockv4 != NULL)
  {
    int yes = 1;

    if (GNUNET_NETWORK_socket_setsockopt
        (plugin->sockv4, SOL_SOCKET, SO_BROADCAST, &yes,
         sizeof (int)) != GNUNET_OK)
    {
      LOG (GNUNET_ERROR_TYPE_WARNING,
           _
           ("Failed to set IPv4 broadcast option for broadcast socket on port %d\n"),
           ntohs (serverAddrv4->sin_port));
    }
    else
    {
      GNUNET_OS_network_interfaces_list (iface_proc, plugin);
      plugin->send_ipv4_broadcast_task =
          GNUNET_SCHEDULER_add_now (&udp_ipv4_broadcast_send, plugin);

      plugin->broadcast_ipv4_mst =
          GNUNET_SERVER_mst_create (broadcast_ipv4_mst_cb, plugin);

      LOG (GNUNET_ERROR_TYPE_DEBUG, "IPv4 Broadcasting running\n");
      plugin->broadcast_ipv4 = GNUNET_YES;
    }
  }

  plugin->broadcast_ipv6 = GNUNET_NO;
  if (plugin->sockv6 != NULL)
  {
    memset (&plugin->ipv6_multicast_address, 0, sizeof (struct sockaddr_in6));
    GNUNET_assert (1 ==
                   inet_pton (AF_INET6, "FF05::13B",
                              &plugin->ipv6_multicast_address.sin6_addr));

    plugin->ipv6_multicast_address.sin6_family = AF_INET6;
    plugin->ipv6_multicast_address.sin6_port = htons (plugin->port);

    plugin->broadcast_ipv6_mst =
        GNUNET_SERVER_mst_create (broadcast_ipv6_mst_cb, plugin);

    /* Create IPv6 multicast request */
    struct ipv6_mreq multicastRequest;

    multicastRequest.ipv6mr_multiaddr =
        plugin->ipv6_multicast_address.sin6_addr;
    /* TODO: 0 selects the "best" interface, tweak to use all interfaces
     *
     * http://tools.ietf.org/html/rfc2553#section-5.2:
     *
     * IPV6_JOIN_GROUP
     *
     * Join a multicast group on a specified local interface.  If the
     * interface index is specified as 0, the kernel chooses the local
     * interface.  For example, some kernels look up the multicast
     * group in the normal IPv6 routing table and using the resulting
     * interface.
     * */
    multicastRequest.ipv6mr_interface = 0;

    /* Join the multicast group */
    if (GNUNET_NETWORK_socket_setsockopt
        (plugin->sockv6, IPPROTO_IPV6, IPV6_JOIN_GROUP,
         (char *) &multicastRequest, sizeof (multicastRequest)) != GNUNET_OK)
    {
      LOG (GNUNET_ERROR_TYPE_WARNING,
      "Failed to join IPv6 multicast group: IPv6 broadcasting not running\n");
    }
    else
    {
#if DEBUG_UDP
      LOG (GNUNET_ERROR_TYPE_DEBUG, "IPv6 broadcasting running\n");
#endif
      plugin->send_ipv6_broadcast_task =
          GNUNET_SCHEDULER_add_now (&udp_ipv6_broadcast_send, plugin);
      plugin->broadcast_ipv6 = GNUNET_YES;
    }
  }
}

void
stop_broadcast (struct Plugin *plugin)
{
  if (plugin->broadcast_ipv4)
  {
    if (plugin->send_ipv4_broadcast_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (plugin->send_ipv4_broadcast_task);
      plugin->send_ipv4_broadcast_task = GNUNET_SCHEDULER_NO_TASK;
    }

    if (plugin->broadcast_ipv4_mst != NULL)
      GNUNET_SERVER_mst_destroy (plugin->broadcast_ipv4_mst);

    while (plugin->ipv4_broadcast_head != NULL)
    {
      struct BroadcastAddress *p = plugin->ipv4_broadcast_head;

      GNUNET_CONTAINER_DLL_remove (plugin->ipv4_broadcast_head,
                                   plugin->ipv4_broadcast_tail, p);
      GNUNET_free (p->addr);
      GNUNET_free (p);
    }
  }

  if (plugin->broadcast_ipv6)
  {
    /* Create IPv6 multicast request */
    struct ipv6_mreq multicastRequest;

    multicastRequest.ipv6mr_multiaddr =
        plugin->ipv6_multicast_address.sin6_addr;
    multicastRequest.ipv6mr_interface = 0;

    /* Join the multicast address */
    if (GNUNET_NETWORK_socket_setsockopt
        (plugin->sockv6, IPPROTO_IPV6, IPV6_LEAVE_GROUP,
        (char *) &multicastRequest, sizeof (multicastRequest)) != GNUNET_OK)
    {
       GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, setsockopt);
    }
    else
    {
#if DEBUG_UDP
      LOG (GNUNET_ERROR_TYPE_DEBUG, "IPv6 Broadcasting stopped\n");
#endif
    }

    if (plugin->send_ipv6_broadcast_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (plugin->send_ipv6_broadcast_task);
      plugin->send_ipv6_broadcast_task = GNUNET_SCHEDULER_NO_TASK;
    }
    if (plugin->broadcast_ipv6_mst != NULL)
      GNUNET_SERVER_mst_destroy (plugin->broadcast_ipv6_mst);
  }

}

/* end of plugin_transport_udp_broadcasting.c */
