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

/* *********** Cryogenic ********** */
#if LINUX
#include <sys/stat.h>
#include <fcntl.h>

#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/time.h>

#define PM_MAGIC 'k'
#define PM_SET_DELAY_AND_TIMEOUT _IOW(PM_MAGIC, 1, struct pm_times)

struct pm_times {
	unsigned long delay_msecs;
	unsigned long timeout_msecs;
};
#endif
/************************************/


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

  /**
   * ID of select broadcast task
   */
  struct GNUNET_SCHEDULER_Task * broadcast_task;

  struct Plugin *plugin;

  void *addr;

  socklen_t addrlen;

#if LINUX
  /**
   * Cryogenic handle.
   */
  struct GNUNET_DISK_FileHandle *cryogenic_fd;

  /**
   * Time out for cryogenic.
   */
  struct pm_times cryogenic_times;
#endif
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


static int
broadcast_ipv6_mst_cb (void *cls, void *client,
                       const struct GNUNET_MessageHeader *message)
{
  struct Plugin *plugin = cls;
  struct Mstv6Context *mc = client;
  struct GNUNET_HELLO_Address *address;
  const struct GNUNET_MessageHeader *hello;
  const struct UDP_Beacon_Message *msg;
  struct GNUNET_ATS_Information atsi;

  msg = (const struct UDP_Beacon_Message *) message;

  if (GNUNET_MESSAGE_TYPE_TRANSPORT_BROADCAST_BEACON !=
      ntohs (msg->header.type))
    return GNUNET_OK;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received beacon with %u bytes from peer `%s' via address `%s'\n",
       ntohs (msg->header.size), GNUNET_i2s (&msg->sender),
       udp_address_to_string (NULL, &mc->addr, sizeof (mc->addr)));

  /* setup ATS */
  atsi.type = htonl (GNUNET_ATS_NETWORK_TYPE);
  atsi.value = mc->ats_address_network_type;
  GNUNET_break (ntohl(mc->ats_address_network_type) != GNUNET_ATS_NET_UNSPECIFIED);

  hello = (struct GNUNET_MessageHeader *) &msg[1];
  address = GNUNET_HELLO_address_allocate (&msg->sender, PLUGIN_NAME,
      (const char *) &mc->addr, sizeof (mc->addr), GNUNET_HELLO_ADDRESS_INFO_INBOUND);
  plugin->env->receive (plugin->env->cls, address, NULL, hello);
  plugin->env->update_address_metrics (plugin->env->cls, address,
				       NULL, &atsi, 1);
  GNUNET_HELLO_address_free (address);
  GNUNET_STATISTICS_update (plugin->env->stats,
                            _
                            ("# IPv6 multicast HELLO beacons received via udp"),
                            1, GNUNET_NO);
  GNUNET_free (mc);
  return GNUNET_OK;
}


static int
broadcast_ipv4_mst_cb (void *cls, void *client,
                       const struct GNUNET_MessageHeader *message)
{
  struct Plugin *plugin = cls;
  struct Mstv4Context *mc = client;
  struct GNUNET_HELLO_Address *address;
  const struct GNUNET_MessageHeader *hello;
  const struct UDP_Beacon_Message *msg;
  struct GNUNET_ATS_Information atsi;

  msg = (const struct UDP_Beacon_Message *) message;

  if (GNUNET_MESSAGE_TYPE_TRANSPORT_BROADCAST_BEACON !=
      ntohs (msg->header.type))
    return GNUNET_OK;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received beacon with %u bytes from peer `%s' via address `%s'\n",
       ntohs (msg->header.size), GNUNET_i2s (&msg->sender),
       udp_address_to_string (NULL, &mc->addr, sizeof (mc->addr)));


  /* setup ATS */
  atsi.type = htonl (GNUNET_ATS_NETWORK_TYPE);
  atsi.value = mc->ats_address_network_type;
  GNUNET_break (ntohl(mc->ats_address_network_type) != GNUNET_ATS_NET_UNSPECIFIED);

  hello = (struct GNUNET_MessageHeader *) &msg[1];
  address = GNUNET_HELLO_address_allocate (&msg->sender, PLUGIN_NAME,
      (const char *) &mc->addr, sizeof (mc->addr), GNUNET_HELLO_ADDRESS_INFO_INBOUND);
  plugin->env->receive (plugin->env->cls, address, NULL, hello);
  plugin->env->update_address_metrics (plugin->env->cls, address,
                                       NULL, &atsi, 1);
  GNUNET_HELLO_address_free (address);

  GNUNET_STATISTICS_update (plugin->env->stats,
                            _("# IPv4 broadcast HELLO beacons received via udp"),
                            1, GNUNET_NO);
  GNUNET_free (mc);
  return GNUNET_OK;
}


void
udp_broadcast_receive (struct Plugin *plugin,
                       const char *buf,
                       ssize_t size,
                       const struct sockaddr *addr,
                       size_t addrlen)
{
  struct GNUNET_ATS_Information ats;

  if (addrlen == sizeof (struct sockaddr_in))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Received IPv4 HELLO beacon broadcast with %i bytes from address %s\n",
         size, GNUNET_a2s ((const struct sockaddr *) addr, addrlen));
    struct Mstv4Context *mc;

    mc = GNUNET_new (struct Mstv4Context);
    struct sockaddr_in *av4 = (struct sockaddr_in *) addr;

    mc->addr.ipv4_addr = av4->sin_addr.s_addr;
    mc->addr.u4_port = av4->sin_port;
    ats = plugin->env->get_address_type (plugin->env->cls, (const struct sockaddr *) addr, addrlen);
    mc->ats_address_network_type = ats.value;

    GNUNET_assert (NULL != plugin->broadcast_ipv4_mst);
    if (GNUNET_OK !=
        GNUNET_SERVER_mst_receive (plugin->broadcast_ipv4_mst, mc, buf, size,
                                   GNUNET_NO, GNUNET_NO))
      GNUNET_free (mc);
  }
  if (addrlen == sizeof (struct sockaddr_in6))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Received IPv6 HELLO beacon broadcast with %i bytes from address %s\n",
         size, GNUNET_a2s ((const struct sockaddr *) &addr, addrlen));
    struct Mstv6Context *mc;

    mc = GNUNET_new (struct Mstv6Context);
    struct sockaddr_in6 *av6 = (struct sockaddr_in6 *) addr;

    mc->addr.ipv6_addr = av6->sin6_addr;
    mc->addr.u6_port = av6->sin6_port;
    ats = plugin->env->get_address_type (plugin->env->cls, (const struct sockaddr *) addr, addrlen);
    mc->ats_address_network_type = ats.value;
    GNUNET_assert (NULL != plugin->broadcast_ipv4_mst);
    if (GNUNET_OK !=
        GNUNET_SERVER_mst_receive (plugin->broadcast_ipv6_mst, mc, buf, size,
                                   GNUNET_NO, GNUNET_NO))
      GNUNET_free (mc);
  }
}


static unsigned int
prepare_beacon (struct Plugin *plugin, struct UDP_Beacon_Message *msg)
{
  uint16_t hello_size;
  uint16_t msg_size;

  const struct GNUNET_MessageHeader *hello;
  hello = plugin->env->get_our_hello ();
  if (NULL == hello)
    return 0;
  hello_size = GNUNET_HELLO_size ((struct GNUNET_HELLO_Message *) hello);
  msg_size = hello_size + sizeof (struct UDP_Beacon_Message);

  if (hello_size < (sizeof (struct GNUNET_MessageHeader)) ||
      (msg_size > (UDP_MTU)))
    return 0;

  msg->sender = *(plugin->env->my_identity);
  msg->header.size = htons (msg_size);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_BROADCAST_BEACON);
  memcpy (&msg[1], hello, hello_size);
  return msg_size;
}


static void
udp_ipv4_broadcast_send (void *cls,
                         const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct BroadcastAddress *baddr = cls;
  struct Plugin *plugin = baddr->plugin;
  int sent;
  uint16_t msg_size;
  char buf[65536] GNUNET_ALIGN;

  baddr->broadcast_task = NULL;

  msg_size = prepare_beacon(plugin, (struct UDP_Beacon_Message *) &buf);
  if (0 != msg_size)
  {
    struct sockaddr_in *addr = (struct sockaddr_in *) baddr->addr;

    addr->sin_port = htons (plugin->port);
    sent = GNUNET_NETWORK_socket_sendto (plugin->sockv4, &buf, msg_size,
                                      (const struct sockaddr *) addr,
                                      baddr->addrlen);
    if (sent == GNUNET_SYSERR)
    {
      if ((ENETUNREACH == errno) || (ENETDOWN == errno))
      {
        /* "Network unreachable" or "Network down"
         *
         * This indicates that we just do not have network connectivity
         */
        GNUNET_log (GNUNET_ERROR_TYPE_BULK | GNUNET_ERROR_TYPE_WARNING,
            "Network connectivity is down, cannot send beacon!\n");
      }
      else
        GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "sendto");
    }
    else
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Sent HELLO beacon broadcast with %i bytes to address %s\n", sent,
           GNUNET_a2s (baddr->addr, baddr->addrlen));
    }
  }

#if LINUX
  /*
   * Cryogenic
   */
  if (NULL != baddr->cryogenic_fd)
  {
    baddr->cryogenic_times.delay_msecs = (plugin->broadcast_interval.rel_value_us/1000.0)*0.5;
    baddr->cryogenic_times.timeout_msecs = (plugin->broadcast_interval.rel_value_us/1000.0)*1.5;

    if (ioctl(baddr->cryogenic_fd->fd,
    		  PM_SET_DELAY_AND_TIMEOUT,
    		  &baddr->cryogenic_times) < 0)
    {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "ioctl");
      baddr->broadcast_task =
          GNUNET_SCHEDULER_add_delayed (plugin->broadcast_interval,
      	                                &udp_ipv4_broadcast_send, baddr);
    }
    else
      GNUNET_SCHEDULER_add_write_file (GNUNET_TIME_UNIT_FOREVER_REL,
    		                           baddr->cryogenic_fd,
        		                       &udp_ipv4_broadcast_send,
        		                       baddr);

  }
  else
#endif
    baddr->broadcast_task =
        GNUNET_SCHEDULER_add_delayed (plugin->broadcast_interval,
	                                  &udp_ipv4_broadcast_send, baddr);
}


static void
udp_ipv6_broadcast_send (void *cls,
                         const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct BroadcastAddress *baddr = cls;
  struct Plugin *plugin = baddr->plugin;
  ssize_t sent;
  uint16_t msg_size;
  char buf[65536] GNUNET_ALIGN;
  const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *) baddr->addr;

  baddr->broadcast_task = NULL;

  msg_size = prepare_beacon(plugin, (struct UDP_Beacon_Message *) &buf);
  /* Note: unclear if this actually works to limit the multicast to
     the specified interface as we're not (necessarily) using a
     link-local multicast group and the kernel suggests that the
     scope ID is only respected for link-local addresses; however,
     if the scope ID is ignored, the kernel should just multicast
     on ALL interfaces, which is merely slightly less efficient;
     in that case, we might want to revert to only doing this
     once, and not per interface (hard to test...) */
  plugin->ipv6_multicast_address.sin6_scope_id = s6->sin6_scope_id;
  sent = GNUNET_NETWORK_socket_sendto (plugin->sockv6, &buf, msg_size,
                                    (const struct sockaddr *)
                                    &plugin->ipv6_multicast_address,
                                    sizeof (struct sockaddr_in6));
  plugin->ipv6_multicast_address.sin6_scope_id = 0;
  if (sent == GNUNET_SYSERR)
  {
    if ((ENETUNREACH == errno) || (ENETDOWN == errno))
    {
      /* "Network unreachable" or "Network down"
       *
       * This indicates that this system is IPv6 enabled, but does not
       * have a valid global IPv6 address assigned
       */
      GNUNET_log (GNUNET_ERROR_TYPE_BULK | GNUNET_ERROR_TYPE_WARNING,
          "Network connectivity is down, cannot send beacon!\n");
    }
    else
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "sendto");
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Sending IPv6 HELLO beacon broadcast with %d bytes to address %s\n",
         (int) sent,
         GNUNET_a2s ((const struct sockaddr *) &plugin->ipv6_multicast_address,
                     sizeof (struct sockaddr_in6)));
  }
#if LINUX
  /*
   * Cryogenic
   */
  if (NULL != baddr->cryogenic_fd)
  {
    baddr->cryogenic_times.delay_msecs = (plugin->broadcast_interval.rel_value_us/1000.0)*0.5;
    baddr->cryogenic_times.timeout_msecs = (plugin->broadcast_interval.rel_value_us/1000.0)*1.5;

    if (ioctl(baddr->cryogenic_fd->fd,
    		  PM_SET_DELAY_AND_TIMEOUT,
    		  &baddr->cryogenic_times) < 0)
    {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "ioctl");
      baddr->broadcast_task =
          GNUNET_SCHEDULER_add_delayed (plugin->broadcast_interval,
                                        &udp_ipv6_broadcast_send, baddr);
    }
    else
      GNUNET_SCHEDULER_add_write_file (GNUNET_TIME_UNIT_FOREVER_REL,
    		                       baddr->cryogenic_fd,
                                       &udp_ipv4_broadcast_send,
                                       baddr);
  }
  else
#endif
    baddr->broadcast_task =
        GNUNET_SCHEDULER_add_delayed (plugin->broadcast_interval,
                                      &udp_ipv6_broadcast_send, baddr);
}


/**
 * Callback function invoked for each interface found.
 *
 * @param cls closure with the `struct Plugin`
 * @param name name of the interface (can be NULL for unknown)
 * @param isDefault is this presumably the default interface
 * @param addr address of this interface (can be NULL for unknown or unassigned)
 * @param broadcast_addr the broadcast address (can be NULL for unknown or unassigned)
 * @param netmask the network mask (can be NULL for unknown or unassigned)
 * @param addrlen length of the address
 * @return #GNUNET_OK to continue iteration, #GNUNET_SYSERR to abort
 */
static int
iface_proc (void *cls,
            const char *name,
            int isDefault,
            const struct sockaddr *addr,
            const struct sockaddr *broadcast_addr,
            const struct sockaddr *netmask, socklen_t addrlen)
{
  struct Plugin *plugin = cls;
  struct BroadcastAddress *ba;
  struct GNUNET_ATS_Information network;

  if (NULL == addr)
    return GNUNET_OK;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "address %s for interface %s %p\n ",
              GNUNET_a2s (addr, addrlen), name, addr);
  if (NULL == broadcast_addr)
    return GNUNET_OK;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "broadcast address %s for interface %s %p\n ",
              GNUNET_a2s (broadcast_addr, addrlen), name, broadcast_addr);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "netmask %s for interface %s %p\n ",
              GNUNET_a2s (netmask, addrlen), name, netmask);

  network = plugin->env->get_address_type (plugin->env->cls, broadcast_addr, addrlen);
  if (GNUNET_ATS_NET_LOOPBACK == ntohl(network.value))
  {
    /* Broadcasting on loopback does not make sense */
    return GNUNET_YES;
  }

  ba = GNUNET_new (struct BroadcastAddress);
  ba->plugin = plugin;
  ba->addr = GNUNET_malloc (addrlen);
  memcpy (ba->addr, broadcast_addr, addrlen);
  ba->addrlen = addrlen;

  if ( (GNUNET_YES == plugin->enable_ipv4) &&
       (NULL != plugin->sockv4) &&
       (addrlen == sizeof (struct sockaddr_in)) )
  {
#if LINUX
    /*
     * setup Cryogenic FD for ipv4 broadcasting
     */
    char *filename;

    GNUNET_asprintf (&filename,
                     "/dev/cryogenic/%s",
                     name);
    if (0 == ACCESS (name, R_OK))
    {
      ba->cryogenic_fd =
        GNUNET_DISK_file_open (filename,
                               GNUNET_DISK_OPEN_WRITE,
                               GNUNET_DISK_PERM_NONE);
    }
    GNUNET_free (filename);
#endif
    ba->broadcast_task =
        GNUNET_SCHEDULER_add_now (&udp_ipv4_broadcast_send, ba);
  }
  if ((GNUNET_YES == plugin->enable_ipv6) &&
      (NULL != plugin->sockv6) &&
      (addrlen == sizeof (struct sockaddr_in6)))
  {
    /* Create IPv6 multicast request */
    struct ipv6_mreq multicastRequest;
    const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *) broadcast_addr;

    multicastRequest.ipv6mr_multiaddr =
        plugin->ipv6_multicast_address.sin6_addr;
    /* http://tools.ietf.org/html/rfc2553#section-5.2:
     *
     * IPV6_JOIN_GROUP
     *
     * Join a multicast group on a specified local interface.  If the
     * interface index is specified as 0, the kernel chooses the local
     * interface.  For example, some kernels look up the multicast
     * group in the normal IPv6 routing table and using the resulting
     * interface; we do this for each interface, so no need to use
     * zero (anymore...).
     */
    multicastRequest.ipv6mr_interface = s6->sin6_scope_id;

    /* Join the multicast group */
    if (GNUNET_OK !=
        GNUNET_NETWORK_socket_setsockopt
        (plugin->sockv6, IPPROTO_IPV6, IPV6_JOIN_GROUP,
         &multicastRequest, sizeof (multicastRequest)))
    {
      LOG (GNUNET_ERROR_TYPE_WARNING,
      "Failed to join IPv6 multicast group: IPv6 broadcasting not running\n");
    }
    else
    {
#if LINUX
      /*
       * setup Cryogenic FD for ipv6 broadcasting
       */
      char *filename;

      GNUNET_asprintf (&filename,
                       "/dev/cryogenic/%s",
                       name);
      if (0 == ACCESS (name, R_OK))
      {
        ba->cryogenic_fd =
          GNUNET_DISK_file_open (filename,
                                 GNUNET_DISK_OPEN_WRITE,
                                 GNUNET_DISK_PERM_NONE);
      }
      GNUNET_free (filename);
#endif
      ba->broadcast_task =
          GNUNET_SCHEDULER_add_now (&udp_ipv6_broadcast_send, ba);
    }
  }
  GNUNET_CONTAINER_DLL_insert (plugin->broadcast_head,
                               plugin->broadcast_tail, ba);
  return GNUNET_OK;
}


void
setup_broadcast (struct Plugin *plugin,
                 struct sockaddr_in6 *server_addrv6,
                 struct sockaddr_in *server_addrv4)
{
  const struct GNUNET_MessageHeader *hello;

  hello = plugin->env->get_our_hello ();
  if (GNUNET_YES ==
      GNUNET_HELLO_is_friend_only ((const struct GNUNET_HELLO_Message *) hello))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         _("Disabling HELLO broadcasting due to friend-to-friend only configuration!\n"));
    return;
  }

  /* always create tokenizers */
  plugin->broadcast_ipv4_mst =
    GNUNET_SERVER_mst_create (&broadcast_ipv4_mst_cb, plugin);
  plugin->broadcast_ipv6_mst =
    GNUNET_SERVER_mst_create (&broadcast_ipv6_mst_cb, plugin);

  if (GNUNET_YES != plugin->enable_broadcasting)
    return; /* We do not send, just receive */

  /* create IPv4 broadcast socket */
  if ((GNUNET_YES == plugin->enable_ipv4) && (NULL != plugin->sockv4))
  {
    static int yes = 1;

    if (GNUNET_NETWORK_socket_setsockopt
        (plugin->sockv4, SOL_SOCKET, SO_BROADCAST, &yes,
         sizeof (int)) != GNUNET_OK)
    {
      LOG (GNUNET_ERROR_TYPE_WARNING,
           _("Failed to set IPv4 broadcast option for broadcast socket on port %d\n"),
           ntohs (server_addrv4->sin_port));
    }
  }
  /* create IPv6 multicast socket */
  if ((GNUNET_YES == plugin->enable_ipv6) && (plugin->sockv6 != NULL))
  {
    memset (&plugin->ipv6_multicast_address, 0, sizeof (struct sockaddr_in6));
    GNUNET_assert (1 ==
                   inet_pton (AF_INET6, "FF05::13B",
                              &plugin->ipv6_multicast_address.sin6_addr));
    plugin->ipv6_multicast_address.sin6_family = AF_INET6;
    plugin->ipv6_multicast_address.sin6_port = htons (plugin->port);
  }
  GNUNET_OS_network_interfaces_list (&iface_proc, plugin);
}


void
stop_broadcast (struct Plugin *plugin)
{
  if (GNUNET_YES == plugin->enable_broadcasting)
  {
    /* Disable broadcasting */
    while (plugin->broadcast_head != NULL)
    {
      struct BroadcastAddress *p = plugin->broadcast_head;

      if (p->broadcast_task != NULL)
      {
        GNUNET_SCHEDULER_cancel (p->broadcast_task);
        p->broadcast_task = NULL;
      }
      if ((GNUNET_YES == plugin->enable_ipv6) &&
          (NULL != plugin->sockv6) &&
          (p->addrlen == sizeof (struct sockaddr_in6)))
      {
        /* Create IPv6 multicast request */
        struct ipv6_mreq multicastRequest;
        const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *) p->addr;

        multicastRequest.ipv6mr_multiaddr =
          plugin->ipv6_multicast_address.sin6_addr;
        multicastRequest.ipv6mr_interface = s6->sin6_scope_id;

        /* Leave the multicast group */
        if (GNUNET_OK ==
            GNUNET_NETWORK_socket_setsockopt
            (plugin->sockv6, IPPROTO_IPV6, IPV6_LEAVE_GROUP,
             &multicastRequest, sizeof (multicastRequest)))
        {
          GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "setsockopt");
        }
        else
        {
          LOG (GNUNET_ERROR_TYPE_DEBUG, "IPv6 multicasting stopped\n");
        }
      }

#if LINUX
    GNUNET_DISK_file_close(p->cryogenic_fd);
#endif
      GNUNET_CONTAINER_DLL_remove (plugin->broadcast_head,
                                   plugin->broadcast_tail, p);
      GNUNET_free (p->addr);
      GNUNET_free (p);
    }
  }

  /* Destroy MSTs */
  if (NULL != plugin->broadcast_ipv4_mst)
  {
    GNUNET_SERVER_mst_destroy (plugin->broadcast_ipv4_mst);
    plugin->broadcast_ipv4_mst = NULL;
  }
  if (NULL != plugin->broadcast_ipv6_mst)
  {
    GNUNET_SERVER_mst_destroy (plugin->broadcast_ipv6_mst);
    plugin->broadcast_ipv6_mst = NULL;
  }
}

/* end of plugin_transport_udp_broadcasting.c */
