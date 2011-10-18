/*
     This file is part of GNUnet.
     (C) 2010 Christian Grothoff

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
 * @file vpn/gnunet-daemon-exit.c
 * @brief
 * @author Philipp Toelke
 */
#include <platform.h>
#include <gnunet_common.h>
#include <gnunet_program_lib.h>
#include <gnunet_protocols.h>
#include <gnunet_applications.h>
#include <gnunet_mesh_service.h>
#include <gnunet_constants.h>
#include <string.h>

#include "gnunet-vpn-packet.h"
#include "gnunet-helper-vpn-api.h"
#include "gnunet-vpn-checksum.h"

GNUNET_SCHEDULER_TaskIdentifier shs_task;

/**
 * The handle to the configuration used throughout the process
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * The handle to the helper
 */
struct GNUNET_VPN_HELPER_Handle *helper_handle;

/**
 * Final status code.
 */
static int ret;

/**
 * The handle to mesh
 */
static struct GNUNET_MESH_Handle *mesh_handle;

/**
 * This hashmaps contains the mapping from peer, service-descriptor,
 * source-port and destination-port to a struct redirect_state
 */
static struct GNUNET_CONTAINER_MultiHashMap *udp_connections;
static struct GNUNET_CONTAINER_Heap *udp_connections_heap;
static struct GNUNET_CONTAINER_MultiHashMap *tcp_connections;
static struct GNUNET_CONTAINER_Heap *tcp_connections_heap;

/**
 * If there are at least this many udp-Connections, old ones will be removed
 */
static long long unsigned int max_udp_connections = 200;

/**
 * If there are at least this many tcp-Connections, old ones will be removed
 */
static long long unsigned int max_tcp_connections = 200;

struct remote_addr
{
  char addrlen;
  unsigned char addr[16];
  char proto;
};

/**
 * This struct is saved into the services-hashmap
 */
struct redirect_service
{
  /**
   * One of 4 or 6
   */
  unsigned int version;
  uint16_t my_port;
  uint16_t remote_port;

  union
  {
    struct
    {
      char ip4address[4];
    } v4;
    struct
    {
      char ip6address[16];
    } v6;
  };
};

struct redirect_info
{
    /**
     * The source-address of this connection. When a packet to this address is
     * received, this tunnel is used to forward it.  ipv4-addresses will be put
     * here left-aligned */
  char addr[16];
    /**
     * The source-port of this connection
     */
  uint16_t pt;
};

/**
 * This struct is saved into {tcp,udp}_connections;
 */
struct redirect_state
{
  struct GNUNET_MESH_Tunnel *tunnel;
  GNUNET_HashCode desc;
  struct redirect_service *serv;
  struct remote_addr remote;

  struct GNUNET_CONTAINER_HeapNode *heap_node;
  struct GNUNET_CONTAINER_MultiHashMap *hashmap;
  GNUNET_HashCode hash;

  enum
  { SERVICE, REMOTE } type;

  /**
   * The source-address and -port of this connection
   */
  struct redirect_info redirect_info;
};

/**
 * This hashmaps saves interesting things about the configured services
 */
static struct GNUNET_CONTAINER_MultiHashMap *udp_services;
static struct GNUNET_CONTAINER_MultiHashMap *tcp_services;

struct tunnel_notify_queue
{
  struct tunnel_notify_queue *next;
  struct tunnel_notify_queue *prev;
  void *cls;
  size_t len;
};

/**
 * Function that frees everything from a hashmap
 */
static int
free_iterate (void *cls __attribute__ ((unused)), const GNUNET_HashCode * hash
              __attribute__ ((unused)), void *value)
{
  GNUNET_free (value);
  return GNUNET_YES;
}

/**
 * Function scheduled as very last function, cleans up after us
 */
static void
cleanup (void *cls
         __attribute__ ((unused)),
         const struct GNUNET_SCHEDULER_TaskContext *tskctx)
{
  GNUNET_assert (0 != (tskctx->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN));

  GNUNET_CONTAINER_multihashmap_iterate (udp_connections, free_iterate, NULL);

  GNUNET_CONTAINER_multihashmap_iterate (tcp_connections, free_iterate, NULL);

  if (mesh_handle != NULL)
  {
    GNUNET_MESH_disconnect (mesh_handle);
    mesh_handle = NULL;
  }
}

static void
collect_connections (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if ((tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) != 0)
    return;


  struct GNUNET_CONTAINER_Heap *heap = cls;

  struct redirect_state *state = GNUNET_CONTAINER_heap_remove_root (heap);

  /* This is free()ed memory! */
  state->heap_node = NULL;

  /* FIXME! GNUNET_MESH_close_tunnel(state->tunnel); */

  GNUNET_assert (GNUNET_OK ==
		 GNUNET_CONTAINER_multihashmap_remove (state->hashmap, &state->hash, state));

  GNUNET_free (state);
}

static void
hash_redirect_info (GNUNET_HashCode * hash, struct redirect_info *u_i,
                    size_t addrlen)
{

  /* the gnunet hashmap only uses the first sizeof(unsigned int) of the hash
   *
   * build the hash out of the last bytes of the address and the 2 bytes of
   * the port
   */
  memcpy (hash, &u_i->pt, sizeof (u_i->pt));
  memcpy (((unsigned char *) hash) + 2,
          u_i->addr + (addrlen - (sizeof (unsigned int) - 2)),
          (sizeof (unsigned int) - 2));
  memset (((unsigned char *) hash) + sizeof (unsigned int), 0,
          sizeof (GNUNET_HashCode) - sizeof (unsigned int));
}

/**
 * cls is the pointer to a GNUNET_MessageHeader that is
 * followed by the service-descriptor and the udp-packet that should be sent;
 */
static size_t
send_udp_to_peer_notify_callback (void *cls, size_t size, void *buf)
{
  struct GNUNET_MESH_Tunnel **tunnel = cls;

  GNUNET_MESH_tunnel_set_data (*tunnel, NULL);
  struct GNUNET_MessageHeader *hdr =
      (struct GNUNET_MessageHeader *) (tunnel + 1);
  GNUNET_assert (size >= ntohs (hdr->size));
  memcpy (buf, hdr, ntohs (hdr->size));
  size = ntohs (hdr->size);

  if (NULL != GNUNET_MESH_tunnel_get_head (*tunnel))
  {
    struct tunnel_notify_queue *element = GNUNET_MESH_tunnel_get_head (*tunnel);
    struct tunnel_notify_queue *head = GNUNET_MESH_tunnel_get_head (*tunnel);
    struct tunnel_notify_queue *tail = GNUNET_MESH_tunnel_get_tail (*tunnel);

    GNUNET_CONTAINER_DLL_remove (head, tail, element);

    GNUNET_MESH_tunnel_set_head (*tunnel, head);
    GNUNET_MESH_tunnel_set_tail (*tunnel, tail);

    struct GNUNET_MESH_TransmitHandle *th =
        GNUNET_MESH_notify_transmit_ready (*tunnel,
                                           GNUNET_NO,
                                           42,
                                           GNUNET_TIME_relative_divide
                                           (GNUNET_CONSTANTS_MAX_CORK_DELAY, 2),
                                           (const struct GNUNET_PeerIdentity *)
                                           NULL, element->len,
                                           send_udp_to_peer_notify_callback,
                                           element->cls);

    /* save the handle */
    GNUNET_MESH_tunnel_set_data (*tunnel, th);
    GNUNET_free (element);
  }

  GNUNET_free (cls);

  return size;
}

/**
 * @brief Handles an UDP-Packet received from the helper.
 *
 * @param udp A pointer to the Packet
 * @param dadr The IP-Destination-address
 * @param addrlen The length of the address
 */
static void
udp_from_helper (struct udp_pkt *udp, unsigned char *dadr, size_t addrlen)
{
  struct redirect_info u_i;
  struct GNUNET_MESH_Tunnel *tunnel;
  uint32_t len;
  struct GNUNET_MessageHeader *msg;

  memset (&u_i, 0, sizeof (struct redirect_info));

  memcpy (&u_i.addr, dadr, addrlen);

  u_i.pt = udp->dpt;

  /* get tunnel and service-descriptor from this */
  GNUNET_HashCode hash;

  hash_redirect_info (&hash, &u_i, addrlen);

  struct redirect_state *state =
      GNUNET_CONTAINER_multihashmap_get (udp_connections, &hash);

  /* Mark this connection as freshly used */
  GNUNET_CONTAINER_heap_update_cost (udp_connections_heap, state->heap_node,
                                     GNUNET_TIME_absolute_get ().abs_value);

  tunnel = state->tunnel;

  if (state->type == SERVICE)
  {
    /* check if spt == serv.remote if yes: set spt = serv.myport ("nat") */
    if (ntohs (udp->spt) == state->serv->remote_port)
    {
      udp->spt = htons (state->serv->my_port);
    }
    else
    {
      /* otherwise the answer came from a different port (tftp does this)
       * add this new port to the list of all services, so that the packets
       * coming back from the client to this new port will be routed correctly
       */
      struct redirect_service *serv =
          GNUNET_malloc (sizeof (struct redirect_service));
      memcpy (serv, state->serv, sizeof (struct redirect_service));
      serv->my_port = ntohs (udp->spt);
      serv->remote_port = ntohs (udp->spt);
      uint16_t *desc = alloca (sizeof (GNUNET_HashCode) + 2);

      memcpy ((GNUNET_HashCode *) (desc + 1), &state->desc,
              sizeof (GNUNET_HashCode));
      *desc = ntohs (udp->spt);
      GNUNET_assert (GNUNET_OK ==
                     GNUNET_CONTAINER_multihashmap_put (udp_services,
                                                        (GNUNET_HashCode *)
                                                        desc, serv,
                                                        GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));

      state->serv = serv;
    }
  }

  /* send udp-packet back */
  len =
      sizeof (struct GNUNET_MessageHeader) + sizeof (GNUNET_HashCode) +
      ntohs (udp->len);
  struct GNUNET_MESH_Tunnel **ctunnel =
      GNUNET_malloc (sizeof (struct GNUNET_MESH_TUNNEL *) + len);
  *ctunnel = tunnel;
  msg = (struct GNUNET_MessageHeader *) (ctunnel + 1);
  msg->size = htons (len);
  msg->type =
      htons (state->type ==
             SERVICE ? GNUNET_MESSAGE_TYPE_VPN_SERVICE_UDP_BACK :
             GNUNET_MESSAGE_TYPE_VPN_REMOTE_UDP_BACK);
  GNUNET_HashCode *desc = (GNUNET_HashCode *) (msg + 1);

  if (state->type == SERVICE)
    memcpy (desc, &state->desc, sizeof (GNUNET_HashCode));
  else
    memcpy (desc, &state->remote, sizeof (struct remote_addr));
  void *_udp = desc + 1;

  memcpy (_udp, udp, ntohs (udp->len));

  if (NULL == GNUNET_MESH_tunnel_get_data (tunnel))
  {
    /* No notify is pending */
    struct GNUNET_MESH_TransmitHandle *th =
        GNUNET_MESH_notify_transmit_ready (tunnel,
                                           GNUNET_NO,
                                           42,
                                           GNUNET_TIME_relative_divide
                                           (GNUNET_CONSTANTS_MAX_CORK_DELAY, 2),
                                           (const struct GNUNET_PeerIdentity *)
                                           NULL, len,
                                           send_udp_to_peer_notify_callback,
                                           ctunnel);

    /* save the handle */
    GNUNET_MESH_tunnel_set_data (tunnel, th);
  }
  else
  {
    struct tunnel_notify_queue *head = GNUNET_MESH_tunnel_get_head (tunnel);
    struct tunnel_notify_queue *tail = GNUNET_MESH_tunnel_get_tail (tunnel);

    struct tunnel_notify_queue *element =
        GNUNET_malloc (sizeof (struct tunnel_notify_queue));
    element->cls = ctunnel;
    element->len = len;

    GNUNET_CONTAINER_DLL_insert_tail (head, tail, element);
    GNUNET_MESH_tunnel_set_head (tunnel, head);
    GNUNET_MESH_tunnel_set_tail (tunnel, tail);
  }
}

/**
 * @brief Handles a TCP-Packet received from the helper.
 *
 * @param tcp A pointer to the Packet
 * @param dadr The IP-Destination-address
 * @param addrlen The length of the address
 * @param pktlen the length of the packet, including its header
 */
static void
tcp_from_helper (struct tcp_pkt *tcp, unsigned char *dadr, size_t addrlen,
                 size_t pktlen)
{
  struct redirect_info u_i;
  struct GNUNET_MESH_Tunnel *tunnel;
  uint32_t len;
  struct GNUNET_MessageHeader *msg;

  memset (&u_i, 0, sizeof (struct redirect_info));

  memcpy (&u_i.addr, dadr, addrlen);
  u_i.pt = tcp->dpt;

  /* get tunnel and service-descriptor from this */
  GNUNET_HashCode hash;

  hash_redirect_info (&hash, &u_i, addrlen);

  struct redirect_state *state =
      GNUNET_CONTAINER_multihashmap_get (tcp_connections, &hash);

  if (state == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "No mapping for this connection; hash is %x\n",
                *((uint32_t *) & hash));
    return;
  }

  /* Mark this connection as freshly used */
  GNUNET_CONTAINER_heap_update_cost (tcp_connections_heap, state->heap_node,
                                     GNUNET_TIME_absolute_get ().abs_value);

  tunnel = state->tunnel;

  if (state->type == SERVICE)
  {
    /* check if spt == serv.remote if yes: set spt = serv.myport ("nat") */
    if (ntohs (tcp->spt) == state->serv->remote_port)
    {
      tcp->spt = htons (state->serv->my_port);
    }
    else
    {
      // This is an illegal packet.
      return;
    }
  }

  /* send tcp-packet back */
  len =
      sizeof (struct GNUNET_MessageHeader) + sizeof (GNUNET_HashCode) + pktlen;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "len: %d\n", pktlen);
  struct GNUNET_MESH_Tunnel **ctunnel =
      GNUNET_malloc (sizeof (struct GNUNET_MESH_TUNNEL *) + len);
  *ctunnel = tunnel;
  msg = (struct GNUNET_MessageHeader *) (ctunnel + 1);
  msg->size = htons (len);
  msg->type =
      htons (state->type ==
             SERVICE ? GNUNET_MESSAGE_TYPE_VPN_SERVICE_TCP_BACK :
             GNUNET_MESSAGE_TYPE_VPN_REMOTE_TCP_BACK);
  GNUNET_HashCode *desc = (GNUNET_HashCode *) (msg + 1);

  if (state->type == SERVICE)
    memcpy (desc, &state->desc, sizeof (GNUNET_HashCode));
  else
    memcpy (desc, &state->remote, sizeof (struct remote_addr));
  void *_tcp = desc + 1;

  memcpy (_tcp, tcp, pktlen);

  if (NULL == GNUNET_MESH_tunnel_get_data (tunnel))
  {
    /* No notify is pending */
    struct GNUNET_MESH_TransmitHandle *th =
        GNUNET_MESH_notify_transmit_ready (tunnel,
                                           GNUNET_NO,
                                           42,
                                           GNUNET_TIME_relative_divide
                                           (GNUNET_CONSTANTS_MAX_CORK_DELAY, 2),
                                           (const struct GNUNET_PeerIdentity *)
                                           NULL,
                                           len,
                                           send_udp_to_peer_notify_callback,
                                           ctunnel);

    /* save the handle */
    GNUNET_MESH_tunnel_set_data (tunnel, th);
  }
  else
  {
    struct tunnel_notify_queue *head = GNUNET_MESH_tunnel_get_head (tunnel);
    struct tunnel_notify_queue *tail = GNUNET_MESH_tunnel_get_tail (tunnel);

    struct tunnel_notify_queue *element =
        GNUNET_malloc (sizeof (struct tunnel_notify_queue));
    element->cls = ctunnel;
    element->len = len;

    GNUNET_CONTAINER_DLL_insert_tail (head, tail, element);
    GNUNET_MESH_tunnel_set_head (tunnel, head);
    GNUNET_MESH_tunnel_set_tail (tunnel, tail);
  }
}


/**
 * Receive packets from the helper-process
 */
static void
message_token (void *cls __attribute__ ((unused)), void *client
               __attribute__ ((unused)),
               const struct GNUNET_MessageHeader *message)
{
  GNUNET_assert (ntohs (message->type) == GNUNET_MESSAGE_TYPE_VPN_HELPER);

  struct tun_pkt *pkt_tun = (struct tun_pkt *) message;

  /* ethertype is ipv6 */
  if (ntohs (pkt_tun->tun.type) == 0x86dd)
  {
    struct ip6_pkt *pkt6 = (struct ip6_pkt *) pkt_tun;

    if (IPPROTO_UDP == pkt6->ip6_hdr.nxthdr)
      udp_from_helper (&((struct ip6_udp *) pkt6)->udp_hdr,
                       (unsigned char *) &pkt6->ip6_hdr.dadr, 16);
    else if (IPPROTO_TCP == pkt6->ip6_hdr.nxthdr)
      tcp_from_helper (&((struct ip6_tcp *) pkt6)->tcp_hdr,
                       (unsigned char *) &pkt6->ip6_hdr.dadr, 16,
                       ntohs (pkt6->ip6_hdr.paylgth));
  }
  else if (ntohs (pkt_tun->tun.type) == 0x0800)
  {
    struct ip_pkt *pkt4 = (struct ip_pkt *) pkt_tun;
    uint32_t tmp = pkt4->ip_hdr.dadr;

    if (IPPROTO_UDP == pkt4->ip_hdr.proto)
      udp_from_helper (&((struct ip_udp *) pkt4)->udp_hdr,
                       (unsigned char *) &tmp, 4);
    else if (IPPROTO_TCP == pkt4->ip_hdr.proto)
    {
      size_t pktlen = ntohs (pkt4->ip_hdr.tot_lngth);

      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "tot: %d\n", pktlen);
      pktlen -= 4 * pkt4->ip_hdr.hdr_lngth;
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "-hdr: %d\n", pktlen);
      tcp_from_helper (&((struct ip_tcp *) pkt4)->tcp_hdr,
                       (unsigned char *) &tmp, 4, pktlen);
    }
  }
  else
  {
    return;
  }
}

/**
 * Reads the configuration servicecfg and populates udp_services
 *
 * @param cls unused
 * @param section name of section in config, equal to hostname
 */
static void
read_service_conf (void *cls __attribute__ ((unused)), const char *section)
{
  if ((strlen (section) < 8) ||
      (0 != strcmp (".gnunet.", section + (strlen (section) - 8))))
    return;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Parsing dns-name %d %s %s\n",
              strlen (section), section, section + (strlen (section) - 8));

  char *cpy;
  char *redirect;
  char *hostname;
  char *hostport;
  uint16_t *desc = alloca (sizeof (GNUNET_HashCode) + 2);

  GNUNET_CRYPTO_hash (section, strlen (section) + 1,
                      (GNUNET_HashCode *) (desc + 1));

#define TCP 2
#define UDP 1

  int proto = UDP;

  do
  {
    if (proto == UDP &&
        (GNUNET_OK !=
         GNUNET_CONFIGURATION_get_value_string (cfg, section, "UDP_REDIRECTS",
                                                &cpy)))
      goto next;
    else if (proto == TCP &&
             (GNUNET_OK !=
              GNUNET_CONFIGURATION_get_value_string (cfg, section,
                                                     "TCP_REDIRECTS", &cpy)))
      goto next;

    for (redirect = strtok (cpy, " "); redirect != NULL;
         redirect = strtok (NULL, " "))
    {
      if (NULL == (hostname = strstr (redirect, ":")))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                    "Warning: option %s is not formatted correctly!\n",
                    redirect);
        continue;
      }
      hostname[0] = '\0';
      hostname++;
      if (NULL == (hostport = strstr (hostname, ":")))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                    "Warning: option %s is not formatted correctly!\n",
                    redirect);
        continue;
      }
      hostport[0] = '\0';
      hostport++;

      int local_port = atoi (redirect);

      if (!((local_port > 0) && (local_port < 65536)))
        GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                    "Warning: %s is not a correct port.", redirect);

      *desc = local_port;

      struct redirect_service *serv =
          GNUNET_malloc (sizeof (struct redirect_service));
      serv->my_port = local_port;

      if (0 == strcmp ("localhost4", hostname))
      {
        serv->version = 4;

        char *ip4addr;

        GNUNET_assert (GNUNET_OK ==
                       GNUNET_CONFIGURATION_get_value_string (cfg, "exit",
                                                              "IPV4ADDR",
                                                              &ip4addr));
        GNUNET_assert (1 == inet_pton (AF_INET, ip4addr, serv->v4.ip4address));
        GNUNET_free (ip4addr);
      }
      else if (0 == strcmp ("localhost6", hostname))
      {
        serv->version = 6;

        char *ip6addr;

        GNUNET_assert (GNUNET_OK ==
                       GNUNET_CONFIGURATION_get_value_string (cfg, "exit",
                                                              "IPV6ADDR",
                                                              &ip6addr));
        GNUNET_assert (1 == inet_pton (AF_INET6, ip6addr, serv->v6.ip6address));
        GNUNET_free (ip6addr);
      }
      else
      {
        struct addrinfo* res;

        int ret = getaddrinfo(hostname, NULL, NULL, &res);

        if (ret != 0)
          {
            GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "No addresses found for %s!\n", hostname);
            continue;
          }
        else
          {
            char buf[256];
            struct addrinfo* c = res;

            if(c)
              {
                if (c->ai_family == AF_INET)
                  {
                    serv->version = 4;
                    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Found %s as address for %s\n", inet_ntop(c->ai_family, &((struct sockaddr_in *)(c->ai_addr))->sin_addr, (char*)&buf, 256), hostname);
                    memcpy(serv->v4.ip4address, &((struct sockaddr_in *)(c->ai_addr))->sin_addr, 4);
                  }
                else if (c->ai_family == AF_INET6)
                  {
                    serv->version = 6;
                    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Found %s as address for %s\n", inet_ntop(c->ai_family, &((struct sockaddr_in6*)(c->ai_addr))->sin6_addr, (char*)&buf, 256), hostname);
                    memcpy(serv->v6.ip6address, &((struct sockaddr_in6 *)(c->ai_addr))->sin6_addr, 16);
                  }
              }
            else
              {
                freeaddrinfo(res);
                continue;
              }
            freeaddrinfo(res);
          }
      }
      serv->remote_port = atoi (hostport);
      if (UDP == proto)
        GNUNET_assert (GNUNET_OK ==
                       GNUNET_CONTAINER_multihashmap_put (udp_services,
                                                          (GNUNET_HashCode *)
                                                          desc, serv,
                                                          GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
      else
        GNUNET_assert (GNUNET_OK ==
                       GNUNET_CONTAINER_multihashmap_put (tcp_services,
                                                          (GNUNET_HashCode *)
                                                          desc, serv,
                                                          GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));

    }
    GNUNET_free (cpy);
next:
    proto = (proto == UDP) ? TCP : UDP;
  }
  while (proto != UDP);
}

/**
 * Start the helper-process
 *
 * If cls != NULL it is assumed that this function is called as a result of a dying
 * helper. cls is then taken as handle to the old helper and is cleaned up.
 */
static void
start_helper_and_schedule (void *cls,
                           const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;

  if (cls != NULL)
    cleanup_helper (cls);
  cls = NULL;

  char *ifname;
  char *ipv6addr;
  char *ipv6prefix;
  char *ipv4addr;
  char *ipv4mask;

  if (GNUNET_SYSERR ==
      GNUNET_CONFIGURATION_get_value_string (cfg, "exit", "IFNAME", &ifname))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "No entry 'IFNAME' in configuration!\n");
    exit (1);
  }

  if (GNUNET_SYSERR ==
      GNUNET_CONFIGURATION_get_value_string (cfg, "exit", "IPV6ADDR",
                                             &ipv6addr))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "No entry 'IPV6ADDR' in configuration!\n");
    exit (1);
  }

  if (GNUNET_SYSERR ==
      GNUNET_CONFIGURATION_get_value_string (cfg, "exit", "IPV6PREFIX",
                                             &ipv6prefix))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "No entry 'IPV6PREFIX' in configuration!\n");
    exit (1);
  }

  if (GNUNET_SYSERR ==
      GNUNET_CONFIGURATION_get_value_string (cfg, "exit", "IPV4ADDR",
                                             &ipv4addr))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "No entry 'IPV4ADDR' in configuration!\n");
    exit (1);
  }

  if (GNUNET_SYSERR ==
      GNUNET_CONFIGURATION_get_value_string (cfg, "exit", "IPV4MASK",
                                             &ipv4mask))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "No entry 'IPV4MASK' in configuration!\n");
    exit (1);
  }

  /* Start the helper
   * Messages get passed to the function message_token
   * When the helper dies, this function will be called again with the
   * helper_handle as cls.
   */
  helper_handle =
      start_helper (ifname, ipv6addr, ipv6prefix, ipv4addr, ipv4mask,
                    "exit-gnunet", start_helper_and_schedule, message_token,
                    NULL);

  GNUNET_free (ipv6addr);
  GNUNET_free (ipv6prefix);
  GNUNET_free (ipv4addr);
  GNUNET_free (ipv4mask);
  GNUNET_free (ifname);
}

static void
prepare_ipv4_packet (size_t len, uint16_t pktlen, void *payload,
                     uint16_t protocol, void *ipaddress, void *tunnel,
                     struct redirect_state *state, struct ip_pkt *pkt4)
{
  uint32_t tmp, tmp2;

  pkt4->shdr.type = htons (GNUNET_MESSAGE_TYPE_VPN_HELPER);
  pkt4->shdr.size = htons (len);
  pkt4->tun.flags = 0;
  pkt4->tun.type = htons (0x0800);

  memcpy (&pkt4->data, payload, pktlen);

  pkt4->ip_hdr.version = 4;
  pkt4->ip_hdr.hdr_lngth = 5;
  pkt4->ip_hdr.diff_serv = 0;
  pkt4->ip_hdr.tot_lngth = htons (20 + pktlen);
  pkt4->ip_hdr.ident = 0;
  pkt4->ip_hdr.flags = 0;
  pkt4->ip_hdr.frag_off = 0;
  pkt4->ip_hdr.ttl = 255;
  pkt4->ip_hdr.proto = protocol;
  pkt4->ip_hdr.chks = 0;        /* Will be calculated later */

  memcpy (&tmp, ipaddress, 4);
  pkt4->ip_hdr.dadr = tmp;

  /* Generate a new src-address */
  char *ipv4addr;
  char *ipv4mask;

  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONFIGURATION_get_value_string (cfg, "exit", "IPV4ADDR",
                                                        &ipv4addr));
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONFIGURATION_get_value_string (cfg, "exit", "IPV4MASK",
                                                        &ipv4mask));
  inet_pton (AF_INET, ipv4addr, &tmp);
  inet_pton (AF_INET, ipv4mask, &tmp2);
  GNUNET_free (ipv4addr);
  GNUNET_free (ipv4mask);

  /* This should be a noop */
  tmp = tmp & tmp2;

  tmp |= ntohl (*((uint32_t *) tunnel)) & (~tmp2);

  pkt4->ip_hdr.sadr = tmp;

  memcpy (&state->redirect_info.addr, &tmp, 4);
  if (IPPROTO_UDP == protocol)
  {
    struct ip_udp *pkt4_udp = (struct ip_udp *) pkt4;

    state->redirect_info.pt = pkt4_udp->udp_hdr.spt;

    pkt4_udp->udp_hdr.crc = 0;  /* Optional for IPv4 */
  }
  else if (IPPROTO_TCP == protocol)
  {
    struct ip_tcp *pkt4_tcp = (struct ip_tcp *) pkt4;

    state->redirect_info.pt = pkt4_tcp->tcp_hdr.spt;

    pkt4_tcp->tcp_hdr.crc = 0;
    uint32_t sum = 0;

    tmp = pkt4->ip_hdr.sadr;
    sum = calculate_checksum_update (sum, (uint16_t *) & tmp, 4);
    tmp = pkt4->ip_hdr.dadr;
    sum = calculate_checksum_update (sum, (uint16_t *) & tmp, 4);

    tmp = (protocol << 16) | (0xffff & pktlen);

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "line: %08x, %x \n", tmp,
                (0xffff & pktlen));

    tmp = htonl (tmp);

    sum = calculate_checksum_update (sum, (uint16_t *) & tmp, 4);

    sum =
        calculate_checksum_update (sum, (uint16_t *) & pkt4_tcp->tcp_hdr,
                                   pktlen);
    pkt4_tcp->tcp_hdr.crc = calculate_checksum_end (sum);
  }

  pkt4->ip_hdr.chks =
      calculate_ip_checksum ((uint16_t *) & pkt4->ip_hdr, 5 * 4);
}

static void
prepare_ipv6_packet (size_t len, uint16_t pktlen, void *payload,
                     uint16_t protocol, void *ipaddress, void *tunnel,
                     struct redirect_state *state, struct ip6_pkt *pkt6)
{
  uint32_t tmp;

  pkt6->shdr.type = htons (GNUNET_MESSAGE_TYPE_VPN_HELPER);
  pkt6->shdr.size = htons (len);
  pkt6->tun.flags = 0;

  pkt6->tun.type = htons (0x86dd);

  memcpy (&pkt6->data, payload, pktlen);

  pkt6->ip6_hdr.version = 6;
  pkt6->ip6_hdr.nxthdr = protocol;
  pkt6->ip6_hdr.paylgth = htons (pktlen);
  pkt6->ip6_hdr.hoplmt = 64;

  memcpy (pkt6->ip6_hdr.dadr, ipaddress, 16);

  /* Generate a new src-address
   * This takes as much from the address of the tunnel as fits into
   * the host-mask*/
  char *ipv6addr;
  unsigned long long ipv6prefix;

  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONFIGURATION_get_value_string (cfg, "exit", "IPV6ADDR",
                                                        &ipv6addr));
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONFIGURATION_get_value_number (cfg, "exit",
                                                        "IPV6PREFIX",
                                                        &ipv6prefix));
  GNUNET_assert (ipv6prefix < 127);
  ipv6prefix = (ipv6prefix + 7) / 8;

  inet_pton (AF_INET6, ipv6addr, &pkt6->ip6_hdr.sadr);
  GNUNET_free (ipv6addr);

  if (ipv6prefix < (16 - sizeof (void *)))
    ipv6prefix = 16 - sizeof (void *);

  unsigned int offset = ipv6prefix - (16 - sizeof (void *));

  memcpy ((((char *) &pkt6->ip6_hdr.sadr)) + ipv6prefix,
          ((char *) &tunnel) + offset, 16 - ipv6prefix);

  /* copy the needed information into the state */
  memcpy (&state->redirect_info.addr, &pkt6->ip6_hdr.sadr, 16);

  if (IPPROTO_UDP == protocol)
  {
    struct ip6_udp *pkt6_udp = (struct ip6_udp *) pkt6;

    state->redirect_info.pt = pkt6_udp->udp_hdr.spt;

    pkt6_udp->udp_hdr.crc = 0;
    uint32_t sum = 0;

    sum =
        calculate_checksum_update (sum, (uint16_t *) & pkt6_udp->ip6_hdr.sadr,
                                   16);
    sum =
        calculate_checksum_update (sum, (uint16_t *) & pkt6_udp->ip6_hdr.dadr,
                                   16);
    tmp = (htons (pktlen) & 0xffff);
    sum = calculate_checksum_update (sum, (uint16_t *) & tmp, 4);
    tmp = htons (((pkt6_udp->ip6_hdr.nxthdr & 0x00ff)));
    sum = calculate_checksum_update (sum, (uint16_t *) & tmp, 4);

    sum =
        calculate_checksum_update (sum, (uint16_t *) & pkt6_udp->udp_hdr,
                                   ntohs (pkt6_udp->udp_hdr.len));
    pkt6_udp->udp_hdr.crc = calculate_checksum_end (sum);
  }
  else if (IPPROTO_TCP == protocol)
  {
    struct ip6_tcp *pkt6_tcp = (struct ip6_tcp *) pkt6;

    state->redirect_info.pt = pkt6_tcp->tcp_hdr.spt;

    pkt6_tcp->tcp_hdr.crc = 0;
    uint32_t sum = 0;

    sum =
        calculate_checksum_update (sum, (uint16_t *) & pkt6->ip6_hdr.sadr, 16);
    sum =
        calculate_checksum_update (sum, (uint16_t *) & pkt6->ip6_hdr.dadr, 16);
    tmp = htonl (pktlen);
    sum = calculate_checksum_update (sum, (uint16_t *) & tmp, 4);
    tmp = htonl (((pkt6->ip6_hdr.nxthdr & 0x000000ff)));
    sum = calculate_checksum_update (sum, (uint16_t *) & tmp, 4);

    sum =
        calculate_checksum_update (sum, (uint16_t *) & pkt6_tcp->tcp_hdr,
                                   ntohs (pkt6->ip6_hdr.paylgth));
    pkt6_tcp->tcp_hdr.crc = calculate_checksum_end (sum);
  }
}

/**
 * The messages are one GNUNET_HashCode for the service followed by a struct tcp_pkt
 */
static int
receive_tcp_service (void *cls
                     __attribute__ ((unused)),
                     struct GNUNET_MESH_Tunnel *tunnel, void **tunnel_ctx
                     __attribute__ ((unused)),
                     const struct GNUNET_PeerIdentity *sender
                     __attribute__ ((unused)),
                     const struct GNUNET_MessageHeader *message,
                     const struct GNUNET_ATS_Information *atsi
                     __attribute__ ((unused)))
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received TCP-Packet\n");
  GNUNET_HashCode *desc = (GNUNET_HashCode *) (message + 1);
  struct tcp_pkt *pkt = (struct tcp_pkt *) (desc + 1);
  uint16_t pkt_len =
      ntohs (message->size) - sizeof (struct GNUNET_MessageHeader) -
      sizeof (GNUNET_HashCode);

  /** Get the configuration from the services-hashmap.
   *
   * Which service is needed only depends on the service-descriptor and the
   * destination-port
   */
  uint16_t *tcp_desc = alloca (sizeof (GNUNET_HashCode) + 2);

  memcpy (tcp_desc + 1, desc, sizeof (GNUNET_HashCode));
  *tcp_desc = ntohs (pkt->dpt);
  struct redirect_service *serv =
      GNUNET_CONTAINER_multihashmap_get (tcp_services,
                                         (GNUNET_HashCode *) tcp_desc);

  if (NULL == serv)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "No service found for TCP dpt %d!\n",
                *tcp_desc);
    return GNUNET_YES;
  }

  pkt->dpt = htons (serv->remote_port);

  /*
   * At this point it would be possible to check against some kind of ACL.
   */

  char *buf;
  size_t len;

  /* Prepare the state.
   * This will be saved in the hashmap, so that the receiving procedure knows
   * through which tunnel this connection has to be routed.
   */
  struct redirect_state *state = GNUNET_malloc (sizeof (struct redirect_state));

  state->tunnel = tunnel;
  state->serv = serv;
  state->type = SERVICE;
  state->hashmap = tcp_connections;
  memcpy (&state->desc, desc, sizeof (GNUNET_HashCode));

  len =
      sizeof (struct GNUNET_MessageHeader) + sizeof (struct pkt_tun) +
      sizeof (struct ip6_hdr) + pkt_len;
  buf = alloca (len);

  memset (buf, 0, len);

  switch (serv->version)
  {
  case 4:
    prepare_ipv4_packet (len, pkt_len, pkt, IPPROTO_TCP,
                         &serv->v4.ip4address, tunnel, state,
                         (struct ip_pkt *) buf);
    break;
  case 6:
    prepare_ipv6_packet (len, pkt_len, pkt, IPPROTO_TCP,
                         &serv->v6.ip6address, tunnel, state,
                         (struct ip6_pkt *) buf);

    break;
  default:
    GNUNET_assert (0);
    break;
  }

  hash_redirect_info (&state->hash, &state->redirect_info,
                      serv->version == 4 ? 4 : 16);

  if (GNUNET_NO ==
      GNUNET_CONTAINER_multihashmap_contains (tcp_connections, &state->hash))
  {
    GNUNET_CONTAINER_multihashmap_put (tcp_connections, &state->hash, state,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);

    state->heap_node =
        GNUNET_CONTAINER_heap_insert (tcp_connections_heap, state,
                                      GNUNET_TIME_absolute_get ().abs_value);

    if (GNUNET_CONTAINER_heap_get_size (tcp_connections_heap) >
        max_tcp_connections)
      GNUNET_SCHEDULER_add_now (collect_connections, tcp_connections_heap);
  }
  else
    GNUNET_free (state);

  (void) GNUNET_DISK_file_write (helper_handle->fh_to_helper, buf, len);
  return GNUNET_YES;
}

static int
receive_tcp_remote (void *cls
                    __attribute__ ((unused)), struct GNUNET_MESH_Tunnel *tunnel,
                    void **tunnel_ctx
                    __attribute__ ((unused)),
                    const struct GNUNET_PeerIdentity *sender
                    __attribute__ ((unused)),
                    const struct GNUNET_MessageHeader *message,
                    const struct GNUNET_ATS_Information *atsi
                    __attribute__ ((unused)))
{
  GNUNET_HashCode *desc = (GNUNET_HashCode *) (message + 1);
  struct tcp_pkt *pkt = (struct tcp_pkt *) (desc + 1);
  struct remote_addr *s = (struct remote_addr *) desc;
  char *buf;
  size_t len;
  uint16_t pkt_len =
      ntohs (message->size) - sizeof (struct GNUNET_MessageHeader) -
      sizeof (GNUNET_HashCode);

  struct redirect_state *state = GNUNET_malloc (sizeof (struct redirect_state));

  state->tunnel = tunnel;
  state->type = REMOTE;
  state->hashmap = tcp_connections;
  memcpy (&state->remote, s, sizeof (struct remote_addr));

  len =
      sizeof (struct GNUNET_MessageHeader) + sizeof (struct pkt_tun) +
      sizeof (struct ip6_hdr) + pkt_len;
  buf = alloca (len);

  memset (buf, 0, len);

  switch (s->addrlen)
  {
  case 4:
    prepare_ipv4_packet (len, pkt_len, pkt, IPPROTO_TCP,
                         &s->addr, tunnel, state, (struct ip_pkt *) buf);
    break;
  case 16:
    prepare_ipv6_packet (len, pkt_len, pkt, IPPROTO_TCP,
                         &s->addr, tunnel, state, (struct ip6_pkt *) buf);
    break;
  default:
    GNUNET_free (state);
    return GNUNET_SYSERR;
  }

  hash_redirect_info (&state->hash, &state->redirect_info, s->addrlen);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Packet from remote; hash is %x\n",
              *((uint32_t *) & state->hash));

  if (GNUNET_NO ==
      GNUNET_CONTAINER_multihashmap_contains (tcp_connections, &state->hash))
  {
    GNUNET_CONTAINER_multihashmap_put (tcp_connections, &state->hash, state,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);

    state->heap_node =
        GNUNET_CONTAINER_heap_insert (tcp_connections_heap, state,
                                      GNUNET_TIME_absolute_get ().abs_value);

    if (GNUNET_CONTAINER_heap_get_size (tcp_connections_heap) >
        max_tcp_connections)
      GNUNET_SCHEDULER_add_now (collect_connections, tcp_connections_heap);
  }
  else
    GNUNET_free (state);

  (void) GNUNET_DISK_file_write (helper_handle->fh_to_helper, buf, len);
  return GNUNET_YES;

}

static int
receive_udp_remote (void *cls
                    __attribute__ ((unused)), struct GNUNET_MESH_Tunnel *tunnel,
                    void **tunnel_ctx
                    __attribute__ ((unused)),
                    const struct GNUNET_PeerIdentity *sender
                    __attribute__ ((unused)),
                    const struct GNUNET_MessageHeader *message,
                    const struct GNUNET_ATS_Information *atsi
                    __attribute__ ((unused)))
{
  GNUNET_HashCode *desc = (GNUNET_HashCode *) (message + 1);
  struct udp_pkt *pkt = (struct udp_pkt *) (desc + 1);
  struct remote_addr *s = (struct remote_addr *) desc;
  char *buf;
  size_t len;

  GNUNET_assert (ntohs (pkt->len) ==
                 ntohs (message->size) - sizeof (struct GNUNET_MessageHeader) -
                 sizeof (GNUNET_HashCode));

  /* Prepare the state.
   * This will be saved in the hashmap, so that the receiving procedure knows
   * through which tunnel this connection has to be routed.
   */
  struct redirect_state *state = GNUNET_malloc (sizeof (struct redirect_state));

  state->tunnel = tunnel;
  state->hashmap = udp_connections;
  state->type = REMOTE;
  memcpy (&state->remote, s, sizeof (struct remote_addr));

  len =
      sizeof (struct GNUNET_MessageHeader) + sizeof (struct pkt_tun) +
      sizeof (struct ip6_hdr) + ntohs (pkt->len);
  buf = alloca (len);

  memset (buf, 0, len);

  switch (s->addrlen)
  {
  case 4:
    prepare_ipv4_packet (len, ntohs (pkt->len), pkt, IPPROTO_UDP, 
                         &s->addr, tunnel, state, (struct ip_pkt *) buf);
    break;
  case 16:
    prepare_ipv6_packet (len, ntohs (pkt->len), pkt, IPPROTO_UDP, 
                         &s->addr, tunnel, state, (struct ip6_pkt *) buf);
    break;
  default:
    GNUNET_assert (0);
    break;
  }

  hash_redirect_info (&state->hash, &state->redirect_info, s->addrlen);

  if (GNUNET_NO ==
      GNUNET_CONTAINER_multihashmap_contains (udp_connections, &state->hash))
  {
    GNUNET_CONTAINER_multihashmap_put (udp_connections, &state->hash, state,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);

    state->heap_node =
        GNUNET_CONTAINER_heap_insert (udp_connections_heap, state,
                                      GNUNET_TIME_absolute_get ().abs_value);

    if (GNUNET_CONTAINER_heap_get_size (udp_connections_heap) >
        max_udp_connections)
      GNUNET_SCHEDULER_add_now (collect_connections, udp_connections_heap);
  }
  else
    GNUNET_free (state);

  (void) GNUNET_DISK_file_write (helper_handle->fh_to_helper, buf, len);
  return GNUNET_YES;
}

/**
 * The messages are one GNUNET_HashCode for the service, followed by a struct udp_pkt
 */
static int
receive_udp_service (void *cls
                     __attribute__ ((unused)),
                     struct GNUNET_MESH_Tunnel *tunnel, void **tunnel_ctx
                     __attribute__ ((unused)),
                     const struct GNUNET_PeerIdentity *sender
                     __attribute__ ((unused)),
                     const struct GNUNET_MessageHeader *message,
                     const struct GNUNET_ATS_Information *atsi
                     __attribute__ ((unused)))
{
  GNUNET_HashCode *desc = (GNUNET_HashCode *) (message + 1);
  struct udp_pkt *pkt = (struct udp_pkt *) (desc + 1);

  GNUNET_assert (ntohs (pkt->len) ==
                 ntohs (message->size) - sizeof (struct GNUNET_MessageHeader) -
                 sizeof (GNUNET_HashCode));

  /* Get the configuration from the hashmap */
  uint16_t *udp_desc = alloca (sizeof (GNUNET_HashCode) + 2);

  memcpy (udp_desc + 1, desc, sizeof (GNUNET_HashCode));
  *udp_desc = ntohs (pkt->dpt);
  struct redirect_service *serv =
      GNUNET_CONTAINER_multihashmap_get (udp_services,
                                         (GNUNET_HashCode *) udp_desc);

  if (NULL == serv)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "No service found for UDP dpt %d!\n",
                *udp_desc);
    return GNUNET_YES;
  }

  pkt->dpt = htons (serv->remote_port);

  /*
   * At this point it would be possible to check against some kind of ACL.
   */

  char *buf;
  size_t len;

  /* Prepare the state.
   * This will be saved in the hashmap, so that the receiving procedure knows
   * through which tunnel this connection has to be routed.
   */
  struct redirect_state *state = GNUNET_malloc (sizeof (struct redirect_state));

  state->tunnel = tunnel;
  state->serv = serv;
  state->type = SERVICE;
  state->hashmap = udp_connections;
  memcpy (&state->desc, desc, sizeof (GNUNET_HashCode));

  len =
      sizeof (struct GNUNET_MessageHeader) + sizeof (struct pkt_tun) +
      sizeof (struct ip6_hdr) + ntohs (pkt->len);
  buf = alloca (len);

  memset (buf, 0, len);

  switch (serv->version)
  {
  case 4:
    prepare_ipv4_packet (len, ntohs (pkt->len), pkt, IPPROTO_UDP,
                         &serv->v4.ip4address, tunnel, state,
                         (struct ip_pkt *) buf);
    break;
  case 6:
    prepare_ipv6_packet (len, ntohs (pkt->len), pkt, IPPROTO_UDP,
                         &serv->v6.ip6address, tunnel, state,
                         (struct ip6_pkt *) buf);

    break;
  default:
    GNUNET_assert (0);
    break;
  }

  hash_redirect_info (&state->hash, &state->redirect_info,
                      serv->version == 4 ? 4 : 16);

  if (GNUNET_NO ==
      GNUNET_CONTAINER_multihashmap_contains (udp_connections, &state->hash))
  {
    GNUNET_CONTAINER_multihashmap_put (udp_connections, &state->hash, state,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);

    state->heap_node =
        GNUNET_CONTAINER_heap_insert (udp_connections_heap, state,
                                      GNUNET_TIME_absolute_get ().abs_value);

    if (GNUNET_CONTAINER_heap_get_size (udp_connections_heap) >
        max_udp_connections)
      GNUNET_SCHEDULER_add_now (collect_connections, udp_connections_heap);
  }
  else
    GNUNET_free (state);

  (void) GNUNET_DISK_file_write (helper_handle->fh_to_helper, buf, len);
  return GNUNET_YES;
}

static void
connect_to_mesh ()
{
  int udp, tcp;
  int handler_idx, app_idx;

  udp = GNUNET_CONFIGURATION_get_value_yesno (cfg, "exit", "ENABLE_UDP");
  tcp = GNUNET_CONFIGURATION_get_value_yesno (cfg, "exit", "ENABLE_TCP");

  static struct GNUNET_MESH_MessageHandler handlers[] = {
    {receive_udp_service, GNUNET_MESSAGE_TYPE_VPN_SERVICE_UDP, 0},
    {receive_tcp_service, GNUNET_MESSAGE_TYPE_VPN_SERVICE_TCP, 0},
    {NULL, 0, 0},
    {NULL, 0, 0},
    {NULL, 0, 0}
  };

  static GNUNET_MESH_ApplicationType apptypes[] = {
    GNUNET_APPLICATION_TYPE_END,
    GNUNET_APPLICATION_TYPE_END,
    GNUNET_APPLICATION_TYPE_END
  };

  app_idx = 0;
  handler_idx = 2;

  if (GNUNET_YES == udp)
  {
    handlers[handler_idx].callback = receive_udp_remote;
    handlers[handler_idx].expected_size = 0;
    handlers[handler_idx].type = GNUNET_MESSAGE_TYPE_VPN_REMOTE_UDP;
    apptypes[app_idx] = GNUNET_APPLICATION_TYPE_INTERNET_UDP_GATEWAY;
    handler_idx++;
    app_idx++;
  }

  if (GNUNET_YES == tcp)
  {
    handlers[handler_idx].callback = receive_tcp_remote;
    handlers[handler_idx].expected_size = 0;
    handlers[handler_idx].type = GNUNET_MESSAGE_TYPE_VPN_REMOTE_TCP;
    apptypes[app_idx] = GNUNET_APPLICATION_TYPE_INTERNET_TCP_GATEWAY;
    handler_idx++;
    app_idx++;
  }

  mesh_handle = GNUNET_MESH_connect (cfg, NULL, NULL, handlers, apptypes);
}


/**
 * @brief Main function that will be run by the scheduler.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param cfg_ configuration
 */
static void
run (void *cls, char *const *args __attribute__ ((unused)), const char *cfgfile
     __attribute__ ((unused)), const struct GNUNET_CONFIGURATION_Handle *cfg_)
{
  cfg = cfg_;

  connect_to_mesh ();

  udp_connections = GNUNET_CONTAINER_multihashmap_create (65536);
  udp_connections_heap =
      GNUNET_CONTAINER_heap_create (GNUNET_CONTAINER_HEAP_ORDER_MIN);
  tcp_connections = GNUNET_CONTAINER_multihashmap_create (65536);
  tcp_connections_heap =
      GNUNET_CONTAINER_heap_create (GNUNET_CONTAINER_HEAP_ORDER_MIN);
  udp_services = GNUNET_CONTAINER_multihashmap_create (65536);
  tcp_services = GNUNET_CONTAINER_multihashmap_create (65536);

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (cfg, "exit", "MAX_UDP_CONNECTIONS",
					     &max_udp_connections))
    max_udp_connections = 1024;
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (cfg, "exit", "MAX_TCP_CONNECTIONS",
					     &max_tcp_connections))
    max_tcp_connections = 256;
  GNUNET_CONFIGURATION_iterate_sections (cfg, read_service_conf, NULL);
  GNUNET_SCHEDULER_add_now (start_helper_and_schedule, NULL);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &cleanup, cls);
}


/**
 * The main function 
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  return (GNUNET_OK ==
          GNUNET_PROGRAM_run (argc, argv, "gnunet-daemon-exit", 
			      gettext_noop ("Daemon to run to provide an IP exit node for the VPN"),
                              options, &run, NULL)) ? ret : 1;
}


/* end of gnunet-daemon-exit.c */
