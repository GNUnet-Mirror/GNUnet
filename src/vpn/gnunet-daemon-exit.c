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
#include <gnunet_mesh_service.h>
#include <gnunet_constants.h>
#include <string.h>

#include "gnunet-vpn-packet.h"
#include "gnunet-helper-vpn-api.h"
#include "gnunet-vpn-checksum.h"

/**
 * The handle to the configuration used throughout the process
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * The handle to the service-configuration
 */
static struct GNUNET_CONFIGURATION_Handle *servicecfg;

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
 * This hashmap contains the mapping from peer, service-descriptor,
 * source-port and destination-port to a socket
 */
static struct GNUNET_CONTAINER_MultiHashMap *udp_connections;

/**
 * This struct is saved into the services-hashmap
 */
struct udp_service
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

struct udp_info
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
 * This struct is saved into udp_connections;
 */
struct udp_state
{
  struct GNUNET_MESH_Tunnel *tunnel;
  GNUNET_HashCode desc;
  struct udp_service *serv;

  /**
   * The source-address and -port of this connection
   */
  struct udp_info udp_info;
};

/**
 * This hashmap saves interesting things about the configured services
 */
static struct GNUNET_CONTAINER_MultiHashMap *udp_services;

/**
 * Function that frees everything from a hashmap
 */
static int
free_iterate(void* cls, const GNUNET_HashCode* hash, void* value)
{
  GNUNET_free(value);
  return GNUNET_YES;
}

/**
 * Function scheduled as very last function, cleans up after us
 */
static void
cleanup(void* cls, const struct GNUNET_SCHEDULER_TaskContext* tskctx) {
    GNUNET_assert (0 != (tskctx->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN));

    GNUNET_CONTAINER_multihashmap_iterate(udp_connections,
                                          free_iterate,
                                          NULL);

    if (mesh_handle != NULL)
      {
	GNUNET_MESH_disconnect(mesh_handle);
	mesh_handle = NULL;
      }
}

/**
 * cls is the pointer to a GNUNET_MessageHeader that is
 * followed by the service-descriptor and the udp-packet that should be sent;
 */
static size_t
send_udp_to_peer_notify_callback (void *cls, size_t size, void *buf)
{
  struct GNUNET_MessageHeader *hdr = cls;
  GNUNET_assert (size >= ntohs (hdr->size));
  memcpy (buf, hdr, ntohs (hdr->size));
  size = ntohs(hdr->size);
  GNUNET_free (cls);
  return size;
}

/**
 * Receive packets from the helper-process
 */
static void
message_token (void *cls,
               void *client, const struct GNUNET_MessageHeader *message)
{
  GNUNET_assert (ntohs (message->type) == GNUNET_MESSAGE_TYPE_VPN_HELPER);

  struct tun_pkt *pkt_tun = (struct tun_pkt *) message;

  struct GNUNET_MessageHeader *msg;
  struct GNUNET_MESH_Tunnel *tunnel;
  uint32_t len;

  struct udp_pkt *udp;
  struct udp_info u_i;
  memset(&u_i, 0, sizeof(struct udp_info));

  unsigned int version;

  /* ethertype is ipv6 */
  if (ntohs (pkt_tun->tun.type) == 0x86dd)
    {
      struct ip6_udp *pkt6 = (struct ip6_udp*)pkt_tun;
      if (pkt6->ip6_hdr.nxthdr != 0x11) return;
      /* lookup in udp_connections for dpt/dadr*/
      memcpy(&u_i.addr, pkt6->ip6_hdr.dadr, 16);
      udp = &pkt6->udp_hdr;
      version = 6;
    }
  else if (ntohs(pkt_tun->tun.type) == 0x0800)
    {
      struct ip_udp *pkt4 = (struct ip_udp*)pkt_tun;
      if (pkt4->ip_hdr.proto != 0x11) return;
      uint32_t tmp = pkt4->ip_hdr.dadr;
      memcpy(&u_i.addr, &tmp, 4);
      udp = &pkt4->udp_hdr;
      version = 4;
    }
  else
    {
      return;
    }

  u_i.pt = udp->dpt;

  /* get tunnel and service-descriptor from this*/
  GNUNET_HashCode hash;
  GNUNET_CRYPTO_hash(&u_i, sizeof(struct udp_info), &hash);
  struct udp_state *state = GNUNET_CONTAINER_multihashmap_get(udp_connections, &hash);

  tunnel = state->tunnel;

  /* check if spt == serv.remote if yes: set spt = serv.myport*/
  if (ntohs(udp->spt) == state->serv->remote_port)
    {
      udp->spt = htons(state->serv->my_port);
    }
  else
    {
      struct udp_service *serv = GNUNET_malloc(sizeof(struct udp_service));
      memcpy(serv, state->serv, sizeof(struct udp_service));
      serv->my_port = ntohs(udp->spt);
      serv->remote_port = ntohs(udp->spt);
      uint16_t *desc = alloca (sizeof (GNUNET_HashCode) + 2);
      memcpy((GNUNET_HashCode *) (desc + 1), &state->desc, sizeof(GNUNET_HashCode));
      *desc = ntohs(udp->spt);
      GNUNET_HashCode hash;
      GNUNET_CRYPTO_hash (desc, sizeof (GNUNET_HashCode) + 2, &hash);
      GNUNET_assert (GNUNET_OK ==
		     GNUNET_CONTAINER_multihashmap_put (udp_services,
							&hash, serv,
							GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
      state->serv = serv;
    }
  /* send udp-packet back */ 
  len = sizeof(struct GNUNET_MessageHeader) + sizeof(GNUNET_HashCode) + ntohs(udp->len);
  msg = GNUNET_malloc(len);
  msg->size = htons(len);
  msg->type = htons(GNUNET_MESSAGE_TYPE_SERVICE_UDP_BACK);
  GNUNET_HashCode *desc = (GNUNET_HashCode*)(msg+1);
  memcpy(desc, &state->desc, sizeof(GNUNET_HashCode));
  void* _udp = desc+1;
  memcpy(_udp, udp, ntohs(udp->len));

  GNUNET_MESH_notify_transmit_ready (tunnel,
				     GNUNET_NO,
				     42,
				     GNUNET_TIME_relative_divide(GNUNET_CONSTANTS_MAX_CORK_DELAY, 2),
				     len,
				     send_udp_to_peer_notify_callback,
				     msg);
}


/**
 * Reads the configuration servicecfg and populates udp_services
 *
 * @param cls unused
 * @param section name of section in config, equal to hostname
 * @param option type of redirect
 * @param value specification of services, format is
 *         "OFFERED-PORT:HOSTNAME:HOST-PORT" (SPACE &lt;more of those&gt;)*
 */
static void
read_service_conf (void *cls, const char *section, const char *option,
                   const char *value)
{
  char *cpy;
  char *redirect;
  char *hostname;
  char *hostport;
  GNUNET_HashCode hash;
  uint16_t *desc = alloca (sizeof (GNUNET_HashCode) + 2);
  GNUNET_CRYPTO_hash (section, strlen (section) + 1,
                      (GNUNET_HashCode *) (desc + 1));

  if (0 == strcmp ("UDP_REDIRECTS", option))
    {
      cpy = GNUNET_strdup (value);
      for (redirect = strtok (cpy, " "); redirect != NULL; redirect = strtok (NULL, " "))
	{     
	  if (NULL == (hostname = strstr (redirect, ":")))
	    {
	      // FIXME: bitch
	      continue;
	    }
	  hostname[0] = '\0';
	  hostname++;
	  if (NULL == (hostport = strstr (hostname, ":")))
	    {
	      // FIXME: bitch
	      continue;
	    }
	  hostport[0] = '\0';
	  hostport++;
	  
          int local_port = atoi (redirect);
          GNUNET_assert ((local_port > 0) && (local_port < 65536)); // FIXME: don't crash!!!
          *desc = local_port;

          GNUNET_CRYPTO_hash (desc, sizeof (GNUNET_HashCode) + 2, &hash);

          struct udp_service *serv =
            GNUNET_malloc (sizeof (struct udp_service));
          memset (serv, 0, sizeof (struct udp_service));
          serv->my_port = local_port;

          if (0 == strcmp ("localhost4", hostname))
            {
              serv->version = 4;

              char *ip4addr;
              GNUNET_assert (GNUNET_OK ==
                             GNUNET_CONFIGURATION_get_value_string (cfg,
                                                                    "exit",
                                                                    "IPV4ADDR",
                                                                    &ip4addr));
              GNUNET_assert (1 ==
                             inet_pton (AF_INET, ip4addr,
                                        serv->v4.ip4address));
              GNUNET_free (ip4addr);
            }
          else if (0 == strcmp ("localhost6", hostname))
            {
              serv->version = 6;

              char *ip6addr;
              GNUNET_assert (GNUNET_OK ==
                             GNUNET_CONFIGURATION_get_value_string (cfg,
                                                                    "exit",
                                                                    "IPV6ADDR",
                                                                    &ip6addr));
              GNUNET_assert (1 ==
                             inet_pton (AF_INET6, ip6addr,
                                        serv->v6.ip6address));
              GNUNET_free (ip6addr);
            }
          else
            {
              // Lookup, yadayadayada
              GNUNET_assert (0);
            }
          serv->remote_port = atoi (hostport);
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Store with key1 %x\n",
                      *((unsigned long long *) (desc + 1)));
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Store with key2 %x\n",
                      *((unsigned long long *) &hash));
          GNUNET_assert (GNUNET_OK ==
                         GNUNET_CONTAINER_multihashmap_put (udp_services,
                                                            &hash, serv,
                                                            GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
        }
      GNUNET_free (cpy);
    }
}

/**
 * Start the helper-process
 *
 * If cls != NULL it is assumed that this function is called as a result of a dying
 * helper. cls is then taken as handle to the old helper and is cleaned up.
 */
static void
start_helper_and_schedule(void *cls,
			  const struct GNUNET_SCHEDULER_TaskContext *tc) {
    if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
      return;

    if (cls != NULL)
      cleanup_helper(cls);
    cls = NULL;

    char* ifname;
    char* ipv6addr;
    char* ipv6prefix;
    char* ipv4addr;
    char* ipv4mask;

    if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_string(cfg, "exit", "IFNAME", &ifname))
      {
	GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "No entry 'IFNAME' in configuration!\n");
	exit(1);
      }

    if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_string(cfg, "exit", "IPV6ADDR", &ipv6addr))
      {
	GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "No entry 'IPV6ADDR' in configuration!\n");
	exit(1);
      }

    if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_string(cfg, "exit", "IPV6PREFIX", &ipv6prefix))
      {
	GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "No entry 'IPV6PREFIX' in configuration!\n");
	exit(1);
      }

    if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_string(cfg, "exit", "IPV4ADDR", &ipv4addr))
      {
	GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "No entry 'IPV4ADDR' in configuration!\n");
	exit(1);
      }

    if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_string(cfg, "exit", "IPV4MASK", &ipv4mask))
      {
	GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "No entry 'IPV4MASK' in configuration!\n");
	exit(1);
      }

    /* Start the helper
     * Messages get passed to the function message_token
     * When the helper dies, this function will be called again with the
     * helper_handle as cls.
     */
    helper_handle = start_helper(ifname,
				 ipv6addr,
				 ipv6prefix,
                                 ipv4addr,
                                 ipv4mask,
				 "exit-gnunet",
				 start_helper_and_schedule,
				 message_token,
				 NULL,
				 NULL);

    GNUNET_free(ipv6addr);
    GNUNET_free(ipv6prefix);
    GNUNET_free(ipv4addr);
    GNUNET_free(ipv4mask);
    GNUNET_free(ifname);
}

/**
 * The messages are one GNUNET_HashCode for the service, followed by a struct udp_pkt
 */
static int
receive_udp_service (void *cls,
                     struct GNUNET_MESH_Tunnel *tunnel,
                     void **tunnel_ctx,
                     const struct GNUNET_MessageHeader *message,
                     const struct GNUNET_TRANSPORT_ATS_Information *atsi)
{
  GNUNET_HashCode hash;
  GNUNET_HashCode *desc = (GNUNET_HashCode *) (message + 1);
  struct udp_pkt *pkt = (struct udp_pkt *) (desc + 1);
  struct ip6_udp *pkt6;
  struct ip_udp *pkt4;

  GNUNET_assert (ntohs (pkt->len) ==
                 ntohs (message->size) -
                 sizeof (struct GNUNET_MessageHeader) -
                 sizeof (GNUNET_HashCode));

  /* Get the configuration from the hashmap */
  uint16_t *udp_desc = alloca(sizeof(GNUNET_HashCode)+2);
  memcpy(udp_desc + 1, desc, sizeof(GNUNET_HashCode));
  *udp_desc = ntohs(pkt->dpt);
  GNUNET_CRYPTO_hash(udp_desc, sizeof(GNUNET_HashCode)+2, &hash);
  struct udp_service *serv = GNUNET_CONTAINER_multihashmap_get(udp_services, &hash);
  if (NULL == serv)
    {
      GNUNET_log(GNUNET_ERROR_TYPE_INFO, "No service found for dpt %d!\n", *udp_desc);
      return GNUNET_YES;
    }

  pkt->dpt = htons(serv->remote_port);
  /* FIXME -> check acl etc */

  char* buf;
  size_t len;
  uint32_t tmp, tmp2;

  /* Prepare the state.
   * This will be saved in the hashmap, so that the receiving procedure knows
   * through which tunnel this connection has to be routed.
   */
  struct udp_state *state = GNUNET_malloc (sizeof (struct udp_state));
  memset(state, 0, sizeof(struct udp_state));
  state->tunnel = tunnel;
  state->serv = serv;
  memcpy(&state->desc, desc, sizeof(GNUNET_HashCode));

  switch (serv->version)
    {
    case 4:
      len = sizeof (struct GNUNET_MessageHeader) + sizeof (struct pkt_tun) +
                sizeof (struct ip_hdr) + ntohs (pkt->len);
      pkt4 = alloca(len);
      memset (pkt4, 0, len);
      buf = (char*)pkt4;

      pkt4->shdr.type = htons(GNUNET_MESSAGE_TYPE_VPN_HELPER);
      pkt4->shdr.size = htons(len);
      pkt4->tun.flags = 0;
      pkt4->tun.type = htons(0x0800);

      memcpy(&pkt4->udp_hdr, pkt, ntohs(pkt->len));

      pkt4->ip_hdr.version = 4;
      pkt4->ip_hdr.hdr_lngth = 5;
      pkt4->ip_hdr.diff_serv = 0;
      pkt4->ip_hdr.tot_lngth = htons(20 + ntohs(pkt->len));
      pkt4->ip_hdr.ident = 0;
      pkt4->ip_hdr.flags = 0;
      pkt4->ip_hdr.frag_off = 0;
      pkt4->ip_hdr.ttl = 255;
      pkt4->ip_hdr.proto = 0x11; /* UDP */
      pkt4->ip_hdr.chks = 0; /* Will be calculated later*/

      memcpy(&tmp, &serv->v4.ip4address, 4);
      pkt4->ip_hdr.dadr = tmp;

      /* Generate a new src-address */
      char* ipv4addr;
      char* ipv4mask;
      GNUNET_assert(GNUNET_OK == GNUNET_CONFIGURATION_get_value_string(cfg, "exit", "IPV4ADDR", &ipv4addr));
      GNUNET_assert(GNUNET_OK == GNUNET_CONFIGURATION_get_value_string(cfg, "exit", "IPV4MASK", &ipv4mask));
      inet_pton(AF_INET, ipv4addr, &tmp);
      inet_pton(AF_INET, ipv4mask, &tmp2);
      GNUNET_free(ipv4addr);
      GNUNET_free(ipv4mask);

      /* This should be a noop */
      tmp = tmp & tmp2;

      tmp |= ntohl(*((uint32_t*)tunnel)) & (~tmp2);

      pkt4->ip_hdr.sadr = tmp;

      memcpy(&state->udp_info.addr, &tmp, 4);
      state->udp_info.pt = pkt4->udp_hdr.spt;

      pkt4->udp_hdr.crc = 0; /* Optional for IPv4 */

      pkt4->ip_hdr.chks = calculate_ip_checksum((uint16_t*)&pkt4->ip_hdr, 5*4);

      break;
    case 6:
      len = sizeof (struct GNUNET_MessageHeader) + sizeof (struct pkt_tun) +
                sizeof (struct ip6_hdr) + ntohs (pkt->len);
      pkt6 =
        alloca (len);
      memset (pkt6, 0, len);
      buf =(char*) pkt6;

      pkt6->shdr.type = htons(GNUNET_MESSAGE_TYPE_VPN_HELPER);
      pkt6->shdr.size = htons(len);
      pkt6->tun.flags = 0;
      pkt6->tun.type = htons(0x86dd);

      memcpy (&pkt6->udp_hdr, pkt, ntohs (pkt->len));

      pkt6->ip6_hdr.version = 6;
      pkt6->ip6_hdr.nxthdr = 0x11;  //UDP
      pkt6->ip6_hdr.paylgth = pkt->len;
      pkt6->ip6_hdr.hoplmt = 64;

      memcpy(pkt6->ip6_hdr.dadr, &serv->v6.ip6address, 16);

      /* Generate a new src-address
       * This takes as much from the address of the tunnel as fits into
       * the host-mask*/
      char* ipv6addr;
      unsigned long long ipv6prefix;
      GNUNET_assert(GNUNET_OK == GNUNET_CONFIGURATION_get_value_string(cfg, "exit", "IPV6ADDR", &ipv6addr));
      GNUNET_assert(GNUNET_OK == GNUNET_CONFIGURATION_get_value_number(cfg, "exit", "IPV6PREFIX", &ipv6prefix));
      GNUNET_assert(ipv6prefix < 127);
      ipv6prefix = (ipv6prefix + 7)/8;

      inet_pton (AF_INET6, ipv6addr, &pkt6->ip6_hdr.sadr);
      GNUNET_free(ipv6addr);

      if (ipv6prefix < (16 - sizeof(void*)))
        ipv6prefix = 16 - sizeof(void*);

      unsigned int offset = ipv6prefix - (16-sizeof(void*));
      memcpy((((char*)&pkt6->ip6_hdr.sadr))+ipv6prefix, ((char*)&tunnel)+offset, 16 - ipv6prefix);

      /* copy the needed information into the state */
      memcpy(&state->udp_info.addr, &pkt6->ip6_hdr.sadr, 16);
      state->udp_info.pt = pkt6->udp_hdr.spt;

      pkt6->udp_hdr.crc = 0;
      uint32_t sum = 0;
      sum = calculate_checksum_update(sum, (uint16_t*)&pkt6->ip6_hdr.sadr, 16);
      sum = calculate_checksum_update(sum, (uint16_t*)&pkt6->ip6_hdr.dadr, 16);
      tmp = (pkt6->udp_hdr.len & 0xffff);
      sum = calculate_checksum_update(sum, (uint16_t*)&tmp, 4);
      tmp = htons(((pkt6->ip6_hdr.nxthdr & 0x00ff)));
      sum = calculate_checksum_update(sum, (uint16_t*)&tmp, 4);

      sum = calculate_checksum_update(sum, (uint16_t*)&pkt6->udp_hdr, ntohs(pkt6->udp_hdr.len));
      pkt6->udp_hdr.crc = calculate_checksum_end(sum);

      break;
    default:
      GNUNET_assert(0);
      break;
    }

  GNUNET_CRYPTO_hash (&state->udp_info, sizeof(struct udp_info), &hash);

  if (GNUNET_NO ==
      GNUNET_CONTAINER_multihashmap_contains (udp_connections, &hash))
    GNUNET_CONTAINER_multihashmap_put (udp_connections, &hash, state,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
  else
    GNUNET_free(state);

  (void)GNUNET_DISK_file_write(helper_handle->fh_to_helper, buf, len);
  return GNUNET_YES;
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
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg_)
{
  const static struct GNUNET_MESH_MessageHandler handlers[] = {
	{receive_udp_service, GNUNET_MESSAGE_TYPE_SERVICE_UDP, 0},
	{NULL, 0, 0}
  };
  mesh_handle = GNUNET_MESH_connect(cfg_,
				    NULL,
				    NULL, /* FIXME */
				    handlers);

  cfg = cfg_;
  udp_connections = GNUNET_CONTAINER_multihashmap_create(65536);
  udp_services = GNUNET_CONTAINER_multihashmap_create(65536);

  char *services;
  GNUNET_CONFIGURATION_get_value_filename(cfg, "dns", "SERVICES", &services);
  servicecfg = GNUNET_CONFIGURATION_create();
  if (GNUNET_OK == GNUNET_CONFIGURATION_parse(servicecfg, services))
    {
      GNUNET_log(GNUNET_ERROR_TYPE_INFO, "Parsing services %s\n", services);
      GNUNET_CONFIGURATION_iterate(servicecfg, read_service_conf, NULL);
    }
  if (NULL != services)
    GNUNET_free(services);

  GNUNET_SCHEDULER_add_now (start_helper_and_schedule, NULL);
  GNUNET_SCHEDULER_add_delayed(GNUNET_TIME_UNIT_FOREVER_REL, &cleanup, cls);
}

/**
 * The main function to obtain template from gnunetd.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv) {
    static const struct GNUNET_GETOPT_CommandLineOption options[] = {
	GNUNET_GETOPT_OPTION_END
    };

    return (GNUNET_OK ==
	    GNUNET_PROGRAM_run (argc,
				argv,
				"exit",
				gettext_noop ("help text"),
				options, &run, NULL)) ? ret : 1;
}

/* end of gnunet-daemon-exit.c */

