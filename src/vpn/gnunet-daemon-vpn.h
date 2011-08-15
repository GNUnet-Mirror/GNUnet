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
 * @file vpn/gnunet-daemon-vpn.h
 * @brief
 * @author Philipp Toelke
 */
#ifndef GNUNET_DAEMON_VPN_H
#define GNUNET_DAEMON_VPN_H

#include "gnunet-service-dns-p.h"

/**
 * This gets scheduled with cls pointing to an answer_packet and does everything
 * needed in order to send it to the helper.
 *
 * At the moment this means "inventing" and IPv6-Address for .gnunet-services and
 * doing nothing for "real" services.
 */
void process_answer (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);

void send_icmp6_response (void *cls,
                          const struct GNUNET_SCHEDULER_TaskContext *tc);
void send_icmp4_response (void *cls,
                          const struct GNUNET_SCHEDULER_TaskContext *tc);

size_t                       send_udp_service (void *cls, size_t size,
                                               void *buf);

GNUNET_HashCode *address6_mapping_exists (unsigned char addr[]);
GNUNET_HashCode *address4_mapping_exists (uint32_t addr);

unsigned int port_in_ports (uint64_t ports, uint16_t port);

void send_pkt_to_peer (void *cls, const struct GNUNET_PeerIdentity *peer,
                       const struct GNUNET_TRANSPORT_ATS_Information *atsi);

/**
 * The configuration to use
 */
extern const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * The handle to mesh
 */
extern struct GNUNET_MESH_Handle *mesh_handle;

/**
 * The hashmap containing the mappings from ipv6-addresses to gnunet-descriptors
 */
extern struct GNUNET_CONTAINER_MultiHashMap *hashmap;

struct map_entry
{
    /** The description of the service (used for service) */
  struct GNUNET_vpn_service_descriptor desc;

    /** The real address of the service (used for remote) */
  char addrlen;
  char addr[16];

  struct GNUNET_MESH_Tunnel *tunnel;
  uint16_t namelen;
  char additional_ports[8192];

  struct GNUNET_CONTAINER_HeapNode *heap_node;
  GNUNET_HashCode hash;
    /**
     * After this struct the name is located in DNS-Format!
     */
};

/**
 * Sets a bit active in a bitArray.
 *
 * @param bitArray memory area to set the bit in
 * @param bitIdx which bit to set
 */
void setBit (char *bitArray, unsigned int bitIdx);

/**
 * Clears a bit from bitArray.
 *
 * @param bitArray memory area to set the bit in
 * @param bitIdx which bit to unset
 */
void clearBit (char *bitArray, unsigned int bitIdx);

/**
 * Checks if a bit is active in the bitArray
 *
 * @param bitArray memory area to set the bit in
 * @param bitIdx which bit to test
 * @return GNUNET_YES if the bit is set, GNUNET_NO if not.
 */
int testBit (char *bitArray, unsigned int bitIdx);

struct remote_addr
{
  char addrlen;
  unsigned char addr[16];
  char proto;
};

#endif /* end of include guard: GNUNET-DAEMON-VPN_H */
