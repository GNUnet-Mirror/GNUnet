/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2015, 2016 GNUnet e.V.

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
 * This code provides some support for doing STUN transactions.  We
 * receive the simplest possible packet as the STUN server and try
 * to respond properly.
 *
 * All STUN packets start with a simple header made of a type,
 * length (excluding the header) and a 16-byte random transaction id.
 * Following the header we may have zero or more attributes, each
 * structured as a type, length and a value (whose format depends
 * on the type, but often contains addresses).
 * Of course all fields are in network format.
 *
 * This code was based on ministun.c.
 *
 * @file nat/gnunet-service-nat_stun.c
 * @brief Functions for STUN functionality
 * @author Bruno Souza Cabral
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "nat_stun.h"

#define LOG(kind,...) GNUNET_log_from (kind, "stun", __VA_ARGS__)


/**
 * Context for #stun_get_mapped(). 
 * Used to store state across processing attributes.
 */
struct StunState
{
  uint16_t attr;
};


/**
 * Extract the STUN_MAPPED_ADDRESS from the stun response.
 * This is used as a callback for stun_handle_response
 * when called from stun_request.
 *
 * @param[out] st pointer where we will set the type
 * @param attr received stun attribute
 * @param magic Magic cookie
 * @param[out] arg pointer to a sockaddr_in where we will set the reported IP and port
 * @return #GNUNET_OK if @a arg was initialized
 */
static int
stun_get_mapped (struct StunState *st,
                 const struct stun_attr *attr,
		 uint32_t magic,
                 struct sockaddr_in *arg)
{
  const struct stun_addr *returned_addr;
  struct sockaddr_in *sa = (struct sockaddr_in *) arg;
  uint16_t type = ntohs (attr->attr);

  switch (type)
  {
  case STUN_MAPPED_ADDRESS:
    if ( (st->attr == STUN_XOR_MAPPED_ADDRESS) ||
	 (st->attr == STUN_MS_XOR_MAPPED_ADDRESS) )
      return GNUNET_NO;
    magic = 0;
    break;
  case STUN_MS_XOR_MAPPED_ADDRESS:
    if (st->attr == STUN_XOR_MAPPED_ADDRESS)
      return GNUNET_NO;
    break;
  case STUN_XOR_MAPPED_ADDRESS:
    break;
  default:
    return GNUNET_NO;
  }  
  
  if (ntohs (attr->len) < sizeof (struct stun_addr))
    return GNUNET_NO;
  returned_addr = (const struct stun_addr *)(attr + 1);
  if (AF_INET != returned_addr->family)
    return GNUNET_NO;
  st->attr = type;
  sa->sin_family = AF_INET;
  sa->sin_port = returned_addr->port ^ htons (ntohl(magic) >> 16);
  sa->sin_addr.s_addr = returned_addr->addr ^ magic;
  return GNUNET_OK;
}


/**
 * Handle an incoming STUN response.  Do some basic sanity checks on
 * packet size and content, try to extract information.
 * At the moment this only processes BIND requests,
 * and returns the externally visible address of the original
 * request.
 *
 * @param data the packet
 * @param len the length of the packet in @a data
 * @param[out] arg sockaddr_in where we will set our discovered address
 * @return #GNUNET_OK on success,
 *         #GNUNET_NO if the packet is invalid (not a stun packet)
 */
int
GNUNET_NAT_stun_handle_packet_ (const void *data,
				size_t len,
				struct sockaddr_in *arg)
{
  const struct stun_header *hdr;
  const struct stun_attr *attr;
  struct StunState st;
  uint32_t advertised_message_size;
  uint32_t message_magic_cookie;
  int ret = GNUNET_SYSERR;

  /* On entry, 'len' is the length of the UDP payload. After the
   * initial checks it becomes the size of unprocessed options,
   * while 'data' is advanced accordingly.
   */
  if (len < sizeof(struct stun_header))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Packet too short to be a STUN packet\n");
    return GNUNET_NO;
  }
  hdr = data;
  /* Skip header as it is already in hdr */
  len -= sizeof(struct stun_header);
  data += sizeof(struct stun_header);

  /* len as advertised in the message */
  advertised_message_size = ntohs (hdr->msglen);
  message_magic_cookie = ntohl (hdr->magic);
  /* Compare if the cookie match */
  if (STUN_MAGIC_COOKIE != message_magic_cookie)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Invalid magic cookie for STUN packet\n");
    return GNUNET_NO;
  }

  LOG (GNUNET_ERROR_TYPE_INFO,
       "STUN Packet, msg %s (%04x), length: %d\n",
       stun_msg2str (ntohs (hdr->msgtype)),
       ntohs (hdr->msgtype),
       advertised_message_size);
  if (advertised_message_size > len)
  {
    LOG (GNUNET_ERROR_TYPE_INFO,
         "Scrambled STUN packet length (got %d, expecting %d)\n",
         advertised_message_size,
         (int) len);
    return GNUNET_NO;
  }
  len = advertised_message_size;
  memset (&st, 0, sizeof(st));

  while (len > 0)
  {
    if (len < sizeof (struct stun_attr))
    {
      LOG (GNUNET_ERROR_TYPE_INFO,
           "Attribute too short (got %d, expecting %d)\n",
           (int) len,
           (int) sizeof (struct stun_attr));
      break;
    }
    attr = (const struct stun_attr *) data;

    /* compute total attribute length */
    advertised_message_size = ntohs (attr->len) + sizeof (struct stun_attr);

    /* Check if we still have space in our buffer */
    if (advertised_message_size > len)
    {
      LOG (GNUNET_ERROR_TYPE_INFO,
           "Inconsistent attribute (length %d exceeds remaining msg len %d)\n",
           advertised_message_size,
           (int) len);
      break;
    }
    if (GNUNET_OK ==
	stun_get_mapped (&st,
			 attr,
			 hdr->magic,
			 arg))
      ret = GNUNET_OK;
    data += advertised_message_size;
    len -= advertised_message_size;
  }
  return ret;
}

/* end of gnunet-service-nat_stun.c */
