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

#include "gnunet-vpn-packet.h"

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
 * FIXME
 */
struct udp_state
{
  struct GNUNET_PeerIdentity peer;
  struct GNUNET_MESH_Tunnel *tunnel;
  GNUNET_HashCode desc;
  short spt;
  short dpt;
};

/**
 * FIXME
 */
struct send_cls
{
  struct GNUNET_NETWORK_Handle *sock;
  struct udp_state state;
};

/**
 * Function scheduled as very last function, cleans up after us
 */
static void
cleanup(void* cls, const struct GNUNET_SCHEDULER_TaskContext* tskctx) {
    GNUNET_assert (0 != (tskctx->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN));

    if (mesh_handle != NULL)
      {
	GNUNET_MESH_disconnect(mesh_handle);
	mesh_handle = NULL;
      }
}

static size_t
send_udp_service (void *cls, size_t size, void *buf)
{
  struct GNUNET_MessageHeader *hdr = cls;
  GNUNET_assert(size >= ntohs(hdr->size));

  memcpy(buf, cls, ntohs(hdr->size));
  size_t ret = ntohs(hdr->size);
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Sending %d bytes back!\n", ntohs(hdr->size));
  GNUNET_free(cls);
  return ret;
}

void
receive_from_network (void *cls,
		      const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN)
    {
      GNUNET_free(cls);
      return;
    }
  struct send_cls *data = cls;

  char buf[1400];

  struct sockaddr_in addr_in;
  socklen_t addr_len = sizeof(struct sockaddr_in);
  ssize_t len = GNUNET_NETWORK_socket_recvfrom (data->sock, buf, 1400, (struct sockaddr*)&addr_in, &addr_len);

  if (len < 0) {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Problem reading from socket: %m\n");
    goto out;
  }

  size_t len_udp = len + sizeof (struct udp_pkt);
  size_t len_pkt = len_udp + sizeof (struct GNUNET_MessageHeader) + sizeof(GNUNET_HashCode);
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Sending data back: data: %d; udp: %d, pkt:%d\n", len, len_udp, len_pkt);

  struct GNUNET_MessageHeader *hdr = GNUNET_malloc (len_pkt);
  GNUNET_HashCode *desc = (GNUNET_HashCode *) (hdr + 1);
  struct udp_pkt *pkt = (struct udp_pkt *) (desc + 1);

  hdr->size = htons (len_pkt);
  hdr->type = htons (GNUNET_MESSAGE_TYPE_SERVICE_UDP_BACK);

  pkt->dpt = htons(data->state.spt);
  pkt->spt = addr_in.sin_port;
  pkt->len = htons (len_udp);
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "UDP from %d to %d\n", ntohs(pkt->spt), ntohs(pkt->dpt));
  /* The chksm can only be computed knowing the ip-addresses */

  memcpy (desc, &data->state.desc, sizeof (GNUNET_HashCode));
  memcpy (pkt + 1, buf, len);

  GNUNET_MESH_notify_transmit_ready (data->state.tunnel, 42,
				     GNUNET_NO,
				     GNUNET_TIME_relative_divide(GNUNET_CONSTANTS_MAX_CORK_DELAY, 2),
				     len_pkt,
				     send_udp_service, hdr);

out:
  GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL, data->sock,
				 receive_from_network, cls);
}

void
send_to_network (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN)
    return;
  struct send_cls *data = cls;
  struct udp_pkt *pkt = (struct udp_pkt *) (data + 1);

  struct sockaddr_in a4;
  memset(&a4, 0, sizeof(struct sockaddr_in));
  a4.sin_family = AF_INET;
  a4.sin_port = htons(data->state.dpt);
  memcpy(&a4.sin_addr.s_addr, (char[]){127, 0, 0, 1}, 4);

  GNUNET_NETWORK_socket_sendto (data->sock, pkt + 1,
				ntohs (pkt->len) - sizeof (struct udp_pkt),
				(struct sockaddr*)&a4, sizeof a4);

  GNUNET_free(cls);

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
  GNUNET_HashCode *desc = (GNUNET_HashCode *) (message + 1);
  struct udp_pkt *pkt = (struct udp_pkt *) (desc + 1);

  /* FIXME -> check acl etc */
  GNUNET_assert (ntohs (pkt->len) ==
		 ntohs (message->size) -
		 sizeof (struct GNUNET_MessageHeader) -
		 sizeof (GNUNET_HashCode));

  size_t state_size = sizeof (struct udp_state);
  size_t cls_size = sizeof (struct send_cls) + ntohs (pkt->len);
  struct send_cls *send = GNUNET_malloc (cls_size);
  struct udp_state *state = &send->state;
  unsigned int new = GNUNET_NO;

  state->tunnel = tunnel;
  memcpy (&state->desc, desc, sizeof (GNUNET_HashCode));
  state->spt = ntohs (pkt->spt);

  /* Hash without the dpt, so that eg tftp works */
  state->dpt = 0;

  memcpy (send + 1, pkt, ntohs (pkt->len));

  GNUNET_HashCode hash;
  GNUNET_CRYPTO_hash (state, state_size, &hash);

  state->dpt = ntohs (pkt->dpt);

  struct GNUNET_NETWORK_Handle *sock =
    GNUNET_CONTAINER_multihashmap_get (udp_connections, &hash);

  if (sock == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Creating new Socket!\n");
      sock = GNUNET_NETWORK_socket_create (AF_INET, SOCK_DGRAM, 0);
      GNUNET_assert(sock != NULL);
      new = GNUNET_YES;
    }

  send->sock = sock;

  GNUNET_CONTAINER_multihashmap_put (udp_connections, &hash, sock,
				     GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);


  if (new)
    {
      struct send_cls *recv = GNUNET_malloc (sizeof (struct send_cls));
      memcpy (recv, send, sizeof (struct send_cls));
      GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL, sock,
				     receive_from_network, recv);
    }

  GNUNET_SCHEDULER_add_write_net (GNUNET_TIME_UNIT_FOREVER_REL, sock,
				  send_to_network, send);

  return GNUNET_OK;
}

/**
 * Main function that will be run by the scheduler.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param cfg configuration
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

  udp_connections = GNUNET_CONTAINER_multihashmap_create(65536);
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
				"gnunet-daemon-exit",
				gettext_noop ("help text"),
				options, &run, NULL)) ? ret : 1;
}

/* end of gnunet-daemon-exit.c */

