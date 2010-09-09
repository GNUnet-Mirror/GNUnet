/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

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
 * @file vpn/gnunet-service-dns.c
 * @author Philipp Tölke
 */
#include "platform.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_service_lib.h"
#include "gnunet_network_lib.h"
#include "gnunet_os_lib.h"
#include "gnunet-service-dns-p.h"
#include "gnunet_protocols.h"
#include "gnunet-vpn-packet.h"
#include "gnunet-vpn-pretty-print.h"

struct dns_cls {
	struct GNUNET_SCHEDULER_Handle *sched;

	struct GNUNET_NETWORK_Handle *dnsout;

	unsigned short dnsoutport;
};

static struct dns_cls mycls;

void hijack(unsigned short port) {
	char port_s[6];

	snprintf(port_s, 6, "%d", port);
	GNUNET_OS_start_process(NULL, NULL, "gnunet-helper-hijack-dns", "gnunet-hijack-dns", port_s, NULL);
}

void unhijack(unsigned short port) {
	char port_s[6];

	snprintf(port_s, 6, "%d", port);
	GNUNET_OS_start_process(NULL, NULL, "gnunet-helper-hijack-dns", "gnunet-hijack-dns", "-d", port_s, NULL);
}

void receive_query(void *cls, struct GNUNET_SERVER_Client *client, const struct GNUNET_MessageHeader *message)
{
	GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Received query!\n");
	struct query_packet* pkt = (struct query_packet*)message;
	GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Of length %d\n", ntohs(pkt->hdr.size));
	struct dns_pkt* dns = (struct dns_pkt*)pkt->data;

	pkt_printf_dns(dns);

	GNUNET_SERVER_receive_done(client, GNUNET_OK);
}

/**
 * Task run during shutdown.
 *
 * @param cls unused
 * @param tc unused
 */
static void
cleanup_task (void *cls,
	      const struct GNUNET_SCHEDULER_TaskContext *tc)
{
	unhijack(mycls.dnsoutport);
}

/**
 * @param cls closure
 * @param sched scheduler to use
 * @param server the initialized server
 * @param cfg configuration to use
 */
static void
run (void *cls,
     struct GNUNET_SCHEDULER_Handle *sched,
     struct GNUNET_SERVER_Handle *server,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  static const struct GNUNET_SERVER_MessageHandler handlers[] = {
	  /* callback, cls, type, size */
    {&receive_query, NULL, GNUNET_MESSAGE_TYPE_LOCAL_QUERY_DNS, 0},
    {NULL, NULL, 0, 0}
  };
  struct sockaddr_in addr;

  mycls.sched = sched;
  mycls.dnsout = GNUNET_NETWORK_socket_create (AF_INET, SOCK_DGRAM, 0);
  if (mycls.dnsout == NULL) 
    return;
  memset(&addr, 0, sizeof(struct sockaddr_in));

  int err = GNUNET_NETWORK_socket_bind (mycls.dnsout,
					(struct sockaddr*)&addr, 
					sizeof(struct sockaddr_in));
  // FIXME: check err
  fprintf (stderr, "FIXME: check err: %d\n", err);
#if WHY_ON_EARTH_DO_WE_DO_THIS
  socklen_t addrlen = sizeof(struct sockaddr_in);
  err = getsockname(GNUNET_NETWORK_get_fd(mycls.dnsout),
		    (struct sockaddr*) &addr, 
		    &addrlen);
#endif

  mycls.dnsoutport = htons(addr.sin_port);

  hijack(htons(addr.sin_port));

  GNUNET_SERVER_add_handlers (server, handlers);
  GNUNET_SCHEDULER_add_delayed (sched,
		  GNUNET_TIME_UNIT_FOREVER_REL,
		  &cleanup_task,
		  cls);
}

/**
 * The main function for the dns service.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  return (GNUNET_OK ==
          GNUNET_SERVICE_run (argc,
                              argv,
                              "gnunet-service-dns",
			      GNUNET_SERVICE_OPTION_NONE,
			      &run, NULL)) ? 0 : 1;
}
