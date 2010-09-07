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
 * @file vpn/gnunet-daemon-vpn.c
 * @brief 
 * @author Philipp Tölke
 */
#include "platform.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_program_lib.h"
#include "gnunet_os_lib.h"
#include "gnunet-vpn-helper-p.h"
#include "gnunet-vpn-packet.h"
#include "gnunet-vpn-pretty-print.h"
#include "gnunet_common.h"
#include "gnunet_protocols.h"
#include "gnunet_server_lib.h"
#include "gnunet-service-dns-p.h"
#include "gnunet_client_lib.h"

/**
 * Final status code.
 */
static int ret;

struct vpn_cls {
	struct GNUNET_DISK_PipeHandle* helper_in; // From the helper
	struct GNUNET_DISK_PipeHandle* helper_out; // To the helper
	const struct GNUNET_DISK_FileHandle* fh_from_helper;

	struct GNUNET_SERVER_MessageStreamTokenizer* mst;

	struct GNUNET_SCHEDULER_Handle *sched;

	struct GNUNET_CLIENT_Connection *dns_connection;

	pid_t helper_pid;
};

static struct vpn_cls mycls;

static void cleanup(void* cls, const struct GNUNET_SCHEDULER_TaskContext* tskctx) {
	if (tskctx->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) {
		PLIBC_KILL(mycls.helper_pid, SIGTERM);
		GNUNET_OS_process_wait(mycls.helper_pid);
	}
}

static void helper_read(void* cls, const struct GNUNET_SCHEDULER_TaskContext* tsdkctx);

static void start_helper_and_schedule() {
	mycls.helper_in = GNUNET_DISK_pipe(1);
	mycls.helper_out = GNUNET_DISK_pipe(1);

	mycls.helper_pid = GNUNET_OS_start_process(mycls.helper_in, mycls.helper_out, "gnunet-helper-vpn", "gnunet-helper-vpn", NULL);

	mycls.fh_from_helper = GNUNET_DISK_pipe_handle (mycls.helper_out, GNUNET_DISK_PIPE_END_READ);

	GNUNET_DISK_pipe_close_end(mycls.helper_out, GNUNET_DISK_PIPE_END_WRITE);
	GNUNET_DISK_pipe_close_end(mycls.helper_in, GNUNET_DISK_PIPE_END_READ);

	GNUNET_SCHEDULER_add_read_file (mycls.sched, GNUNET_TIME_UNIT_FOREVER_REL, mycls.fh_from_helper, &helper_read, NULL);
}


static void restart_helper(void* cls, const struct GNUNET_SCHEDULER_TaskContext* tskctx) {
	// FIXME: Ratelimit this!

	// Kill the helper
	PLIBC_KILL(mycls.helper_pid, SIGKILL);
	GNUNET_OS_process_wait(mycls.helper_pid);

	// Restart the helper
	start_helper_and_schedule(mycls);

}

static void helper_read(void* cls, const struct GNUNET_SCHEDULER_TaskContext* tsdkctx) {
	char buf[65535];

	if (tsdkctx->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN)
		return;

	int t = GNUNET_DISK_file_read(mycls.fh_from_helper, &buf, 65535);
	if (t<=0) {
		GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Read error for header: %m\n");
		GNUNET_SCHEDULER_add_now(mycls.sched, restart_helper, cls);
		return;
	}

	/* FIXME */ GNUNET_SERVER_mst_receive(mycls.mst, NULL, buf, t, 0, 0);

	GNUNET_SCHEDULER_add_read_file (mycls.sched, GNUNET_TIME_UNIT_FOREVER_REL, mycls.fh_from_helper, &helper_read, NULL);
}

size_t send_query(void* cls, size_t size, void* buf)
{
	struct query_packet* pkt = cls;
	size_t len = ntohs(pkt->hdr.size);
	memcpy(buf, cls, len);
	GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Sent %d bytes.\n", len);
	GNUNET_free(cls);
	return len;
}

static void message_token(void *cls, void *client, const struct GNUNET_MessageHeader *message) {
	if (ntohs(message->type) != GNUNET_MESSAGE_TYPE_VPN_HELPER) return;

	struct tun_pkt *pkt_tun = (struct tun_pkt*) message;

	if (ntohs(pkt_tun->tun.type) == 0x86dd) {
		struct ip6_pkt *pkt6 = (struct ip6_pkt*) message;
		struct ip6_tcp *pkt6_tcp;
		struct ip6_udp *pkt6_udp;

		pkt_printf(pkt6);
		switch(pkt6->ip6_hdr.nxthdr) {
			case 0x06:
				pkt6_tcp = (struct ip6_tcp*)pkt6;
				pkt_printf_ip6tcp(pkt6_tcp);
				break;
			case 0x11:
				pkt6_udp = (struct ip6_udp*)pkt6;
				pkt_printf_ip6udp(pkt6_udp);
				if (ntohs(pkt6_udp->udp_hdr.dpt) == 53) {
					pkt_printf_ip6dns((struct ip6_udp_dns*)pkt6_udp);
				}
				break;
		}
	} else if (ntohs(pkt_tun->tun.type) == 0x0800) {
		struct ip_pkt *pkt = (struct ip_pkt*) message;
		struct ip_udp *udp = (struct ip_udp*) message;
		if (pkt->ip_hdr.proto == 0x11 && ntohl(udp->ip_hdr.dadr) == 0x0a0a0a02 && ntohs(udp->udp_hdr.dpt) == 53 ) {
			size_t len = sizeof(struct query_packet*) + ntohs(udp->udp_hdr.len) - 7; /* 7 = 8 for the udp-header - 1 for the unsigned char data[1]; */
			struct query_packet* query = GNUNET_malloc(len);
			query->hdr.type = htons(GNUNET_MESSAGE_TYPE_LOCAL_QUERY_DNS);
			query->hdr.size = htons(len);
			query->orig_to = pkt->ip_hdr.dadr;
			query->orig_from = pkt->ip_hdr.sadr;
			query->src_port = udp->udp_hdr.spt;
			memcpy(query->data, udp->data, ntohs(udp->udp_hdr.len) - 8);
			GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Queued sending\n");
			GNUNET_CLIENT_notify_transmit_ready(mycls.dns_connection, len, GNUNET_TIME_UNIT_FOREVER_REL, GNUNET_YES, &send_query, query);
		}
	}

}

/**
 * Main function that will be run by the scheduler.
 *
 * @param cls closure
 * @param sched the scheduler to use
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param cfg configuration
 */
static void
run (void *cls,
     struct GNUNET_SCHEDULER_Handle *sched,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg) 
{
  mycls.sched = sched;
  mycls.mst = GNUNET_SERVER_mst_create(&message_token, NULL);

  mycls.dns_connection = GNUNET_CLIENT_connect (sched, "gnunet-service-dns", cfg);
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Connection: %x\n", mycls.dns_connection);

  GNUNET_SCHEDULER_add_delayed(sched, GNUNET_TIME_UNIT_FOREVER_REL, &cleanup, cls); 
  start_helper_and_schedule(mycls);
}


/**
 * The main function to obtain template from gnunetd.
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
          GNUNET_PROGRAM_run (argc,
                              argv,
                              "gnunet-daemon-vpn",
                              gettext_noop ("help text"),
                              options, &run, NULL)) ? ret : 1;
}

/* end of gnunet-daemon-vpn.c */
