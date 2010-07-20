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
/* #include "gnunet_template_service.h" */

/**
 * Final status code.
 */
static int ret;

struct vpn_cls {
	struct GNUNET_DISK_PipeHandle* helper_in;
	struct GNUNET_DISK_PipeHandle* helper_out;
	const struct GNUNET_DISK_FileHandle* fh_from_helper;

	struct GNUNET_SCHEDULER_Handle *sched;

	pid_t helper_pid;
};

static void cleanup(void* cls, const struct GNUNET_SCHEDULER_TaskContext* tskctx) {
	struct vpn_cls* mycls = (struct vpn_cls*) cls;
	if (tskctx->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) {
		PLIBC_KILL(mycls->helper_pid, SIGTERM);
		GNUNET_OS_process_wait(mycls->helper_pid);
	}
}

static void helper_read(void* cls, const struct GNUNET_SCHEDULER_TaskContext* tsdkctx);

static void start_helper_and_schedule(struct vpn_cls* mycls) {
	mycls->helper_in = GNUNET_DISK_pipe(1);
	mycls->helper_out = GNUNET_DISK_pipe(1);

	mycls->helper_pid = GNUNET_OS_start_process(mycls->helper_in, mycls->helper_out, "gnunet-vpn-helper", "gnunet-vpn-helper", NULL);

	mycls->fh_from_helper = GNUNET_DISK_pipe_handle (mycls->helper_out, GNUNET_DISK_PIPE_END_READ);
	
	GNUNET_SCHEDULER_add_read_file (mycls->sched, GNUNET_TIME_UNIT_FOREVER_REL, mycls->fh_from_helper, &helper_read, mycls);
}


static void restart_helper(void* cls, const struct GNUNET_SCHEDULER_TaskContext* tskctx) {
	struct vpn_cls* mycls = (struct vpn_cls*) cls;

	// Kill the helper
	PLIBC_KILL(mycls->helper_pid, SIGTERM);
	GNUNET_OS_process_wait(mycls->helper_pid);

	// Restart the helper
	start_helper_and_schedule(mycls);

}

static void helper_read(void* cls, const struct GNUNET_SCHEDULER_TaskContext* tsdkctx) {
	struct vpn_cls* mycls = (struct vpn_cls*) cls;
	struct suid_packet_header hdr = { .size = 0 };

	int r = 0;

	if (tsdkctx->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN)
		return;

	while (r < sizeof(struct suid_packet_header)) {
		int t = GNUNET_DISK_file_read(mycls->fh_from_helper, &hdr, sizeof(struct suid_packet_header));
		if (t<=0) {
			fprintf(stderr, "Read error for header: %m\n");
			GNUNET_SCHEDULER_add_now(mycls->sched, restart_helper, cls);
			return;
		}
		r += t;
	}

	struct suid_packet *pkt = (struct suid_packet*) GNUNET_malloc(ntohl(hdr.size));

	memcpy(pkt, &hdr, sizeof(struct suid_packet_header));

	while (r < ntohl(pkt->hdr.size)) {
		int t = GNUNET_DISK_file_read(mycls->fh_from_helper, (unsigned char*)pkt + r, ntohl(pkt->hdr.size) - r);
		if (t<=0) {
			fprintf(stderr, "Read error for data: %m\n");
			GNUNET_SCHEDULER_add_now(mycls->sched, restart_helper, cls);
			return;
		}
		r += t;
	}

	struct ip6_pkt *pkt6 = (struct ip6_pkt*) pkt;
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

	GNUNET_free(pkt);

	GNUNET_SCHEDULER_add_read_file (mycls->sched, GNUNET_TIME_UNIT_FOREVER_REL, mycls->fh_from_helper, &helper_read, mycls);
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
		const struct GNUNET_CONFIGURATION_Handle *cfg) {

	struct vpn_cls* mycls = (struct vpn_cls*) cls;

	mycls->sched = sched;

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

  struct vpn_cls* cls = (struct vpn_cls*)malloc(sizeof(struct vpn_cls));

  return (GNUNET_OK ==
          GNUNET_PROGRAM_run (argc,
                              argv,
                              "gnunet-daemon-vpn",
                              gettext_noop ("help text"),
                              options, &run, cls)) ? ret : 1;
}

/* end of gnunet-daemon-vpn.c */
