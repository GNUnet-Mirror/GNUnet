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
#include "gnunet_container_lib.h"

/**
 * Final status code.
 */
static int ret;

struct vpn_cls {
	struct GNUNET_DISK_PipeHandle* helper_in; // From the helper
	struct GNUNET_DISK_PipeHandle* helper_out; // To the helper
	const struct GNUNET_DISK_FileHandle* fh_from_helper;
	const struct GNUNET_DISK_FileHandle* fh_to_helper;

	struct GNUNET_SERVER_MessageStreamTokenizer* mst;

	struct GNUNET_SCHEDULER_Handle *sched;

	struct GNUNET_CLIENT_Connection *dns_connection;
	unsigned char restart_hijack;

	pid_t helper_pid;

	const struct GNUNET_CONFIGURATION_Handle *cfg;

	struct query_packet_list *head;
	struct query_packet_list *tail;

	struct answer_packet_list *answer_proc_head;
	struct answer_packet_list *answer_proc_tail;
};

static struct vpn_cls mycls;

size_t send_query(void* cls, size_t size, void* buf);

static void cleanup(void* cls, const struct GNUNET_SCHEDULER_TaskContext* tskctx) {
  GNUNET_assert (0 != (tskctx->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN));
  PLIBC_KILL(mycls.helper_pid, SIGTERM);
  GNUNET_OS_process_wait(mycls.helper_pid);
  if (mycls.dns_connection != NULL)
    {
      GNUNET_CLIENT_disconnect (mycls.dns_connection, GNUNET_NO);
      mycls.dns_connection = NULL;
    }
}

static void helper_read(void* cls, const struct GNUNET_SCHEDULER_TaskContext* tsdkctx);

static void start_helper_and_schedule(void *cls,
				      const struct GNUNET_SCHEDULER_TaskContext *tc) {

	if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
	  return;

	mycls.helper_in = GNUNET_DISK_pipe (GNUNET_YES, GNUNET_YES, GNUNET_NO);
	mycls.helper_out = GNUNET_DISK_pipe (GNUNET_YES, GNUNET_NO, GNUNET_YES);

	if (mycls.helper_in == NULL || mycls.helper_out == NULL) return;

	mycls.helper_pid = GNUNET_OS_start_process(mycls.helper_in, mycls.helper_out, "gnunet-helper-vpn", "gnunet-helper-vpn", NULL);

	mycls.fh_from_helper = GNUNET_DISK_pipe_handle (mycls.helper_out, GNUNET_DISK_PIPE_END_READ);
	mycls.fh_to_helper = GNUNET_DISK_pipe_handle (mycls.helper_in, GNUNET_DISK_PIPE_END_WRITE);

	GNUNET_DISK_pipe_close_end(mycls.helper_out, GNUNET_DISK_PIPE_END_WRITE);
	GNUNET_DISK_pipe_close_end(mycls.helper_in, GNUNET_DISK_PIPE_END_READ);

	GNUNET_SCHEDULER_add_read_file (mycls.sched, GNUNET_TIME_UNIT_FOREVER_REL, mycls.fh_from_helper, &helper_read, NULL);
}


static void restart_helper(void* cls, const struct GNUNET_SCHEDULER_TaskContext* tskctx) {
	// Kill the helper
	PLIBC_KILL(mycls.helper_pid, SIGKILL);
	GNUNET_OS_process_wait(mycls.helper_pid);

	/* Tell the dns-service to rehijack the dns-port
	 * The routing-table gets flushed if an interface disappears.
	 */
	mycls.restart_hijack = 1;
	GNUNET_CLIENT_notify_transmit_ready(mycls.dns_connection, sizeof(struct GNUNET_MessageHeader), GNUNET_TIME_UNIT_FOREVER_REL, GNUNET_YES, &send_query, NULL);

	GNUNET_DISK_pipe_close(mycls.helper_in);
	GNUNET_DISK_pipe_close(mycls.helper_out);

	// Restart the helper
	GNUNET_SCHEDULER_add_delayed (mycls.sched, GNUNET_TIME_UNIT_SECONDS, start_helper_and_schedule, NULL);

}

static void helper_read(void* cls, const struct GNUNET_SCHEDULER_TaskContext* tsdkctx) {
	char buf[65535];

	if (tsdkctx->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN)
		return;

	int t = GNUNET_DISK_file_read(mycls.fh_from_helper, &buf, 65535);
	if (t<=0) {
		GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Read error for header from vpn-helper: %m\n");
		GNUNET_SCHEDULER_add_now(mycls.sched, restart_helper, cls);
		return;
	}

	/* FIXME */ GNUNET_SERVER_mst_receive(mycls.mst, NULL, buf, t, 0, 0);

	GNUNET_SCHEDULER_add_read_file (mycls.sched, GNUNET_TIME_UNIT_FOREVER_REL, mycls.fh_from_helper, &helper_read, NULL);
}

static uint16_t calculate_ip_checksum(uint16_t* hdr, short len) {
	uint32_t sum = 0;
	for(; len >= 2; len -= 2)
		sum += *(hdr++);
	if (len == 1)
		sum += *((unsigned char*)hdr);

	sum = (sum >> 16) + (sum & 0xFFFF);

	return ~sum;
}

static void helper_write(void* cls, const struct GNUNET_SCHEDULER_TaskContext* tsdkctx) {
	if (tsdkctx->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN)
		return;
	struct answer_packet_list* ans = mycls.answer_proc_head;
	size_t len = ntohs(ans->pkt.hdr.size);

	GNUNET_assert(ans->pkt.subtype == GNUNET_DNS_ANSWER_TYPE_IP);

	size_t data_len = len - sizeof(struct answer_packet) + 1;
	size_t net_len = sizeof(struct ip_hdr) + sizeof(struct udp_dns) + data_len;
	size_t pkt_len = sizeof(struct GNUNET_MessageHeader) + sizeof(struct pkt_tun) + net_len;

	struct ip_udp_dns* pkt = alloca(pkt_len);
	memset(pkt, 0, pkt_len);

	pkt->shdr.size = htons(pkt_len);
	pkt->shdr.type = htons(GNUNET_MESSAGE_TYPE_VPN_HELPER);

	pkt->tun.flags = 0;
	pkt->tun.type = htons(0x0800);

	pkt->ip_hdr.version = 4;
	pkt->ip_hdr.hdr_lngth = 5;
	pkt->ip_hdr.diff_serv = 0;
	pkt->ip_hdr.tot_lngth = htons(net_len);
	pkt->ip_hdr.ident = 0;
	pkt->ip_hdr.flags = 0;
	pkt->ip_hdr.frag_off = 0;
	pkt->ip_hdr.ttl = 255;
	pkt->ip_hdr.proto = 0x11; /* UDP */
	pkt->ip_hdr.chks = 0; /* Will be calculated later*/
	pkt->ip_hdr.sadr = ans->pkt.from;
	pkt->ip_hdr.dadr = ans->pkt.to;

	pkt->ip_hdr.chks = calculate_ip_checksum((uint16_t*)&pkt->ip_hdr, 5*4);

	pkt->udp_dns.udp_hdr.spt = htons(53);
	pkt->udp_dns.udp_hdr.dpt = ans->pkt.dst_port;
	pkt->udp_dns.udp_hdr.len = htons(net_len - sizeof(struct ip_hdr));
	pkt->udp_dns.udp_hdr.crc = 0; /* Optional for IPv4 */

	memcpy(&pkt->udp_dns.data, ans->pkt.data, data_len);
	
	GNUNET_CONTAINER_DLL_remove (mycls.answer_proc_head, mycls.answer_proc_tail, ans);
	GNUNET_free(ans);

	/* FIXME */ GNUNET_DISK_file_write(mycls.fh_to_helper, pkt, pkt_len);

	if (mycls.answer_proc_head != NULL)
		GNUNET_SCHEDULER_add_write_file (mycls.sched, GNUNET_TIME_UNIT_FOREVER_REL, mycls.fh_to_helper, &helper_write, NULL);
}

size_t send_query(void* cls, size_t size, void* buf)
{
  size_t len;
  if (mycls.restart_hijack == 1)
    {
      mycls.restart_hijack = 0;
      GNUNET_assert(sizeof(struct GNUNET_MessageHeader) >= size);
      struct GNUNET_MessageHeader* hdr = buf;
      len = sizeof(struct GNUNET_MessageHeader);
      hdr->size = htons(len);
      hdr->type = htons(GNUNET_MESSAGE_TYPE_REHIJACK);
    }
  else
    {
	struct query_packet_list* query = mycls.head;
	len = ntohs(query->pkt.hdr.size);

	GNUNET_assert(len <= size);

	memcpy(buf, &query->pkt.hdr, len);

	GNUNET_CONTAINER_DLL_remove (mycls.head, mycls.tail, query);

	GNUNET_free(query);
    }

	if (mycls.head != NULL || mycls.restart_hijack == 1) {
		GNUNET_CLIENT_notify_transmit_ready(mycls.dns_connection, ntohs(mycls.head->pkt.hdr.size), GNUNET_TIME_UNIT_FOREVER_REL, GNUNET_YES, &send_query, NULL);
	}

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
		GNUNET_assert(pkt->ip_hdr.version == 4);
		if (pkt->ip_hdr.proto == 0x11 && ntohs(udp->udp_hdr.dpt) == 53 ) {
			size_t len = sizeof(struct query_packet) + ntohs(udp->udp_hdr.len) - 9; /* 9 = 8 for the udp-header + 1 for the unsigned char data[1]; */
			struct query_packet_list* query = GNUNET_malloc(len + 2*sizeof(struct query_packet_list*));
			query->pkt.hdr.type = htons(GNUNET_MESSAGE_TYPE_LOCAL_QUERY_DNS);
			query->pkt.hdr.size = htons(len);
			query->pkt.orig_to = pkt->ip_hdr.dadr;
			query->pkt.orig_from = pkt->ip_hdr.sadr;
			query->pkt.src_port = udp->udp_hdr.spt;
			memcpy(query->pkt.data, udp->data, ntohs(udp->udp_hdr.len) - 8);

			GNUNET_CONTAINER_DLL_insert_after(mycls.head, mycls.tail, mycls.tail, query);

			if (mycls.dns_connection != NULL)
			  /* struct GNUNET_CLIENT_TransmitHandle* th = */ GNUNET_CLIENT_notify_transmit_ready(mycls.dns_connection, len, GNUNET_TIME_UNIT_FOREVER_REL, GNUNET_YES, &send_query, NULL);
		}
	}

}

static void 
dns_answer_handler(void* cls, const struct GNUNET_MessageHeader *msg);

static void 
reconnect_to_service_dns (void *cls,
			  const struct GNUNET_SCHEDULER_TaskContext *tc) {
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Connecting\n");
  GNUNET_assert (mycls.dns_connection == NULL);
  mycls.dns_connection = GNUNET_CLIENT_connect (mycls.sched, "dns", mycls.cfg); 
  GNUNET_CLIENT_receive(mycls.dns_connection, &dns_answer_handler, NULL, GNUNET_TIME_UNIT_FOREVER_REL);
  if (mycls.head != NULL)
    /* struct GNUNET_CLIENT_TransmitHandle* th = */ GNUNET_CLIENT_notify_transmit_ready(mycls.dns_connection, ntohs(mycls.head->pkt.hdr.size), GNUNET_TIME_UNIT_FOREVER_REL, GNUNET_YES, &send_query, NULL);
}

static void
process_answer(void* cls, const struct GNUNET_SCHEDULER_TaskContext* tc) {
    struct answer_packet* pkt = cls;

    if (pkt->subtype == GNUNET_DNS_ANSWER_TYPE_IP)
      {
	struct answer_packet_list* list = GNUNET_malloc(htons(pkt->hdr.size) + 2*sizeof(struct answer_packet_list*));

	memcpy(&list->pkt, pkt, htons(pkt->hdr.size));

	GNUNET_CONTAINER_DLL_insert_after(mycls.answer_proc_head, mycls.answer_proc_tail, mycls.answer_proc_tail, list);

	GNUNET_SCHEDULER_add_write_file (mycls.sched, GNUNET_TIME_UNIT_FOREVER_REL, mycls.fh_to_helper, &helper_write, NULL);

	return;
      }

    if (pkt->subtype == GNUNET_DNS_ANSWER_TYPE_SERVICE)
      {
	/*FIXME:
 	 * -find new IP-address for this service
	 * -create a DNS-Answer
 	 */
      }
}

static void
dns_answer_handler(void* cls, const struct GNUNET_MessageHeader *msg)
{
  if (msg == NULL)
    {
      GNUNET_CLIENT_disconnect(mycls.dns_connection, GNUNET_NO);
      mycls.dns_connection = NULL;
      GNUNET_SCHEDULER_add_delayed (mycls.sched,
				    GNUNET_TIME_UNIT_SECONDS,
				    &reconnect_to_service_dns,
				    NULL);
      return;
    }

  if (msg->type != htons(GNUNET_MESSAGE_TYPE_LOCAL_RESPONSE_DNS)) 
    {
      GNUNET_break (0);
      GNUNET_CLIENT_disconnect(mycls.dns_connection, GNUNET_NO);
      mycls.dns_connection = NULL;
      GNUNET_SCHEDULER_add_now (mycls.sched,
				&reconnect_to_service_dns,
				NULL);
      return;
    }
  void *pkt = GNUNET_malloc(ntohs(msg->size));

  memcpy(pkt, msg, ntohs(msg->size));

  GNUNET_SCHEDULER_add_now(mycls.sched, process_answer, pkt);
  GNUNET_CLIENT_receive(mycls.dns_connection, &dns_answer_handler, NULL, GNUNET_TIME_UNIT_FOREVER_REL);
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
  mycls.cfg = cfg;
  mycls.restart_hijack = 0;
  GNUNET_SCHEDULER_add_now (sched, &reconnect_to_service_dns, NULL);
  GNUNET_SCHEDULER_add_delayed(sched, GNUNET_TIME_UNIT_FOREVER_REL, &cleanup, cls); 
  GNUNET_SCHEDULER_add_now (sched, start_helper_and_schedule, NULL);
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
