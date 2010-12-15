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
 * @author Philipp Toelke
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
#include "gnunet_container_lib.h"
#include "gnunet-dns-parser.h"
#include "gnunet_dht_service.h"
#include "gnunet_block_lib.h"
#include "block_dns.h"
#include "gnunet_crypto_lib.h"
#include "gnunet_signatures.h"

/**
 * The UDP-Socket through which DNS-Resolves will be sent if they are not to be
 * sent through gnunet. The port of this socket will not be hijacked.
 */
static struct GNUNET_NETWORK_Handle *dnsout;

/**
 * The port bound to the socket dnsout
 */
static unsigned short dnsoutport;

/**
 * A handle to the DHT-Service
 */
static struct GNUNET_DHT_Handle *dht;

/**
 * The configuration to use
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * A list of DNS-Responses that have to be sent to the requesting client
 */
static struct answer_packet_list *head;

/**
 * The tail of the list of DNS-responses
 */
static struct answer_packet_list *tail;

/**
 * A structure containing a mapping from network-byte-ordered DNS-id to
 * some information needed to handle this query
 *
 * It currently allocates at least
 * (1 + machine-width + 32 + 32 + 16 + machine-width + 8) * 65536 bit
 * = 1.7 MiB on 64 bit.
 * = 1.2 MiB on 32 bit.
 */
static struct {
    unsigned valid:1;
    struct GNUNET_SERVER_Client* client;
    unsigned local_ip:32;
    unsigned remote_ip:32;
    unsigned local_port:16;
    char* name;
    unsigned namelen:8;
} query_states[65536];

/**
 * A struct used to give more than one value as
 * closure to receive_dht
 */
struct receive_dht_cls {
    unsigned short id;
    struct GNUNET_DHT_GetHandle* handle;
};

/**
 * Hijack all outgoing DNS-Traffic but for traffic leaving "our" port.
 */
static void
hijack(void* cls, const struct GNUNET_SCHEDULER_TaskContext* tc) {
    char port_s[6];

    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Hijacking, port is %d\n", dnsoutport);
    snprintf(port_s, 6, "%d", dnsoutport);
    GNUNET_OS_process_close (GNUNET_OS_start_process(NULL,
						     NULL,
						     "gnunet-helper-hijack-dns",
						     "gnunet-hijack-dns",
						     port_s,
						     NULL));
}

/**
 * Delete the hijacking-routes
 */
static void
unhijack(unsigned short port) {
    char port_s[6];

    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "unHijacking, port is %d\n", port);
    snprintf(port_s, 6, "%d", port);
    GNUNET_OS_start_process(NULL,
			    NULL,
			    "gnunet-helper-hijack-dns",
			    "gnunet-hijack-dns",
			    "-d",
			    port_s,
			    NULL);
}

/**
 * Send the DNS-Response to the client. Gets called via the notify_transmit_ready-
 * system.
 */
static size_t
send_answer(void* cls, size_t size, void* buf) {
    struct answer_packet_list* query = head;
    size_t len = ntohs(query->pkt.hdr.size);

    GNUNET_assert(len <= size);

    memcpy(buf, &query->pkt.hdr, len);

    GNUNET_CONTAINER_DLL_remove (head, tail, query);

    GNUNET_free(query);

    /* When more data is to be sent, reschedule */
    if (head != NULL)
      GNUNET_SERVER_notify_transmit_ready(cls,
					  ntohs(head->pkt.hdr.size),
					  GNUNET_TIME_UNIT_FOREVER_REL,
					  &send_answer,
					  cls);

    return len;
}

static void
send_rev_query(void * cls, const struct GNUNET_SCHEDULER_TaskContext *tc) {
    struct dns_pkt_parsed* pdns = (struct dns_pkt_parsed*) cls;

    unsigned short id = pdns->s.id;

    if (query_states[id].valid != GNUNET_YES) return;
    query_states[id].valid = GNUNET_NO;

    GNUNET_assert(query_states[id].namelen == 74);

    size_t len = sizeof(struct answer_packet) - 1 \
		 + sizeof(struct dns_static) \
		 + 74 /* this is the length of a reverse ipv6-lookup */ \
		 + sizeof(struct dns_query_line) \
		 + 2 /* To hold the pointer (as defined in RFC1035) to the name */ \
		 + sizeof(struct dns_record_line) - 1 \
		 - 2 /* We do not know the lenght of the answer yet*/ \
		 - 2 /* No idea why... */ ;

    struct answer_packet_list* answer = GNUNET_malloc(len + 2*sizeof(struct answer_packet_list*));
    memset(answer, 0, len + 2*sizeof(struct answer_packet_list*));

    answer->pkt.hdr.type = htons(GNUNET_MESSAGE_TYPE_LOCAL_RESPONSE_DNS);
    answer->pkt.hdr.size = htons(len);
    answer->pkt.subtype = GNUNET_DNS_ANSWER_TYPE_REV;

    answer->pkt.from = query_states[id].remote_ip;

    answer->pkt.to = query_states[id].local_ip;
    answer->pkt.dst_port = query_states[id].local_port;

    struct dns_pkt *dpkt = (struct dns_pkt*)answer->pkt.data;

    dpkt->s.id = id;
    dpkt->s.aa = 1;
    dpkt->s.qr = 1;
    dpkt->s.ra = 1;
    dpkt->s.qdcount = htons(1);
    dpkt->s.ancount = htons(1);

    memcpy(dpkt->data, query_states[id].name, query_states[id].namelen);
    GNUNET_free(query_states[id].name);

    struct dns_query_line* dque = (struct dns_query_line*)(dpkt->data+(query_states[id].namelen));
    dque->type = htons(12); /* PTR */
    dque->class = htons(1); /* IN */

    char* anname = (char*)(dpkt->data+(query_states[id].namelen)+sizeof(struct dns_query_line));
    memcpy(anname, (char[]){0xc0, 0x0c}, 2);

    struct dns_record_line *drec_data = (struct dns_record_line*)(dpkt->data+(query_states[id].namelen)+sizeof(struct dns_query_line)+2);
    drec_data->type = htons(12); /* AAAA */
    drec_data->class = htons(1); /* IN */
    drec_data->ttl = htonl(3600); /* FIXME: read from block */

    /* Calculate at which offset in the packet the length of the name and the
     * name, it is filled in by the daemon-vpn */
    answer->pkt.addroffset = htons((unsigned short)((unsigned long)(&drec_data->data_len)-(unsigned long)(&answer->pkt)));

    GNUNET_CONTAINER_DLL_insert_after(head, tail, tail, answer);

    GNUNET_SERVER_notify_transmit_ready(query_states[id].client,
					len,
					GNUNET_TIME_UNIT_FOREVER_REL,
					&send_answer,
					query_states[id].client);

    /*
     * build
     * complete dns-packet with empty name in the answer
     * provide offsett of the name
     */
}

/**
 * Receive a block from the dht.
 */
static void
receive_dht(void *cls,
	    struct GNUNET_TIME_Absolute exp,
	    const GNUNET_HashCode *key,
	    const struct GNUNET_PeerIdentity *const *get_path,
	    const struct GNUNET_PeerIdentity *const *put_path,
	    enum GNUNET_BLOCK_Type type,
	    size_t size,
	    const void *data) {

    unsigned short id = ((struct receive_dht_cls*)cls)->id;
    struct GNUNET_DHT_GetHandle* handle = ((struct receive_dht_cls*)cls)->handle;
    GNUNET_free(cls);

    GNUNET_assert(type == GNUNET_BLOCK_TYPE_DNS);

    /* If no query with this id is pending, ignore the block */
    if (query_states[id].valid != GNUNET_YES) return;
    query_states[id].valid = GNUNET_NO;

    const struct GNUNET_DNS_Record* rec = data;
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
	       "Got block of size %d, peer: %08x, desc: %08x\n",
	       size,
	       *((unsigned int*)&rec->peer),
	       *((unsigned int*)&rec->service_descriptor));

    size_t len = sizeof(struct answer_packet) - 1 \
		 + sizeof(struct dns_static) \
		 + query_states[id].namelen \
		 + sizeof(struct dns_query_line) \
		 + 2 /* To hold the pointer (as defined in RFC1035) to the name */ \
		 + sizeof(struct dns_record_line) - 1 \
		 + 16; /* To hold the IPv6-Address */

    struct answer_packet_list* answer = GNUNET_malloc(len + 2*sizeof(struct answer_packet_list*));
    memset(answer, 0, len + 2*sizeof(struct answer_packet_list*));

    answer->pkt.hdr.type = htons(GNUNET_MESSAGE_TYPE_LOCAL_RESPONSE_DNS);
    answer->pkt.hdr.size = htons(len);
    answer->pkt.subtype = GNUNET_DNS_ANSWER_TYPE_SERVICE;

    GNUNET_CRYPTO_hash(&rec->peer,
		       sizeof(struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
		       &answer->pkt.service_descr.peer);

    memcpy(&answer->pkt.service_descr.service_descriptor,
	   &rec->service_descriptor,
	   sizeof(GNUNET_HashCode));
    memcpy(&answer->pkt.service_descr.service_type,
	   &rec->service_type,
	   sizeof(answer->pkt.service_descr.service_type));
    memcpy(&answer->pkt.service_descr.ports, &rec->ports, sizeof(answer->pkt.service_descr.ports));

    answer->pkt.from = query_states[id].remote_ip;

    answer->pkt.to = query_states[id].local_ip;
    answer->pkt.dst_port = query_states[id].local_port;

    struct dns_pkt *dpkt = (struct dns_pkt*)answer->pkt.data;

    dpkt->s.id = id;
    dpkt->s.aa = 1;
    dpkt->s.qr = 1;
    dpkt->s.ra = 1;
    dpkt->s.qdcount = htons(1);
    dpkt->s.ancount = htons(1);

    memcpy(dpkt->data, query_states[id].name, query_states[id].namelen);
    GNUNET_free(query_states[id].name);

    struct dns_query_line* dque = (struct dns_query_line*)(dpkt->data+(query_states[id].namelen));
    dque->type = htons(28); /* AAAA */
    dque->class = htons(1); /* IN */

    char* anname = (char*)(dpkt->data+(query_states[id].namelen)+sizeof(struct dns_query_line));
    memcpy(anname, (char[]){0xc0, 0x0c}, 2);

    struct dns_record_line *drec_data = (struct dns_record_line*)(dpkt->data+(query_states[id].namelen)+sizeof(struct dns_query_line)+2);
    drec_data->type = htons(28); /* AAAA */
    drec_data->class = htons(1); /* IN */
    drec_data->ttl = htonl(3600); /* FIXME: read from block */
    drec_data->data_len = htons(16);

    /* Calculate at which offset in the packet the IPv6-Address belongs, it is
     * filled in by the daemon-vpn */
    answer->pkt.addroffset = htons((unsigned short)((unsigned long)(&drec_data->data)-(unsigned long)(&answer->pkt)));

    GNUNET_CONTAINER_DLL_insert_after(head, tail, tail, answer);

    GNUNET_SERVER_notify_transmit_ready(query_states[id].client,
					len,
					GNUNET_TIME_UNIT_FOREVER_REL,
					&send_answer,
					query_states[id].client);

    GNUNET_DHT_get_stop(handle);
}

/**
 * This receives a GNUNET_MESSAGE_TYPE_REHIJACK and rehijacks the DNS
 */
static void
rehijack(void *cls,
	 struct GNUNET_SERVER_Client *client,
	 const struct GNUNET_MessageHeader *message) {
    unhijack(dnsoutport);
    GNUNET_SCHEDULER_add_delayed(GNUNET_TIME_UNIT_SECONDS, hijack, NULL);

    GNUNET_SERVER_receive_done(client, GNUNET_OK);
}

/**
 * This receives the dns-payload from the daemon-vpn and sends it on over the udp-socket
 */
static void
receive_query(void *cls,
	      struct GNUNET_SERVER_Client *client,
	      const struct GNUNET_MessageHeader *message) {
    struct query_packet* pkt = (struct query_packet*)message;
    struct dns_pkt* dns = (struct dns_pkt*)pkt->data;
    struct dns_pkt_parsed* pdns = parse_dns_packet(dns);

    query_states[dns->s.id].valid = GNUNET_YES;
    query_states[dns->s.id].client = client;
    query_states[dns->s.id].local_ip = pkt->orig_from;
    query_states[dns->s.id].local_port = pkt->src_port;
    query_states[dns->s.id].remote_ip = pkt->orig_to;
    query_states[dns->s.id].namelen = strlen((char*)dns->data) + 1;
    query_states[dns->s.id].name = GNUNET_malloc(query_states[dns->s.id].namelen);
    memcpy(query_states[dns->s.id].name, dns->data, query_states[dns->s.id].namelen);

    /* The query is for a .gnunet-address */
    if (pdns->queries[0]->namelen > 9 &&
	0 == strncmp(pdns->queries[0]->name+(pdns->queries[0]->namelen - 9), ".gnunet.", 9))
      {
	GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Query for .gnunet!\n");
	GNUNET_HashCode key;
	GNUNET_CRYPTO_hash(pdns->queries[0]->name, pdns->queries[0]->namelen, &key);

	GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
		   "Getting with key %08x, len is %d\n",
		   *((unsigned int*)&key),
		   pdns->queries[0]->namelen);

	struct receive_dht_cls* cls = GNUNET_malloc(sizeof(struct receive_dht_cls));
	cls->id = dns->s.id;

	cls->handle = GNUNET_DHT_get_start(dht,
					   GNUNET_TIME_UNIT_MINUTES,
					   GNUNET_BLOCK_TYPE_DNS,
					   &key,
					   DEFAULT_GET_REPLICATION,
					   GNUNET_DHT_RO_NONE,
					   NULL,
					   0,
					   NULL,
					   0,
					   receive_dht,
					   cls);

	goto outfree;
      }

    /* The query is for a PTR of a previosly resolved virtual IP */
    if (htons(pdns->queries[0]->qtype) == 12 &&
	pdns->queries[0]->namelen > 19 &&
	0 == strncmp(pdns->queries[0]->name+(pdns->queries[0]->namelen - 19), ".4.3.2.1.ip6.arpa.", 19))
      {
	GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Reverse-Query for .gnunet!\n");

	GNUNET_SCHEDULER_add_now(send_rev_query, pdns);

	goto out;
      }

    /* The query should be sent to the network */

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof dest);
    dest.sin_port = htons(53);
    dest.sin_addr.s_addr = pkt->orig_to;

    GNUNET_NETWORK_socket_sendto(dnsout,
				 dns,
				 ntohs(pkt->hdr.size) - sizeof(struct query_packet) + 1,
				 (struct sockaddr*) &dest,
				 sizeof dest);

outfree:
    free_parsed_dns_packet(pdns);
    pdns = NULL;
out:
    GNUNET_SERVER_receive_done(client, GNUNET_OK);
}

/**
 * Read a response-packet of the UDP-Socket
 */
static void
read_response (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc) {
    unsigned char buf[65536];
    struct dns_pkt* dns = (struct dns_pkt*)buf;

    if (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN)
      return;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    socklen_t addrlen = sizeof addr;

    int r;
    r = GNUNET_NETWORK_socket_recvfrom(dnsout,
				       buf,
				       65536,
				       (struct sockaddr*)&addr,
				       &addrlen);

    /* if (r < 0) FIXME */

    if (query_states[dns->s.id].valid == GNUNET_YES) {
	query_states[dns->s.id].valid = GNUNET_NO;

	size_t len = sizeof(struct answer_packet) + r - 1; /* 1 for the unsigned char data[1]; */
	struct answer_packet_list* answer = GNUNET_malloc(len + 2*sizeof(struct answer_packet_list*));
	answer->pkt.hdr.type = htons(GNUNET_MESSAGE_TYPE_LOCAL_RESPONSE_DNS);
	answer->pkt.hdr.size = htons(len);
	answer->pkt.subtype = GNUNET_DNS_ANSWER_TYPE_IP;
	answer->pkt.from = addr.sin_addr.s_addr;
	answer->pkt.to = query_states[dns->s.id].local_ip;
	answer->pkt.dst_port = query_states[dns->s.id].local_port;
	memcpy(answer->pkt.data, buf, r);

	GNUNET_CONTAINER_DLL_insert_after(head, tail, tail, answer);

	GNUNET_SERVER_notify_transmit_ready(query_states[dns->s.id].client,
					    len,
					    GNUNET_TIME_UNIT_FOREVER_REL,
					    &send_answer,
					    query_states[dns->s.id].client);
    }

    GNUNET_SCHEDULER_add_read_net(GNUNET_TIME_UNIT_FOREVER_REL,
				  dnsout,
				  &read_response,
				  NULL);
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
  unhijack(dnsoutport);
  GNUNET_DHT_disconnect(dht);
}

/**
 * Publish a DNS-record in the DHT. This is up to now just for testing.
 */
static void
publish_name (void *cls,
	      const struct GNUNET_SCHEDULER_TaskContext *tc) {
    if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
      return;

    char* name = "philipptoelke.gnunet.";
    size_t size = sizeof(struct GNUNET_DNS_Record);
    struct GNUNET_DNS_Record data;
    memset(&data, 0, size);

    data.purpose.size = htonl(size - sizeof(struct GNUNET_CRYPTO_RsaSignature));
    data.purpose.purpose = GNUNET_SIGNATURE_PURPOSE_DNS_RECORD;

    GNUNET_CRYPTO_hash(name, strlen(name)+1, &data.service_descriptor);

    data.service_type = htonl(GNUNET_DNS_SERVICE_TYPE_UDP);
    data.ports = htons(69);

    char* keyfile;
    if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_filename(cfg, "GNUNETD",
							     "HOSTKEY", &keyfile))
      {
	GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "could not read keyfile-value\n");
	if (keyfile != NULL) GNUNET_free(keyfile);
	return;
      }

    struct GNUNET_CRYPTO_RsaPrivateKey *my_private_key = GNUNET_CRYPTO_rsa_key_create_from_file(keyfile);
    GNUNET_free(keyfile);

    GNUNET_CRYPTO_rsa_key_get_public(my_private_key, &data.peer);

    data.expiration_time = GNUNET_TIME_relative_to_absolute(GNUNET_TIME_UNIT_HOURS);

  /* Sign the block */
    if (GNUNET_OK != GNUNET_CRYPTO_rsa_sign(my_private_key,
					    &data.purpose,
					    &data.signature))
      {
	GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "could not sign DNS_Record\n");
	return;
      }
    GNUNET_CRYPTO_rsa_key_free(my_private_key);

    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
	       "Putting with key %08x\n",
	       *((unsigned int*)&data.service_descriptor));

    GNUNET_DHT_put(dht,
		   &data.service_descriptor,
		   DEFAULT_PUT_REPLICATION,
		   GNUNET_DHT_RO_NONE,
		   GNUNET_BLOCK_TYPE_DNS,
		   size,
		   (char*)&data,
		   GNUNET_TIME_relative_to_absolute(GNUNET_TIME_UNIT_HOURS),
		   GNUNET_TIME_UNIT_MINUTES,
		   NULL,
		   NULL);

    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_HOURS,
				  publish_name,
				  NULL);
}

/**
 * @param cls closure
 * @param sched scheduler to use
 * @param server the initialized server
 * @param cfg configuration to use
 */
static void
run (void *cls,
     struct GNUNET_SERVER_Handle *server,
     const struct GNUNET_CONFIGURATION_Handle *cfg_)
{
  static const struct GNUNET_SERVER_MessageHandler handlers[] = {
      /* callback, cls, type, size */
	{&receive_query, NULL, GNUNET_MESSAGE_TYPE_LOCAL_QUERY_DNS, 0},
	{&rehijack, NULL, GNUNET_MESSAGE_TYPE_REHIJACK, sizeof(struct GNUNET_MessageHeader)},
	{NULL, NULL, 0, 0}
  };

  cfg = cfg_;

  unsigned int i;
  for (i = 0; i < 65536; i++) {
      query_states[i].valid = GNUNET_NO;
  }

  dht = GNUNET_DHT_connect(cfg, 1024);

  struct sockaddr_in addr;

  dnsout = GNUNET_NETWORK_socket_create (AF_INET, SOCK_DGRAM, 0);
  if (dnsout == NULL)
    return;
  memset(&addr, 0, sizeof(struct sockaddr_in));

  int err = GNUNET_NETWORK_socket_bind (dnsout,
					(struct sockaddr*)&addr,
					sizeof(struct sockaddr_in));

  if (err != GNUNET_YES) {
      GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Could not bind a port, exiting\n");
      return;
  }

  /* Read the port we bound to */
  socklen_t addrlen = sizeof(struct sockaddr_in);
  err = getsockname(GNUNET_NETWORK_get_fd(dnsout),
		    (struct sockaddr*) &addr,
		    &addrlen);

  dnsoutport = htons(addr.sin_port);

  GNUNET_SCHEDULER_add_now (publish_name, NULL);

  GNUNET_SCHEDULER_add_read_net(GNUNET_TIME_UNIT_FOREVER_REL, dnsout, &read_response, NULL);

  GNUNET_SERVER_add_handlers (server, handlers);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
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
			      "dns",
			      GNUNET_SERVICE_OPTION_NONE,
			      &run, NULL)) ? 0 : 1;
}
