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
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <linux/if.h>

#include <fcntl.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <string.h>

#include <signal.h>

#include <stdio.h>
#include <unistd.h>

#include "gnunet-vpn-helper-p.h"
#include "tun.h"

#ifndef _LINUX_IN6_H
// This is in linux/include/net/ipv6.h.

struct in6_ifreq {
    struct in6_addr ifr6_addr;
    __u32 ifr6_prefixlen;
    unsigned int ifr6_ifindex;
};

#endif

int running = 1;

void term(int sig) {
	fprintf(stderr, "Got SIGTERM...\n");
	if (sig == SIGTERM)
		running = 0;
}

static void set_address(char* dev, char* address, unsigned long prefix_len) { /* {{{ */
	int fd = socket(AF_INET6, SOCK_DGRAM, 0);

	struct ifreq ifr;
	struct in6_ifreq ifr6;

	struct sockaddr_in6 sa6;
	memset(&sa6, 0, sizeof(struct sockaddr_in6));

	sa6.sin6_family = AF_INET6;

	/* FIXME */ inet_pton(AF_INET6, address, sa6.sin6_addr.s6_addr);

	memcpy((char *) &ifr6.ifr6_addr, (char *) &sa6.sin6_addr, sizeof(struct in6_addr));

	strncpy(ifr.ifr_name, dev, IFNAMSIZ);

	if (ioctl(fd, SIOGIFINDEX, &ifr) < 0) {
		perror("SIOGIFINDEX");
	}

	ifr6.ifr6_ifindex = ifr.ifr_ifindex;
	ifr6.ifr6_prefixlen = prefix_len;

	if (ioctl(fd, SIOCSIFADDR, &ifr6) < 0) {
		perror("SIOCSIFADDR");
	}

	/* FIXME */ ioctl(fd, SIOCGIFFLAGS, &ifr);
	ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
	/* FIXME */ ioctl(fd, SIOCSIFFLAGS, &ifr);
} /* }}} */

void setnonblocking(int fd) {/*{{{*/
	int opts;

	opts = fcntl(fd,F_GETFL);
	if (opts < 0) {
			perror("fcntl(F_GETFL)");
	}
	opts = (opts | O_NONBLOCK);
	if (fcntl(fd,F_SETFL,opts) < 0) {
			perror("fcntl(F_SETFL)");
	}
	return;
}/*}}}*/

int main(int argc, char** argv) {
	unsigned char buf[65600]; // 64k + 64;

	char dev[IFNAMSIZ];
	memset(dev, 0, IFNAMSIZ);

	signal(SIGTERM, &term);

	int fd_tun = init_tun(dev);
	fprintf(stderr, "Initialized the interface %s as %d.\n", dev, fd_tun);

	// TODO: get this out of argv
	char address[] = "1234::1";
	unsigned long prefix_len = 16;

	set_address(dev, address, prefix_len);

	uid_t uid = getuid ();
	if (setresuid (uid, uid, uid) != 0 )
		fprintf (stderr, "Failed to setresuid: %m\n");

	setnonblocking(0);
	setnonblocking(1);
	setnonblocking(fd_tun);

	fd_set fds_w;
	fd_set fds_r;

	int rea = 1;
	int wri = 1;

	int write_fd_possible = 0;
	int write_stdout_possible = 0;
outer:
	while(rea != 0 && wri != 0 && running == 1) {
		FD_ZERO(&fds_w);
		FD_ZERO(&fds_r);

		if (rea) {
			FD_SET(fd_tun, &fds_r);
			if (!write_stdout_possible)
				FD_SET(1, &fds_w);
		}

		if (wri) {
			FD_SET(0, &fds_r);
			if (!write_fd_possible)
				FD_SET(fd_tun, &fds_w);
		}

		int r = select(fd_tun+1, &fds_r, &fds_w, (fd_set*)0, 0);

		if(r > 0) {
			if (FD_ISSET(fd_tun, &fds_w)) write_fd_possible = 1;
			if (FD_ISSET(1, &fds_w)) write_stdout_possible = 1;

			if (FD_ISSET(0, &fds_r) && write_fd_possible) {
				write_fd_possible = 0;
				struct suid_packet *pkt = (struct suid_packet*) buf;
				r = read(0, buf, sizeof(struct suid_packet_header));
				if (r < 0) {
					fprintf(stderr, "read-error: %m\n");
					shutdown(fd_tun, SHUT_WR);
					shutdown(0, SHUT_RD);
					wri=0;
					goto outer;
				}
				while (r < ntohl(pkt->hdr.size)) {
					int t = read(0, buf + r, ntohl(pkt->hdr.size) - r);
					if (r < 0) {
						fprintf(stderr, "read-error: %m\n");
						shutdown(fd_tun, SHUT_WR);
						shutdown(0, SHUT_RD);
						wri=0;
						goto outer;
					}
					r += t;
				}
				r = 0;
				while (r < ntohl(pkt->hdr.size) - sizeof(struct suid_packet_header)) {
					int t = write(fd_tun, pkt->data, ntohl(pkt->hdr.size) - sizeof(struct suid_packet_header) - r);
					if (t < 0) {
						fprintf(stderr, "write-error 3: %m\n");
						shutdown(fd_tun, SHUT_WR);
						shutdown(0, SHUT_RD);
						wri = 0;
						goto outer;
					}
					r += t;
				}
			} else if (write_stdout_possible && FD_ISSET(fd_tun, &fds_r)) {
				write_stdout_possible = 0;
				r = read(fd_tun, buf, 65600);
				if (r < 0) {
					fprintf(stderr, "read-error: %m\n");
					shutdown(fd_tun, SHUT_RD);
					shutdown(1, SHUT_WR);
					rea = 0;
					goto outer;
				}
				struct suid_packet_header hdr = { .size = htonl(r + sizeof(struct suid_packet_header))};
				r = 0;
				while(r < sizeof(struct suid_packet_header)) {
					int t = write(1, &hdr, sizeof(struct suid_packet_header) - r);
					if (t < 0) {
						fprintf(stderr, "write-error 2: %m\n");
						shutdown(fd_tun, SHUT_RD);
						shutdown(1, SHUT_WR);
						rea = 0;
						goto outer;
					}
					r += t;
				}
				while(r < ntohl(hdr.size)) {
					int t = write(1, buf, ntohl(hdr.size) - r);
					if (t < 0) {
						fprintf(stderr, "write-error 1: %m, written %d/%d\n", r, ntohl(hdr.size));
						shutdown(fd_tun, SHUT_RD);
						shutdown(1, SHUT_WR);
						rea = 0;
						goto outer;
					}
					r += t;
				}
			}
		}
	}
	fprintf(stderr, "Quitting!\n");

	return 0;
}
