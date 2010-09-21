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
#include <platform.h>

#include "gnunet-vpn-tun.h"
#include "gnunet_common.h"
#include "gnunet_protocols.h"
#include "gnunet-vpn-helper-p.h"

#ifndef _LINUX_IN6_H
// This is in linux/include/net/ipv6.h.

#define MAX_SIZE (65535 - sizeof(struct GNUNET_MessageHeader))

struct in6_ifreq {
    struct in6_addr ifr6_addr;
    uint32_t ifr6_prefixlen;
    unsigned int ifr6_ifindex;
};

#endif

int running = 1;

void term(int sig) {
	fprintf(stderr, "Got SIGTERM...\n");
	if (sig == SIGTERM)
		running = 0;
}

static void set_address6(char* dev, char* address, unsigned long prefix_len) { /* {{{ */
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
	close(fd);
} /* }}} */

static void set_address4(char* dev, char* address, char* mask) { /* {{{ */
	int fd=0;
	struct sockaddr_in* addr;
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(struct ifreq));
	addr = (struct sockaddr_in *)&(ifr.ifr_addr);
	memset(addr, 0, sizeof(struct sockaddr_in));
	addr->sin_family = AF_INET;
	addr->sin_addr.s_addr = inet_addr(address);

	/* FIXME */ inet_pton(AF_INET, address, &addr->sin_addr.s_addr);

	fd = socket(PF_INET, SOCK_DGRAM, 0);
	if(fd < 0) {
		perror("socket()");
		return;
	}

	strncpy(ifr.ifr_name, dev, IFNAMSIZ);

	if(ioctl(fd, SIOCSIFADDR, &ifr) != 0 ) {
		perror("SIOCSIFADDR");
		close(fd);
		return;
	}

	addr = (struct sockaddr_in*)&(ifr.ifr_netmask);
	/* FIXME */ inet_pton(AF_INET, mask, &addr->sin_addr.s_addr);

	if(ioctl(fd, SIOCSIFNETMASK, &ifr) != 0 ) {
		perror("SIOCSIFNETMASK");
		close(fd);
		return;
	}

	/* FIXME */ ioctl(fd, SIOCGIFFLAGS, &ifr);
	ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
	/* FIXME */ ioctl(fd, SIOCSIFFLAGS, &ifr);
	close(fd);
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
	unsigned char buf[MAX_SIZE];

	char dev[IFNAMSIZ];
	memset(dev, 0, IFNAMSIZ);

	signal(SIGTERM, &term);

	int fd_tun = init_tun(dev);

	if (fd_tun < 0) {
		fprintf(stderr, "Could not initialize tun-interface: %s\n", strerror(errno));
		exit(1);
	}

	{
	// TODO: get this out of argv
	char address[] = "1234::1";
	unsigned long prefix_len = 16;

	set_address6(dev, address, prefix_len);
	}

	{
	char address[] = "10.10.10.1";
	char mask[] = "255.255.255.252";

	set_address4(dev, address, mask);
	}

	uid_t uid = getuid ();
	if (setresuid (uid, uid, uid) != 0 )
		fprintf (stderr, "Failed to setresuid: %s\n", strerror(errno));

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
	while((rea == 1 || wri == 1) && running == 1) {
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
				r = read(0, buf, sizeof(struct GNUNET_MessageHeader));
				if (r <= 0) {
					fprintf(stderr, "read-error: %m\n");
					shutdown(fd_tun, SHUT_WR);
					shutdown(0, SHUT_RD);
					wri=0;
					goto outer;
				}
				while (r < ntohs(pkt->hdr.size)) {
					int t = read(0, buf + r, ntohs(pkt->hdr.size) - r);
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
				while (r < ntohs(pkt->hdr.size) - sizeof(struct GNUNET_MessageHeader)) {
					int t = write(fd_tun, pkt->data, ntohs(pkt->hdr.size) - sizeof(struct GNUNET_MessageHeader) - r);
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
				r = read(fd_tun, buf, MAX_SIZE);
				if (r <= 0) {
					fprintf(stderr, "read-error: %m\n");
					shutdown(fd_tun, SHUT_RD);
					shutdown(1, SHUT_WR);
					rea = 0;
					goto outer;
				}
				struct GNUNET_MessageHeader hdr = { .size = htons(r + sizeof(struct GNUNET_MessageHeader)), .type = htons(GNUNET_MESSAGE_TYPE_VPN_HELPER) };
				r = 0;
				while(r < sizeof(struct GNUNET_MessageHeader)) {
					int t = write(1, &hdr, sizeof(struct GNUNET_MessageHeader) - r);
					if (t < 0) {
						fprintf(stderr, "write-error 2: %m\n");
						shutdown(fd_tun, SHUT_RD);
						shutdown(1, SHUT_WR);
						rea = 0;
						goto outer;
					}
					r += t;
				}
				while(r < ntohs(hdr.size)) {
					int t = write(1, buf, ntohs(hdr.size) - r);
					if (t < 0) {
						fprintf(stderr, "write-error 1: %s, written %d/%d\n", strerror(errno), r, ntohs(hdr.size));
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

	close(fd_tun);

	return 0;
}
