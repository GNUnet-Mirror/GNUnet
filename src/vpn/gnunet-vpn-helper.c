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

void setnonblocking(int fd) {
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
}

static int copy (int in, int out) {
	unsigned char buf[65600]; // 64k + 64;
	int r = read(in, buf, 65600);
	int w = 0;
	if (r < 0) return r;
	while (w < r) {
		int t = write(out, buf + w, r - w);
		if (t > 0) w += t;
		if (t < 0) return t;
	}
	return 0;
}

int main(int argc, char** argv) {
	char dev[IFNAMSIZ];
	memset(dev, 0, IFNAMSIZ);

	signal(SIGTERM, &term);

	int fd_tun = init_tun(dev);
	fprintf(stderr, "Initialized the interface %s as %d.\n", dev, fd_tun);

	// TODO: get this out of argv
	char address[] = "1234::1";
	unsigned long prefix_len = 8;

	set_address(dev, address, prefix_len);

	uid_t uid = getuid ();
	if (setresuid (uid, uid, uid) != 0 )
		fprintf (stderr, "Failed to setresuid: %m\n");

	setnonblocking(0);
	setnonblocking(1);
	setnonblocking(fd_tun);

	fd_set fds_w;
	fd_set fds_r;

	int r = 1;
	int w = 1;
	while(r != 0 && w != 0 && running == 1) {
		FD_ZERO(&fds_w);
		FD_ZERO(&fds_r);

		if (r) {
			FD_SET(fd_tun, &fds_r);
			FD_SET(1, &fds_w);
		}

		if (w) {
			FD_SET(0, &fds_r);
			FD_SET(fd_tun, &fds_w);
		}

		int r = select(fd_tun+1, &fds_r, &fds_w, (fd_set*)0, 0);

		if(r > 0) {
			if (FD_ISSET(0, &fds_r) && FD_ISSET(fd_tun, &fds_w)) {
				if (copy(0, fd_tun) < 0) {
					fprintf(stderr, "Closing Write\n");
					shutdown(fd_tun, SHUT_WR);
					w = 0;
				}
			} else if (FD_ISSET(1, &fds_w) && FD_ISSET(fd_tun, &fds_r)) {
				if (copy(fd_tun, 1) < 0) {
					fprintf(stderr, "Closing Read\n");
					shutdown(fd_tun, SHUT_RD);
					r = 0;
				}
			}
		}
	}
	fprintf(stderr, "Quitting!\n");

	return 0;
}
