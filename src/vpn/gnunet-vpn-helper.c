#define _GNU_SOURCE
#include <arpa/inet.h>
#include <linux/if.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <string.h>

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

int main(int argc, char** argv) {
	char dev[IFNAMSIZ];
	memset(dev, 0, IFNAMSIZ);

	int fd_tun = init_tun(dev);
	fprintf(stderr, "Initialized the interface %s as %d.\n", dev, fd_tun);

	// TODO: get this out of argv
	char address[] = "1234::1";
	unsigned long prefix_len = 8;

	set_address(dev, address, prefix_len);

	uid_t uid = getuid ();
	if (setresuid (uid, uid, uid) != 0 )
		fprintf (stderr, "Failed to setresuid: %m\n");

	// Wait
	read(0, dev, 10);

	return 0;
}
