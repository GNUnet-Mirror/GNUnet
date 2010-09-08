#include "platform.h"
#include <linux/if_tun.h>

/**
 * Creates a tun-interface called dev;
 * dev is asumed to point to a char[IFNAMSIZ]
 * if *dev == 0, uses the name supplied by the kernel
 * returns the fd to the tun or -1
 */
int init_tun(char *dev) {{{
	if (!dev) {
		errno = EINVAL;
		return -1;
	}

	struct ifreq ifr;
	int fd, err;

	if( (fd = open("/dev/net/tun", O_RDWR)) < 0 ) {
		fprintf(stderr, "opening /dev/net/tun: %s\n", strerror(errno));
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));

	ifr.ifr_flags = IFF_TUN;

	if (*dev)
		strncpy(ifr.ifr_name, dev, IFNAMSIZ);

	if ((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ){
		close(fd);
		fprintf(stderr, "ioctl'ing /dev/net/tun: %s\n", strerror(errno));
		return err;
	}

	strcpy(dev, ifr.ifr_name);
	return fd;
}}}
