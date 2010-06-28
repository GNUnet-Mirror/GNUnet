#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include <linux/if.h>
#include <linux/if_tun.h>

#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

int tun_alloc(char *dev) {
	struct ifreq ifr;
	int fd, err;

	if( (fd = open("/dev/net/tun", O_RDWR)) < 0 ) {
		fprintf(stderr, "open: %s\n", strerror(errno));
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));

	ifr.ifr_flags = IFF_TUN; 
	if(*dev)
		strncpy(ifr.ifr_name, dev, IFNAMSIZ);

	if ((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ){
		close(fd);
		fprintf(stderr, "ioctl: %s\n", strerror(errno));
		return err;
	}
	strcpy(dev, ifr.ifr_name);
	return fd;
}

void n2o(fd) {
	char buf[1024];
	int r, w;
	for(;;) {
		r = read(fd, buf, 1024);
		if (r < 0) {
			fprintf(stderr, "n2o read: %s\n", strerror(errno));
			exit(1);
		}
		if (r == 0) {
			close(fd);
			exit(0);
		}
		while (r > 0) {
			w = write(1, buf, r);
			if (w < 0) {
				fprintf(stderr, "n2o write: %s\n", strerror(errno));
				close(fd);
				exit(1);
			}
			r -= w;
		}
	}
}

void o2n(fd) {
	char buf[1024];
	int r, w;
	for(;;) {
		r = read(0, buf, 1024);
		if (r < 0) {
			fprintf(stderr, "o2n read: %s\n", strerror(errno));
			exit(1);
		}
		if (r == 0) {
			close(fd);
			exit(0);
		}
		while (r > 0) {
			w = write(fd, buf, r);
			if (w < 0) {
				fprintf(stderr, "o2n write: %s\n", strerror(errno));
				close(fd);
				exit(1);
			}
			r -= w;
		}
	}
}

int main(int argc, char** argv) {
	char name[IFNAMSIZ];
	int fd;

	memset(name, 0, IFNAMSIZ);

	strncpy(name, "mynet", IFNAMSIZ);
	fprintf(stderr, "fd = %d, name = %s\n", fd = tun_alloc(name), name);

	if (fork() == 0)
		n2o(fd);

	o2n(fd);

	return 0;
}
