#ifndef _GNTUN_TUN_H_
#define _GNTUN_TUN_H_

/**
 * Creates a tun-interface called dev;
 * if *dev == 0, uses the name supplied by the kernel
 * returns the fd to the tun or -1
 */
int init_tun(char *dev);

#endif
