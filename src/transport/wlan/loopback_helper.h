/*
 * loopback_helper.h
 *
 *  Created on: 28.03.2011
 *      Author: David Brodski
 */

#ifndef LOOPBACK_HELPER_H_
#define LOOPBACK_HELPER_H_

//static void sigfunc(int sig);

//static void stdin_send(void *cls, void *client, const struct GNUNET_MessageHeader *hdr);

//static void file_in_send(void *cls, void *client, const struct GNUNET_MessageHeader *hdr);

int
testmode (int argc, char *argv[]);


#define FIFO_FILE1       "/tmp/test-transport/api-wlan-p1/WLAN_FIFO_in"
#define FIFO_FILE2       "/tmp/test-transport/api-wlan-p1/WLAN_FIFO_out"

extern int closeprog;

#endif /* LOOPBACK_HELPER_H_ */
