/*
 * helper_common.h
 *
 *  Created on: 28.03.2011
 *      Author: david
 */

#ifndef HELPER_COMMON_H_
#define HELPER_COMMON_H_

int
send_mac_to_plugin (char *buffer, uint8_t * mac);


#define MAXLINE 4096

struct sendbuf
{
  unsigned int pos;
  unsigned int size;
  char buf[MAXLINE * 2];
};

#endif /* HELPER_COMMON_H_ */
