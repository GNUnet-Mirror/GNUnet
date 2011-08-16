/*
 * helper_common.h
 *
 *  Created on: 28.03.2011
 *      Author: david
 */

#ifndef HELPER_COMMON_H_
#define HELPER_COMMON_H_

int
getFrequencyFromChannel (int channel);
int
getChannelFromFrequency (int frequency);
int
send_mac_to_plugin (char *buffer, uint8_t * mac);

#endif /* HELPER_COMMON_H_ */
