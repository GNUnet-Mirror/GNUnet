#ifndef _GNVPN_DNSP_H_
#define _GNVPN_DNSP_H_

/**
 * Parses the dns-name pointed to by src+idx returning idx so, that src+idx points
 * to the first unused char.
 */
unsigned int parse_dns_name(unsigned char* dest, const unsigned char* src, unsigned short idx);

#endif
