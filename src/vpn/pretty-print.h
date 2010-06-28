#ifndef _GNTUN_PP_H_
#define _GNTUN_PP_H_

extern void pp_hexdump(unsigned char* data, char* dest, int max);

extern void pp_write_header(char* dest, struct ip6_pkt* pkt);

extern void pkt_printf(struct ip6_pkt* pkt);

void pkt_printf_ip6tcp(struct ip6_tcp* pkt);

#endif
