#include "platform.h"
#include "gnunet-dns-parser.h"

unsigned int parse_dns_name(unsigned char* d, const unsigned char* src, unsigned short idx) {/*{{{*/
	unsigned char* dest = d;

	int len = src[idx++];
	while (len != 0) {
		if (len & 0xC0) { /* Compressed name, offset in this and the next octet */
			unsigned short offset = ((len & 0x3F) << 8) | src[idx++];
			parse_dns_name(dest, src, offset - 12); /* 12 for the Header of the DNS-Packet, idx starts at 0 which is 12 bytes from the start of the packet */
			return idx;
		}
		memcpy(dest, src+idx, len);
		idx += len;
		dest += len;
		*dest = '.';
		dest++;
		len = src[idx++];
	};
	*dest = 0;

	return idx;
}
/*}}}*/
