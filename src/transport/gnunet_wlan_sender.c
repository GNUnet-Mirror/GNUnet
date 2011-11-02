
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#define WLAN_MTU 1500

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <netpacket/packet.h>
#include <linux/if_ether.h>
#include <linux/if.h>
#include <linux/wireless.h>
#include <netinet/in.h>
#include <linux/if_tun.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
//#include <sys/utsname.h>
#include <sys/param.h>

#include <time.h>


#include "gnunet/gnunet_protocols.h"
#include "plugin_transport_wlan.h"

/**
 * LLC fields for better compatibility
 */
#define WLAN_LLC_DSAP_FIELD 0x1f
#define WLAN_LLC_SSAP_FIELD 0x1f

#define IEEE80211_ADDR_LEN      6       /* size of 802.11 address */

#define IEEE80211_FC0_VERSION_MASK              0x03
#define IEEE80211_FC0_VERSION_SHIFT             0
#define IEEE80211_FC0_VERSION_0                 0x00
#define IEEE80211_FC0_TYPE_MASK                 0x0c
#define IEEE80211_FC0_TYPE_SHIFT                2
#define IEEE80211_FC0_TYPE_MGT                  0x00
#define IEEE80211_FC0_TYPE_CTL                  0x04
#define IEEE80211_FC0_TYPE_DATA                 0x08


/*
 * generic definitions for IEEE 802.11 frames
 */
struct ieee80211_frame
{
  u_int8_t i_fc[2];
  u_int8_t i_dur[2];
  u_int8_t i_addr1[IEEE80211_ADDR_LEN];
  u_int8_t i_addr2[IEEE80211_ADDR_LEN];
  u_int8_t i_addr3[IEEE80211_ADDR_LEN];
  u_int8_t i_seq[2];
  u_int8_t llc[4];
#if DEBUG_wlan_ip_udp_packets_on_air > 1
  struct iph ip;
  struct udphdr udp;
#endif
} GNUNET_PACKED;

/**
 * function to fill the radiotap header
 * @param plugin pointer to the plugin struct
 * @param endpoint pointer to the endpoint
 * @param header pointer to the radiotap header
 * @return GNUNET_YES at success
 */
static int
getRadiotapHeader ( struct Radiotap_Send *header)
{


    header->rate = 255;
    header->tx_power = 0;
    header->antenna = 0;

  return GNUNET_YES;
}

/**
 * function to generate the wlan hardware header for one packet
 * @param Header address to write the header to
 * @param to_mac_addr address of the recipient
 * @param plugin pointer to the plugin struct
 * @param size size of the whole packet, needed to calculate the time to send the packet
 * @return GNUNET_YES if there was no error
 */
static int
getWlanHeader (struct ieee80211_frame *Header,
               const char *to_mac_addr, const char *mac,
               unsigned int size)
{
  uint16_t *tmp16;
  const int rate = 11000000;

  Header->i_fc[0] = IEEE80211_FC0_TYPE_DATA;
  Header->i_fc[1] = 0x00;
  memcpy (&Header->i_addr3, &mac_bssid, sizeof (mac_bssid));
  memcpy (&Header->i_addr2, mac,
		  sizeof (mac_bssid));
  memcpy (&Header->i_addr1, to_mac_addr, sizeof (mac_bssid));

  tmp16 = (uint16_t *) Header->i_dur;
  *tmp16 = (uint16_t) htole16 ((size * 1000000) / rate + 290);
  Header->llc[0] = WLAN_LLC_DSAP_FIELD;
  Header->llc[1] = WLAN_LLC_SSAP_FIELD;

#if DEBUG_wlan_ip_udp_packets_on_air > 1
  uint crc = 0;
  uint16_t *x;
  int count;

  Header->ip.ip_dst.s_addr = *((uint32_t *) & to_mac_addr->mac[2]);
  Header->ip.ip_src.s_addr = *((uint32_t *) & plugin->mac_address.mac[2]);
  Header->ip.ip_v = 4;
  Header->ip.ip_hl = 5;
  Header->ip.ip_p = 17;
  Header->ip.ip_ttl = 1;
  Header->ip.ip_len = htons (size + 8);
  Header->ip.ip_sum = 0;
  x = (uint16_t *) & Header->ip;
  count = sizeof (struct iph);
  while (count > 1)
  {
    /* This is the inner loop */
    crc += (unsigned short) *x++;
    count -= 2;
  }
  /* Add left-over byte, if any */
  if (count > 0)
    crc += *(unsigned char *) x;
  crc = (crc & 0xffff) + (crc >> 16);
  Header->ip.ip_sum = htons (~(unsigned short) crc);
  Header->udp.len = htons (size - sizeof (struct ieee80211_frame));

#endif

  return GNUNET_YES;
}

int main(int argc, char *argv[]){
	struct GNUNET_MessageHeader *msg;
	struct GNUNET_MessageHeader *msg2;
	struct ieee80211_frame *wlan_header;
	struct Radiotap_Send *radiotap;

	char inmac[6];
	char outmac[6];
	int pos;
	long long count;
	double bytes_per_s;
	time_t start;
	time_t akt;

	if (4 != argc) {
		fprintf(
				stderr,
				"This program must be started with the interface and the targets and source mac as argument.\nThis program was compiled at ----- %s ----\n",
				__TIMESTAMP__);
		fprintf(stderr, "Usage: interface-name mac-target mac-source\n" "\n");
		return 1;
	}


	pid_t pid;
	int rv;
	int	commpipe[2];		/* This holds the fd for the input & output of the pipe */

	/* Setup communication pipeline first */
	if(pipe(commpipe)){
		fprintf(stderr,"Pipe error!\n");
		exit(1);
	}

	/* Attempt to fork and check for errors */
	if( (pid=fork()) == -1){
		fprintf(stderr,"Fork error. Exiting.\n");  /* something went wrong */
		exit(1);
	}

	if(pid){
		/* A positive (non-negative) PID indicates the parent process */
		//dup2(commpipe[1],1);	/* Replace stdout with out side of the pipe */
		close(commpipe[0]);		/* Close unused side of pipe (in side) */
		setvbuf(stdout,(char*)NULL,_IONBF,0);	/* Set non-buffered output on stdout */

		sscanf(argv[3], "%x-%x-%x-%x-%x-%x", &inmac[0],&inmac[1],&inmac[2],&inmac[3],&inmac[4],&inmac[5]);
		sscanf(argv[2], "%x-%x-%x-%x-%x-%x", &outmac[0],&outmac[1],&outmac[2],&outmac[3],&outmac[4],&outmac[5]);

		msg = malloc(WLAN_MTU);
		msg->type = htons (GNUNET_MESSAGE_TYPE_WLAN_HELPER_DATA);
		msg->size = htons (WLAN_MTU);
		radiotap = (struct Radiotap_Send *) &msg[1];
		wlan_header = (struct ieee80211_frame *) &radiotap[1];
		pos = 0;

		getRadiotapHeader(radiotap);
		getWlanHeader(wlan_header, outmac, inmac, WLAN_MTU - sizeof(struct GNUNET_MessageHeader));

		start = time(NULL);
		while (1){
			pos += write(commpipe[1], msg, WLAN_MTU - pos);
			if (pos % WLAN_MTU == 0){
				pos = 0;
				count ++;

				if  (count % 1000 == 0){
					akt = time(NULL);
					bytes_per_s = count * WLAN_MTU / (akt - start);
					bytes_per_s /= 1024;
					printf("send %f kbytes/s\n", bytes_per_s);
				}
			}

		}
		/*
		sleep(2);
		printf("Hello\n");
		sleep(2);
		printf("Goodbye\n");
		sleep(2);
		printf("exit\n");
		*/
		//wait(&rv);				/* Wait for child process to end */
		//fprintf(stderr,"Child exited with a %d value\n",rv);
	}
	else{
		/* A zero PID indicates that this is the child process */
		dup2(commpipe[0],0);	/* Replace stdin with the in side of the pipe */
		close(commpipe[1]);		/* Close unused side of pipe (out side) */
		/* Replace the child fork with a new process */
		if(execl("gnunet-transport-wlan-helper","gnunet-transport-wlan-helper", argv[1], NULL) == -1){
			fprintf(stderr,"execl Error!");
			exit(1);
		}
	}
	return 0;
}
