/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
     option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     General Public License for more details.

     You should have received a copy of the GNU General Public License
     along with GNUnet; see the file COPYING.  If not, write to the
     Free Software Foundation, Inc., 59 Temple Place - Suite 330,
     Boston, MA 02111-1307, USA.
*/

/**
 * @file fragmentation/test_fragmentation_enhanced.c
 * @brief testcase for the fragmentation.c
 * @author Ji Lu
 */

#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_fragmentation_lib.h"

struct combine{
	struct GNUNET_FRAGMENT_Context* ctx;
	struct GNUNET_PeerIdentity* sender;
};

void message_proc1(void *cls, const struct GNUNET_MessageHeader * msg){

	fprintf(stderr, "enter into message_proc1\n");

	struct GNUNET_MessageHeader * originalMsg = (struct GNUNET_MessageHeader *)cls;

	if(ntohs(originalMsg->size) != ntohs(msg->size)){
			fprintf(stderr, "the received message has the different size with the sent one!\n");
		}
	if(ntohs(originalMsg->type) != ntohs(msg->type)){
			fprintf(stderr, "the received message has the different type with the sent one!\n");
		}
	if(memcmp(msg, originalMsg, originalMsg->size)){
			fprintf(stderr, "the received message is not the sent one!\n");
	}
	else{
			fprintf(stdout, "You got the right message!\n");
	}

}

void message_proc2(void *cls, const struct GNUNET_MessageHeader * msg){

	printf("enter into message_proc2\n");

	struct combine * com2 = (struct combine* )cls;
	GNUNET_FRAGMENT_process(com2->ctx, com2->sender, msg);

}

int
main(int argc, char * argv[]){
	
	uint32_t mtu = 512;
	struct GNUNET_FRAGMENT_Context * ctx;
	struct GNUNET_MessageHeader *msg = (struct GNUNET_MessageHeader *)GNUNET_malloc(sizeof(struct GNUNET_MessageHeader)+2*mtu);
	ctx = GNUNET_FRAGMENT_context_create(NULL, message_proc1, msg);
	msg->size = htons(sizeof(struct GNUNET_MessageHeader)+4*mtu);
	msg->type = htons(GNUNET_MESSAGE_TYPE_HELLO);
	struct GNUNET_PeerIdentity *sender;
	sender = (struct GNUNET_PeerIdentity *)GNUNET_malloc(sizeof(struct GNUNET_PeerIdentity));

	memset(sender, 9, sizeof(struct GNUNET_PeerIdentity));

	memset(&msg[1], 5, 2*mtu);

	struct combine *com;
	com = (struct combine *)GNUNET_malloc(sizeof(struct combine));
	com->ctx = ctx;
	com->sender = sender;
	GNUNET_FRAGMENT_fragment(msg, mtu, message_proc2, com);
	GNUNET_free(msg);
	return 0;
}
