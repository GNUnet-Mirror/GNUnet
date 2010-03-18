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
	if(memcmp(msg+960, originalMsg+960, 68)){
			fprintf(stderr, "the received message is not the sent one!\n");
	}

}

void message_proc2(void *cls, const struct GNUNET_MessageHeader * msg){
	printf("enter into message_proc2\n");
	struct combine * com2 = (struct combine* )cls;
	GNUNET_FRAGMENT_process(com2->ctx, com2->sender, msg);
}

int
main(int argc, char * argv[]){
	
	uint16_t mtu = 512;
	struct GNUNET_FRAGMENT_Context * ctx;
	struct GNUNET_MessageHeader *msg = GNUNET_malloc(sizeof(struct GNUNET_MessageHeader)+2*mtu);
	ctx = GNUNET_FRAGMENT_context_create(NULL, message_proc1, msg);
	msg->size = htons(sizeof(struct GNUNET_MessageHeader)+2*mtu);
	msg->type = htons(GNUNET_MESSAGE_TYPE_HELLO);
	struct GNUNET_PeerIdentity *sender;
	sender = GNUNET_malloc(sizeof(struct GNUNET_PeerIdentity));

	memset(sender, 9, sizeof(struct GNUNET_PeerIdentity));

	memset(&msg[1], 5, 2*mtu);
	struct combine *com;
	com = GNUNET_malloc(sizeof(struct combine));
	com->ctx = ctx;
	com->sender = sender;
	GNUNET_FRAGMENT_fragment(msg, mtu, message_proc2, com);
	GNUNET_free(msg);
	return 0;
}
