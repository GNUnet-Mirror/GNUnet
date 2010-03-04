#include "platform.h"
#include "gnunet_fragmentation_lib.h"

void message_proc1(void *cls, const struct GNUNET_MessageHeader * msg){

	struct GNUNET_MessageHeader * originalMsg = (struct GNUNET_MessageHeader *)cls;
	if(originalMsg->size != msg->size){
			fprintf(stderr, "the received message has the different size with the sent one!");
		}
	if(originalMsg->type != msg->type){
			fprintf(stderr, "the received message has the different type with the sent one!");
		}
	if(memcmp(&originalMsg[1], &msg[1], originalMsg->size - sizeof(struct GNUNET_MessageHeader))){
			fprintf(stderr, "the received message is not the sent one!");
	}

}

void message_proc2(void *cls, const struct GNUNET_MessageHeader * msg){
	struct GNUNET_FRAGMENT_Context * ctx = (struct GNUNET_FRAGMENT_Context * )cls;
	struct Fragment *frag;
	struct GNUNET_PeerIdentity sender;
	GNUNET_FRAGMENT_process(ctx, &sender, msg);
}

int
main(int argc, char * argv[]){

	struct GNUNET_FRAGMENT_Context * ctx;
	struct GNUNET_MessageHeader *msg;
	ctx = GNUNET_FRAGMENT_context_create(stats, message_proc1, msg);
	msg->size = sizeof(struct GNUNET_MessageHeader)+2*mtu;
	msg->type = GNUNET_MESSAGE_TYPE_HELLO;
	memcpy(&msg[1], 5, 2*mtu);
	GNUNET_FRAGMENT_fragment(msg, mtu, message_proc2, ctx);

	return 0;
}
