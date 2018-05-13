struct GNUNET_MQ_Envelope *env;
struct GNUNET_MessageHeader *msg;

env = GNUNET_MQ_msg_extra (msg, payload_size, GNUNET_MY_MESSAGE_TYPE);
GNUNET_memcpy (&msg[1],
               &payload,
               payload_size);
// Send message via message queue 'mq'
GNUNET_mq_send (mq, env);
