#include "platform.h"
#include "gnunet_client_lib.h"
#include "gnunet_arm_service.h"
#include "gnunet_hello_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_server_lib.h"
#include "gnunet_time_lib.h"
#include "gnunet_transport_service.h"
#include "transport.h"

// FIXME: document
struct AddressLookUpCB
{
  GNUNET_TRANSPORT_AddressLookUpCallback cb;
  void *cls;
  struct GNUNET_TIME_Absolute timeout;
  struct GNUNET_CLIENT_Connection *client;
};


// FIXME: document
static void
address_response_processor (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct AddressLookUpCB *alucb = cls;
  const char *address;
  uint16_t size;

  if (msg == NULL)
    {
      /* timeout */
      alucb->cb (alucb->cls, NULL);
      GNUNET_CLIENT_disconnect (alucb->client);
      GNUNET_free (alucb);
      return;
    }
  size = ntohs (msg->size);
  if (size == sizeof (struct GNUNET_MessageHeader))
    {
      /* last reply */
      address = NULL;
    }
  else
    {
      address = (const char *) &msg[1];
      if (address[size - sizeof (struct GNUNET_MessageHeader) - 1] != '\0')
        {
          /* invalid reply */
          GNUNET_break_op (0);
          alucb->cb (alucb->cls, NULL);
          GNUNET_CLIENT_disconnect (alucb->client);
          GNUNET_free (alucb);
          return;
        }
      else
        {
          /* expect more replies */
          GNUNET_CLIENT_receive (alucb->client, &address_response_processor,
                                 alucb,
                                 GNUNET_TIME_absolute_get_remaining
                                 (alucb->timeout));
        }
    }
  alucb->cb (alucb->cls, address);
  if (address == NULL)
    {
      /* done! */
      GNUNET_CLIENT_disconnect (alucb->client);
      GNUNET_free (alucb);
    }
}

void
GNUNET_TRANSPORT_address_lookup (struct GNUNET_SCHEDULER_Handle *sched,
                                 const struct GNUNET_CONFIGURATION_Handle
                                 *cfg, const char *address, size_t addressLen,
                                 const char *nameTrans,
                                 struct GNUNET_TIME_Relative timeout,
                                 GNUNET_TRANSPORT_AddressLookUpCallback aluc,
                                 void *aluc_cls)
{
  size_t len =
    sizeof (struct AddressLookupMessage) + addressLen + strlen (nameTrans) +
    1;
  struct AddressLookupMessage *msg;
  struct GNUNET_TIME_Absolute abs_timeout;
  struct AddressLookUpCB *aluCB;
  struct GNUNET_CLIENT_Connection *client;

  if (len >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
    {
      GNUNET_break (0);
      aluc (aluc_cls, NULL);
      return;
    }
  client = GNUNET_CLIENT_connect (sched, "transport", cfg);
  if (client == NULL)
    {
      aluc (aluc_cls, NULL);
      return;
    }
  abs_timeout = GNUNET_TIME_relative_to_absolute (timeout);
  msg = GNUNET_malloc (len);
  msg->header->size = htons (len);
  msg->header->type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_ADDRESS_LOOKUP);
  msg->timeout = GNUNET_TIME_absolute_hton (abs_timeout);
  msg->addrlen = htonl (addressLen);
  char *addrbuf = (char *) &msg[1];
  memcpy (addrbuf, address, addressLen);
  char *tbuf = &addrbuf[addressLen];
  memcpy (tbuf, nameTrans, strlen (nameTrans) + 1);
  aluCB = GNUNET_malloc (sizeof (struct AddressLookUpCB));
  aluCB->cb = aluc;
  aluCB->cb_cls = aluc_cls;
  aluCB->timeout = abs_timeout;
  aluCB->client = client;
  GNUNET_CLIENT_transmit_and_get_response (client, msg->header, timeout,
                                           GNUNET_YES,
                                           &address_response_processor,
                                           aluCB);
  GNUNET_free (msg);
}
