/*
     This file is part of GNUnet.
     (C) 2013 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 3, or (at your
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
 * Aim of test_scalarproduct_api : This test creates two peers. Peer1 is the
 * responder peer, Bob and Peer2 is the initiator peer, Alice. Both peers
 * connect to VectorProduct Service, and use the API to issue requests to
 * service. Test passes, when the expected scalar product is received from the
 * service.
 */

/**
 * @file scalarproduct/testbed_scalarproduct_api.c
 * @brief VectorProduct API testing between 4 peers using testing API
 * @author Gaurav Kukreja
 * @author Christian Fuchs
 */

#include <string.h>

#include <inttypes.h>
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testbed_service.h"
#include "gnunet_common.h"
#include "gnunet_scalarproduct_service.h"
#include "gnunet_protocols.h"

#define NUM_PEERS 2

#define LOG(kind,...) GNUNET_log_from (kind, "test-scalarproduct-api",__VA_ARGS__)

/**
 * Structure for holding peer's sockets and IO Handles
 */
struct PeerData
{
  /**
   * Handle to testbed peer
   */
  struct GNUNET_TESTBED_Peer *peer;

  /**
   * The service connect operation to stream
   */
  struct GNUNET_TESTBED_Operation *op;

  /**
   * Our Peer id
   */
  struct GNUNET_PeerIdentity our_id;

  /**
   * Pointer to Vector Product Handle
   */
  struct GNUNET_SCALARPRODUCT_Handle *vh;
};

/**
 * Different states in test setup
 */
enum SetupState
{
  /**
   * Get the identity of peer 1
   */
  PEER1_GET_IDENTITY,

  /**
   * Get the identity of peer 2
   */
  PEER2_GET_IDENTITY,

  /**
   * Connect to stream service of peer 1
   */
  PEER1_SCALARPRODUCT_CONNECT,

  /**
   * Connect to stream service of peer 2
   */
  PEER2_SCALARPRODUCT_CONNECT

};

/******************************************************************************
 *** Global Variables                            *****************************
 ******************************************************************************/

/**
 * Maximum allowed message-ids we can check in one go (with one GNUNET_message)
 */
static unsigned int max_mids;

/**
 * Session Key used by both the test peers
 */
char input_key[103] = "helloworldhelloworldhelloworldhelloworldhelloworldhelloworldhelloworldhelloworldhelloworldhelloworldhe";

/**
 * Input elements for peer1
 */
char input_elements_peer1[] = "11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11";
//char input_elements_peer1[] = "11,11,11";

/**
 * Input Mask for peer 1
 */
char input_mask_peer1[] = "1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1";
//char input_mask_peer1[] = "1,1,1";

/**
 * the array of converted message IDs to send to our service
 */
static int32_t * elements_peer1 = NULL;

/**
 * Number of elements
 */
uint16_t element_count_peer1 = 0;

/**
 * Input elements for peer2
 */
char input_elements_peer2[] = "11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11";
//char input_elements_peer2[] = "11,11,11";

/**
 * Input Mask for peer 2
 */
char input_mask_peer2[] = "1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1";
//char input_mask_peer2[] = "1,1,1";

/**
 * the array of converted message IDs to send to our service
 */
static int32_t * elements_peer2 = NULL;

/**
 * the array of converted message IDs to send to our service
 */
static unsigned char * mask_peer2 = NULL;

/**
 * Number of elements
 */
uint16_t element_count_peer2 = 0;

/**
 * Data context for peer 1
 */
static struct PeerData peer1;

/**
 * Data context for peer 2
 */
static struct PeerData peer2;

/**
 * Various states during test setup
 */
static enum SetupState setup_state;

/**
 * Testbed operation handle
 */
static struct GNUNET_TESTBED_Operation *op;

static int ok;

static int responder_ok;

static int requester_ok;

static GNUNET_SCHEDULER_TaskIdentifier abort_task;
/******************************************************************************
 *** Static Functions                             *****************************
 ******************************************************************************/

static void
do_shutdown (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Close sockets and stop testing deamons nicely
 */
static void
do_close (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{

  if (peer1.op != NULL)
    do_shutdown (&peer1, NULL);

  if (peer2.op != NULL)
    do_shutdown (&peer2, NULL);

  if (GNUNET_SCHEDULER_NO_TASK != abort_task)
    GNUNET_SCHEDULER_cancel (abort_task);

  GNUNET_SCHEDULER_shutdown (); /* For shutting down testbed */
}

/**
 * Shutdown a peer
 *
 * @param cls pointer to "struct PeerData" of the peer to be disconnected
 * @param tc Task Context
 */
static void
do_shutdown (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  static int shutdown;
  shutdown++;
  struct PeerData* peer = (struct PeerData*) cls;

  if (peer == &peer1)
    LOG (GNUNET_ERROR_TYPE_INFO, "Disconnecting Peer1\n\n");
  else if (peer == &peer2)
    LOG (GNUNET_ERROR_TYPE_INFO, "Disconnecting Peer2\n\n");

  // peer->op contains handle to the TESTBED_connect_service operation
  // calling operation done, leads to call to scalarproduct_da
  if (peer->op != NULL)
    {
      GNUNET_TESTBED_operation_done (peer->op);
      peer->op = NULL;
    }

  if (shutdown >= 2)
    GNUNET_SCHEDULER_add_now (&do_close, NULL);
}


/**
 * Something went wrong and timed out. Kill everything and set error flag
 */
static void
do_abort (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "test: ABORT due to Timeout\n");
  ok = GNUNET_SYSERR;
  abort_task = 0;
  do_close (cls, tc);
}


/**
 * Controller event callback
 *
 * @param cls NULL
 * @param event the controller event
 */
static void
controller_event_cb (void *cls,
                     const struct GNUNET_TESTBED_EventInformation *event)
{
  GNUNET_assert (event->type == GNUNET_TESTBED_ET_OPERATION_FINISHED);

  switch (setup_state)
    {
    case PEER1_SCALARPRODUCT_CONNECT:
    case PEER2_SCALARPRODUCT_CONNECT:
      GNUNET_assert (NULL == event->details.operation_finished.emsg);
      break;
    default:
      GNUNET_assert (0);
    }
}


static void
responder_callback (void *cls,
                    const struct GNUNET_HashCode * key,
                    enum GNUNET_SCALARPRODUCT_ResponseStatus status)
{

  if (status == GNUNET_SCALARPRODUCT_Status_Failure)
    {
      LOG (GNUNET_ERROR_TYPE_WARNING, "Responder Client received status failure\n");
      responder_ok = -1;
    }
  else if (status == GNUNET_SCALARPRODUCT_Status_InvalidResponse)
    {
      LOG (GNUNET_ERROR_TYPE_WARNING, "Responder Client received status invalid response\n");
      responder_ok = -1;
    }
  else if (GNUNET_SCALARPRODUCT_Status_Timeout == status)
    {
      LOG (GNUNET_ERROR_TYPE_WARNING, "Responder Client received timeout occured\n");
      responder_ok = -1;
    }
  else if (GNUNET_SCALARPRODUCT_Status_ServiceDisconnected == status)
    {
      LOG (GNUNET_ERROR_TYPE_WARNING, "Responder Client received service disconnected!!\n");
      responder_ok = -1;
    }
  else if (GNUNET_SCALARPRODUCT_Status_Success == status)
    {
      LOG (GNUNET_ERROR_TYPE_INFO, "Responder Client expected response received!\n");
      responder_ok = 1;
    }
  else
    {
      LOG (GNUNET_ERROR_TYPE_WARNING, "Responder Client status = %d!\n", (int) status);
      responder_ok = -1;
    }
  // TODO : Responder Session Complete. Shutdown Test Cleanly!!!
  //do_shutdown(&peer1, NULL);
  GNUNET_SCHEDULER_add_now (&do_shutdown, &peer1);
  return;
}


static void
requester_callback (void *cls,
        const struct GNUNET_HashCode * key,
        const struct GNUNET_PeerIdentity * peer,
        enum GNUNET_SCALARPRODUCT_ResponseStatus status,
        const struct GNUNET_SCALARPRODUCT_client_response *msg)
{
  uint32_t product_len;

  if (status == GNUNET_SCALARPRODUCT_Status_Failure)
    {
      LOG (GNUNET_ERROR_TYPE_WARNING, "Requester Client received status failure\n");
      requester_ok = -1;
    }
  else if (status == GNUNET_SCALARPRODUCT_Status_InvalidResponse)
    {
      LOG (GNUNET_ERROR_TYPE_WARNING, "Requester Client received status invalid response\n");
      requester_ok = -1;
    }
  else if (GNUNET_SCALARPRODUCT_Status_Timeout == status)
    {
      LOG (GNUNET_ERROR_TYPE_WARNING, "Requester Client timeout occured\n");
      requester_ok = -1;
    }
  else if (GNUNET_SCALARPRODUCT_Status_ServiceDisconnected == status)
    {
      LOG (GNUNET_ERROR_TYPE_WARNING, "Requester Client service disconnected!!\n");
      requester_ok = -1;
    }
  else if (GNUNET_SCALARPRODUCT_Status_Success != status)
    {
      LOG (GNUNET_ERROR_TYPE_WARNING, "Requester Client Status = %d\n", (int) status);
      requester_ok = -1;
    }
  else if (GNUNET_SCALARPRODUCT_Status_Success == status)
    {
      LOG (GNUNET_ERROR_TYPE_INFO, "Requester Client expected response received!\n");
      product_len = ntohl(msg->product_length);

      if (0 < product_len)
        {
          gcry_mpi_t result;
          gcry_error_t ret = 0;
          size_t read = 0;
          ret = gcry_mpi_scan (&result, GCRYMPI_FMT_USG, &msg[1], product_len, &read);

          if (0 != ret)
            {
              GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Could not convert to mpi to value!\n");
              ok = -1;
            }
          else
            {
              uint16_t i = 0;

              // calculate expected product
              gcry_mpi_t expected_result;
              gcry_mpi_t v1;
              gcry_mpi_t v2;
              gcry_mpi_t v1_v2_prod;

              expected_result = gcry_mpi_new (0);

              for (i = 0; i < element_count_peer1; i++)
                {
                  uint32_t value;
                  v1_v2_prod = gcry_mpi_new (0);

                  // long to gcry_mpi_t
                  value = elements_peer1[i] >= 0 ? elements_peer1[i] : -elements_peer1[i];
                  if (elements_peer1[i] < 0)
                    {
                      v1 = gcry_mpi_new (0);
                      gcry_mpi_sub_ui (v1, v1, value);
                    }
                  else
                    v1 = gcry_mpi_set_ui (NULL, value);

                  // long to gcry_mpi_t
                  value = elements_peer2[i] >= 0 ? elements_peer2[i] : -elements_peer2[i];
                  if (elements_peer2[i] < 0)
                    {
                      v2 = gcry_mpi_new (0);
                      gcry_mpi_sub_ui (v2, v2, value);
                    }
                  else
                    v2 = gcry_mpi_set_ui (NULL, value);

                  gcry_mpi_mul (v1_v2_prod, v1, v2);
                  gcry_mpi_add (expected_result, expected_result, v1_v2_prod);

                  gcry_mpi_release (v1);
                  gcry_mpi_release (v2);
                  gcry_mpi_release (v1_v2_prod);

                }

              // compare the result
              if (!gcry_mpi_cmp (expected_result, result))
                {
                  LOG (GNUNET_ERROR_TYPE_INFO, "Scalar Product matches expected Result!!\n");
                  requester_ok = 1;
                }
              else
                {
                  LOG (GNUNET_ERROR_TYPE_WARNING, "Scalar Product DOES NOT match expected Result!!\n");
                  requester_ok = -1;
                }
              gcry_mpi_release (result);
              gcry_mpi_release (expected_result);
            }
        }
      else
        { //currently not used, but if we get more info due to MESH we will need this
          LOG (GNUNET_ERROR_TYPE_WARNING, "Error during computation of vector product, return code: %d\n", product_len);
          requester_ok = -1;
        }
    }

  //do_shutdown(&peer2, NULL);
  GNUNET_SCHEDULER_add_now (&do_shutdown, &peer2);
  return;
}

/**
 * Prepare the message to be sent by peer2 to its scalarproduct service, to
 * initiate a request to peer1.
 */
static struct GNUNET_SCALARPRODUCT_QueueEntry *
requester_request ()
{
  unsigned int i;
  int exit_loop;
  uint16_t mask_length = 0;
  char * begin = input_elements_peer2;
  char * end;
  int32_t element;
  struct GNUNET_SCALARPRODUCT_QueueEntry *qe;
  struct GNUNET_HashCode key;

  GNUNET_assert (peer2.vh != NULL);

  GNUNET_CRYPTO_hash (input_key, strlen (input_key), &key);

  /* Read input_elements_peer2, and put in elements_peer2 array */
  exit_loop = 0;
  do
    {
      unsigned int mcount = element_count_peer2;
      //ignore empty rows of ,,,,,,
      while (*begin == ',')
        begin++;
      // get the length of the current element and replace , with null
      for (end = begin; *end && *end != ','; end++);

      if (*end == '\0')
        exit_loop = 1;

      if (1 != sscanf (begin, "%" SCNd32, &element))
        {
          FPRINTF (stderr, _ ("Could not convert `%s' to int32_t.\n"), begin);
          ok = -1;
          return NULL;
        }

      GNUNET_array_append (elements_peer2, mcount, element);
      element_count_peer2++;

      begin = ++end;
    }
  while (!exit_loop && element_count_peer2 < max_mids);
  GNUNET_assert (elements_peer2 != NULL);
  GNUNET_assert (element_count_peer2 >= 1);

  /* Read input_mask_peer2 and read in mask_peer2 array */
  mask_length = element_count_peer2 / 8 + (element_count_peer2 % 8 ? 1 : 0);
  mask_peer2 = GNUNET_malloc ((element_count_peer2 / 8) + 2);
  GNUNET_assert (NULL != mask_peer2);
  if (NULL != input_mask_peer2)
    {
      begin = input_mask_peer2;
      unsigned short mask_count = 0;
      int exit_loop = 0;

      do
        {
          //ignore empty rows of ,,,,,,
          while (* begin == ',')
            begin++;
          // get the length of the current element and replace , with null
          // gnunet_ascii-armor uses base32, thus we can use , as separator!
          for (end = begin; *end && *end != ','; end++);

          if (*end == '\0')
            exit_loop = 1;

          if (1 != sscanf (begin, "%" SCNd32, &element))
            {
              FPRINTF (stderr, _ ("Could not convert `%s' to int32_t.\n"), begin);
              ok = -1;
              return NULL;
            }

          GNUNET_assert (mask_count <= element_count_peer2);

          if (element)
            mask_peer2[mask_count / 8] = mask_peer2[mask_count / 8] | 1 << (mask_count % 8);

          mask_count++;
          begin = ++end;
        }
      while (!exit_loop);
      // +1 to see if we would have more data, which would indicate malformed/superficial input
      GNUNET_assert (mask_count == element_count_peer2);
    }
  else
    {
      for (i = 0; i <= mask_length; i++)
        mask_peer2[i] = UCHAR_MAX; // all 1's
    }

  qe = GNUNET_SCALARPRODUCT_request (peer2.vh,
                                     &key,
                                     &peer1.our_id,
                                     element_count_peer2,
                                     mask_length,
                                     elements_peer2, mask_peer2,
                                     GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10),
                                     &requester_callback,
                                     NULL);

  if (qe == NULL)
    {
      LOG(GNUNET_ERROR_TYPE_ERROR, "Could not send request to scalarproduct service! Exitting!");
      ok = -1;
      return NULL;
    }

  return qe;
}


/**
 * Function prepares the message to be sent by peer1 to its scalarproduct service
 * to prepare response, and wait for a request session to be initiated by peer1
 */
static struct GNUNET_SCALARPRODUCT_QueueEntry *
responder_prepare_response ()
{
  GNUNET_assert (peer1.vh != NULL);

  char * begin = input_elements_peer1;
  char * end;
  int32_t element;
  struct GNUNET_SCALARPRODUCT_QueueEntry *qe;
  struct GNUNET_HashCode key;

  GNUNET_CRYPTO_hash (input_key, strlen (input_key), &key);

  /* Read input_elements_peer1, and put in elements_peer1 array */
  int exit_loop = 0;
  do
    {
      unsigned int mcount = element_count_peer1;
      //ignore empty rows of ,,,,,,
      while (*begin == ',')
        begin++;
      // get the length of the current element and replace , with null
      for (end = begin; *end && *end != ','; end++);

      if (*end == '\0')
        exit_loop = 1;

      if (1 != sscanf (begin, "%" SCNd32, &element))
        {
          FPRINTF (stderr, _ ("Could not convert `%s' to int32_t.\n"), begin);
          ok = -1;
          return NULL;
        }

      GNUNET_array_append (elements_peer1, mcount, element);
      element_count_peer1++;

      begin = ++end;
    }
  while (!exit_loop && element_count_peer1 < max_mids);
  GNUNET_assert (elements_peer1 != NULL);
  GNUNET_assert (element_count_peer1 >= 1);

  qe = GNUNET_SCALARPRODUCT_prepare_response (peer1.vh,
                                              &key,
                                              element_count_peer1,
                                              elements_peer1,
                                              GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10),
                                              &responder_callback,
                                              NULL);

  if (qe == NULL)
    {
      LOG(GNUNET_ERROR_TYPE_ERROR, "Could not send request to scalarproduct service! Exitting!");
      ok = -1;
      return NULL;
    }

  return qe;
}


/**
 * Scheduler task to initiate requester client
 *
 * @param cls void* to struct PeerData
 * @param tc Task Context
 */
static void
request_task(void *cls,
              const struct GNUNET_SCHEDULER_TaskContext
              * tc)
{
  requester_request();
  return;
}

/**
 * Scheduler task to initiate responder client
 *
 * @param cls void* to struct PeerData
 * @param tc Task Context
 */
static void
prepare_response_task(void *cls,
              const struct GNUNET_SCHEDULER_TaskContext
              * tc)
{
  responder_prepare_response();
  return;
}


/**
 * Adapter function called to destroy a connection to
 * a service. This function is called when GNUNET_TESTBED_operation_done is
 * called for peer->op, which holds the handle for GNUNET_TESTBED_service_connect
 * operation.
 *
 * @param cls closure
 * @param op_result service handle returned from the connect adapter
 */
static void
scalarproduct_da (void *cls, void *op_result)
{
  struct PeerData* peer = (struct PeerData*) cls;

  GNUNET_SCALARPRODUCT_cancel (peer->vh);
  return;
}


/**
 * Adapter function called to establish a connection to
 * a service. This function is called to by GNUNET_TESTBED_service_connect.
 *
 * @param cls closure
 * @param cfg configuration of the peer to connect to; will be available until
 *          GNUNET_TESTBED_operation_done() is called on the operation returned
 *          from GNUNET_TESTBED_service_connect()
 * @return service handle to return in 'op_result', NULL on error
 */
static void *
scalarproduct_ca (void *cls, const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct PeerData *p = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Peer %u (`%s') started\n", (&peer1 == p) ? 1 : 2,
              GNUNET_i2s (&p->our_id));

  switch (setup_state)
    {
    case PEER1_SCALARPRODUCT_CONNECT:
      /* Connect peer 2 to scalarproduct service */
      {
        peer2.op = GNUNET_TESTBED_service_connect (&peer2, peer2.peer, "scalarproduct",
                                                   NULL, NULL, scalarproduct_ca,
                                                   scalarproduct_da, &peer2);
        setup_state = PEER2_SCALARPRODUCT_CONNECT;
      }

      /* Actually connect peer 1 to scalarproduct service */
      peer1.vh = GNUNET_SCALARPRODUCT_connect (cfg);
      return peer1.vh;

    case PEER2_SCALARPRODUCT_CONNECT:
      /* Actually connect peer 2 to scalarproduct service */
      peer2.vh = GNUNET_SCALARPRODUCT_connect (cfg);

      /* Schedule tasks to initiate request from peer2 and prepare_response from peer1 */
      if(peer1.vh != NULL && peer2.vh != NULL)
      {
        GNUNET_SCHEDULER_add_now(&prepare_response_task, &peer1);
        GNUNET_SCHEDULER_add_now(&request_task, &peer2);
      }

      return peer2.vh;
    default:
      GNUNET_assert (0);
    }
}


/**
 * Callback to be called when the requested peer information is available
 *
 * @param cb_cls the closure from GNUNET_TETSBED_peer_get_information()
 * @param op the operation this callback corresponds to
 * @param pinfo the result; will be NULL if the operation has failed
 * @param emsg error message if the operation has failed; will be NULL if the
 *          operation is successfull
 */
static void
peerinfo_cb (void *cb_cls, struct GNUNET_TESTBED_Operation *op_,
             const struct GNUNET_TESTBED_PeerInformation *pinfo,
             const char *emsg)
{
  GNUNET_assert (NULL == emsg);
  GNUNET_assert (op == op_);
  switch (setup_state)
    {
    case PEER1_GET_IDENTITY:
      {
        memcpy (&peer1.our_id, pinfo->result.id,
                sizeof (struct GNUNET_PeerIdentity));
        GNUNET_TESTBED_operation_done (op);

        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Peer 1 id: %s\n", GNUNET_i2s_full
                    (&peer1.our_id));

        /* Request for peer id of peer 2*/
        op = GNUNET_TESTBED_peer_get_information (peer2.peer,
                                                  GNUNET_TESTBED_PIT_IDENTITY,
                                                  &peerinfo_cb, NULL);
        setup_state = PEER2_GET_IDENTITY;
      }
      break;
    case PEER2_GET_IDENTITY:
      {
        memcpy (&peer2.our_id, pinfo->result.id,
                sizeof (struct GNUNET_PeerIdentity));
        GNUNET_TESTBED_operation_done (op);

        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Peer 2 id: %s\n", GNUNET_i2s_full
                    (&peer2.our_id));

        /* Connect peer 1 to scalarproduct service */
        peer1.op = GNUNET_TESTBED_service_connect (&peer1, peer1.peer, "scalarproduct",
                                                   NULL, NULL, scalarproduct_ca,
                                                   scalarproduct_da, &peer1);
        setup_state = PEER1_SCALARPRODUCT_CONNECT;
      }
      break;
    default:
      GNUNET_assert (0);
    }
}


/**
 * Signature of a main function for a testcase.
 *
 * @param cls closure
 * @param num_peers number of peers in 'peers'
 * @param peers handle to peers run in the testbed
 */
static void
test_master (void *cls, unsigned int num_peers,
             struct GNUNET_TESTBED_Peer **peers)
{
  GNUNET_assert (NULL != peers);
  GNUNET_assert (NULL != peers[0]);
  GNUNET_assert (NULL != peers[1]);
  peer1.peer = peers[0];
  peer2.peer = peers[1];
  /* Get the peer identity and configuration of peer 1 */
  op = GNUNET_TESTBED_peer_get_information (peer1.peer,
                                            GNUNET_TESTBED_PIT_IDENTITY,
                                            &peerinfo_cb, NULL);
  setup_state = PEER1_GET_IDENTITY;

  /* Abort task for stopping test on timeout */
  abort_task =
          GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                        (GNUNET_TIME_UNIT_SECONDS, 20), &do_abort,
                                        NULL);
}


/**
 * Main function
 */
int
main (int argc, char **argv)
{
  uint64_t event_mask;

  ok = GNUNET_NO;
  event_mask = 0;
  event_mask |= (1LL << GNUNET_TESTBED_ET_OPERATION_FINISHED);
  max_mids = (GNUNET_SERVER_MAX_MESSAGE_SIZE - sizeof (struct GNUNET_MessageHeader))
          / sizeof (struct GNUNET_CRYPTO_HashAsciiEncoded) - 1;

  (void) GNUNET_TESTBED_test_run ("test_scalarproduct_api",
                                  "test_scalarproduct_api_data.conf",
                                  NUM_PEERS, event_mask, &controller_event_cb,
                                  NULL,
                                  &test_master, NULL);

  if (GNUNET_SYSERR == ok)
    {
      LOG (GNUNET_ERROR_TYPE_ERROR, "Test failing due to some error before calling API for request or prepare_response\n");
      return 1;
    }
  else if (GNUNET_SYSERR == responder_ok)
    {
      LOG (GNUNET_ERROR_TYPE_ERROR, "Test failing due to some error in responding_client\n");
      return 1;
    }
  else if (GNUNET_SYSERR == requester_ok)
    {
      LOG (GNUNET_ERROR_TYPE_ERROR, "Test failing due to some error in requesting client\n");
      return 1;
    }
  else
    return 0;
}


