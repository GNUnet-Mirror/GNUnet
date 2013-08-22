
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
 * AIM OF THIS TEST
 * 
 * The aim for the extended test is to verify the queuing functionality in the 
 * service and the API. The API queues requests received from the clients. The 
 * service queues requests that are received from other services.
 * 
 * To test this, we create 4 peers. peer1 and peer2 are designated responders, 
 * and peer3 and peer4 are designated as requesters. Each peer calls API for the
 * vectorproduct service accordingly.
 * 
 * * peer1 tells the service to prepare response for requests with keys 
 *   input_key_p1_p3(shared key b/w peer1 and peer3) and input_key_p1_p4. 
 *   Similarly peer2 tells service to prepare response for requests with keys 
 *   input_key_p2_p3, and input_key_p2_p4.
 * * Simultaneously, peer3 tells its service to send a request to peer1 with key
 *   input_key_p1_p3, and a request to peer2 with key input_key_p2_p3. Similarly, 
 *   peer 4 sends requests with appropriate keys.
 * 
 * Each peer sends 2 requests to its service, which tests the queuing in API. 
 * Each service receives 2 requests from other service, which tests the queuing 
 * functionality in the service.
 */


/**
 * @file vectorproduct/test_vectorproduct_api_4peers.c
 * @brief Vectorproduct API testing between 4 peers using testing API
 * @author Gaurav Kukreja
 * @author Christian Fuchs
 */

#include <string.h>

#include <inttypes.h>
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testbed_service.h"
#include "gnunet_common.h"
#include "gnunet_vectorproduct_service.h"
#include "gnunet_protocols.h"

#define LOG(kind,...) GNUNET_log_from (kind, "test-vectorproduct-api-4peers",__VA_ARGS__)

#define NUM_PEERS 4

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
  struct GNUNET_VECTORPRODUCT_Handle *vh;

  /**
   * Input elements for peer
   */
  char * input_elements;

  /**
   * Input Mask for peer
   */
  char * input_mask;

  /**
   * 2 Input keys for peer for 2 sessions of each peer
   */
  char * input_keys[2];

  /**
   * Number of requests(or prepare_response) sent by the peer
   */
  int request_num;

  /**
   * Number of callbacks received by the peer
   */
  int callback_num;

  /**
   * PeerData of the peers, this peer will talk to 
   */
  struct PeerData * peers[2];


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
   * Get the identity of peer 3
   */
  PEER3_GET_IDENTITY,

  /**
   * Get the identity of peer 4
   */
  PEER4_GET_IDENTITY,

  /**
   * Connect to stream service of peer 1
   */
  PEER1_VECTORPRODUCT_CONNECT,

  /**
   * Connect to stream service of peer 2
   */
  PEER2_VECTORPRODUCT_CONNECT,

  /**
   * Connect to stream service of peer 3
   */
  PEER3_VECTORPRODUCT_CONNECT,

  /**
   * Connect to stream service of peer 4
   */
  PEER4_VECTORPRODUCT_CONNECT

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
char input_key_p1_p3[103] = "111111111111111111111111111111111111111111111111113333333333333333333333333333333333333333333333333333";

/**
 * Session Key used by both the test peers
 */
char input_key_p1_p4[103] = "111111111111111111111111111111111111111111111111114444444444444444444444444444444444444444444444444444";

/**
 * Session Key used by both the test peers
 */
char input_key_p2_p3[103] = "222222222222222222222222222222222222222222222222223333333333333333333333333333333333333333333333333333";

/**
 * Session Key used by both the test peers
 */
char input_key_p2_p4[103] = "222222222222222222222222222222222222222222222222224444444444444444444444444444444444444444444444444444";

/**
 * Input elements for peer1
 */
//char input_elements_peer1[] = "11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11";
char input_elements_peer1[] = "11,11,11";

/**
 * Input Mask for peer 1
 */
//char input_mask_peer1[] = "1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1";
char input_mask_peer1[] = "1,1,1";

/**
 * Input elements for peer2
 */
//char input_elements_peer2[] = "11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11";
char input_elements_peer2[] = "11,11,11";
/**
 * Input Mask for peer 2
 */
//char input_mask_peer2[] = "1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1";
char input_mask_peer2[] = "1,1,1";

/**
 * Input elements for peer3
 */
//char input_elements_peer3[] = "11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11";
char input_elements_peer3[] = "11,11,11";

/**
 * Input Mask for peer 3
 */
//char input_mask_peer3[] = "1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1";
char input_mask_peer3[] = "1,1,1";

/**
 * Input elements for peer4
 */
//char input_elements_peer4[] = "11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11";
char input_elements_peer4[] = "11,11,11";
/**
 * Input Mask for peer 4
 */
//char input_mask_peer4[] = "1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1";
char input_mask_peer4[] = "1,1,1";


/**
 * Data context for peer 1
 */
static struct PeerData peer1;

/**
 * Data context for peer 2
 */
static struct PeerData peer2;

/**
 * Data context for peer 3
 */
static struct PeerData peer3;

/**
 * Data context for peer 4
 */
static struct PeerData peer4;

/**
 * Various states during test setup
 */
static enum SetupState setup_state;

/**
 * Testbed operation handle
 */
static struct GNUNET_TESTBED_Operation *op;

/**
 * Return value for the test
 */
static int ok;

/**
 * Abort Task for timeout
 */
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
    GNUNET_SCHEDULER_add_now (&do_shutdown, &peer1);

  if (peer2.op != NULL)
    GNUNET_SCHEDULER_add_now (&do_shutdown, &peer2);

  if (peer3.op != NULL)
    GNUNET_SCHEDULER_add_now (&do_shutdown, &peer3);

  if (peer4.op != NULL)
    GNUNET_SCHEDULER_add_now (&do_shutdown, &peer4);

  if (GNUNET_SCHEDULER_NO_TASK != abort_task)
    GNUNET_SCHEDULER_cancel (abort_task);

  GNUNET_SCHEDULER_shutdown (); /* For shutting down testbed */
}


static void
do_shutdown (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  static int shutdown;
  shutdown++;
  struct PeerData* peer = (struct PeerData*) cls;

  if (peer == &peer1)
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Shutting down Peer 1!!! \n");
  else if (peer == &peer2)
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Shutting down Peer 2!!! \n");
  else if (peer == &peer3)
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Shutting down Peer 3!!! \n");
  else if (peer == &peer4)
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Shutting down Peer 4!!! \n");

  // peer->op contains handle to the TESTBED_connect_service operation
  // calling operation done, leads to call to vectorproduct_da
  GNUNET_TESTBED_operation_done (peer->op);
  peer->op = NULL;

  if (shutdown == 4)
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
  switch (event->type)
    {
    case GNUNET_TESTBED_ET_OPERATION_FINISHED:
      switch (setup_state)
        {
        case PEER1_VECTORPRODUCT_CONNECT:
        case PEER2_VECTORPRODUCT_CONNECT:
          GNUNET_assert (NULL == event->details.operation_finished.emsg);
          break;
        default:
          GNUNET_assert (0);
        }
      break;
    default:
      GNUNET_assert (0);
    }
}


static void
responder_callback (void *cls,
                    const struct GNUNET_HashCode * key,
                    enum GNUNET_VECTORPRODUCT_ResponseStatus status)
{
  struct PeerData * peer = cls;

  peer->callback_num++;

  if (peer == &peer1)
    {
        LOG (GNUNET_ERROR_TYPE_DEBUG, "Peer1 received callback!!!\n");
    }
  else if (peer == &peer2)
    {
        LOG (GNUNET_ERROR_TYPE_DEBUG, "Peer2 received callback!!!\n");
    }
  else
    LOG (GNUNET_ERROR_TYPE_ERROR, "Requester callback received, but peer is neither peer1 nor peer2!!!\n");


  if (status == GNUNET_VECTORPRODUCT_Status_Failure)
    {
      LOG (GNUNET_ERROR_TYPE_ERROR, "Responder Client received status failure\n");
      ok = -1;
    }
  else if (status == GNUNET_VECTORPRODUCT_Status_InvalidResponse)
    {
      LOG (GNUNET_ERROR_TYPE_ERROR, "Responder Client received status invalid response\n");
      ok = -1;
    }
  else if (GNUNET_VECTORPRODUCT_Status_Timeout == status)
    {
      LOG (GNUNET_ERROR_TYPE_ERROR, "Responder Client received timeout occured\n");
      ok = -1;
    }
  else if (GNUNET_VECTORPRODUCT_Status_ServiceDisconnected == status)
    {
      LOG (GNUNET_ERROR_TYPE_ERROR, "Responder Client received service disconnected!!\n");
      ok = -1;
    }
  else if (GNUNET_VECTORPRODUCT_Status_Success == status)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Responder Client expected response received!\n");
      ok = 1;
    }
  else
    {
      LOG (GNUNET_ERROR_TYPE_ERROR, "Responder Client status = %d!\n", (int) status);
      ok = -1;
    }

  // TODO : Responder Session Complete. Shutdown Test Cleanly!!!
  if (peer->callback_num == 2)
    GNUNET_SCHEDULER_add_now (&do_shutdown, peer);
}


static void
requester_callback (void *cls,
                    const struct GNUNET_HashCode * key,
                    const struct GNUNET_PeerIdentity * peer,
                    enum GNUNET_VECTORPRODUCT_ResponseStatus status,
                    const struct GNUNET_VECTORPRODUCT_client_response *msg)
{
  struct PeerData * peer_ = cls;
  uint32_t product_len;

  peer_->callback_num++;
  
  if (peer_ == &peer3)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Peer3 received callback!!!\n");
    }
  else if (peer_ == &peer4)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Peer4 received callback!!!\n");
    }
  else
    LOG (GNUNET_ERROR_TYPE_ERROR, "Requester callback received, but peer is neither peer3 nor peer4!!!\n");


  if (status == GNUNET_VECTORPRODUCT_Status_Failure)
    {
      LOG (GNUNET_ERROR_TYPE_ERROR, "Requester Client received status failure\n");
      ok = -1;
    }
  else if (status == GNUNET_VECTORPRODUCT_Status_InvalidResponse)
    {
      LOG (GNUNET_ERROR_TYPE_ERROR, "Requester Client received status invalid response\n");
      ok = -1;
    }
  else if (GNUNET_VECTORPRODUCT_Status_Timeout == status)
    {
      LOG (GNUNET_ERROR_TYPE_ERROR, "Requester Client timeout occured\n");
      ok = -1;
    }
  else if (GNUNET_VECTORPRODUCT_Status_ServiceDisconnected == status)
    {
      LOG (GNUNET_ERROR_TYPE_ERROR, "Requester Client service disconnected!!\n");
      ok = -1;
    }
  else if (GNUNET_VECTORPRODUCT_Status_Success != status)
    {
      LOG (GNUNET_ERROR_TYPE_ERROR, "Requester Client Status = %d\n", (int) status);
      ok = -1;
    }
  else if (GNUNET_VECTORPRODUCT_Status_Success == status)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Requester client received status successful!\n");
      product_len = ntohl (msg->product_length);

      if (0 < product_len)
        {
          gcry_mpi_t result;
          gcry_error_t ret = 0;
          size_t read = 0;

          ret = gcry_mpi_scan (&result, GCRYMPI_FMT_USG, (void*) &(msg[1]), product_len, &read);

          if (0 != ret)
            {
              GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Could not convert to mpi to value!\n");
            }
          else
            {
              gcry_mpi_release (result);
            }
          ok = 1;
        }
      else
        { 
          //currently not used, but if we get more info due to MESH we will need this
          LOG (GNUNET_ERROR_TYPE_ERROR, "Error during computation of vector product, return code: %d\n", product_len);
          ok = -1;
        }
    }

  if (peer_->callback_num == 2)
    GNUNET_SCHEDULER_add_now (&do_shutdown, peer_);
}


static struct GNUNET_VECTORPRODUCT_QueueEntry *
requester_request (char * input_elements,
                   char * input_mask,
                   char * input_key,
                   struct PeerData * peer,
                   struct PeerData * to_peer)
{
  

  unsigned int i;
  uint16_t element_count = 0;
  int32_t * elements = NULL;
  uint16_t mask_length = 0;
  unsigned char * mask = NULL;
  int32_t element;
  struct GNUNET_VECTORPRODUCT_QueueEntry *qe;
  struct GNUNET_HashCode key;
  int exit_loop;
  char * begin = input_elements;
  char * end;
  
  GNUNET_assert (peer->vh != NULL);
  
  GNUNET_CRYPTO_hash_from_string (input_key, &key);
  
  exit_loop = 0;
  /* Read input_elements, and put in elements array */
  do
    {
      unsigned int mcount = element_count;
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
      
      GNUNET_array_append (elements, mcount, element);
      element_count++;

      begin = ++end;
    }
  while (!exit_loop && element_count < max_mids);
  GNUNET_assert (elements != NULL);
  GNUNET_assert (element_count >= 1);
  
  /* Read input_mask and read in mask array */
  mask_length = element_count / 8 + (element_count % 8 ? 1 : 0);
  mask = GNUNET_malloc ((element_count / 8) + 2);
  GNUNET_assert (NULL != mask);
  if (NULL != input_mask)
    {
      begin = input_mask;
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

          GNUNET_assert (mask_count <= element_count);

          if (element)
            mask[mask_count / 8] = mask[mask_count / 8] | 1 << (mask_count % 8);

          mask_count++;
          begin = ++end;
        }
      while (!exit_loop);
      // +1 to see if we would have more data, which would indicate malformed/superficial input
      GNUNET_assert (mask_count == element_count);
    }
  else
    {
      for (i = 0; i <= mask_length; i++)
        mask[i] = UCHAR_MAX; // all 1's
    }
  
  qe = GNUNET_VECTORPRODUCT_request (peer->vh,
                                     &key,
                                     &to_peer->our_id,
                                     element_count,
                                     mask_length,
                                     elements, mask,
                                     GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 60),
                                     &requester_callback,
                                     peer);

  if (qe == NULL)
    {
      LOG(GNUNET_ERROR_TYPE_WARNING, "Could not send request to vectorproduct service! Exitting!");
      ok = -1;
      return NULL;
    }

  return qe;
}


/**
 * Function prepares the message to be sent by peer1 to its vectorproduct service
 * to prepare response, and wait for a request session to be initiated by peer1
 */
static struct GNUNET_VECTORPRODUCT_QueueEntry *
responder_prepare_response (char * input_elements,
                            char * input_mask,
                            char * input_key,
                            struct PeerData * peer)
{
  GNUNET_assert (peer->vh != NULL);

  unsigned int i;
  uint16_t element_count = 0;
  int32_t * elements = NULL;
  unsigned short mask_length = 0;
  unsigned char * mask = NULL;
  int32_t element;
  struct GNUNET_VECTORPRODUCT_QueueEntry *qe;
  struct GNUNET_HashCode key;
  int exit_loop;
  char * begin;
  char * end;
  
  GNUNET_CRYPTO_hash_from_string (input_key, &key);
  
  /* Read input_elements, and put in elements array */
  exit_loop = 0;
  begin = input_elements;
  do
    {
      unsigned int mcount = element_count;
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

      GNUNET_array_append (elements, mcount, element);
      element_count++;

      begin = ++end;
    }
  while (!exit_loop && element_count < max_mids);
  GNUNET_assert (elements != NULL);
  GNUNET_assert (element_count >= 1);
  
  /* Read input_mask and read in mask array */
  mask_length = element_count / 8 + (element_count % 8 ? 1 : 0);
  mask = GNUNET_malloc ((element_count / 8) + 2);
  GNUNET_assert (NULL != mask);
  if (NULL != input_mask)
    {
      begin = input_mask;
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

          GNUNET_assert (mask_count <= element_count);

          if (element)
            mask[mask_count / 8] = mask[mask_count / 8] | 1 << (mask_count % 8);

          mask_count++;
          begin = ++end;
        }
      while (!exit_loop);
      // +1 to see if we would have more data, which would indicate malformed/superficial input
      GNUNET_assert (mask_count == element_count);
    }
  else
    {
      for (i = 0; i <= mask_length; i++)
        mask[i] = UCHAR_MAX; // all 1's
    }

  qe = GNUNET_VECTORPRODUCT_prepare_response (peer->vh,
                                              &key,
                                              element_count,
                                              elements,
                                              GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 60),
                                              &responder_callback,
                                              peer);

  if (qe == NULL)
    {
      LOG(GNUNET_ERROR_TYPE_ERROR, "Could not send request to vectorproduct service! Exitting!");
      ok = -1;
      return NULL;
    }

  return qe;
}


static void
request_task (void *cls,
              const struct GNUNET_SCHEDULER_TaskContext
              * tc)
{
  struct PeerData * peer = cls;

  requester_request (peer->input_elements, peer->input_mask, peer->input_keys[peer->request_num], peer, peer->peers[peer->request_num]);
  peer->request_num++;
  return;
}


static void
prepare_response_task (void *cls,
                       const struct GNUNET_SCHEDULER_TaskContext
                       * tc)
{
  struct PeerData * peer = cls;

  responder_prepare_response (peer->input_elements, peer->input_mask, peer->input_keys[peer->request_num], peer);
  peer->request_num++;
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
vectorproduct_da (void *cls, void *op_result)
{
  struct PeerData* peer = (struct PeerData*) cls;

  GNUNET_VECTORPRODUCT_disconnect (peer->vh);
  return;

  GNUNET_assert (0);
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
vectorproduct_ca (void *cls, const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct PeerData *p = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Peer %u (`%s') started\n", (&peer1 == p) ? 1 : 2,
              GNUNET_i2s (&p->our_id));

  switch (setup_state)
    {
    case PEER1_VECTORPRODUCT_CONNECT:
      /* Connect peer 2 to vectorproduct service */
      {
        peer2.op = GNUNET_TESTBED_service_connect (&peer2, peer2.peer, "vectorproduct",
                                                   NULL, NULL, vectorproduct_ca,
                                                   vectorproduct_da, &peer2);
        setup_state = PEER2_VECTORPRODUCT_CONNECT;
      }

      peer1.vh = GNUNET_VECTORPRODUCT_connect (cfg);
      return peer1.vh;

    case PEER2_VECTORPRODUCT_CONNECT:
      /* Connect peer 3 to vectorproduct service */
      {
        peer3.op = GNUNET_TESTBED_service_connect (&peer3, peer3.peer, "vectorproduct",
                                                   NULL, NULL, vectorproduct_ca,
                                                   vectorproduct_da, &peer3);
        setup_state = PEER3_VECTORPRODUCT_CONNECT;
      }

      peer2.vh = GNUNET_VECTORPRODUCT_connect (cfg);
      return peer2.vh;

    case PEER3_VECTORPRODUCT_CONNECT:
      /* Connect peer 4 to vectorproduct service */
      {
        peer4.op = GNUNET_TESTBED_service_connect (&peer4, peer4.peer, "vectorproduct",
                                                   NULL, NULL, vectorproduct_ca,
                                                   vectorproduct_da, &peer4);
        setup_state = PEER4_VECTORPRODUCT_CONNECT;
      }

      peer3.vh = GNUNET_VECTORPRODUCT_connect (cfg);
      return peer3.vh;

    case PEER4_VECTORPRODUCT_CONNECT:
      peer4.vh = GNUNET_VECTORPRODUCT_connect (cfg);

      /* Schedule the tasks to issue prepare_response calls from peer1 and peer2
       * for peer3 and peer4.
       */
      GNUNET_SCHEDULER_add_now (&prepare_response_task, &peer1);
      GNUNET_SCHEDULER_add_now (&prepare_response_task, &peer1);
      GNUNET_SCHEDULER_add_now (&prepare_response_task, &peer2);
      GNUNET_SCHEDULER_add_now (&prepare_response_task, &peer2);

      /* 
       * Schedule the tasks to issue requests calls from peer3 and peer4
       * to peer1 and peer2
       */
      GNUNET_SCHEDULER_add_now (&request_task, &peer3);
      GNUNET_SCHEDULER_add_now (&request_task, &peer3);
      GNUNET_SCHEDULER_add_now (&request_task, &peer4);
      GNUNET_SCHEDULER_add_now (&request_task, &peer4);

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

        /* Request for peer id of peer 3*/
        op = GNUNET_TESTBED_peer_get_information (peer3.peer,
                                                  GNUNET_TESTBED_PIT_IDENTITY,
                                                  &peerinfo_cb, NULL);
        setup_state = PEER3_GET_IDENTITY;
      }
      break;
    case PEER3_GET_IDENTITY:
      {
        memcpy (&peer3.our_id, pinfo->result.id,
                sizeof (struct GNUNET_PeerIdentity));
        GNUNET_TESTBED_operation_done (op);

        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Peer 3 id: %s\n", GNUNET_i2s_full
                    (&peer3.our_id));

        /* Request for peer id of peer 4*/
        op = GNUNET_TESTBED_peer_get_information (peer4.peer,
                                                  GNUNET_TESTBED_PIT_IDENTITY,
                                                  &peerinfo_cb, NULL);
        setup_state = PEER4_GET_IDENTITY;
      }
      break;
    case PEER4_GET_IDENTITY:
      {
        memcpy (&peer4.our_id, pinfo->result.id,
                sizeof (struct GNUNET_PeerIdentity));
        GNUNET_TESTBED_operation_done (op);

        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Peer 2 id: %s\n", GNUNET_i2s_full
                    (&peer2.our_id));

        /* Connect peer 1 to vectorproduct service */
        peer1.op = GNUNET_TESTBED_service_connect (&peer1, peer1.peer, "vectorproduct",
                                                   NULL, NULL, vectorproduct_ca,
                                                   vectorproduct_da, &peer1);
        setup_state = PEER1_VECTORPRODUCT_CONNECT;
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
  GNUNET_assert (NULL != peers[2]);
  GNUNET_assert (NULL != peers[3]);
  peer1.peer = peers[0];
  peer1.input_elements = input_elements_peer1;
  peer1.input_mask = input_mask_peer1;
  peer1.request_num = 0;
  peer1.callback_num = 0;
  peer1.input_keys[0] = input_key_p1_p3;
  peer1.input_keys[1] = input_key_p1_p4;

  peer2.peer = peers[1];
  peer2.input_elements = input_elements_peer2;
  peer2.input_mask = input_mask_peer2;
  peer2.request_num = 0;
  peer2.callback_num = 0;
  peer2.input_keys[0] = input_key_p2_p3;
  peer2.input_keys[1] = input_key_p2_p4;

  peer3.peer = peers[2];
  peer3.input_elements = input_elements_peer3;
  peer3.input_mask = input_mask_peer3;
  peer3.request_num = 0;
  peer3.callback_num = 0;
  peer3.input_keys[0] = input_key_p1_p3;
  peer3.input_keys[1] = input_key_p2_p3;
  peer3.peers[0] = &peer1;
  peer3.peers[1] = &peer2;


  peer4.peer = peers[3];
  peer4.input_elements = input_elements_peer4;
  peer4.input_mask = input_mask_peer4;
  peer4.request_num = 0;
  peer4.callback_num = 0;
  peer4.input_keys[0] = input_key_p1_p4;
  peer4.input_keys[1] = input_key_p2_p4;
  peer4.peers[0] = &peer1;
  peer4.peers[1] = &peer2;
  
  /* Get the peer identity and configuration of peer 1 */
  op = GNUNET_TESTBED_peer_get_information (peer1.peer,
                                            GNUNET_TESTBED_PIT_IDENTITY,
                                            &peerinfo_cb, NULL);
  setup_state = PEER1_GET_IDENTITY;
  abort_task =
          GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                        (GNUNET_TIME_UNIT_SECONDS, 120), &do_abort,
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
  (void) GNUNET_TESTBED_test_run ("test_vectorproduct_api_4peers",
                                  "test_vectorproduct_api_data.conf",
                                  NUM_PEERS, event_mask, &controller_event_cb,
                                  NULL,
                                  &test_master, NULL);
  if (GNUNET_SYSERR == ok)
    return 1;
  return 0;
}
