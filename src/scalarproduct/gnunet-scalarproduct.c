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
 * @file scalarproduct/gnunet-scalarproduct.c
 * @brief scalarproduct client
 * @author Christian M. Fuchs
 */
#define GCRYPT_NO_DEPRECATED
#include <gcrypt.h>
#include <inttypes.h>

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_scalarproduct_service.h"
#include "gnunet_protocols.h"
#include "scalarproduct.h"

#define LOG(kind,...) GNUNET_log_from (kind, "gnunet-scalarproduct",__VA_ARGS__)
#define INPUTSTRINGLENGTH       1024

/**
 * A primitive closure structure holding information about our session
 */
struct ScalarProductCallbackClosure
{
  /**
   * the session key identifying this computation
   */
  struct GNUNET_HashCode key;

  /**
   * PeerID we want to compute a scalar product with
   */
  struct GNUNET_PeerIdentity peer;
};

/**
 * Option -p: destination peer identity for checking message-ids with
 */
static char *input_peer_id;

/**
 * Option -p: destination peer identity for checking message-ids with
 */
static char *input_key;

/**
 * Option -e: vector to calculate a scalarproduct with
 */
static char *input_elements;

/**
 * Option -m: message-ids to calculate a scalarproduct with
 */
static char *input_mask;

/**
 * Global return value
 */
static int ret = -1;


/**
 * Callback called if we are initiating a new computation session
 *
 * @param cls unused
 * @param status if our job was successfully processed
 */
static void
responder_callback (void *cls,
                    enum GNUNET_SCALARPRODUCT_ResponseStatus status)
{
  struct ScalarProductCallbackClosure * closure = cls;

  switch (status)
  {
  case GNUNET_SCALARPRODUCT_Status_Success:
    ret = 0;
    LOG (GNUNET_ERROR_TYPE_INFO, "Session %s concluded.\n", GNUNET_h2s (&closure->key));
    break;
  case GNUNET_SCALARPRODUCT_Status_InvalidResponse:
    LOG (GNUNET_ERROR_TYPE_ERROR, "Session %s failed: invalid response\n", GNUNET_h2s (&closure->key));
    break;
  case GNUNET_SCALARPRODUCT_Status_Failure:
    LOG (GNUNET_ERROR_TYPE_ERROR, "Session %s failed: service failure\n", GNUNET_h2s (&closure->key));
  case GNUNET_SCALARPRODUCT_Status_ServiceDisconnected:
    LOG (GNUNET_ERROR_TYPE_ERROR, "Session %s failed: service disconnect!!\n", GNUNET_h2s (&closure->key));
    break;
  default:
    LOG (GNUNET_ERROR_TYPE_ERROR, "Session %s failed: return code %d\n", GNUNET_h2s (&closure->key), status);
  }
  GNUNET_SCHEDULER_shutdown();
}


/**
 * Callback called if we are initiating a new computation session
 *
 * @param cls unused
 * @param status if our job was successfully processed
 * @param result the result in gnu/gcry MPI format
 */
static void
requester_callback (void *cls,
                    enum GNUNET_SCALARPRODUCT_ResponseStatus status,
                    gcry_mpi_t result)
{
  struct ScalarProductCallbackClosure * closure = cls;
  unsigned char * buf;
  gcry_error_t rc;

  switch (status)
  {
  case GNUNET_SCALARPRODUCT_Status_Success:
    if (0 == (rc = gcry_mpi_aprint (GCRYMPI_FMT_HEX, &buf, NULL, result)))
    {
      ret = 0;
      printf ("%s", buf);
    }
    else
      LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_mpi_aprint", rc);
    break;
  case GNUNET_SCALARPRODUCT_Status_InvalidResponse:
    LOG (GNUNET_ERROR_TYPE_ERROR, "Session %s with peer %s failed: invalid response received\n", GNUNET_h2s (&closure->key), GNUNET_i2s (&closure->peer));
    break;
  case GNUNET_SCALARPRODUCT_Status_Failure:
    LOG (GNUNET_ERROR_TYPE_ERROR, "Session %s with peer %s failed: API failure\n", GNUNET_h2s (&closure->key), GNUNET_i2s (&closure->peer));
  case GNUNET_SCALARPRODUCT_Status_ServiceDisconnected:
    LOG (GNUNET_ERROR_TYPE_ERROR, "Session %s with peer %s was disconnected from service.\n", GNUNET_h2s (&closure->key), GNUNET_i2s (&closure->peer));
    break;
  default:
    LOG (GNUNET_ERROR_TYPE_ERROR, "Session %s with peer %s failed: return code %d\n", GNUNET_h2s (&closure->key), GNUNET_i2s (&closure->peer), status);
  }
  GNUNET_SCHEDULER_shutdown();
}

/**
 * Task run during shutdown.
 *
 * @param cls unused
 * @param tc unused
 */
static void
shutdown_task (void *cls,
               const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_SCALARPRODUCT_disconnect ();
}

/**
 * Main function that will be run by the scheduler.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param cfg configuration
 */
static void
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  char *begin = input_elements;
  char *end;
  int32_t element;
  int i;
  int32_t *elements;
  unsigned char * mask;
  uint32_t mask_bytes;
  uint32_t element_count = 0;
  struct ScalarProductCallbackClosure * closure;

  if (NULL == input_elements)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _ ("You must specify at least one message ID to check!\n"));
    return;
  }

  if (NULL == input_key)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _ ("This program needs a session identifier for comparing vectors.\n"));
    return;
  }

  if (1 > strnlen (input_key, sizeof (struct GNUNET_HashCode)))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _ ("Please give a session key for --input_key!\n"));
    return;
  }
  closure = GNUNET_new (struct ScalarProductCallbackClosure);
  GNUNET_CRYPTO_hash (input_key, strlen (input_key), &closure->key);

  if (input_peer_id &&
      (GNUNET_OK !=
       GNUNET_CRYPTO_hash_from_string (input_peer_id,
                                       (struct GNUNET_HashCode *) &closure->peer)))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _ ("Tried to set initiator mode, as peer ID was given. "
            "However, `%s' is not a valid peer identifier.\n"),
         input_peer_id);
    return;
  }

  /* Count input_elements_peer1, and put in elements_peer1 array */
  do
  {
    // get the length of the current element and replace , with null
    for (end = begin; *end && *end != ','; end++);

    if (1 == sscanf (begin, "%" SCNd32 ",", &element))
    {
      //element in the middle
      element_count++;
      begin = end + 1;
    }
    else if (0 == *begin)
    {
      break;
    }
    else
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
           _ ("Could not convert `%s' to int32_t.\n"), begin);
      return;
    }
  }
  while (1);
  if (0 == element_count)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _ ("Need elements to compute the vectorproduct, got none.\n"));
    return;
  }

  begin = input_elements;
  elements = GNUNET_malloc (sizeof (int32_t) * element_count);
  element_count = 0;
  /* Read input_elements_peer1, and put in elements_peer1 array */
  do
  {
    // get the length of the current element and replace , with null
    for (end = begin; *end && *end != ','; end++);

    if (1 == sscanf (begin, "%" SCNd32 ",", &elements[element_count]))
    {
      //element in the middle
      element_count++;
      begin = end + 1;
    }
    else if (0 == *begin)
    {
      break;
    }
  }
  while (1);

  mask_bytes = element_count / 8 + (element_count % 8 ? 1 : 0);
  mask = GNUNET_malloc ((element_count / 8) + 1);

  /* Read input_mask_peer1 and read in mask_peer1 array */
  if ((NULL != input_peer_id) && (NULL != input_mask))
  {
    begin = input_mask;
    unsigned short mask_count = 0;

    do
    {
      // get the length of the current element and replace , with null
      for (end = begin; *end && *end != ','; end++);

      if (1 == sscanf (begin, "%" SCNd32 ",", &element))
      {
        //element in the middle
        begin = end + 1;
      }
      else if (*begin == 0)
      {
        break;
      }
      else
      {
        LOG (GNUNET_ERROR_TYPE_ERROR,
             _ ("Could not convert `%s' to integer.\n"), begin);
        return;
      }

      if (element)
        mask[mask_count / 8] = mask[mask_count / 8] | 1 << (mask_count % 8);
      mask_count++;
    }
    while (mask_count < element_count);
  }
  else if (NULL != input_peer_id)
    for (i = 0; i <= mask_bytes; i++)
      mask[i] = UCHAR_MAX; // all 1's

  if (input_peer_id &&
      (NULL == GNUNET_SCALARPRODUCT_request (cfg,
                                             &closure->key,
                                             &closure->peer,
                                             elements, element_count,
                                             mask, mask_bytes,
                                             &requester_callback,
                                             (void *) &closure)))
  {
    GNUNET_free (elements);
    return;
  }

  if ((NULL == input_peer_id) &&
      (NULL == GNUNET_SCALARPRODUCT_response (cfg,
                                              &closure->key,
                                              elements, element_count,
                                              &responder_callback,
                                              (void *) &closure)))
  {
    GNUNET_free (elements);
    return;
  }
  GNUNET_free (elements);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
                                &shutdown_task,
                                NULL);

  ret = 0;
}


/**
 * The main function to the scalarproduct client.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    {'e', "elements", "\"val1,val2,...,valn\"",
      gettext_noop ("A comma separated list of elements to compare as vector with our remote peer."),
      1, &GNUNET_GETOPT_set_string, &input_elements},
    {'m', "mask", "\"0,1,...,maskn\"",
      gettext_noop ("A comma separated mask to select which elements should actually be compared."),
      1, &GNUNET_GETOPT_set_string, &input_mask},
    {'p', "peer", "PEERID",
      gettext_noop ("[Optional] peer to calculate our scalarproduct with. If this parameter is not given, the service will wait for a remote peer to compute the request."),
      1, &GNUNET_GETOPT_set_string, &input_peer_id},
    {'k', "key", "TRANSACTION_ID",
      gettext_noop ("Transaction ID shared with peer."),
      1, &GNUNET_GETOPT_set_string, &input_key},
    GNUNET_GETOPT_OPTION_END
  };

  return (GNUNET_OK ==
          GNUNET_PROGRAM_run (argc,
                              argv,
                              "gnunet-scalarproduct",
                              gettext_noop ("Calculate the Vectorproduct with a GNUnet peer."),
                              options, &run, NULL)) ? ret : 1;
}

