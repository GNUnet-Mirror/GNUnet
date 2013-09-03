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
static char *input_peer_id = NULL;

/**
 * Option -p: destination peer identity for checking message-ids with
 */
static char *input_key = NULL;

/**
 * Option -e: vector to calculate a scalarproduct with
 */
static char *input_elements = NULL;

/**
 * Option -m: message-ids to calculate a scalarproduct with
 */
static char *input_mask = NULL;

/**
 * Global return value
 */
static int ret;


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
  ret = -1;

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

  GNUNET_SCALARPRODUCT_disconnect ();
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Callback called if we are initiating a new computation session
 * 
 * @param cls unused
 * @param key unused
 * @param peer unused
 * @param status if our job was successfully processed 
 * @param size size of the msg returned
 * @param msg the response we got.
 * @param type of the message received 
 */
static void
requester_callback (void *cls,
                    enum GNUNET_SCALARPRODUCT_ResponseStatus status,
                    gcry_mpi_t result)
{
  struct ScalarProductCallbackClosure * closure = cls;
  unsigned char * buf;
  gcry_error_t rc;
  ret = -1;

  switch (status)
  {
  case GNUNET_SCALARPRODUCT_Status_Success:

    if (0 == (rc = gcry_mpi_aprint (GCRYMPI_FMT_HEX, &buf, NULL, result)))
      printf ("Successfully computed result for session %s with peer %s: %s\n", GNUNET_h2s (&closure->key), GNUNET_i2s (&closure->peer), buf);
    else {
      printf ("Session %s with peer %s failed: \n", GNUNET_h2s (&closure->key), GNUNET_i2s (&closure->peer));
      LOG_GCRY(GNUNET_ERROR_TYPE_ERROR, "gcry_mpi_aprint", rc);
    }
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
  GNUNET_SCALARPRODUCT_disconnect ();
  GNUNET_SCHEDULER_shutdown ();
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
  char * begin = input_elements;
  char * end;
  int32_t element;
  int i;
  ret = -1;
  int32_t * elements;
  unsigned char * mask;
  unsigned short mask_bytes;
  unsigned short element_count;
  struct ScalarProductCallbackClosure * closure;

  if (NULL == input_elements)
  {
    FPRINTF (stderr, "%s", _ ("You must specify at least one message ID to check!\n"));
    return;
  }

  if (NULL == input_key)
  {
    FPRINTF (stderr, "%s", _ ("This program needs a session identifier for comparing vectors.\n"));
    return;
  }

  if (1 > strnlen (input_key, sizeof (struct GNUNET_HashCode)))
  {
    FPRINTF (stderr, _ ("Please give a session key for --input_key!\n"));
    return;
  }
  closure = GNUNET_new(struct ScalarProductCallbackClosure);
  GNUNET_CRYPTO_hash (input_key, strlen (input_key), &closure->key);

  if (input_peer_id && GNUNET_OK != GNUNET_CRYPTO_hash_from_string (input_peer_id,
                                                                    (struct GNUNET_HashCode *) &closure->peer))
  {
    FPRINTF (stderr, _ ("Tried to set initiator mode, as peer ID was given. "
                        "However, `%s' is not a valid peer identifier.\n"),
             input_peer_id);
    return;
  }

  int exit_loop = 0;
  /* Read input_elements_peer1, and put in elements_peer1 array */
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

    if (*end == ',')
      *end = '\0';

    if (1 != sscanf (begin, "%" SCNd32, &element))
    {
      FPRINTF (stderr, _ ("Could not convert `%s' to int32_t.\n"), begin);
      return;
    }

    GNUNET_array_append (elements, mcount, element);
    element_count++;

    begin = ++end;
  }
  while (!exit_loop);

  GNUNET_assert (elements != NULL);
  GNUNET_assert (element_count > 1);
  mask_bytes = element_count / 8 + (element_count % 8 ? 1 : 0);
  mask = GNUNET_malloc ((element_count / 8) + 2);

  /* Read input_mask_peer1 and read in mask_peer1 array */
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

      if (*end == ',')
        *end = '\0';

      if (1 != sscanf (begin, "%" SCNd32, &element))
      {
        FPRINTF (stderr, _ ("Could not convert `%s' to int32_t.\n"), begin);
        return;
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
  else if (input_peer_id)
  {
    for (i = 0; i <= mask_bytes; i++)
      mask[i] = UCHAR_MAX; // all 1's
  }


  if (input_peer_id && !GNUNET_SCALARPRODUCT_request (cfg,
                                                      &closure->key,
                                                      &closure->peer,
                                                      elements, element_count,
                                                      mask, mask_bytes,
                                                      &requester_callback,
                                                      (void *) &closure))
    return;


  if (!input_peer_id && !GNUNET_SCALARPRODUCT_response (cfg,
                                                        &closure->key,
                                                        elements, element_count,
                                                        &responder_callback,
                                                        (void *) &closure))
    return;

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

