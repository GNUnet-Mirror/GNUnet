/*
     This file is part of GNUnet.
     (C) 2013, 2014 Christian Grothoff (and other contributing authors)

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


/**
 * the session key identifying this computation
 */
static struct GNUNET_HashCode session_key;

/**
 * PeerID we want to compute a scalar product with
 */
static struct GNUNET_PeerIdentity peer_id;

/**
 * Option -p: destination peer identity for checking message-ids with
 */
static char *input_peer_id;

/**
 * Option -p: destination peer identity for checking message-ids with
 */
static char *input_session_key;

/**
 * Option -e: vector to calculate a scalarproduct with
 */
static char *input_elements;

/**
 * Global return value
 */
static int ret = -1;

/**
 * our Scalarproduct Computation handle
 */
static struct GNUNET_SCALARPRODUCT_ComputationHandle *computation;


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
  switch (status)
  {
  case GNUNET_SCALARPRODUCT_Status_Success:
    ret = 0;
    LOG (GNUNET_ERROR_TYPE_INFO,
         "Session %s concluded.\n",
         GNUNET_h2s (&session_key));
    break;
  case GNUNET_SCALARPRODUCT_Status_InvalidResponse:
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Session %s failed: invalid response\n",
         GNUNET_h2s (&session_key));
    break;
  case GNUNET_SCALARPRODUCT_Status_Failure:
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Session %s failed: service failure\n",
         GNUNET_h2s (&session_key));
    break;
  case GNUNET_SCALARPRODUCT_Status_ServiceDisconnected:
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Session %s failed: service disconnect!\n",
         GNUNET_h2s (&session_key));
    break;
  default:
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Session %s failed: return code %d\n",
         GNUNET_h2s (&session_key),
         status);
  }
  computation = NULL;
  GNUNET_SCHEDULER_shutdown ();
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
  unsigned char *buf;
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
      LOG_GCRY (GNUNET_ERROR_TYPE_ERROR,
                "gcry_mpi_aprint",
                rc);
    break;
  case GNUNET_SCALARPRODUCT_Status_InvalidResponse:
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Session %s with peer %s failed: invalid response received\n",
         GNUNET_h2s (&session_key),
         GNUNET_i2s (&peer_id));
    break;
  case GNUNET_SCALARPRODUCT_Status_Failure:
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Session %s with peer %s failed: API failure\n",
         GNUNET_h2s (&session_key),
         GNUNET_i2s (&peer_id));
    break;
  case GNUNET_SCALARPRODUCT_Status_ServiceDisconnected:
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Session %s with peer %s was disconnected from service.\n",
         GNUNET_h2s (&session_key),
         GNUNET_i2s (&peer_id));
    break;
  default:
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Session %s with peer %s failed: return code %d\n",
         GNUNET_h2s (&session_key),
         GNUNET_i2s (&peer_id),
         status);
  }
  computation = NULL;
  GNUNET_SCHEDULER_shutdown ();
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
  if (NULL != computation)
  {
    GNUNET_SCALARPRODUCT_cancel (computation);
    ret = 1; /* aborted */
  }
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
  unsigned int i;
  struct GNUNET_SCALARPRODUCT_Element *elements;
  uint32_t element_count = 0;

  if (NULL == input_elements)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _("You must specify at least one message ID to check!\n"));
    return;
  }
  if ( (NULL == input_session_key) ||
       (0 == strlen (input_session_key)) )
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _("This program needs a session identifier for comparing vectors.\n"));
    return;
  }
  GNUNET_CRYPTO_hash (input_session_key,
                      strlen (input_session_key),
                      &session_key);
  if ( (NULL != input_peer_id) &&
       (GNUNET_OK !=
        GNUNET_CRYPTO_eddsa_public_key_from_string (input_peer_id,
                                                    strlen (input_peer_id),
                                                    &peer_id.public_key)) )
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _("Tried to set initiator mode, as peer ID was given. "
           "However, `%s' is not a valid peer identifier.\n"),
         input_peer_id);
    return;
  }

  for (end = begin; 0 != *end; end++)
    if (*end == ';')
      element_count++;
  if (0 == element_count) {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _("Need elements to compute the vectorproduct, got none.\n"));
    return;
  }

  elements = GNUNET_malloc (sizeof(struct GNUNET_SCALARPRODUCT_Element) * element_count);

  for (i = 0; i < element_count;i++)
  {
    struct GNUNET_SCALARPRODUCT_Element element;
    char* separator = NULL;

    /* get the length of the current key,value; tupel */
    for (end = begin; *end != ';'; end++)
      if (*end == ',')
        separator = end;

    /* final element */
    if ( (NULL == separator) ||
         (begin == separator) ||
         (separator == end - 1) )
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
           _("Malformed input, could not parse `%s'\n"),
           begin);
      GNUNET_free (elements);
      return;
    }

    /* read the element's key */
    *separator = 0;
    GNUNET_CRYPTO_hash (begin,
                        strlen (begin),
                        &element.key);

    /* read the element's value */
    if (1 !=
        sscanf (separator + 1,
                "%" SCNd64 ";",
                &element.value) )
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
           _("Could not convert `%s' to int64_t.\n"),
           begin);
      GNUNET_free(elements);
      return;
    }
    elements[i] = element;
    begin = end + 1;
  }

  if ( ( (NULL != input_peer_id) &&
         (NULL == (computation
                   = GNUNET_SCALARPRODUCT_start_computation (cfg,
                                                             &session_key,
                                                             &peer_id,
                                                             elements, element_count,
                                                             &requester_callback,
                                                             NULL))) ) ||
       ( (NULL == input_peer_id) &&
         (NULL == (computation
                   = GNUNET_SCALARPRODUCT_accept_computation (cfg,
                                                              &session_key,
                                                              elements, element_count,
                                                              &responder_callback,
                                                              NULL))) ) )
  {
    GNUNET_break (0);
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
    {'e', "elements", "\"key1,val1;key2,val2;...,keyn,valn;\"",
      gettext_noop ("A comma separated list of elements to compare as vector with our remote peer."),
      1, &GNUNET_GETOPT_set_string, &input_elements},
    {'p', "peer", "PEERID",
      gettext_noop ("[Optional] peer to calculate our scalarproduct with. If this parameter is not given, the service will wait for a remote peer to compute the request."),
      1, &GNUNET_GETOPT_set_string, &input_peer_id},
    {'k', "key", "TRANSACTION_ID",
      gettext_noop ("Transaction ID shared with peer."),
      1, &GNUNET_GETOPT_set_string, &input_session_key},
    GNUNET_GETOPT_OPTION_END
  };

  return (GNUNET_OK ==
          GNUNET_PROGRAM_run (argc,
                              argv,
                              "gnunet-scalarproduct",
                              gettext_noop ("Calculate the Vectorproduct with a GNUnet peer."),
                              options, &run, NULL)) ? ret : 1;
}

/* end of gnunet-scalarproduct.c */
