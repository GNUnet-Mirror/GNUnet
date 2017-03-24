/*
   This file is part of GNUnet.
   Copyright (C) 2012-2015 GNUnet e.V.

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
   Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
   Boston, MA 02110-1301, USA.
   */
/**
 * @author Martin Schanzenbach
 * @file src/identity-provider/gnunet-service-identity-provider.c
 * @brief Identity Token Service
 *
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include <jansson.h>
#include "gnunet_signatures.h"

/**
 * The token
 */
static char* token;

/**
 * Weather to print the token
 */
static int print_token;

static void
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  char *payload;
  char *header;
  //Get token parts
  const char *header_b64;
  const char *payload_b64;
  const char *signature_b32;
  const char *keystring;
  char *data;
  json_t *payload_json;
  json_t *keystring_json;
  json_error_t error;
  struct GNUNET_CRYPTO_EcdsaPublicKey key;
  struct GNUNET_CRYPTO_EccSignaturePurpose *purpose;
  struct GNUNET_CRYPTO_EcdsaSignature sig;

  if (NULL == token)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_MESSAGE,
                _("Option `-t' is required\n"));
    return;
  }
  header_b64 = strtok (token, ".");
  payload_b64 = strtok (NULL, ".");
  signature_b32 = strtok (NULL, ".");
  if ( (NULL == header_b64) ||
       (NULL == payload_b64) ||
       (NULL == signature_b32) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_MESSAGE,
                _("Token `%s' is malformed\n"),
                token);
    GNUNET_free (token);
    token = NULL;
    return;
  }

  //Decode payload
  GNUNET_STRINGS_base64_decode (payload_b64,
                                strlen (payload_b64),
                                &payload);
  //Decode header
  GNUNET_STRINGS_base64_decode (header_b64,
                                strlen (header_b64),
                                &header);


  GNUNET_asprintf(&data,
                  "%s,%s",
                  header_b64,
                  payload_b64);
  char *val = GNUNET_malloc (sizeof (struct GNUNET_CRYPTO_EccSignaturePurpose) + strlen (data));
  purpose = (struct GNUNET_CRYPTO_EccSignaturePurpose*)val;
  purpose->size = htonl(sizeof (struct GNUNET_CRYPTO_EccSignaturePurpose) + strlen (data));
  purpose->purpose = htonl(GNUNET_SIGNATURE_PURPOSE_GNUID_TOKEN);
  GNUNET_memcpy (&purpose[1], data, strlen(data));
  GNUNET_free (data);
  GNUNET_free (token);
  token = NULL;

  if (print_token)
    printf ("Token:\nHeader:\t\t%s\nPayload:\t%s\n",
            header,
            payload);
  GNUNET_free (header);

  payload_json = json_loads (payload, 0, &error);
  GNUNET_free (payload);

  if ((NULL == payload_json) || (! json_is_object (payload_json)) )
  {
    GNUNET_free (val);
    return;
  }
  keystring_json =  json_object_get (payload_json, "iss");
  if (! json_is_string (keystring_json))
  {
    GNUNET_free (val);
    return;
  }
  keystring = json_string_value (keystring_json);
  if (GNUNET_OK !=
      GNUNET_CRYPTO_ecdsa_public_key_from_string (keystring,
                                                  strlen (keystring),
                                                  &key))
  {
    GNUNET_free (val);
    return;
  }
  GNUNET_STRINGS_string_to_data (signature_b32,
                                 strlen (signature_b32),
                                 &sig,
                                 sizeof (struct GNUNET_CRYPTO_EcdsaSignature));

  if (print_token)
    printf ("Signature:\t%s\n",
            keystring);

  if (GNUNET_OK !=
      GNUNET_CRYPTO_ecdsa_verify(GNUNET_SIGNATURE_PURPOSE_GNUID_TOKEN,
                                 purpose,
                                 &sig,
                                 &key))
    printf("Signature not OK!\n");
  else
    printf("Signature OK!\n");
  GNUNET_free (val);
  return;
}


int
main(int argc, char *const argv[])
{
  struct GNUNET_GETOPT_CommandLineOption options[] = {

    GNUNET_GETOPT_OPTION_STRING ('t',
                                 "token",
                                 NULL,
                                 gettext_noop ("GNUid token"),
                                 &token),

    GNUNET_GETOPT_OPTION_SET_ONE ('p',
                                  "print",
                                  gettext_noop ("Print token contents"),
                                  &print_token),

    GNUNET_GETOPT_OPTION_END
  };
  return GNUNET_PROGRAM_run (argc, argv, "ct",
                             "ct", options,
                             &run, NULL);
}
