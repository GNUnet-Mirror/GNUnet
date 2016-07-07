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
  char* payload;
  char* header;
  //Get token parts
  char* header_b64 = strtok (token, ".");
  char* payload_b64 = strtok(NULL, ".");
  char* signature_b32 = strtok(NULL, ".");
  const char* keystring;
  char* data;
  json_t *payload_json;
  json_t *keystring_json;
  json_error_t error;
  struct GNUNET_CRYPTO_EcdsaPublicKey key;
  struct GNUNET_CRYPTO_EccSignaturePurpose *purpose;
  struct GNUNET_CRYPTO_EcdsaSignature sig;
  
  GNUNET_assert (NULL != header_b64);
  GNUNET_assert (NULL != payload_b64);
  GNUNET_assert (NULL != signature_b32);
  
  //Decode payload
  GNUNET_STRINGS_base64_decode (payload_b64,
                                strlen (payload_b64),
                                &payload);
  //Decode header
  GNUNET_STRINGS_base64_decode (header_b64,
                                strlen (header_b64),
                                &header);
  if (NULL == token)
    return;
  

  GNUNET_asprintf(&data,
                  "%s,%s",
                  header_b64,
                  payload_b64);
  char *val = GNUNET_malloc (sizeof (struct GNUNET_CRYPTO_EccSignaturePurpose) + strlen (data));
  purpose = (struct GNUNET_CRYPTO_EccSignaturePurpose*)val;
  purpose->size = htonl(sizeof (struct GNUNET_CRYPTO_EccSignaturePurpose) + strlen (data));
  purpose->purpose = htonl(GNUNET_SIGNATURE_PURPOSE_GNUID_TOKEN);
  memcpy (&purpose[1], data, strlen(data));
  GNUNET_free (data);
  GNUNET_free (header_b64);
  GNUNET_free (header_b64);

  if (print_token)
    printf ("Token:\nHeader:\t\t%s\nPayload:\t%s\n", header, payload);
  GNUNET_free (header);
  GNUNET_free (payload);
  
  payload_json = json_loads (payload, 0, &error);
  if ((NULL == payload_json) || !json_is_object (payload_json))
  {
    GNUNET_free (val);
    return;
  }
  keystring_json =  json_object_get (payload_json, "iss");
  if (!json_is_string (keystring_json))
  {
    GNUNET_free (val);
    return;
  }
  keystring = json_string_value (keystring_json);
  if (GNUNET_OK != GNUNET_CRYPTO_ecdsa_public_key_from_string (keystring,
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
    printf ("Signature:\t%s\n", keystring);
  
  if (GNUNET_OK != GNUNET_CRYPTO_ecdsa_verify(GNUNET_SIGNATURE_PURPOSE_GNUID_TOKEN,
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
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    {'t', "token", NULL,
      gettext_noop ("GNUid token"), 1,
      &GNUNET_GETOPT_set_string, &token},
    {'p', "print", NULL,
      gettext_noop ("Print token contents"), 0,
      &GNUNET_GETOPT_set_one, &print_token},

    GNUNET_GETOPT_OPTION_END
  };
  return GNUNET_PROGRAM_run (argc, argv, "ct",
                             "ct", options,
                             &run, NULL);
}


