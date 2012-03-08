/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2006, 2009, 2010 Christian Grothoff (and other contributing authors)

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
 * @file peerinfo-tool/gnunet-peerinfo.c
 * @brief Print information about other known peers.
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_crypto_lib.h"
#include "gnunet_configuration_lib.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_peerinfo_service.h"
#include "gnunet_transport_service.h"
#include "gnunet_program_lib.h"
#include "gnunet_transport_plugin.h"
#include "../transport/gnunet-service-transport_plugins.h"

static int no_resolve;

static int be_quiet;

static int get_self;

static int get_uri;

static char *put_uri;

static struct GNUNET_PEERINFO_Handle *peerinfo;

/**
 * Configuration handle.
 */
const struct GNUNET_CONFIGURATION_Handle *GST_cfg;

/**
 * Statistics handle.
 */
struct GNUNET_STATISTICS_Handle *GST_stats;

/**
 * Configuration handle.
 */
struct GNUNET_PeerIdentity GST_my_identity;

struct GNUNET_MessageHeader *our_hello = NULL;

static const struct GNUNET_CONFIGURATION_Handle *cfg;

struct PrintContext
{
  struct GNUNET_PeerIdentity peer;
  char **address_list;
  unsigned int num_addresses;
  uint32_t off;
  char *uri;
  size_t uri_len;
};

/**
 * Obtain this peers HELLO message.
 *
 * @return our HELLO message
 */
const struct GNUNET_MessageHeader *
GST_hello_get ()
{
  return (struct GNUNET_MessageHeader *) our_hello;
}

static void
dump_pc (struct PrintContext *pc)
{
  struct GNUNET_CRYPTO_HashAsciiEncoded enc;
  unsigned int i;

  GNUNET_CRYPTO_hash_to_enc (&pc->peer.hashPubKey, &enc);
  printf (_("Peer `%s'\n"), (const char *) &enc);
  for (i = 0; i < pc->num_addresses; i++)
  {
    printf ("\t%s\n", pc->address_list[i]);
    GNUNET_free (pc->address_list[i]);
  }
  printf ("\n");
  GNUNET_array_grow (pc->address_list, pc->num_addresses, 0);
  GNUNET_free (pc);
}


/**
 * Function to call with a human-readable format of an address
 *
 * @param cls closure
 * @param address NULL on error, otherwise 0-terminated printable UTF-8 string
 */
static void
process_resolved_address (void *cls, const char *address)
{
  struct PrintContext *pc = cls;

  if (address == NULL)
  {
    pc->off--;
    if (pc->off == 0)
      dump_pc (pc);
    return;
  }
  GNUNET_array_append (pc->address_list, pc->num_addresses,
                       GNUNET_strdup (address));
}


/**
 * Iterator callback to go over all addresses.
 *
 * @param cls closure
 * @param address the address
 * @param expiration expiration time
 * @return GNUNET_OK to keep the address and continue
 */
static int
count_address (void *cls, const struct GNUNET_HELLO_Address *address,
               struct GNUNET_TIME_Absolute expiration)
{
  struct PrintContext *pc = cls;

  pc->off++;
  return GNUNET_OK;
}


/**
 * Iterator callback to go over all addresses.
 *
 * @param cls closure
 * @param address the address
 * @param expiration expiration time
 * @return GNUNET_OK to keep the address and continue
 */
static int
print_address (void *cls, const struct GNUNET_HELLO_Address *address,
               struct GNUNET_TIME_Absolute expiration)
{
  struct PrintContext *pc = cls;

  GNUNET_TRANSPORT_address_to_string (cfg, address, no_resolve,
                                      GNUNET_TIME_relative_multiply
                                      (GNUNET_TIME_UNIT_SECONDS, 10),
                                      &process_resolved_address, pc);
  return GNUNET_OK;
}


/**
 * Print information about the peer.
 * Currently prints the GNUNET_PeerIdentity and the IP.
 * Could of course do more (e.g. resolve via DNS).
 */
static void
print_peer_info (void *cls, const struct GNUNET_PeerIdentity *peer,
                 const struct GNUNET_HELLO_Message *hello, const char *err_msg)
{
  struct GNUNET_CRYPTO_HashAsciiEncoded enc;
  struct PrintContext *pc;

  if (peer == NULL)
  {
    if (err_msg != NULL)
      FPRINTF (stderr, "%s",  _("Error in communication with PEERINFO service\n"));
    GNUNET_PEERINFO_disconnect (peerinfo);
    GST_plugins_unload ();
    GNUNET_STATISTICS_destroy (GST_stats, GNUNET_NO);
    return;
  }
  if ((be_quiet) || (NULL == hello))
  {
    GNUNET_CRYPTO_hash_to_enc (&peer->hashPubKey, &enc);
    printf ("%s\n", (const char *) &enc);
    return;
  }
  pc = GNUNET_malloc (sizeof (struct PrintContext));
  pc->peer = *peer;
  GNUNET_HELLO_iterate_addresses (hello, GNUNET_NO, &count_address, pc);
  if (0 == pc->off)
  {
    dump_pc (pc);
    return;
  }
  GNUNET_HELLO_iterate_addresses (hello, GNUNET_NO, &print_address, pc);
}

static int
compose_uri (void *cls, const struct GNUNET_HELLO_Address *address,
             struct GNUNET_TIME_Absolute expiration)
{
  struct PrintContext *pc = cls;
  struct GNUNET_TRANSPORT_PluginFunctions *papi;
  static const char *addr;

  papi = GST_plugins_find (address->transport_name);
  if (papi == NULL)
  {
    /* Not an error - we might just not have the right plugin. */
    return GNUNET_OK;
  }

  addr = papi->address_to_string (papi->cls, address->address, address->address_length);
  if (addr != NULL)
  {
    ssize_t l = strlen (addr);
    if (l > 0)
    {
      struct tm *t;
      time_t seconds;
      int s;
      seconds = expiration.abs_value / 1000;
      t = gmtime(&seconds);
      pc->uri = GNUNET_realloc (pc->uri, pc->uri_len + 1 + 14 + 1 + strlen (address->transport_name) + 1 + l + 1 /* 0 */);
      s = sprintf (&pc->uri[pc->uri_len], "!%04u%02u%02u%02u%02u%02u!%s!%s",
          t->tm_year, t->tm_mon, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec,
          address->transport_name, addr);
      if (s > 0)
        pc->uri_len += s;
    }
  }
  return GNUNET_OK;
}

/**
 * Print information about the peer.
 */
static void
print_my_uri (void *cls, const struct GNUNET_PeerIdentity *peer,
              const struct GNUNET_HELLO_Message *hello, const char *err_msg)
{
  struct GNUNET_CRYPTO_HashAsciiEncoded enc;
  struct PrintContext *pc = cls;

  if (peer == NULL)
  {
    if (err_msg != NULL)
      FPRINTF (stderr, "%s",  _("Error in communication with PEERINFO service\n"));
    GNUNET_PEERINFO_disconnect (peerinfo);
    GST_plugins_unload ();
    GNUNET_STATISTICS_destroy (GST_stats, GNUNET_NO);
    return;
  }
  if ((be_quiet) || (NULL == hello))
  {
    GNUNET_CRYPTO_hash_to_enc (&peer->hashPubKey, &enc);
    printf ("%s\n", (const char *) &enc);
    if (be_quiet && get_uri != GNUNET_YES)
      return;
  }
  pc->peer = *peer;
  GNUNET_HELLO_iterate_addresses (hello, GNUNET_NO, &count_address, pc);
  GNUNET_HELLO_iterate_addresses (hello, GNUNET_NO, &compose_uri, pc);
  printf ("%s\n", pc->uri);
  GNUNET_free (pc->uri);
  GNUNET_free (pc);
}

struct GNUNET_PEERINFO_HelloAddressParsingContext
{
  char *tmp;
  char *pos;
  size_t tmp_len;
};

static size_t
add_addr_to_hello (void *cls, size_t max, void *buffer)
{
  struct tm expiration_time;
  char buf[5];
  long l;
  time_t expiration_seconds;
  struct GNUNET_TIME_Absolute expire;

  struct GNUNET_PEERINFO_HelloAddressParsingContext *ctx = cls;
  char *exp1, *exp2;
  struct GNUNET_TRANSPORT_PluginFunctions *papi;
  void *addr;
  size_t addr_len;

  /* End of string */
  if (ctx->pos - ctx->tmp == ctx->tmp_len)
    return 0;

  /* Parsed past the end of string, OR wrong format */
  if ((ctx->pos - ctx->tmp > ctx->tmp_len) || ctx->pos[0] != '!')
  {
    GNUNET_break (0);
    return 0;
  }

  /* Not enough bytes (3 for three '!', 14 for expiration date, and
   * at least 1 for type and 1 for address (1-byte long address is a joke,
   * but it is not completely unrealistic. Zero-length address is.
   */
  if (ctx->tmp_len - (ctx->pos - ctx->tmp) < 1 /*!*/ * 3 + 14 + /* at least */ 2)
  {
    GNUNET_break (0);
    return 0;
  }
  /* Go past the first '!', now we're on expiration date */
  ctx->pos += 1;
  /* Its length is known, so check for the next '!' right away */
  if (ctx->pos[14] != '!')
  {
    GNUNET_break (0);
    return 0;
  }

  memset (&expiration_time, 0, sizeof (struct tm));

  /* This is FAR more strict than strptime(ctx->pos, "%Y%m%d%H%M%S", ...); */
  /* FIXME: make it a separate function, since expiration is specified to every address */
#define GETNDIGITS(n,cond) \
  strncpy (buf, &ctx->pos[0], n); \
  buf[n] = '\0'; \
  errno = 0; \
  l = strtol (buf, NULL, 10); \
  if (errno != 0 || cond) \
  { \
    GNUNET_break (0); \
    return 0; \
  } \
  ctx->pos += n;

  GETNDIGITS (4, l < 1900)
  expiration_time.tm_year = l - 1900;

  GETNDIGITS (2, l < 1 || l > 12)
  expiration_time.tm_mon = l;

  GETNDIGITS (2, l < 1 || l > 31)
  expiration_time.tm_mday = l;

  GETNDIGITS (2, l < 0 || l > 23)
  expiration_time.tm_hour = l;

  GETNDIGITS (2, l < 0 || l > 59)
  expiration_time.tm_min = l;

  /* 60 - with a leap second */
  GETNDIGITS (2, l < 0 || l > 60)
  expiration_time.tm_sec = l;

  expiration_time.tm_isdst = -1;

#undef GETNDIGITS

  expiration_seconds = mktime (&expiration_time);
  if (expiration_seconds == (time_t) -1)
  {
    GNUNET_break (0);
    return 0;
  }
  expire.abs_value = expiration_seconds * 1000;

  /* Now we're at '!', advance to the transport type */
  ctx->pos += 1;

  /* Find the next '!' that separates transport type from
   * the address
   */
  exp1 = strstr (ctx->pos, "!");
  if (exp1 == NULL)
  {
    GNUNET_break (0);
    return 0;
  }
  /* We need it 0-terminated */
  exp1[0] = '\0';
  /* Find the '!' that separates address from the next record.
   * It might not be there, if this is the last record.
   */
  exp2 = strstr (&exp1[1], "!");
  if (exp2 == NULL)
    exp2 = &ctx->tmp[ctx->tmp_len];

  papi = GST_plugins_find (ctx->pos);
  if (papi == NULL)
  {
    /* Not an error - we might just not have the right plugin.
     * Skip this part, advance to the next one and recurse.
     * But only if this is not the end of string.
     */
    ctx->pos = exp2 + 1;
    if (ctx->pos - ctx->tmp >= ctx->tmp_len)
      return 0;
    return add_addr_to_hello (cls, max, buffer);
  }

  if (GNUNET_OK == papi->string_to_address (papi->cls, &exp1[1], exp2 - &exp1[1], &addr, &addr_len))
  {
    struct GNUNET_HELLO_Address address;
    int ret;

    /* address.peer is unset - not used by add_address() */
    address.address_length = addr_len;
    address.address = addr;
    address.transport_name = ctx->pos;
    ret = GNUNET_HELLO_add_address (&address, expire, buffer, max);
    GNUNET_free (addr);
    ctx->pos = exp2;
    return ret;
  }
  return 0;
}

void
parse_hello (const struct GNUNET_CONFIGURATION_Handle *c,
             const char *put_uri)
{
  int r;
  char *scheme_part = NULL;
  char *path_part = NULL;
  char *exc;
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded pub;
  int std_result;
  struct GNUNET_HELLO_Message *hello;
  struct GNUNET_PEERINFO_HelloAddressParsingContext ctx;

  r = GNUNET_STRINGS_parse_uri (put_uri, &scheme_part, (const char **) &path_part);
  if (r == GNUNET_NO)
    return;
  if (scheme_part == NULL || strcmp (scheme_part, "gnunet://") != 0)
  {
    GNUNET_free_non_null (scheme_part);
    return;
  }
  GNUNET_free (scheme_part);

  if (strncmp (path_part, "hello/", 6) != 0)
    return;

  path_part = &path_part[6];
  ctx.tmp = GNUNET_strdup (path_part);
  ctx.tmp_len = strlen (path_part);
  exc = strstr (ctx.tmp, "!");
  if (exc == NULL)
    exc = ctx.pos + ctx.tmp_len; // FIXME-LRN: ctx.pos is uninitialized here!
  ctx.pos = exc;

  std_result = GNUNET_STRINGS_string_to_data (ctx.tmp, exc - ctx.tmp,
      (unsigned char *) &pub, sizeof (pub));
  if (std_result != GNUNET_OK)
  {
    GNUNET_free (ctx.tmp);
    return;
  }

  hello = GNUNET_HELLO_create (&pub, add_addr_to_hello, &ctx);
  GNUNET_free (ctx.tmp);

  /* WARNING: this adds the address from URI WITHOUT verification! */
  GNUNET_PEERINFO_add_peer (peerinfo, hello);
}

static struct GNUNET_TIME_Relative
receive_stub (void *cls, const struct GNUNET_PeerIdentity *peer,
    const struct GNUNET_MessageHeader *message,
    const struct GNUNET_ATS_Information *ats, uint32_t ats_count,
    struct Session *session, const char *sender_address,
    uint16_t sender_address_len)
{
  struct GNUNET_TIME_Relative t;
  t.rel_value = 0;
  return t;
}

static void
address_notification_stub (void *cls, int add_remove,
    const void *addr, size_t addrlen)
{
}

static void
session_end_stub (void *cls, const struct GNUNET_PeerIdentity *peer,
    struct Session * session)
{
}

static const struct GNUNET_ATS_Information
address_to_type_stub (void *cls, const struct sockaddr *addr,
    size_t addrlen)
{
  struct GNUNET_ATS_Information t;
  t.type = 0;
  t.value = 0;
  return t;
}


/**
 * Main function that will be run by the scheduler.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param c configuration
 */
static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  struct GNUNET_CRYPTO_RsaPrivateKey *priv;
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded pub;
  struct GNUNET_PeerIdentity pid;
  struct GNUNET_CRYPTO_HashAsciiEncoded enc;
  char *fn;

  cfg = c;
  if (args[0] != NULL)
  {
    FPRINTF (stderr, _("Invalid command line argument `%s'\n"), args[0]);
    return;
  }
  if (put_uri != NULL && get_uri == GNUNET_YES)
  {
    FPRINTF (stderr, "%s", _("--put-uri and --get-uri are mutually exclusive\n"));
    return;
  }
  if (put_uri != NULL || get_uri == GNUNET_YES || get_self != GNUNET_YES)
  {
    peerinfo = GNUNET_PEERINFO_connect (cfg);
    if (peerinfo == NULL)
    {
      FPRINTF (stderr, "%s",  _("Could not access PEERINFO service.  Exiting.\n"));
      return;
    }
    GST_cfg = c;
    GST_stats = GNUNET_STATISTICS_create ("transport", c);
    /* FIXME: shouldn't we free GST_stats somewhere? */
    GST_plugins_load (receive_stub, address_notification_stub,
        session_end_stub, address_to_type_stub);
  }
  if (put_uri != NULL)
  {
    parse_hello (c, put_uri);
    GST_plugins_unload ();
    GNUNET_STATISTICS_destroy (GST_stats, GNUNET_NO);
    return;
  }
  if (get_self != GNUNET_YES)
  {
    GNUNET_PEERINFO_iterate (peerinfo, NULL,
                             GNUNET_TIME_relative_multiply
                             (GNUNET_TIME_UNIT_SECONDS, 5), &print_peer_info,
                             NULL);
  }
  else
  {
    if (GNUNET_OK !=
        GNUNET_CONFIGURATION_get_value_filename (cfg, "GNUNETD", "HOSTKEY",
                                                 &fn))
    {
      FPRINTF (stderr, _("Could not find option `%s:%s' in configuration.\n"),
               "GNUNETD", "HOSTKEYFILE");
      return;
    }
    priv = GNUNET_CRYPTO_rsa_key_create_from_file (fn);
    if (priv == NULL)
    {
      FPRINTF (stderr, _("Loading hostkey from `%s' failed.\n"), fn);
      GNUNET_free (fn);
      return;
    }
    GNUNET_free (fn);
    GNUNET_CRYPTO_rsa_key_get_public (priv, &pub);
    GNUNET_CRYPTO_rsa_key_free (priv);
    GNUNET_CRYPTO_hash (&pub, sizeof (pub), &pid.hashPubKey);
    GNUNET_CRYPTO_hash_to_enc (&pid.hashPubKey, &enc);
    if (be_quiet)
      printf ("%s\n", (char *) &enc);
    else
      printf (_("I am peer `%s'.\n"), (const char *) &enc);
    if (get_uri == GNUNET_YES)
    {
      struct PrintContext *pc;
      char *pkey;
      ssize_t l, pl;
      pc = GNUNET_malloc (sizeof (struct PrintContext));
      pkey = GNUNET_CRYPTO_rsa_public_key_to_string (&pub);
      pl = strlen ("gnunet://hello/");
      l = strlen (pkey) + pl;
      pc->uri = GNUNET_malloc (l + 1);
      strcpy (pc->uri, "gnunet://hello/");
      strcpy (&pc->uri[pl], pkey);
      pc->uri_len = l;
      GNUNET_PEERINFO_iterate (peerinfo, &pid,
          GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5),
          print_my_uri, pc);
    }
  }
}


/**
 * The main function to obtain peer information.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    {'n', "numeric", NULL,
     gettext_noop ("don't resolve host names"),
     0, &GNUNET_GETOPT_set_one, &no_resolve},
    {'q', "quiet", NULL,
     gettext_noop ("output only the identity strings"),
     0, &GNUNET_GETOPT_set_one, &be_quiet},
    {'s', "self", NULL,
     gettext_noop ("output our own identity only"),
     0, &GNUNET_GETOPT_set_one, &get_self},
    {'g', "get-hello", NULL,
     gettext_noop ("also output HELLO uri(s)"),
     0, &GNUNET_GETOPT_set_one, &get_uri},
    {'p', "put-hello", "HELLO",
     gettext_noop ("add given HELLO uri to the database"),
     1, &GNUNET_GETOPT_set_string, &put_uri},
    GNUNET_GETOPT_OPTION_END
  };
  return (GNUNET_OK ==
          GNUNET_PROGRAM_run (argc, argv, "gnunet-peerinfo",
                              gettext_noop ("Print information about peers."),
                              options, &run, NULL)) ? 0 : 1;
}

/* end of gnunet-peerinfo.c */
