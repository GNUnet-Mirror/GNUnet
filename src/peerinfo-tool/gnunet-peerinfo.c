/*
     This file is part of GNUnet.
     (C) 2001-2012 Christian Grothoff (and other contributing authors)

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
#include "gnunet-peerinfo_plugins.h"


/**
 * Structure we use to collect printable address information.
 */
struct PrintContext;

/**
 * Record we keep for each printable address.
 */
struct AddressRecord
{
  /**
   * Current address-to-string context (if active, otherwise NULL).
   */
  struct GNUNET_TRANSPORT_AddressToStringContext *atsc;

  /**
   * Printable address.
   */
  char *result;
  
  /**
   * Print context this address record belongs to.
   */
  struct PrintContext *pc;
};


/**
 * Structure we use to collect printable address information.
 */
struct PrintContext
{

  /**
   * Kept in DLL.
   */
  struct PrintContext *next;

  /**
   * Kept in DLL.
   */
  struct PrintContext *prev;

  /**
   * Identity of the peer.
   */
  struct GNUNET_PeerIdentity peer;
  
  /**
   * List of printable addresses.
   */
  struct AddressRecord *address_list;

  /**
   * Number of completed addresses in 'address_list'.
   */
  unsigned int num_addresses;

  /**
   * Number of addresses allocated in 'address_list'.
   */
  unsigned int address_list_size;

  /**
   * Current offset in 'address_list' (counted down).
   */
  unsigned int off;

};


/**
 * Context used for building our own URI.
 */
struct GetUriContext
{
  /**
   * Final URI.
   */
  char *uri;

};


/**
 * FIXME.
 */
struct GNUNET_PEERINFO_HelloAddressParsingContext
{
  /**
   * FIXME.
   */
  char *tmp;
  
  /**
   * FIXME.
   */
  char *pos;

  /**
   * FIXME.
   */
  size_t tmp_len;
};


/**
 * Option '-n'
 */
static int no_resolve;

/**
 * Option '-q'
 */
static int be_quiet;

/**
 * Option '-s'
 */
static int get_self;

/**
 * Option 
 */
static int get_uri;

/**
 * Option '-i'
 */
static int get_info;

/**
 * Option 
 */
static char *put_uri;

/**
 * Handle to peerinfo service.
 */
static struct GNUNET_PEERINFO_Handle *peerinfo;

/**
 * Configuration handle.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Main state machine task (if active).
 */
static GNUNET_SCHEDULER_TaskIdentifier tt;

/**
 * Current iterator context (if active, otherwise NULL).
 */
static struct GNUNET_PEERINFO_IteratorContext *pic;

/**
 * My peer identity.
 */
static struct GNUNET_PeerIdentity my_peer_identity;

/**
 * My public key.
 */
static struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded my_public_key;

/**
 * Head of list of print contexts.
 */
static struct PrintContext *pc_head;

/**
 * Tail of list of print contexts.
 */
static struct PrintContext *pc_tail;


/**
 * Main state machine that goes over all options and
 * runs the next requested function.
 *
 * @param cls unused
 * @param tc unused
 */
static void
state_machine (void *cls,
	       const struct GNUNET_SCHEDULER_TaskContext *tc);


/* ********************* 'get_info' ******************* */

/**
 * Print the collected address information to the console and free 'pc'.
 *
 * @param pc printing context
 */
static void
dump_pc (struct PrintContext *pc)
{
  struct GNUNET_CRYPTO_HashAsciiEncoded enc;
  unsigned int i;

  GNUNET_CRYPTO_hash_to_enc (&pc->peer.hashPubKey, &enc);
  printf (_("Peer `%s'\n"), 
	  (const char *) &enc);
  for (i = 0; i < pc->num_addresses; i++)
  {
    if (NULL != pc->address_list[i].result)
    {
      printf ("\t%s\n", pc->address_list[i].result);
      GNUNET_free (pc->address_list[i].result);
    }
  }
  printf ("\n");
  GNUNET_free_non_null (pc->address_list);
  GNUNET_CONTAINER_DLL_remove (pc_head,
			       pc_tail,
			       pc);
  GNUNET_free (pc);
  if ( (NULL == pc_head) &&
       (NULL == pic) )
    tt = GNUNET_SCHEDULER_add_now (&state_machine, NULL);  
}


/* ************************* list all known addresses **************** */


/**
 * Function to call with a human-readable format of an address
 *
 * @param cls closure
 * @param address NULL on error, otherwise 0-terminated printable UTF-8 string
 */
static void
process_resolved_address (void *cls, const char *address)
{
  struct AddressRecord * ar = cls;
  struct PrintContext *pc = ar->pc;

  if (NULL != address)
  {
    if (NULL == ar->result)
      ar->result = GNUNET_strdup (address);
    return;
  }
  ar->atsc = NULL;
  pc->num_addresses++;
  if (pc->num_addresses == pc->address_list_size)
    dump_pc (pc);
}


/**
 * Iterator callback to go over all addresses and count them.
 *
 * @param cls 'struct PrintContext' with 'off' to increment
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
  struct AddressRecord *ar;

  GNUNET_assert (0 < pc->off);
  ar = &pc->address_list[--pc->off];
  ar->pc = pc;
  ar->atsc = GNUNET_TRANSPORT_address_to_string (cfg, address, no_resolve,
						 GNUNET_TIME_relative_multiply
						 (GNUNET_TIME_UNIT_SECONDS, 10),
						 &process_resolved_address, ar);
  return GNUNET_OK;
}


/**
 * Print information about the peer.
 * Currently prints the GNUNET_PeerIdentity and the transport address.
 *
 * @param cls the 'struct PrintContext'
 * @param peer identity of the peer 
 * @param hello addresses of the peer
 * @param err_msg error message
 */
static void
print_peer_info (void *cls, const struct GNUNET_PeerIdentity *peer,
                 const struct GNUNET_HELLO_Message *hello, const char *err_msg)
{
  struct GNUNET_CRYPTO_HashAsciiEncoded enc;
  struct PrintContext *pc;

  if (peer == NULL)
  {
    pic = NULL; /* end of iteration */
    if (err_msg != NULL)
    {
      FPRINTF (stderr, 
	       _("Error in communication with PEERINFO service: %s\n"),
	       err_msg);
    }
    if (NULL == pc_head)
      tt = GNUNET_SCHEDULER_add_now (&state_machine, NULL);
    return;
  }
  if ((GNUNET_YES == be_quiet) || (NULL == hello))
  {
    GNUNET_CRYPTO_hash_to_enc (&peer->hashPubKey, &enc);
    printf ("%s\n", (const char *) &enc);
    return;
  }
  pc = GNUNET_malloc (sizeof (struct PrintContext));
  GNUNET_CONTAINER_DLL_insert (pc_head,
			       pc_tail, 
			       pc);
  pc->peer = *peer;
  GNUNET_HELLO_iterate_addresses (hello, 
				  GNUNET_NO, 
				  &count_address, 
				  pc);
  if (0 == pc->off)
  {
    dump_pc (pc);
    return;
  }
  pc->address_list_size = pc->off;
  pc->address_list = GNUNET_malloc (sizeof (struct AddressRecord) * pc->off);
  GNUNET_HELLO_iterate_addresses (hello, GNUNET_NO, 
				  &print_address, pc);
}


/* ************************* GET URI ************************** */


/**
 * Function that is called on each address of this peer.
 * Expands the corresponding URI string.
 *
 * @param cls the 'GetUriContext'
 * @param address address to add
 * @param expiration expiration time for the address
 * @return GNUNET_OK (continue iteration).
 */
static int
compose_uri (void *cls, const struct GNUNET_HELLO_Address *address,
             struct GNUNET_TIME_Absolute expiration)
{
  struct GetUriContext *guc = cls;
  struct GNUNET_TRANSPORT_PluginFunctions *papi;
  const char *addr;
  char *ret;
  struct tm *t;
  time_t seconds;

  papi = GPI_plugins_find (address->transport_name);
  if (papi == NULL)
  {
    /* Not an error - we might just not have the right plugin. */
    return GNUNET_OK;
  }
  if (NULL == papi->address_to_string)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"URI conversion not implemented for plugin `%s'\n",
		address->transport_name);
    return GNUNET_OK;
  }
  addr = papi->address_to_string (papi->cls, address->address, address->address_length);
  if ( (addr == NULL) || (strlen(addr) == 0) )
    return GNUNET_OK;
  seconds = expiration.abs_value / 1000;
  t = gmtime (&seconds);
  GNUNET_asprintf (&ret,
		   "%s!%04u%02u%02u%02u%02u%02u!%s!%s",
		   guc->uri,
		   t->tm_year,
		   t->tm_mon, 
		   t->tm_mday, 
		   t->tm_hour,
		   t->tm_min,
		   t->tm_sec,
		   address->transport_name, 
		   addr);
  GNUNET_free (guc->uri);
  guc->uri = ret;
  return GNUNET_OK;
}


/**
 * Print URI of the peer.
 *
 * @param cls the 'struct GetUriContext'
 * @param peer identity of the peer (unused)
 * @param hello addresses of the peer
 * @param err_msg error message
 */
static void
print_my_uri (void *cls, const struct GNUNET_PeerIdentity *peer,
              const struct GNUNET_HELLO_Message *hello, 
	      const char *err_msg)
{
  struct GetUriContext *guc = cls;

  if (peer == NULL)
  {
    if (err_msg != NULL)
      FPRINTF (stderr,
	       _("Error in communication with PEERINFO service: %s\n"), 
	       err_msg);
  } 
  else
  {
    if (NULL != hello)
      GNUNET_HELLO_iterate_addresses (hello, GNUNET_NO, &compose_uri, guc);   
    printf ("%s\n", (const char *) guc->uri);
  }
  GNUNET_free (guc->uri);
  GNUNET_free (guc);  
  tt = GNUNET_SCHEDULER_add_now (&state_machine, NULL);
}


/* ************************* import HELLO by URI ********************* */


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

  papi = GPI_plugins_find (ctx->pos);
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
  if (NULL == papi->string_to_address)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		_("Plugin `%s' does not support URIs yet\n"),
		ctx->pos);
    ctx->pos = exp2 + 1;
    if (ctx->pos - ctx->tmp >= ctx->tmp_len)
      return 0;
    return add_addr_to_hello (cls, max, buffer);
  }
  if ((papi->string_to_address != NULL) && (GNUNET_OK ==
      papi->string_to_address (papi->cls, &exp1[1], exp2 - &exp1[1], &addr,
      &addr_len)))
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


static void
parse_hello (const struct GNUNET_CONFIGURATION_Handle *c,
             const char *put_uri)
{
  int r;
  char *scheme_part = NULL;
  char *path_part = NULL;
  char *exc;
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
    exc = ctx.tmp + ctx.tmp_len;
  ctx.pos = exc;

  std_result = GNUNET_STRINGS_string_to_data (ctx.tmp, exc - ctx.tmp,
      (unsigned char *) &my_public_key, sizeof (my_public_key));
  if (std_result != GNUNET_OK)
  {
    GNUNET_free (ctx.tmp);
    return;
  }

  hello = GNUNET_HELLO_create (&my_public_key, add_addr_to_hello, &ctx);
  GNUNET_free (ctx.tmp);

  /* WARNING: this adds the address from URI WITHOUT verification! */
  GNUNET_PEERINFO_add_peer (peerinfo, hello);
  GNUNET_free (hello);
  /* wait 1s to give peerinfo operation a chance to succeed */
  tt = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
				     &state_machine, NULL);
}


/* ************************ Main state machine ********************* */


/**
 * Main state machine that goes over all options and
 * runs the next requested function.
 *
 * @param cls unused
 * @param tc scheduler context
 */
static void
shutdown_task (void *cls,
	       const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct PrintContext *pc;
  struct AddressRecord *ar;
  unsigned int i;

  if (GNUNET_SCHEDULER_NO_TASK != tt)
  {
    GNUNET_SCHEDULER_cancel (tt);
    tt = GNUNET_SCHEDULER_NO_TASK;
  }
  if (NULL != pic)
  {
    GNUNET_PEERINFO_iterate_cancel (pic);
    pic = NULL;
  }
  while (NULL != (pc = pc_head))
  {
    GNUNET_CONTAINER_DLL_remove (pc_head,
				 pc_tail,
				 pc);
    for (i=0;i<pc->address_list_size;i++)
    {
      ar = &pc->address_list[i];
      GNUNET_free_non_null (ar->result);
      if (NULL != ar->atsc)
      {
	GNUNET_TRANSPORT_address_to_string_cancel (ar->atsc);
	ar->atsc = NULL;
      }
    }
    GNUNET_free_non_null (pc->address_list);
    GNUNET_free (pc);
  }
  GPI_plugins_unload ();
  if (NULL != peerinfo)
  {
    GNUNET_PEERINFO_disconnect (peerinfo);
    peerinfo = NULL;
  }
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
  char *fn;

  cfg = c;
  if (args[0] != NULL)
  {
    FPRINTF (stderr, _("Invalid command line argument `%s'\n"), args[0]);
    return;
  }
  peerinfo = GNUNET_PEERINFO_connect (cfg);
  if (peerinfo == NULL)
  {
    FPRINTF (stderr, "%s",  _("Could not access PEERINFO service.  Exiting.\n"));
    return;
  }
  if ( (GNUNET_YES == get_self) || (GNUNET_YES == get_uri) )
  {
    /* load private key */
    if (GNUNET_OK !=
	GNUNET_CONFIGURATION_get_value_filename (cfg, "GNUNETD", "HOSTKEY",
						 &fn))
    {
      FPRINTF (stderr, _("Could not find option `%s:%s' in configuration.\n"),
	       "GNUNETD", "HOSTKEYFILE");
      return;
    }

    if (NULL == (priv = GNUNET_CRYPTO_rsa_key_create_from_file (fn)))
    {
      FPRINTF (stderr, _("Loading hostkey from `%s' failed.\n"), fn);
      GNUNET_free (fn);
      return;
    }
    GNUNET_free (fn);
    GNUNET_CRYPTO_rsa_key_get_public (priv, &my_public_key);
    fprintf (stderr, "PK: `%s\n", 
	     GNUNET_CRYPTO_rsa_public_key_to_string (&my_public_key));
    GNUNET_CRYPTO_rsa_key_free (priv);
    GNUNET_CRYPTO_hash (&my_public_key, sizeof (my_public_key), &my_peer_identity.hashPubKey);
  }

  tt = GNUNET_SCHEDULER_add_now (&state_machine, NULL);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
				&shutdown_task,
				NULL);
}


/**
 * Main state machine that goes over all options and
 * runs the next requested function.
 *
 * @param cls unused
 * @param tc scheduler context
 */
static void
state_machine (void *cls,
	       const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  tt = GNUNET_SCHEDULER_NO_TASK;

  if (NULL != put_uri)
  {
    GPI_plugins_load (cfg);
    parse_hello (cfg, put_uri);
    put_uri = NULL;
    return;
  }
  if (GNUNET_YES == get_info)
  {
    get_info = GNUNET_NO;
    GPI_plugins_load (cfg);
    pic = GNUNET_PEERINFO_iterate (peerinfo, NULL,
				   GNUNET_TIME_UNIT_FOREVER_REL, 
				   &print_peer_info, NULL);
    return;
  }
  if (GNUNET_YES == get_self)
  {
    struct GNUNET_CRYPTO_HashAsciiEncoded enc;

    get_self = GNUNET_NO;
    GNUNET_CRYPTO_hash_to_enc (&my_peer_identity.hashPubKey, &enc);
    if (be_quiet)
      printf ("%s\n", (char *) &enc);
    else
      printf (_("I am peer `%s'.\n"), (const char *) &enc);
  }
  if (GNUNET_YES == get_uri)
  {
    struct GetUriContext *guc;
    char *pkey;

    guc = GNUNET_malloc (sizeof (struct GetUriContext));
    pkey = GNUNET_CRYPTO_rsa_public_key_to_string (&my_public_key);
    GNUNET_asprintf (&guc->uri,
		     "gnunet://hello/%s",
		     pkey);
    GNUNET_free (pkey);
    GPI_plugins_load (cfg);
    pic = GNUNET_PEERINFO_iterate (peerinfo, &my_peer_identity,
				   GNUNET_TIME_UNIT_FOREVER_REL,
				   &print_my_uri, guc);
    get_uri = GNUNET_NO;
    return;
  }
  GNUNET_SCHEDULER_shutdown ();
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
    {'i', "info", NULL,
     gettext_noop ("list all known peers"),
     0, &GNUNET_GETOPT_set_one, &get_info},
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
