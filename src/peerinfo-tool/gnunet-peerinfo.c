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
 * Prefix that every HELLO URI must start with.
 */
#define HELLO_URI_PREFIX "gnunet://hello/"

/**
 * How long until we time out during peerinfo iterations?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)

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
 * Context for 'add_address_to_hello'.
 */
struct GNUNET_PEERINFO_HelloAddressParsingContext
{
  /**
   * Position in the URI with the next address to parse.
   */
  const char *pos;

  /**
   * Set to GNUNET_SYSERR to indicate parse errors.
   */
  int ret;

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
 * Handle to current 'GNUNET_PEERINFO_add_peer' operation.
 */
static struct GNUNET_PEERINFO_AddContext *ac;


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



/**
 * Replace all characters in the input 'in' according
 * to the mapping.  The mapping says to map each character
 * in 'oldchars' to the corresponding character (by offset)
 * in 'newchars'.  
 *
 * @param in input string to remap
 * @param oldchars characters to replace
 * @param newchars replacement characters, must have same length as 'oldchars'
 * @return copy of string with replacement applied.
 */
static char *
map_characters (const char *in,
		const char *oldchars,
		const char *newchars)
{
  char *ret;
  const char *off;
  size_t i;

  GNUNET_assert (strlen (oldchars) == strlen (newchars));
  ret = GNUNET_strdup (in);
  i = 0;
  while (ret[i] != '\0')
  {
    off = strchr (oldchars, ret[i]);
    if (NULL != off)
      ret[i] = newchars[off - oldchars];
    i++;    
  }
  return ret;
}



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
  char *uri_addr;
  char *ret;
  char tbuf[16];
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
   /* For URIs we use '(' and ')' instead of '[' and ']' as brackets are reserved
      characters in URIs */
  uri_addr = map_characters (addr, "[]", "()");
  seconds = expiration.abs_value / 1000;
  t = gmtime (&seconds);
  GNUNET_assert (0 != strftime (tbuf, sizeof (tbuf),
				"%Y%m%d%H%M%S",
				t));
  GNUNET_asprintf (&ret,
		   "%s!%s!%s!%s",
		   guc->uri,
		   tbuf,
		   address->transport_name, 
		   uri_addr);
  GNUNET_free (uri_addr);
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
    pic = NULL;
    if (err_msg != NULL)
      FPRINTF (stderr,
	       _("Error in communication with PEERINFO service: %s\n"), 
	       err_msg);
    GNUNET_free_non_null (guc->uri);
    GNUNET_free (guc);  
    tt = GNUNET_SCHEDULER_add_now (&state_machine, NULL);
    return;
  } 
  if (NULL != hello)
    GNUNET_HELLO_iterate_addresses (hello, GNUNET_NO, &compose_uri, guc);   
  printf ("%s\n", (const char *) guc->uri);
}


/* ************************* import HELLO by URI ********************* */


/**
 * We're building a HELLO.  Parse the next address from the
 * parsing context and append it.
 *
 * @param cls the 'struct GNUNET_PEERINFO_HelloAddressParsingContext'
 * @param max number of bytes available for HELLO construction
 * @param buffer where to copy the next address (in binary format)
 * @return number of bytes added to buffer
 */ 
static size_t
add_address_to_hello (void *cls, size_t max, void *buffer)
{
  struct GNUNET_PEERINFO_HelloAddressParsingContext *ctx = cls;
  const char *tname;
  const char *address;
  char *uri_address;
  char *plugin_address;
  const char *end;
  char *plugin_name;
  struct tm expiration_time;
  time_t expiration_seconds;
  struct GNUNET_TIME_Absolute expire;
  struct GNUNET_TRANSPORT_PluginFunctions *papi;
  void *addr;
  size_t addr_len;
  struct GNUNET_HELLO_Address haddr;
  size_t ret;

  if (NULL == ctx->pos)
    return 0;
  if ('!' != ctx->pos[0])
  {
    ctx->ret = GNUNET_SYSERR;
    GNUNET_break (0);
    return 0;
  }
  ctx->pos++;
  memset (&expiration_time, 0, sizeof (expiration_time));
  tname = strptime (ctx->pos,
		    "%Y%m%d%H%M%S",
		    &expiration_time);

  if (NULL == tname)
  {
    ctx->ret = GNUNET_SYSERR;
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Failed to parse HELLO message: missing expiration time\n"));
    GNUNET_break (0);
    return 0;
  }
  expiration_seconds = mktime (&expiration_time);
  if (expiration_seconds == (time_t) -1)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Failed to parse HELLO message: invalid expiration time\n"));
    ctx->ret = GNUNET_SYSERR;
    GNUNET_break (0);
    return 0;
  }
  expire.abs_value = expiration_seconds * 1000;
  if ('!' != tname[0])
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Failed to parse HELLO message: malformed\n"));
    ctx->ret = GNUNET_SYSERR;
    GNUNET_break (0);
    return 0;
  }
  tname++;
  address = strchr (tname, (int) '!');
  if (NULL == address)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Failed to parse HELLO message: missing transport plugin\n"));
    ctx->ret = GNUNET_SYSERR;
    GNUNET_break (0);
    return 0;
  }
  address++;
  end = strchr (address, (int) '!');
  ctx->pos = end;
  plugin_name = GNUNET_strndup (tname, address - (tname+1));
  papi = GPI_plugins_find (plugin_name);
  if (NULL == papi)
  {
    /* Not an error - we might just not have the right plugin.
     * Skip this part, advance to the next one and recurse.
     * But only if this is not the end of string.
     */
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Plugin `%s' not found\n"),
                plugin_name);
    GNUNET_free (plugin_name);
    GNUNET_break (0);
    return 0;
  }
  if (NULL == papi->string_to_address)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		_("Plugin `%s' does not support URIs yet\n"),
		plugin_name);
    GNUNET_free (plugin_name);
    GNUNET_break (0);
    return 0;
  }
  uri_address = GNUNET_strndup (address, end - address);
  /* For URIs we use '(' and ')' instead of '[' and ']' as brackets are reserved
     characters in URIs; need to convert back to '[]' for the plugin */
   plugin_address = map_characters (uri_address, "()", "[]");
  GNUNET_free (uri_address);
  if (GNUNET_OK !=
      papi->string_to_address (papi->cls, 
			       plugin_address,
			       strlen (plugin_address) + 1,
			       &addr,
			       &addr_len))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Failed to parse `%s' as an address for plugin `%s'\n"),
		plugin_address,
		plugin_name);
    GNUNET_free (plugin_name);
    GNUNET_free (plugin_address);
    return 0;
  }
  GNUNET_free (plugin_address);
  /* address.peer is unset - not used by add_address() */
  haddr.address_length = addr_len;
  haddr.address = addr;
  haddr.transport_name = plugin_name;
  ret = GNUNET_HELLO_add_address (&haddr, expire, buffer, max);
  GNUNET_free (addr);
  GNUNET_free (plugin_name);
  return ret;
}


/**
 * Continuation called from 'GNUNET_PEERINFO_add_peer'
 *
 * @param cls closure, NULL
 * @param emsg error message, NULL on success
 */
static void
add_continuation (void *cls,
		  const char *emsg)
{
  ac = NULL;
  if (NULL != emsg)
    fprintf (stderr,
	     _("Failure adding HELLO: %s\n"),
	     emsg);
  tt = GNUNET_SCHEDULER_add_now (&state_machine, NULL);
}


/**
 * Parse the PUT URI given at the command line and add it to our peerinfo 
 * database.
 *
 * @param put_uri URI string to parse
 * @return GNUNET_OK on success, GNUNET_SYSERR if the URI was invalid, GNUNET_NO on other errors
 */
static int
parse_hello_uri (const char *put_uri)
{
  const char *pks;
  const char *exc;
  struct GNUNET_HELLO_Message *hello;
  struct GNUNET_PEERINFO_HelloAddressParsingContext ctx;

  if (0 != strncmp (put_uri,
		    HELLO_URI_PREFIX,
		    strlen (HELLO_URI_PREFIX)))
    return GNUNET_SYSERR;
  pks = &put_uri[strlen (HELLO_URI_PREFIX)];
  exc = strstr (pks, "!");

  if (GNUNET_OK != GNUNET_STRINGS_string_to_data (pks,
						  (NULL == exc) ? strlen (pks) : (exc - pks),
						  (unsigned char *) &my_public_key, 
						  sizeof (my_public_key)))
    return GNUNET_SYSERR;
  ctx.pos = exc;
  ctx.ret = GNUNET_OK;
  hello = GNUNET_HELLO_create (&my_public_key, &add_address_to_hello, &ctx);

  if (NULL != hello)
  {
    /* WARNING: this adds the address from URI WITHOUT verification! */
    if (GNUNET_OK == ctx.ret)    
      ac = GNUNET_PEERINFO_add_peer (peerinfo, hello, &add_continuation, NULL);
    else
      tt = GNUNET_SCHEDULER_add_now (&state_machine, NULL);
    GNUNET_free (hello);
  }

  /* wait 1s to give peerinfo operation a chance to succeed */
  /* FIXME: current peerinfo API sucks to require this; not to mention
     that we get no feedback to determine if the operation actually succeeded */
  return ctx.ret;
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

  if (NULL != ac)
  {
    GNUNET_PEERINFO_add_peer_cancel (ac);
    ac = NULL;
  }
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
    if (GNUNET_SYSERR == parse_hello_uri (put_uri))
      fprintf (stderr,
	       _("Invalid URI `%s'\n"),
	       put_uri);    
    GNUNET_free (put_uri);
    put_uri = NULL;
    return;
  }
  if (GNUNET_YES == get_info)
  {
    get_info = GNUNET_NO;
    GPI_plugins_load (cfg);
    pic = GNUNET_PEERINFO_iterate (peerinfo, NULL,
				   TIMEOUT,
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
		     "%s%s",
		     HELLO_URI_PREFIX,
		     pkey);
    GNUNET_free (pkey);
    GPI_plugins_load (cfg);
    pic = GNUNET_PEERINFO_iterate (peerinfo, &my_peer_identity,
				   TIMEOUT,
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
