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
#include "gnunet_program_lib.h"
#include "gnunet_hello_lib.h"
#include "gnunet_transport_service.h"
#include "gnunet_peerinfo_service.h"
#include "gnunet-peerinfo_plugins.h"

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
   * Address expiration time
   */
  struct GNUNET_TIME_Absolute expiration;

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

  /**
   * Hello was friend only, GNUNET_YES or GNUNET_NO
   */
  int friend_only;

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
 * Option '-f'
 */
static int include_friend_only;

/**
 * Option '-s'
 */
static int get_self;

/**
 * Option
 */
static int get_uri;

/**
 * Option
 */
static int default_operation;

/**
 * Option '-i'
 */
static int get_info;

/**
 * Option
 */
static char *put_uri;

/**
 * Option -d
 */
static char *dump_hello;

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


/* ********************* 'get_info' ******************* */

/**
 * Print the collected address information to the console and free 'pc'.
 *
 * @param pc printing context
 */
static void
dump_pc (struct PrintContext *pc)
{
  unsigned int i;

  printf (_("%sPeer `%s'\n"),
	  (GNUNET_YES == pc->friend_only) ? "F2F: " : "",
	  GNUNET_i2s_full (&pc->peer));
  for (i = 0; i < pc->num_addresses; i++)
  {
    if (NULL != pc->address_list[i].result)
    {
      printf (_("\tExpires: %s \t %s\n"), GNUNET_STRINGS_absolute_time_to_string(pc->address_list[i].expiration), pc->address_list[i].result);
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
process_resolved_address (void *cls, const char *address, int res)
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
  if (GNUNET_SYSERR == res)
  {
    FPRINTF (stderr,
             _("Failure: Cannot convert address to string for peer `%s'\n"),
             GNUNET_i2s (&ar->pc->peer));
  }
  else
  {
    pc->num_addresses++;
  }
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
  ar->expiration = expiration;
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
  struct PrintContext *pc;
  int friend_only;

  if (NULL == peer)
  {
    pic = NULL; /* end of iteration */
    if (NULL != err_msg)
    {
      FPRINTF (stderr,
	       _("Error in communication with PEERINFO service: %s\n"),
	       err_msg);
    }
    if (NULL == pc_head)
      tt = GNUNET_SCHEDULER_add_now (&state_machine, NULL);
    return;
  }
  friend_only = GNUNET_NO;
  if (NULL != hello)
  	friend_only = GNUNET_HELLO_is_friend_only (hello);
  if ((GNUNET_YES == be_quiet) || (NULL == hello))
  {
    printf ("%s%s\n",
	    (GNUNET_YES == friend_only) ? "F2F: " : "",
	    GNUNET_i2s_full (peer));
    return;
  }
  pc = GNUNET_new (struct PrintContext);
  GNUNET_CONTAINER_DLL_insert (pc_head,
			       pc_tail,
			       pc);
  pc->peer = *peer;
  pc->friend_only = friend_only;
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

/* ************************* DUMP Hello  ************************** */

static int count_addr(void *cls,
										 const struct GNUNET_HELLO_Address *address,
										 struct GNUNET_TIME_Absolute expiration)
{
	int *c = cls;
  (*c) ++;
  return GNUNET_OK;
}

/**
 * Write Hello of my peer to a file.
 *
 * @param cls the 'struct GetUriContext'
 * @param peer identity of the peer (unused)
 * @param hello addresses of the peer
 * @param err_msg error message
 */
static void
dump_my_hello (void *cls, const struct GNUNET_PeerIdentity *peer,
              const struct GNUNET_HELLO_Message *hello,
	      const char *err_msg)
{
	unsigned int size;
	unsigned int c_addr;
  if (peer == NULL)
  {
    pic = NULL;
    if (err_msg != NULL)
      FPRINTF (stderr,
	       _("Error in communication with PEERINFO service: %s\n"),
	       err_msg);
    tt = GNUNET_SCHEDULER_add_now (&state_machine, NULL);
    return;
  }

  if (NULL == hello)
  {
		FPRINTF (stderr,
			 _("Failure: Did not receive %s\n"), "HELLO");
    return;
  }

  size = GNUNET_HELLO_size (hello);
  if (0 == size)
  {
  		FPRINTF (stderr,
  			 _("Failure: Received invalid %s\n"), "HELLO");
      return;
  }
  if (GNUNET_SYSERR == GNUNET_DISK_fn_write (dump_hello, hello, size,
                            GNUNET_DISK_PERM_USER_READ |
                            GNUNET_DISK_PERM_USER_WRITE |
                            GNUNET_DISK_PERM_GROUP_READ |
                            GNUNET_DISK_PERM_OTHER_READ))
  {
  		FPRINTF (stderr, _("Failed to write HELLO with %u bytes to file `%s'\n"),
  			 size, dump_hello);
  		if (0 != UNLINK (dump_hello))
  		GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING |
                              GNUNET_ERROR_TYPE_BULK, "unlink", dump_hello);

  }
  c_addr = 0;
  GNUNET_HELLO_iterate_addresses (hello, GNUNET_NO, count_addr, &c_addr);

  if (!be_quiet)
  {
  		FPRINTF (stderr,
  			 _("Wrote %s HELLO containing %u addresses with %u bytes to file `%s'\n"),
  			 (GNUNET_YES == GNUNET_HELLO_is_friend_only(hello)) ? "friend-only": "public",
  					c_addr, size, dump_hello);
  }

  GNUNET_free (dump_hello);
  dump_hello = NULL;

}


/* ************************* GET URI ************************** */


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
  if (peer == NULL)
  {
    pic = NULL;
    if (err_msg != NULL)
      FPRINTF (stderr,
	       _("Error in communication with PEERINFO service: %s\n"),
	       err_msg);
    tt = GNUNET_SCHEDULER_add_now (&state_machine, NULL);
    return;
  }

  if (NULL == hello)
    return;
  char *uri = GNUNET_HELLO_compose_uri(hello, &GPI_plugins_find);
  if (NULL != uri) {
    printf ("%s\n", (const char *) uri);
    GNUNET_free (uri);
  }
}


/* ************************* import HELLO by URI ********************* */


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
  struct GNUNET_HELLO_Message *hello = NULL;

  int ret = GNUNET_HELLO_parse_uri(put_uri, &my_peer_identity.public_key,
				   &hello, &GPI_plugins_find);

  if (NULL != hello) {
    /* WARNING: this adds the address from URI WITHOUT verification! */
    if (GNUNET_OK == ret)
      ac = GNUNET_PEERINFO_add_peer (peerinfo, hello, &add_continuation, NULL);
    else
      tt = GNUNET_SCHEDULER_add_now (&state_machine, NULL);
    GNUNET_free (hello);
  }

  /* wait 1s to give peerinfo operation a chance to succeed */
  /* FIXME: current peerinfo API sucks to require this; not to mention
     that we get no feedback to determine if the operation actually succeeded */
  return ret;
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
 * Function called with the result of the check if the 'peerinfo'
 * service is running.
 *
 * @param cls closure with our configuration
 * @param result #GNUNET_YES if transport is running
 */
static void
testservice_task (void *cls, int result)
{
  struct GNUNET_CRYPTO_EddsaPrivateKey *priv;
  char *fn;

  if (GNUNET_YES != result)
  {
    FPRINTF (stderr, _("Service `%s' is not running, please start GNUnet\n"), "peerinfo");
    return;
  }

  if (NULL == (peerinfo = GNUNET_PEERINFO_connect (cfg)))
  {
    FPRINTF (stderr, "%s",  _("Could not access PEERINFO service.  Exiting.\n"));
    return;
  }
  if ( (GNUNET_YES == get_self) || (GNUNET_YES == get_uri) || (NULL != dump_hello) )
  {
    /* load private key */
    if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_filename (cfg, "PEER",
                                                              "PRIVATE_KEY",
                                                               &fn))
    {
      GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR, "PEER", "PRIVATE_KEY");
      return;
    }
    if (NULL == (priv = GNUNET_CRYPTO_eddsa_key_create_from_file (fn)))
    {
      FPRINTF (stderr, _("Loading hostkey from `%s' failed.\n"), fn);
      GNUNET_free (fn);
      return;
    }
    GNUNET_free (fn);
    GNUNET_CRYPTO_eddsa_key_get_public (priv,
                                        &my_peer_identity.public_key);
    GNUNET_free (priv);
  }

  tt = GNUNET_SCHEDULER_add_now (&state_machine, NULL);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
                                &shutdown_task,
                                NULL);
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
  cfg = c;
  if ( (NULL != args[0]) &&
       (NULL == put_uri) &&
       (args[0] == strcasestr (args[0], "gnunet://hello/")) )
  {
    put_uri = GNUNET_strdup (args[0]);
    args++;
  }
  if (NULL != args[0])
  {
    FPRINTF (stderr,
	     _("Invalid command line argument `%s'\n"),
	     args[0]);
    return;
  }

  GNUNET_CLIENT_service_test ("peerinfo", cfg, GNUNET_TIME_UNIT_SECONDS,
      &testservice_task, (void *) cfg);
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
    {
      fprintf (stderr,
	       _("Invalid URI `%s'\n"),
	       put_uri);
      GNUNET_SCHEDULER_shutdown ();
    }
    GNUNET_free (put_uri);
    put_uri = NULL;
  }
  else if (GNUNET_YES == get_info)
  {
    get_info = GNUNET_NO;
    GPI_plugins_load (cfg);
    pic = GNUNET_PEERINFO_iterate (peerinfo, include_friend_only, NULL,
				   TIMEOUT,
				   &print_peer_info, NULL);
  }
  else if (GNUNET_YES == get_self)
  {
    get_self = GNUNET_NO;
    if (be_quiet)
      printf ("%s\n",
	      GNUNET_i2s_full (&my_peer_identity));
    else
      printf (_("I am peer `%s'.\n"),
	      GNUNET_i2s_full (&my_peer_identity));
    tt = GNUNET_SCHEDULER_add_now (&state_machine, NULL);
  }
  else if (GNUNET_YES == get_uri)
  {
    GPI_plugins_load (cfg);
    pic = GNUNET_PEERINFO_iterate (peerinfo, include_friend_only, &my_peer_identity,
				   TIMEOUT, &print_my_uri, NULL);
    get_uri = GNUNET_NO;
  }
  else if (NULL != dump_hello)
  {
    pic = GNUNET_PEERINFO_iterate (peerinfo, include_friend_only, &my_peer_identity,
				   TIMEOUT, &dump_my_hello, NULL);
  }
  else if (GNUNET_YES == default_operation)
  {
  	/* default operation list all */
  	default_operation = GNUNET_NO;
  	get_info = GNUNET_YES;
  	tt = GNUNET_SCHEDULER_add_now (&state_machine, NULL);
  }
  else
  {
  	GNUNET_SCHEDULER_shutdown ();
  }
	default_operation = GNUNET_NO;
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
	default_operation = GNUNET_YES;
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    {'n', "numeric", NULL,
     gettext_noop ("don't resolve host names"),
     0, &GNUNET_GETOPT_set_one, &no_resolve},
    {'q', "quiet", NULL,
     gettext_noop ("output only the identity strings"),
     0, &GNUNET_GETOPT_set_one, &be_quiet},
    {'f', "friends", NULL,
     gettext_noop ("include friend-only information"),
     0, &GNUNET_GETOPT_set_one, &include_friend_only},
    {'s', "self", NULL,
     gettext_noop ("output our own identity only"),
     0, &GNUNET_GETOPT_set_one, &get_self},
    {'i', "info", NULL,
     gettext_noop ("list all known peers"),
     0, &GNUNET_GETOPT_set_one, &get_info},
    {'d', "dump-hello", NULL,
     gettext_noop ("dump hello to file"),
     1, &GNUNET_GETOPT_set_string, &dump_hello},
    {'g', "get-hello", NULL,
     gettext_noop ("also output HELLO uri(s)"),
     0, &GNUNET_GETOPT_set_one, &get_uri},
    {'p', "put-hello", "HELLO",
     gettext_noop ("add given HELLO uri to the database"),
     1, &GNUNET_GETOPT_set_string, &put_uri},
    GNUNET_GETOPT_OPTION_END
  };
  int ret;

  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;

  ret = (GNUNET_OK ==
	 GNUNET_PROGRAM_run (argc, argv, "gnunet-peerinfo",
			     gettext_noop ("Print information about peers."),
			     options, &run, NULL)) ? 0 : 1;
  GNUNET_free ((void*) argv);
  return ret;
}

/* end of gnunet-peerinfo.c */
