/*
     This file is part of GNUnet.
     (C) 2012 Christian Grothoff (and other contributing authors)

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
/*
 * @file namestore/test_plugin_namestore.c
 * @brief Test for the namestore plugins
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_namestore_plugin.h"

#define VERBOSE GNUNET_EXTRA_LOGGING

#define ASSERT(x) do { if (! (x)) { printf("Error at %s:%d\n", __FILE__, __LINE__); goto FAILURE;} } while (0)

static int ok;

/**
 * Name of plugin under test.
 */
static const char *plugin_name;


/**
 * Function called when the service shuts down.  Unloads our namestore
 * plugin.
 *
 * @param api api to unload
 */
static void
unload_plugin (struct GNUNET_NAMESTORE_PluginFunctions *api)
{
  char *libname;

  GNUNET_asprintf (&libname, "libgnunet_plugin_namestore_%s", plugin_name);
  GNUNET_break (NULL == GNUNET_PLUGIN_unload (libname, api));
  GNUNET_free (libname);
}


/**
 * Load the namestore plugin.
 *
 * @param cfg configuration to pass
 * @return NULL on error
 */
static struct GNUNET_NAMESTORE_PluginFunctions *
load_plugin (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_NAMESTORE_PluginFunctions *ret;
  char *libname;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Loading `%s' namestore plugin\n"),
              plugin_name);
  GNUNET_asprintf (&libname, "libgnunet_plugin_namestore_%s", plugin_name);
  if (NULL == (ret = GNUNET_PLUGIN_load (libname, (void*) cfg)))
  {
    FPRINTF (stderr, "Failed to load plugin `%s'!\n", plugin_name);
    return NULL;
  }
  GNUNET_free (libname);
  return ret;
}


/**
 * Function called by for each matching record.
 *
 * @param cls closure
 * @param zone hash of the public key of the zone
 * @param loc location of the signature for this record
 * @param name name that is being mapped (at most 255 characters long)
 * @param record_type type of the record (A, AAAA, PKEY, etc.)
 * @param expiration expiration time for the content
 * @param flags flags for the content
 * @param data_size number of bytes in data
 * @param data value, semantics depend on 'record_type' (see RFCs for DNS and 
 *             GNS specification for GNS extensions) 
 */
static void 
test_record (void *cls,
	     const GNUNET_HashCode *zone,
	     const struct GNUNET_NAMESTORE_SignatureLocation *loc,
	     const char *name,
	     uint32_t record_type,
	     struct GNUNET_TIME_Absolute expiration,
	     enum GNUNET_NAMESTORE_RecordFlags flags,
	     size_t data_size,
	     const void *data)
{
  int *idp = cls;
  int id = *idp;
  size_t tdata_size = id * 17;
  char tdata[tdata_size];
  GNUNET_HashCode tzone;
  char tname[32];
  uint32_t trecord_type;
  struct GNUNET_NAMESTORE_SignatureLocation tloc;
  enum GNUNET_NAMESTORE_RecordFlags tflags;		   
  
  memset (&tzone, 42, sizeof (tzone));
  memset (tdata, id % 255, sizeof (tdata));
  GNUNET_snprintf (tname, sizeof (tname),
		   "aa%u", (unsigned int) id);
  trecord_type = id % 4;
  tloc.depth = (id % 10);
  tloc.offset = (id % 3);
  tloc.revision = id % 1024;
  tflags = GNUNET_NAMESTORE_RF_AUTHORITY;
  
  GNUNET_assert (0 == memcmp (&tzone, zone, sizeof (GNUNET_HashCode)));
  GNUNET_assert (trecord_type == record_type);
  GNUNET_assert (0 == strcmp (tname, name));
  GNUNET_assert (tdata_size == data_size);
  GNUNET_assert (0 == memcmp (data, tdata, data_size));
  GNUNET_assert (flags == tflags);
  GNUNET_assert (0 == memcmp (loc, &tloc, sizeof (struct GNUNET_NAMESTORE_SignatureLocation)));
}


static void
get_record (struct GNUNET_NAMESTORE_PluginFunctions *nsp, int id)
{
  GNUNET_HashCode zone;
  GNUNET_HashCode nh;
  char name[32];
  
  memset (&zone, 42, sizeof (zone));
  GNUNET_snprintf (name, sizeof (name),
		   "aa%u", (unsigned int) id);
  GNUNET_CRYPTO_hash (name, strlen (name), &nh);
  GNUNET_assert (1 == nsp->iterate_records (nsp->cls,
					    &zone,
					    &nh,
					    &test_record, &id));
}


/**
 * Function called with the matching node.
 *
 * @param cls closure
 * @param zone hash of public key of the zone
 * @param loc location in the B-tree
 * @param ploc parent's location in the B-tree (must have depth = loc.depth - 1), NULL for root
 * @param num_entries number of entries at this node in the B-tree
 * @param entries the 'num_entries' entries to store (hashes over the
 *                records)
 */
static void
test_node (void *cls,
	   const GNUNET_HashCode *zone,
	   const struct GNUNET_NAMESTORE_SignatureLocation *loc,
	   const struct GNUNET_NAMESTORE_SignatureLocation *ploc,
	   unsigned int num_entries,
	   const GNUNET_HashCode *entries)
{
  int *idp = cls;
  int id = *idp;
  struct GNUNET_NAMESTORE_SignatureLocation tloc;
  struct GNUNET_NAMESTORE_SignatureLocation tploc;
  unsigned int tnum_entries = 1 + (id % 15);
  GNUNET_HashCode tentries[num_entries];
  unsigned int i;

  tloc.depth = (id % 10);
  tloc.offset = (id % 3);
  tloc.revision = id % 1024;
  tploc.depth = tloc.depth + 1;
  tploc.offset = (id % 5);
  tploc.revision = tloc.revision;
  for (i=0;i<tnum_entries;i++)
    memset (&tentries[i], (id+i) % 255, sizeof (GNUNET_HashCode));
  GNUNET_assert (0 == memcmp (&tloc, loc, 
			      sizeof (const struct GNUNET_NAMESTORE_SignatureLocation)));
  GNUNET_assert (0 == memcmp (&tploc, ploc, 
			      sizeof (const struct GNUNET_NAMESTORE_SignatureLocation)));
  GNUNET_assert (num_entries == tnum_entries);
  GNUNET_assert (0 == memcmp (entries, tentries, sizeof (tentries)));
}


static void
get_node (struct GNUNET_NAMESTORE_PluginFunctions *nsp, int id)
{
  GNUNET_HashCode zone;
  struct GNUNET_NAMESTORE_SignatureLocation loc;

  memset (&zone, 42, sizeof (zone));
  loc.depth = (id % 10);
  loc.offset = (id % 3);
  loc.revision = id % 1024;
  GNUNET_assert (GNUNET_OK ==
		 nsp->get_node (nsp->cls,
				&zone,
				&loc,
				&test_node,
				&id));
}


/**
 * Function called with the matching signature.
 *
 * @param cls closure
 * @param zone public key of the zone
 * @param loc location of the root in the B-tree (depth, revision)
 * @param top_sig signature signing the zone
 * @param zone_time time the signature was created
 * @param root_hash top level hash that is being signed
 */
static void
test_signature (void *cls,
		const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *zone_key,
		const struct GNUNET_NAMESTORE_SignatureLocation *loc,
		const struct GNUNET_CRYPTO_RsaSignature *top_sig,
		struct GNUNET_TIME_Absolute zone_time,
		const GNUNET_HashCode *root_hash)
{
  int *idp = cls;
  int id = *idp;
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded tzone_key;
  struct GNUNET_NAMESTORE_SignatureLocation tloc;
  struct GNUNET_CRYPTO_RsaSignature ttop_sig;
  GNUNET_HashCode troot_hash;

  memset (&tzone_key, 13, sizeof (tzone_key));
  tloc.depth = (id % 10);
  tloc.offset = (id % 3);
  tloc.revision = id % 1024;
  memset (&ttop_sig, 24, sizeof (ttop_sig));
  memset (&troot_hash, 42, sizeof (troot_hash));

  GNUNET_assert (0 == memcmp (&tzone_key, zone_key, sizeof (GNUNET_HashCode)));
  GNUNET_assert (0 == memcmp (&tloc, loc, sizeof (struct GNUNET_NAMESTORE_SignatureLocation)));
  GNUNET_assert (0 == memcmp (&ttop_sig, top_sig, sizeof (struct GNUNET_CRYPTO_RsaSignature)));
  GNUNET_assert (0 == memcmp (&troot_hash, root_hash, sizeof (GNUNET_HashCode)));
}


static void
get_signature (struct GNUNET_NAMESTORE_PluginFunctions *nsp, int id)
{
  GNUNET_HashCode root_hash;

  memset (&root_hash, 42, sizeof (root_hash));
  GNUNET_assert (GNUNET_OK ==
		 nsp->get_signature (nsp->cls,
				     &root_hash,
				     test_signature,
				     &id));
}


static void
put_record (struct GNUNET_NAMESTORE_PluginFunctions *nsp, int id)
{
  size_t data_size = id * 17;
  char data[data_size];
  GNUNET_HashCode zone;
  char name[32];
  uint32_t record_type;
  struct GNUNET_NAMESTORE_SignatureLocation loc;
  struct GNUNET_TIME_Absolute expiration;
  enum GNUNET_NAMESTORE_RecordFlags flags;		   
  
  memset (&zone, 42, sizeof (zone));
  memset (data, id % 255, sizeof (data));
  GNUNET_snprintf (name, sizeof (name),
		   "aa%u", (unsigned int) id);
  record_type = id % 4;
  loc.depth = (id % 10);
  loc.offset = (id % 3);
  loc.revision = id % 1024;
  expiration = GNUNET_TIME_relative_to_absolute (GNUNET_TIME_UNIT_HOURS);
  flags = GNUNET_NAMESTORE_RF_AUTHORITY;

  GNUNET_assert (GNUNET_OK ==
		 nsp->put_record (nsp->cls,
				  &zone,
				  name,
				  record_type,
				  &loc,
				  expiration,
				  flags,
				  data_size,
				  data));
}


static void
put_node (struct GNUNET_NAMESTORE_PluginFunctions *nsp,
	  int id)
{
  GNUNET_HashCode zone;
  struct GNUNET_NAMESTORE_SignatureLocation loc;
  struct GNUNET_NAMESTORE_SignatureLocation ploc;
  unsigned int num_entries = 1 + (id % 15);
  GNUNET_HashCode entries[num_entries];
  unsigned int i;

  memset (&zone, 42, sizeof (zone));
  loc.depth = (id % 10);
  loc.offset = (id % 3);
  loc.revision = id % 1024;
  ploc.depth = loc.depth + 1;
  ploc.offset = (id % 5);
  ploc.revision = loc.revision;
  for (i=0;i<num_entries;i++)
    memset (&entries[i], (id+i) % 255, sizeof (GNUNET_HashCode));
  GNUNET_assert (GNUNET_OK ==
		 nsp->put_node (nsp->cls,
				&zone,
				&loc,
				&ploc,
				num_entries,
				entries));
}


static void
put_signature (struct GNUNET_NAMESTORE_PluginFunctions *nsp,
	       int id)
{
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded zone_key;
  struct GNUNET_NAMESTORE_SignatureLocation loc;
  struct GNUNET_CRYPTO_RsaSignature top_sig;
  GNUNET_HashCode root_hash;
  struct GNUNET_TIME_Absolute zone_time;

  memset (&zone_key, 13, sizeof (zone_key));
  loc.depth = (id % 10);
  loc.offset = (id % 3);
  loc.revision = id % 1024;
  memset (&top_sig, 24, sizeof (top_sig));
  memset (&root_hash, 42, sizeof (root_hash));
  zone_time = GNUNET_TIME_relative_to_absolute (GNUNET_TIME_UNIT_HOURS);
  
  GNUNET_assert (GNUNET_OK ==
		 nsp->put_signature (nsp->cls,
				     &zone_key,
				     &loc,
				     &top_sig,
				     &root_hash,
				     zone_time));
}


static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_NAMESTORE_PluginFunctions *nsp;  
  
  ok = 0;
  nsp = load_plugin (cfg);
  if (NULL == nsp)
  {
    FPRINTF (stderr,
             "%s", 
	     "Failed to initialize namestore.  Database likely not setup, skipping test.\n");
    return;
  }
  put_record (nsp, 1);
  get_record (nsp, 1);
  put_node (nsp, 1);
  get_node (nsp, 1);
  put_signature (nsp, 1);
  get_signature (nsp, 1);
  
  unload_plugin (nsp);
}


int
main (int argc, char *argv[])
{
  char *pos;
  char cfg_name[128];

  char *const xargv[] = {
    "test-plugin-namestore",
    "-c",
    cfg_name,
#if VERBOSE
    "-L", "DEBUG",
#endif
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  GNUNET_log_setup ("test-plugin-namestore",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);
  /* determine name of plugin to use */
  plugin_name = argv[0];
  while (NULL != (pos = strstr (plugin_name, "_")))
    plugin_name = pos + 1;
  if (NULL != (pos = strstr (plugin_name, ".")))
    pos[0] = 0;
  else
    pos = (char *) plugin_name;

  GNUNET_snprintf (cfg_name, sizeof (cfg_name), "test_plugin_namestore_%s.conf",
                   plugin_name);
  if (pos != plugin_name)
    pos[0] = '.';
  GNUNET_PROGRAM_run ((sizeof (xargv) / sizeof (char *)) - 1, xargv,
                      "test-plugin-namestore", "nohelp", options, &run, NULL);
  if (ok != 0)
    FPRINTF (stderr, "Missed some testcases: %d\n", ok);
  return ok;
}

/* end of test_plugin_namestore.c */
