#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_lib.h"

static unsigned int nkeys;
static unsigned int nskip;
static int result;





/**
 * Main run function.
 *
 * @param cls NULL
 * @param args arguments passed to GNUNET_PROGRAM_run
 * @param cfgfile the path to configuration file
 * @param cfg the configuration file handle
 */
static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *config)
{
  char *idfile;
  struct GNUNET_DISK_FileHandle *f;
  void *data;
  struct GNUNET_DISK_MapHandle *map;
  struct GNUNET_CRYPTO_EddsaPrivateKey pkey;
  struct GNUNET_PeerIdentity id;
  unsigned int cnt;
  uint64_t fsize;
  unsigned int nmax;

  if ((NULL == args) || (NULL == args[0]))
  {
    FPRINTF (stderr, "Need the hostkey file\n");
    return;
  }
  idfile = args[0];
  if (GNUNET_OK !=
      GNUNET_DISK_file_size (idfile, &fsize, GNUNET_YES, GNUNET_YES))
  {
    GNUNET_break (0);
    return;
  }
  if (0 != (fsize % GNUNET_TESTING_HOSTKEYFILESIZE))
  {
    FPRINTF (stderr,
             _("Incorrect hostkey file format: %s\n"), idfile);
    return;
  }
  f = GNUNET_DISK_file_open (idfile, GNUNET_DISK_OPEN_READ,
                             GNUNET_DISK_PERM_NONE);
  if (NULL == f)
  {
    GNUNET_break (0);
    return;
  }
  data = GNUNET_DISK_file_map (f, &map, GNUNET_DISK_MAP_TYPE_READ, fsize);
  if (NULL == data)
  {
    GNUNET_break (0);
    GNUNET_DISK_file_close (f);
    return;
  }
  nmax = fsize / GNUNET_TESTING_HOSTKEYFILESIZE;
  for (cnt = nskip; cnt < (nskip + nkeys); cnt++)
  {
    if (nskip + cnt >= nmax)
    {
      PRINTF ("Max keys %u reached\n", nmax);
      break;
    }
    (void) memcpy (&pkey, data + (cnt * GNUNET_TESTING_HOSTKEYFILESIZE),
                   GNUNET_TESTING_HOSTKEYFILESIZE);
    GNUNET_CRYPTO_eddsa_key_get_public (&pkey, &id.public_key);
    PRINTF ("Key %u: %s\n", cnt, GNUNET_i2s_full (&id));
  }
  result = GNUNET_OK;
  GNUNET_DISK_file_unmap (map);
  GNUNET_DISK_file_close (f);
}


int main (int argc, char *argv[])
{
  struct GNUNET_GETOPT_CommandLineOption option[] = {
    {'n', "num-keys", "COUNT",
     gettext_noop ("list COUNT number of keys"),
     GNUNET_YES, &GNUNET_GETOPT_set_uint, &nkeys},
    {'s', "skip", "COUNT",
     gettext_noop ("skip COUNT number of keys in the beginning"),
     GNUNET_YES, &GNUNET_GETOPT_set_uint, &nskip},
    GNUNET_GETOPT_OPTION_END
  };
  int ret;

  result = GNUNET_SYSERR;
  nkeys = 10;
  ret = 
      GNUNET_PROGRAM_run (argc, argv, "list-keys", "Lists the peer IDs corresponding to the given keys file\n",
                          option, &run, NULL);
  if (GNUNET_OK != ret)
    return 1;
  if (GNUNET_SYSERR == result)
    return 1;
  return 0;
}
