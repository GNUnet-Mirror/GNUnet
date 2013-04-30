#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_util_lib.h"
#include "gnunet_mesh_service.h"

static void
run (void *cls, char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_MESH_Handle *m;

  m =  GNUNET_MESH_connect (cfg, /* the configuration handle */
                            socket, /* cls */
                            NULL, /* No inbound tunnel handler */
                            NULL, /* No in-tunnel cleaner */
                            NULL,
                            NULL); /* We don't get inbound tunnels */
}

int
main (int argc, char **argv)
{
   static const struct GNUNET_GETOPT_CommandLineOption options[] = {
      GNUNET_GETOPT_OPTION_END
  };
   GNUNET_PROGRAM_run (argc, argv, "mesh-test",
                       "help",
                       options, &run, NULL);
  return 0;
}
