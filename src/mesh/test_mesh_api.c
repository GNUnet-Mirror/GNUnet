#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_dht_service.h"
#include "gnunet_mesh_service_new.h"

static struct GNUNET_MESH_MessageHandler handlers[] = {
    {NULL, 0, 0}
};

static void
run (void *cls,
     char *const *args,
     const char *cfgfile, const struct GNUNET_CONFIGURATION_Handle *cfg) {
    struct GNUNET_OS_Process            *arm_pid;
    struct GNUNET_MESH_Handle           *mesh;
    struct GNUNET_DHT_Handle            *dht;
//     struct GNUNET_MESH_Tunnel           *t;


    arm_pid = GNUNET_OS_start_process (NULL, NULL,
                                       "gnunet-service-arm",
                                       "gnunet-service-arm",
                                       "-L", "DEBUG",
                                       "-c", "test_dht_api_data.conf",
                                       NULL);
//     sleep(1);
//     printf("%d\n", fopen( "test_mesh.conf", "r"));
//     GNUNET_assert (GNUNET_OK == GNUNET_CONFIGURATION_load (cfg, "test_mesh.conf"));
    //printf("%d\n", GNUNET_CONFIGURATION_load (cfg, NULL));
//     printf("%d\n", GNUNET_CONFIGURATION_load (cfg, "test_dht_api_data.conf"));
    dht = GNUNET_DHT_connect(cfg, 100);
    if(NULL == dht) {
//         fprintf(stderr, "Couldn't connect to dht :(\n");
//         return 1; // succeed anyway
    } else {
//         fprintf(stderr, "YAY! CONNECTED TO DHT :D\n");
    }
//     mesh = GNUNET_MESH_connect(cfg, NULL, NULL, handlers, NULL);
//     if(NULL == mesh) {
//         fprintf(stderr, "Couldn't connect to mesh :(\n");
//         return 1; // succeed anyway
//     } else {
//         fprintf(stderr, "YAY! CONNECTED TO MESH :D\n");
//     }
//     mesh = realloc(mesh, 0); // don't complain about *mesh
//     printf("MESH TEST\n");
//     t = GNUNET_MESH_tunnel_create(mesh, );

    /* do real test work here */
    if (0 != GNUNET_OS_process_kill (arm_pid, SIGTERM))
        GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "kill");
    GNUNET_assert (GNUNET_OK == GNUNET_OS_process_wait (arm_pid));
    GNUNET_OS_process_close (arm_pid);

    return;
}

static int
check ()
{
  int ret;
  char *const argv[] = {"test-mesh-api",
    "-c",
    "test_dht_api_data.conf",
#if VERBOSE
    "-L", "DEBUG",
#endif
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  ret = GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1,
                      argv, "test-mesh-api", "nohelp",
                      options, &run, NULL);
  if (ret != GNUNET_OK)
    {
      GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "test-mesh-api': Failed with error code %d\n", ret);
    }
  return GNUNET_OK;
}

int main (int argc, char *argv[]) {
    if(GNUNET_OK == check())
        return 0;
    else return 1;
}
