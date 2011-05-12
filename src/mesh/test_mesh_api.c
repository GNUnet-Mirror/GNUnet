#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_dht_service.h"
#include "gnunet_mesh_service_new.h"

static struct GNUNET_MESH_MessageHandler handlers[] = {
    {NULL, 0, 0}
};

static struct GNUNET_OS_Process            *arm_pid;

static struct GNUNET_MESH_Handle           *mesh;

static struct GNUNET_DHT_Handle            *dht;

static void
  do_shutdown (void *cls,
	       const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (NULL != mesh)
    GNUNET_MESH_disconnect (mesh);
    if (0 != GNUNET_OS_process_kill (arm_pid, SIGTERM))
        GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "kill");
    GNUNET_assert (GNUNET_OK == GNUNET_OS_process_wait (arm_pid));
    GNUNET_OS_process_close (arm_pid);
}


static void
run (void *cls,
     char *const *args,
     const char *cfgfile, const struct GNUNET_CONFIGURATION_Handle *cfg) {
    GNUNET_MESH_ApplicationType         app;
    // char                                buffer[2048];


    arm_pid = GNUNET_OS_start_process (NULL, NULL,
                                       "gnunet-service-arm",
                                       "gnunet-service-arm",
                                       "-L", "DEBUG",
                                       "-c", "test_mesh.conf",
                                       NULL);
    dht = GNUNET_DHT_connect(cfg, 100);
    if(NULL == dht) {
        GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Couldn't connect to dht :(\n");
    } else {
        GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "YAY! CONNECTED TO DHT :D\n");
    }

    app = 0;
    mesh = GNUNET_MESH_connect(cfg, NULL, NULL, handlers, &app);
    if(NULL == mesh) {
        GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Couldn't connect to mesh :(\n");
    } else {
        GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "YAY! CONNECTED TO MESH :D\n");
    }

    /* do real test work here */
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
				  &do_shutdown,
				  NULL);
}





int main (int argc, char *argv[]) {
    int ret;
    char *const argv2[] = {"test-mesh-api",
        "-c", "test_mesh.conf",
        "-L", "DEBUG",
        NULL
    };
    struct GNUNET_GETOPT_CommandLineOption options[] = {
        GNUNET_GETOPT_OPTION_END
    };
      GNUNET_log_setup ("test-dht-api","DEBUG", NULL);
    ret = GNUNET_PROGRAM_run ((sizeof (argv2) / sizeof (char *)) - 1,
                        argv2, "test-mesh-api", "nohelp",
                        options, &run, NULL);
    if (ret != GNUNET_OK) {
        GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "test-mesh-api': Failed with error code %d\n", ret);
    }
    return 0;
}
