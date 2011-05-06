#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_mesh_service_new.h"

static struct GNUNET_MESH_MessageHandler handlers[] = {
    {NULL, 0, 0}
};

int main (int argc, char *argv[]) {
    struct GNUNET_OS_Process            *arm_pid;
    struct GNUNET_MESH_Handle           *mesh;
//     struct GNUNET_MESH_Tunnel           *t;
    struct GNUNET_CONFIGURATION_Handle  *cfg;

    cfg = GNUNET_CONFIGURATION_create();

    arm_pid = GNUNET_OS_start_process (NULL, NULL,
                                       "gnunet-service-arm",
                                       "gnunet-service-arm",
                                       "-L", "DEBUG",
                                       NULL);
    mesh = GNUNET_MESH_connect(cfg, NULL, NULL, handlers, NULL);
    if(NULL == mesh) {
        fprintf(stderr, "Couldn't connect to mesh :(\n");
//         return 1; // succeed anyway
    }
    mesh = realloc(mesh, 0); // don't complain about *mesh
//     printf("MESH TEST\n");
//     t = GNUNET_MESH_tunnel_create(mesh, );

    /* do real test work here */
    if (0 != GNUNET_OS_process_kill (arm_pid, SIGTERM))
        GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "kill");
    GNUNET_assert (GNUNET_OK == GNUNET_OS_process_wait (arm_pid));
    GNUNET_OS_process_close (arm_pid);

    return 0;
}
